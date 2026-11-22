"""Chatbot views — dashboard, chat, history"""
import json
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.db.models import Avg, Count
from .models import UserQuery
from evaluation.models import Evaluation

from services.reasoning_engine import JointReasoningEngine


@login_required
def dashboard(request):
    queries = UserQuery.objects.filter(user=request.user)
    stats = queries.aggregate(
        total=Count('id'),
        avg_confidence=Avg('confidence_score')
    )
    recent = queries[:5]
    return render(request, 'chatbot/dashboard.html', {
        'stats': stats,
        'recent_queries': recent,
    })


@login_required
def chat_view(request):
    from django.utils.dateparse import parse_datetime
    
    queries = UserQuery.objects.filter(user=request.user).order_by('created_at')
    
    # Hide queries from previous sessions if 'New Chat' was clicked
    cleared_at = request.session.get('chat_cleared_at')
    if cleared_at:
        dt = parse_datetime(cleared_at)
        if dt:
            queries = queries.filter(created_at__gte=dt)
    suggestions = [
        "What is a SQL injection attack?",
        "How does ransomware work?",
        "Explain zero-day vulnerabilities",
        "What is a DDoS attack?",
        "How to prevent phishing attacks?",
        "What is cross-site scripting (XSS)?",
    ]
    return render(request, 'chatbot/chat.html', {
        'suggestions': suggestions,
        'history': queries
    })


@login_required
@require_POST
def ask_query(request):
    """AJAX endpoint: process user cybersecurity query through Joint Reasoning Engine"""
    try:
        data = json.loads(request.body)
        query_text = data.get('query', '').strip()
        if not query_text:
            return JsonResponse({'error': 'Query cannot be empty.'}, status=400)
            
        # Security: Enforce safe length constraints to prevent Buffer Overflow / DoS
        if len(query_text) > 4000:
            return JsonResponse({'error': 'Query exceeds maximum allowed limit of 4000 characters.'}, status=400)
            
        # Security: Sanitize query from dangerous HTML tags
        from django.utils.html import escape
        query_text = escape(query_text)

        engine = JointReasoningEngine()
        result = engine.process(query_text, request.user.username)

        # Save query
        user_query = UserQuery.objects.create(
            user=request.user,
            query=query_text,
            ai_response=result['response'],
            confidence_score=result['confidence_score'],
            knowledge_used=result.get('knowledge_context', ''),
        )

        # Save evaluation
        Evaluation.objects.create(
            query=user_query,
            hallucination_score=result['evaluation']['hallucination_score'],
            relevance_score=result['evaluation']['relevance_score'],
            verification_status=result['evaluation']['verification_status'],
            keyword_matches=result['evaluation']['keyword_matches'],
        )

        return JsonResponse({
            'response': result['response'],
            'confidence_score': result['confidence_score'],
            'confidence_label': user_query.confidence_label[0],
            'confidence_color': user_query.confidence_label[1],
            'evaluation': result['evaluation'],
            'knowledge_used': result.get('threats_found', []),
            'query_id': user_query.id,
        })
    except Exception as e:
        return JsonResponse({'error': f'Processing error: {str(e)}'}, status=500)


@login_required
def history(request):
    queries = UserQuery.objects.filter(user=request.user).select_related().prefetch_related('evaluations')
    return render(request, 'chatbot/history.html', {'queries': queries})


@login_required
def query_detail(request, pk):
    query = get_object_or_404(UserQuery, pk=pk, user=request.user)
    evaluation = query.evaluations.first()
    return render(request, 'chatbot/query_detail.html', {'query': query, 'evaluation': evaluation})


@login_required
def delete_query(request, pk):
    query = get_object_or_404(UserQuery, pk=pk, user=request.user)
    if request.method == 'POST':
        query.delete()
        return JsonResponse({'success': True})
    return JsonResponse({'error': 'Method not allowed'}, status=405)


@login_required
@require_POST
def clear_chat(request):
    """Deletes all queries/history associated with the logged-in user."""
    try:
        UserQuery.objects.filter(user=request.user).delete()
        if 'chat_cleared_at' in request.session:
            del request.session['chat_cleared_at']
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': f'Failed to clear chat: {str(e)}'}, status=500)

@login_required
@require_POST
def new_chat(request):
    """Starts a new chat session without deleting old history from DB."""
    from django.utils import timezone
    try:
        request.session['chat_cleared_at'] = timezone.now().isoformat()
        return JsonResponse({'success': True})
    except Exception as e:
        return JsonResponse({'error': f'Failed to start new chat: {str(e)}'}, status=500)

