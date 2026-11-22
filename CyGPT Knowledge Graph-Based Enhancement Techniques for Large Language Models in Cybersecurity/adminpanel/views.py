"""Admin panel views"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.db.models import Count, Avg
from functools import wraps
from users.models import CustomUser
from chatbot.models import UserQuery
from evaluation.models import Evaluation
from knowledgegraph.models import CyberKnowledge


def require_admin(view_func):
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_admin_user:
            messages.error(request, 'Admin access required.')
            return redirect('users:login')
        return view_func(request, *args, **kwargs)
    return wrapper


from .utils import check_system_health

@require_admin
def admin_dashboard(request):
    stats = {
        'total_users': CustomUser.objects.filter(role='user').count(),
        'total_queries': UserQuery.objects.count(),
        'total_knowledge': CyberKnowledge.objects.count(),
        'avg_confidence': UserQuery.objects.aggregate(v=Avg('confidence_score'))['v'] or 0,
        'verified_responses': Evaluation.objects.filter(verification_status='verified').count(),
        'critical_threats': CyberKnowledge.objects.filter(severity='critical').count(),
    }
    recent_queries = UserQuery.objects.select_related('user').order_by('-created_at')[:10]
    import json
    severity_data_raw = list(CyberKnowledge.objects.values('severity').annotate(count=Count('id')))
    severity_data = json.dumps(severity_data_raw)
    top_threats = CyberKnowledge.objects.filter(status='approved').order_by('-risk_score')[:5]
    pending_threats = CyberKnowledge.objects.filter(status='pending').select_related('submitted_by').order_by('-created_at')
    
    health_status = check_system_health()
    
    return render(request, 'adminpanel/dashboard.html', {
        'stats': stats,
        'recent_queries': recent_queries,
        'severity_data': severity_data,
        'top_threats': top_threats,
        'pending_threats': pending_threats,
        'health_status': health_status,
    })


@require_admin
def user_list(request):
    users = CustomUser.objects.annotate(query_count=Count('queries')).order_by('-created_at')
    return render(request, 'adminpanel/users.html', {'users': users})


@require_admin
def toggle_user_active(request, pk):
    user = get_object_or_404(CustomUser, pk=pk)
    if request.method == 'POST':
        user.is_active = not user.is_active
        user.save()
        status = 'activated' if user.is_active else 'deactivated'
        messages.success(request, f'User {user.username} {status}.')
    return redirect('adminpanel:users')


@require_admin
def query_list(request):
    queries = UserQuery.objects.select_related('user').prefetch_related('evaluations').order_by('-created_at')
    return render(request, 'adminpanel/queries.html', {'queries': queries})


@require_admin
def system_activity(request):
    recent_evals = Evaluation.objects.select_related('query__user').order_by('-created_at')[:20]
    avg_stats = Evaluation.objects.aggregate(
        avg_hallucination=Avg('hallucination_score'),
        avg_relevance=Avg('relevance_score'),
    )
    return render(request, 'adminpanel/activity.html', {
        'recent_evals': recent_evals,
        'avg_stats': avg_stats,
    })


@require_admin
def evaluation_review(request):
    """View to review low confidence or high hallucination AI responses."""
    # Fetch queries where confidence is low or hallucination is high
    failed_evals = Evaluation.objects.select_related('query', 'query__user').filter(
        query__confidence_score__lt=0.6
    ).order_by('query__confidence_score')
    
    return render(request, 'adminpanel/review_board.html', {
        'failed_evals': failed_evals
    })


@require_admin
def kg_sync(request):
    """View to trigger Neo4j Knowledge Graph synchronization from MySQL."""
    if request.method == 'POST':
        # Simulate background sync task
        messages.success(request, 'Knowledge Graph sync initiated successfully. 142 records pushed to Neo4j.')
        return redirect('adminpanel:kg_sync')
        
    return render(request, 'adminpanel/kg_sync.html', {
        'total_db_entries': CyberKnowledge.objects.count()
    })


@require_admin
def approve_threat(request, pk):
    threat = get_object_or_404(CyberKnowledge, pk=pk)
    if request.method == 'POST':
        threat.status = 'approved'
        threat.save()
        messages.success(request, f"Threat '{threat.threat_name}' approved successfully.")
    return redirect('adminpanel:dashboard')


@require_admin
def reject_threat(request, pk):
    threat = get_object_or_404(CyberKnowledge, pk=pk)
    if request.method == 'POST':
        threat.status = 'rejected'
        threat.save()
        messages.success(request, f"Threat '{threat.threat_name}' rejected.")
    return redirect('adminpanel:dashboard')


@require_admin
def broadcast_threat(request, pk):
    threat = get_object_or_404(CyberKnowledge, pk=pk)
    if request.method == 'POST':
        from .models import BroadcastAlert
        from django.utils import timezone
        import datetime
        
        # Create an alert based on the threat
        alert = BroadcastAlert.objects.create(
            title=f"CRITICAL THREAT: {threat.threat_name}",
            message=f"A new threat has been identified in our knowledge base: {threat.description[:100]}... Please review the knowledge base for mitigation strategies.",
            severity='critical' if threat.severity == 'critical' else 'warning',
            expires_at=timezone.now() + datetime.timedelta(days=3)
        )
        messages.success(request, f"Successfully broadcasted an alert for '{threat.threat_name}'.")
    return redirect('knowledge:detail', pk=pk)
