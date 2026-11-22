"""Knowledge Graph management views"""
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from django.db.models import Q
from django.http import JsonResponse
from .models import CyberKnowledge, ThreatBookmark
from .forms import KnowledgeForm


def require_admin(view_func):
    """Decorator: require admin role"""
    from functools import wraps
    @wraps(view_func)
    def wrapper(request, *args, **kwargs):
        if not request.user.is_authenticated or not request.user.is_admin_user:
            messages.error(request, 'Admin access required.')
            return redirect('users:login')
        return view_func(request, *args, **kwargs)
    return wrapper


@require_admin
def knowledge_list(request):
    q = request.GET.get('q', '')
    severity = request.GET.get('severity', '')
    knowledge = CyberKnowledge.objects.all()
    if q:
        knowledge = knowledge.filter(
            Q(threat_name__icontains=q) | Q(threat_type__icontains=q) | Q(description__icontains=q)
        )
    if severity:
        knowledge = knowledge.filter(severity=severity)
    return render(request, 'knowledgegraph/list.html', {
        'knowledge': knowledge, 'q': q, 'severity': severity
    })


@login_required
def knowledge_add(request):
    if request.method == 'POST':
        form = KnowledgeForm(request.POST)
        if form.is_valid():
            entry = form.save(commit=False)
            entry.submitted_by = request.user
            if request.user.is_admin_user:
                entry.status = 'approved'
                entry.save()
                messages.success(request, 'Knowledge entry added and approved.')
                return redirect('knowledge:list')
            else:
                entry.status = 'pending'
                entry.save()
                messages.success(request, 'Threat Intelligence submitted successfully. It is pending admin review.')
                return redirect('chatbot:dashboard')
    else:
        form = KnowledgeForm()
    return render(request, 'knowledgegraph/form.html', {'form': form, 'action': 'Submit Threat Intel' if not request.user.is_admin_user else 'Add Knowledge'})


@require_admin
def knowledge_edit(request, pk):
    entry = get_object_or_404(CyberKnowledge, pk=pk)
    if request.method == 'POST':
        form = KnowledgeForm(request.POST, instance=entry)
        if form.is_valid():
            form.save()
            messages.success(request, 'Knowledge entry updated.')
            return redirect('knowledge:list')
    else:
        form = KnowledgeForm(instance=entry)
    return render(request, 'knowledgegraph/form.html', {'form': form, 'action': 'Edit', 'entry': entry})


@require_admin
def knowledge_delete(request, pk):
    entry = get_object_or_404(CyberKnowledge, pk=pk)
    if request.method == 'POST':
        entry.delete()
        messages.success(request, 'Entry deleted.')
        return redirect('knowledge:list')
    return render(request, 'knowledgegraph/confirm_delete.html', {'entry': entry})


@login_required
def knowledge_detail(request, pk):
    entry = get_object_or_404(CyberKnowledge, pk=pk)
    is_bookmarked = False
    if request.user.is_authenticated:
        is_bookmarked = ThreatBookmark.objects.filter(user=request.user, threat=entry).exists()
    return render(request, 'knowledgegraph/detail.html', {'entry': entry, 'is_bookmarked': is_bookmarked})


@login_required
def toggle_bookmark(request, pk):
    if request.method == 'POST':
        threat = get_object_or_404(CyberKnowledge, pk=pk)
        bookmark, created = ThreatBookmark.objects.get_or_create(user=request.user, threat=threat)
        if not created:
            bookmark.delete()
            messages.success(request, f"Removed '{threat.threat_name}' from your followed threats.")
        else:
            messages.success(request, f"You are now following '{threat.threat_name}'.")
    return redirect('knowledge:detail', pk=pk)


@login_required
def graph_visualization(request):
    """Render the dynamic knowledge graph visualization page"""
    return render(request, 'knowledgegraph/graph.html')


@login_required
def api_graph_data(request):
    """Return Knowledge Graph nodes and edges as JSON for Vis.js"""
    knowledge_entries = CyberKnowledge.objects.all()
    
    nodes = []
    edges = []
    
    # Track items by threat_type to easily create edges between similar threats
    type_groups = {}
    
    for entry in knowledge_entries:
        # Determine color based on severity
        severity = entry.severity.upper()
        if severity == 'CRITICAL':
            color = {'background': '#ef4444', 'border': '#b91c1c', 'highlight': {'background': '#f87171', 'border': '#ef4444'}}
        elif severity == 'HIGH':
            color = {'background': '#f59e0b', 'border': '#b45309', 'highlight': {'background': '#fbbf24', 'border': '#f59e0b'}}
        elif severity == 'MEDIUM':
            color = {'background': '#3b82f6', 'border': '#1d4ed8', 'highlight': {'background': '#60a5fa', 'border': '#3b82f6'}}
        else:
            color = {'background': '#10b981', 'border': '#047857', 'highlight': {'background': '#34d399', 'border': '#10b981'}}
            
        nodes.append({
            'id': entry.id,
            'label': entry.threat_name,
            'group': entry.threat_type,
            'color': color,
            'title': f"{entry.threat_name} ({severity})<br>Type: {entry.threat_type}", # Tooltip
            'value': entry.risk_score, # Size of the node
            # Extra data for the info panel on click
            'description': entry.description,
            'attack_method': entry.attack_method,
            'prevention': entry.prevention,
            'severity': severity,
            'risk_score': entry.risk_score,
            'cve': entry.cve_references
        })
        
        if entry.threat_type not in type_groups:
            type_groups[entry.threat_type] = []
        type_groups[entry.threat_type].append(entry.id)
        
    # Generate edges between items of the same threat type (fully connected cluster or chain)
    for group_type, node_ids in type_groups.items():
        # To avoid too many edges, just chain them together or connect to a central hub
        # Here we just link each node to the next one in the same group
        for i in range(len(node_ids) - 1):
            edges.append({
                'from': node_ids[i],
                'to': node_ids[i+1],
                'color': {'color': 'rgba(177, 143, 207, 0.4)'},
                'dashes': True
            })
            
    return JsonResponse({'nodes': nodes, 'edges': edges})

@login_required
def api_query_graph_data(request, query_id):
    """Return Contextual Knowledge Graph nodes and edges for a specific query"""
    from chatbot.models import UserQuery
    from services.reasoning_engine import JointReasoningEngine
    
    user_query = get_object_or_404(UserQuery, pk=query_id, user=request.user)
    
    # Re-run reasoning engine search to get exact matching nodes for this query
    engine = JointReasoningEngine()
    primary_nodes = engine.search_knowledge_base(user_query.query)
    
    if not primary_nodes:
        return JsonResponse({'nodes': [], 'edges': []})
        
    # Focus purely on the #1 most relevant primary node to avoid disconnected multi-clusters
    top_primary_node = primary_nodes[0]
    primary_node_ids = {top_primary_node.id}
    primary_threat_types = {top_primary_node.threat_type}
    
    # Get connected nodes (nodes sharing the same threat_type, limit to 20 to build a nice hub)
    connected_nodes = []
    for t_type in primary_threat_types:
        related = CyberKnowledge.objects.filter(threat_type=t_type).exclude(id=top_primary_node.id)[:20]
        connected_nodes.extend(related)
        
    all_nodes = [top_primary_node] + connected_nodes
    
    nodes = []
    edges = []
    type_groups = {}
    
    for entry in all_nodes:
        # Determine color based on severity
        severity = entry.severity.upper()
        if severity == 'CRITICAL':
            color = {'background': '#ef4444', 'border': '#b91c1c', 'highlight': {'background': '#f87171', 'border': '#ef4444'}}
        elif severity == 'HIGH':
            color = {'background': '#f59e0b', 'border': '#b45309', 'highlight': {'background': '#fbbf24', 'border': '#f59e0b'}}
        elif severity == 'MEDIUM':
            color = {'background': '#3b82f6', 'border': '#1d4ed8', 'highlight': {'background': '#60a5fa', 'border': '#3b82f6'}}
        else:
            color = {'background': '#10b981', 'border': '#047857', 'highlight': {'background': '#34d399', 'border': '#10b981'}}
            
        # Highlight primary nodes slightly differently (e.g. thicker border or bigger size)
        is_primary = entry.id in primary_node_ids
        
        nodes.append({
            'id': entry.id,
            'label': entry.threat_name,
            'group': entry.threat_type,
            'color': color,
            'title': f"{entry.threat_name} ({severity})<br>Type: {entry.threat_type}" + ("<br><b>(Direct Match)</b>" if is_primary else ""),
            'value': entry.risk_score * (1.5 if is_primary else 1.0), # Make primary nodes bigger
            'borderWidth': 3 if is_primary else 1,
            'description': entry.description,
            'attack_method': entry.attack_method,
            'prevention': entry.prevention,
            'severity': severity,
            'risk_score': entry.risk_score,
            'cve': entry.cve_references
        })
        
        if entry.threat_type not in type_groups:
            type_groups[entry.threat_type] = []
        type_groups[entry.threat_type].append(entry.id)
        
    # Generate edges: Connect related nodes directly to their primary node (hub-and-spoke)
    for t_type, primary_ids in type_groups.items():
        # Find which nodes in this type are primary
        p_ids = [nid for nid in primary_ids if nid in primary_node_ids]
        r_ids = [nid for nid in primary_ids if nid not in primary_node_ids]
        
        # If there's a primary node, connect all related nodes to the first primary node of that type
        if p_ids:
            center_node = p_ids[0]
            # Connect center to all related nodes
            for r_id in r_ids:
                edges.append({
                    'from': center_node,
                    'to': r_id,
                    'color': {'color': 'rgba(177, 143, 207, 0.4)'},
                    'dashes': True
                })
            # Connect the primary nodes to each other if there are multiple
            for i in range(len(p_ids) - 1):
                edges.append({
                    'from': p_ids[i],
                    'to': p_ids[i+1],
                    'color': {'color': 'rgba(177, 143, 207, 0.8)'},
                    'width': 2
                })
        else:
            # Fallback if no primary node for some reason
            for i in range(len(primary_ids) - 1):
                edges.append({
                    'from': primary_ids[i],
                    'to': primary_ids[i+1],
                    'color': {'color': 'rgba(177, 143, 207, 0.4)'},
                    'dashes': True
                })
            
    return JsonResponse({'nodes': nodes, 'edges': edges})
