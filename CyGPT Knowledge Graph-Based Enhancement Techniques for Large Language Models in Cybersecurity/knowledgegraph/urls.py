from django.urls import path
from . import views

app_name = 'knowledge'

urlpatterns = [
    path('', views.knowledge_list, name='list'),
    path('add/', views.knowledge_add, name='add'),
    path('graph/', views.graph_visualization, name='graph'),
    path('api/graph-data/', views.api_graph_data, name='api_graph_data'),
    path('api/graph-data/query/<int:query_id>/', views.api_query_graph_data, name='api_query_graph_data'),
    path('<int:pk>/edit/', views.knowledge_edit, name='edit'),
    path('<int:pk>/delete/', views.knowledge_delete, name='delete'),
    path('<int:pk>/', views.knowledge_detail, name='detail'),
    path('<int:pk>/bookmark/', views.toggle_bookmark, name='toggle_bookmark'),
]
