from django.urls import path
from . import views

app_name = 'adminpanel'

urlpatterns = [
    path('', views.admin_dashboard, name='dashboard'),
    path('users/', views.user_list, name='users'),
    path('users/<int:pk>/toggle/', views.toggle_user_active, name='toggle_user'),
    path('queries/', views.query_list, name='queries'),
    path('activity/', views.system_activity, name='activity'),
    path('review-board/', views.evaluation_review, name='review_board'),
    path('kg-sync/', views.kg_sync, name='kg_sync'),
    path('threats/<int:pk>/approve/', views.approve_threat, name='approve_threat'),
    path('threats/<int:pk>/reject/', views.reject_threat, name='reject_threat'),
    path('threats/<int:pk>/broadcast/', views.broadcast_threat, name='broadcast_threat'),
]
