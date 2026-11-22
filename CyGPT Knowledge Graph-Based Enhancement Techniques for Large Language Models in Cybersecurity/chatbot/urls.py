from django.urls import path
from . import views

app_name = 'chatbot'

urlpatterns = [
    path('dashboard/', views.dashboard, name='dashboard'),
    path('chat/', views.chat_view, name='chat'),
    path('ask/', views.ask_query, name='ask'),
    path('history/', views.history, name='history'),
    path('query/<int:pk>/', views.query_detail, name='query_detail'),
    path('query/<int:pk>/delete/', views.delete_query, name='delete_query'),
    path('clear/', views.clear_chat, name='clear_chat'),
    path('new/', views.new_chat, name='new_chat'),
]
