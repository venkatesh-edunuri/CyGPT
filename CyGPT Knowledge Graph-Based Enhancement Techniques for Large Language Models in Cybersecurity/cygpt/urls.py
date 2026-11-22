"""CyGPT URL Configuration"""
from django.contrib import admin
from django.urls import path, include
from django.conf import settings
from django.conf.urls.static import static
from cygpt.views import landing_view

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', landing_view, name='landing'),
    path('users/', include('users.urls')),
    path('chatbot/', include('chatbot.urls')),
    path('knowledge/', include('knowledgegraph.urls')),
    path('adminpanel/', include('adminpanel.urls')),
] + static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)

handler404 = 'cygpt.views.handler404'
handler500 = 'cygpt.views.handler500'
