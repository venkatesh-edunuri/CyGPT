from django.contrib import admin
from .models import CyberKnowledge


@admin.register(CyberKnowledge)
class CyberKnowledgeAdmin(admin.ModelAdmin):
    list_display = ['threat_name', 'threat_type', 'severity', 'risk_score', 'created_at']
    list_filter = ['severity', 'threat_type']
    search_fields = ['threat_name', 'description']
