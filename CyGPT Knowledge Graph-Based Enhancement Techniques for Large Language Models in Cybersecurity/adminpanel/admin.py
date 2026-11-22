from django.contrib import admin
from .models import BroadcastAlert

@admin.register(BroadcastAlert)
class BroadcastAlertAdmin(admin.ModelAdmin):
    list_display = ('title', 'severity', 'is_active', 'created_at', 'expires_at')
    list_filter = ('severity', 'is_active')
    search_fields = ('title', 'message')
