from django.contrib import admin
from .models import UserQuery


@admin.register(UserQuery)
class UserQueryAdmin(admin.ModelAdmin):
    list_display = ['user', 'query', 'confidence_score', 'created_at']
    list_filter = ['created_at']
    search_fields = ['query', 'user__email']
    readonly_fields = ['created_at']
