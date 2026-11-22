from django.contrib import admin
from .models import Evaluation


@admin.register(Evaluation)
class EvaluationAdmin(admin.ModelAdmin):
    list_display = ['query', 'hallucination_score', 'relevance_score', 'verification_status', 'created_at']
    list_filter = ['verification_status']
