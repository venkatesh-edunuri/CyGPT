"""Chatbot query and response models"""
from django.db import models
from django.conf import settings


class UserQuery(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='queries')
    query = models.TextField()
    ai_response = models.TextField(blank=True)
    confidence_score = models.FloatField(default=0.0)
    knowledge_used = models.TextField(blank=True, help_text='Knowledge entries used in this query')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username}: {self.query[:50]}"

    @property
    def confidence_label(self):
        if self.confidence_score >= 0.8:
            return ('High', 'success')
        elif self.confidence_score >= 0.5:
            return ('Medium', 'warning')
        return ('Low', 'danger')
