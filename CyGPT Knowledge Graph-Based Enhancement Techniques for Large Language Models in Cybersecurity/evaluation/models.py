"""Response evaluation models"""
from django.db import models


class Evaluation(models.Model):
    STATUS_CHOICES = [
        ('verified', 'Verified'),
        ('partial', 'Partially Verified'),
        ('unverified', 'Unverified'),
    ]
    query = models.ForeignKey('chatbot.UserQuery', on_delete=models.CASCADE, related_name='evaluations')
    hallucination_score = models.FloatField(default=0.0, help_text='0=no hallucination, 1=full hallucination')
    relevance_score = models.FloatField(default=0.0, help_text='0=not relevant, 1=fully relevant')
    verification_status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='unverified')
    keyword_matches = models.IntegerField(default=0)
    created_at = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Eval for Query #{self.query_id} — {self.verification_status}"

    @property
    def reliability_score(self):
        """Combined reliability: high relevance + low hallucination"""
        return round((self.relevance_score + (1 - self.hallucination_score)) / 2 * 100, 1)
