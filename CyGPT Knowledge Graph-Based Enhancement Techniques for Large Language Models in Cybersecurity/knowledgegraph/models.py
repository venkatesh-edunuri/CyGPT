"""Cybersecurity Knowledge Graph models"""
from django.db import models


from django.conf import settings

class CyberKnowledge(models.Model):
    SEVERITY_CHOICES = [
        ('low', 'Low'),
        ('medium', 'Medium'),
        ('high', 'High'),
        ('critical', 'Critical'),
    ]
    STATUS_CHOICES = [
        ('pending', 'Pending Approval'),
        ('approved', 'Approved'),
        ('rejected', 'Rejected'),
    ]
    THREAT_TYPE_CHOICES = [
        ('Malware', 'Malware'),
        ('Phishing', 'Phishing'),
        ('Ransomware', 'Ransomware'),
        ('DDoS', 'DDoS'),
        ('SQL Injection', 'SQL Injection'),
        ('Cross-Site Scripting (XSS)', 'Cross-Site Scripting (XSS)'),
        ('Zero-Day Exploit', 'Zero-Day Exploit'),
        ('Social Engineering', 'Social Engineering'),
        ('Insider Threat', 'Insider Threat'),
        ('Advanced Persistent Threat (APT)', 'Advanced Persistent Threat (APT)'),
        ('Other', 'Other'),
    ]
    
    threat_name = models.CharField(max_length=200)
    threat_type = models.CharField(max_length=100, choices=THREAT_TYPE_CHOICES, default='Malware')
    description = models.TextField()
    attack_method = models.TextField()
    prevention = models.TextField()
    severity = models.CharField(max_length=20, choices=SEVERITY_CHOICES, default='medium')
    risk_score = models.FloatField(default=5.0)
    related_vulnerabilities = models.TextField(blank=True)
    cve_references = models.TextField(blank=True, help_text='CVE IDs comma-separated')
    
    status = models.CharField(max_length=20, choices=STATUS_CHOICES, default='approved')
    submitted_by = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.SET_NULL, null=True, blank=True, related_name='submitted_threats')
    
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ['-risk_score', '-created_at']
        verbose_name = 'Cyber Knowledge'
        verbose_name_plural = 'Cyber Knowledge'

    def __str__(self):
        return f"{self.threat_name} ({self.severity})"

    @property
    def severity_color(self):
        colors = {'low': 'success', 'medium': 'warning', 'high': 'danger', 'critical': 'danger'}
        return colors.get(self.severity, 'secondary')


class ThreatBookmark(models.Model):
    user = models.ForeignKey(settings.AUTH_USER_MODEL, on_delete=models.CASCADE, related_name='bookmarked_threats')
    threat = models.ForeignKey(CyberKnowledge, on_delete=models.CASCADE, related_name='bookmarks')
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        unique_together = ('user', 'threat')
        ordering = ['-created_at']

    def __str__(self):
        return f"{self.user.username} bookmarked {self.threat.threat_name}"
