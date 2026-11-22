from django import forms
from .models import CyberKnowledge


class KnowledgeForm(forms.ModelForm):
    class Meta:
        model = CyberKnowledge
        fields = ['threat_name', 'threat_type', 'description', 'attack_method',
                  'prevention', 'severity', 'risk_score', 'related_vulnerabilities', 'cve_references']
        labels = {
            'cve_references': 'CVE References (Known Security Vulnerabilities)',
        }
        widgets = {
            'threat_name': forms.TextInput(attrs={'class': 'form-control'}),
            'threat_type': forms.Select(attrs={'class': 'form-select'}),
            'description': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'attack_method': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'prevention': forms.Textarea(attrs={'class': 'form-control', 'rows': 3}),
            'severity': forms.Select(attrs={'class': 'form-select'}),
            'risk_score': forms.NumberInput(attrs={'class': 'form-control', 'min': 0, 'max': 10, 'step': 0.1}),
            'related_vulnerabilities': forms.Textarea(attrs={'class': 'form-control', 'rows': 2}),
            'cve_references': forms.TextInput(attrs={
                'class': 'form-control', 
                'placeholder': 'Select or type a CVE...', 
                'list': 'cve-examples'
            }),
        }
