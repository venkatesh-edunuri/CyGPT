"""User forms for registration, login, profile, and password recovery"""
from django import forms
from django.contrib.auth.forms import UserCreationForm, AuthenticationForm
from .models import CustomUser


class RegisterForm(UserCreationForm):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={
        'class': 'form-control bg-white text-dark border-secondary',
        'placeholder': 'Email address'
    }))
    username = forms.CharField(widget=forms.TextInput(attrs={
        'class': 'form-control bg-white text-dark border-secondary',
        'placeholder': 'Username'
    }))
    password1 = forms.CharField(label='Password', widget=forms.PasswordInput(attrs={
        'class': 'form-control bg-white text-dark border-secondary',
        'placeholder': 'Password'
    }))
    password2 = forms.CharField(label='Confirm Password', widget=forms.PasswordInput(attrs={
        'class': 'form-control bg-white text-dark border-secondary',
        'placeholder': 'Confirm Password'
    }))

    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'password1', 'password2']


class LoginForm(AuthenticationForm):
    username = forms.EmailField(widget=forms.EmailInput(attrs={
        'class': 'form-control bg-white text-dark border-secondary',
        'placeholder': 'Email address',
        'autofocus': True
    }))
    password = forms.CharField(widget=forms.PasswordInput(attrs={
        'class': 'form-control bg-white text-dark border-secondary',
        'placeholder': 'Password'
    }))


class ProfileForm(forms.ModelForm):
    class Meta:
        model = CustomUser
        fields = ['username', 'email', 'bio', 'avatar']
        widgets = {
            'username': forms.TextInput(attrs={'class': 'form-control bg-white text-dark border-secondary'}),
            'email': forms.EmailInput(attrs={'class': 'form-control bg-white text-dark border-secondary'}),
            'bio': forms.Textarea(attrs={'class': 'form-control bg-white text-dark border-secondary', 'rows': 3}),
        }


class ForgotPasswordForm(forms.Form):
    email = forms.EmailField(required=True, widget=forms.EmailInput(attrs={
        'class': 'form-control bg-white text-dark border-secondary',
        'placeholder': 'Enter your registered email'
    }))


class ResetPasswordForm(forms.Form):
    password1 = forms.CharField(label='New Password', widget=forms.PasswordInput(attrs={
        'class': 'form-control bg-white text-dark border-secondary',
        'placeholder': 'New Password'
    }))
    password2 = forms.CharField(label='Confirm New Password', widget=forms.PasswordInput(attrs={
        'class': 'form-control bg-white text-dark border-secondary',
        'placeholder': 'Confirm New Password'
    }))
