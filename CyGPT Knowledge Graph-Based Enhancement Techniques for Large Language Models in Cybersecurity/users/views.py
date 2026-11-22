"""User authentication, profile, password recovery, and JWT token views"""
import json
import logging
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import login, logout, authenticate, update_session_auth_hash
from django.contrib.auth.decorators import login_required
from django.contrib.auth.forms import PasswordChangeForm
from django.contrib import messages
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST
from django.core import signing

from .forms import RegisterForm, LoginForm, ProfileForm, ForgotPasswordForm, ResetPasswordForm
from .models import CustomUser
from .jwt_utils import generate_jwt_token, validate_jwt_token
from chatbot.models import UserQuery

logger = logging.getLogger(__name__)


def register_view(request):
    if request.user.is_authenticated:
        return redirect('chatbot:dashboard')
    if request.method == 'POST':
        form = RegisterForm(request.POST)
        if form.is_valid():
            try:
                user = form.save()
                login(request, user)
                messages.success(request, 'Account created successfully! Welcome to CyGPT.')
                return redirect('chatbot:dashboard')
            except Exception as e:
                logger.error(f"Error saving registered user: {e}")
                messages.error(request, 'Registration failed due to a database error.')
        else:
            messages.error(request, 'Registration failed. Please check the form fields.')
    else:
        form = RegisterForm()
    return render(request, 'users/register.html', {'form': form})


def login_view(request):
    if request.user.is_authenticated:
        return redirect('chatbot:dashboard')
    if request.method == 'POST':
        form = LoginForm(request, data=request.POST)
        if form.is_valid():
            user = form.get_user()
            login(request, user)
            messages.success(request, f'Welcome back, {user.username}!')
            next_url = request.GET.get('next', 'chatbot:dashboard')
            return redirect(next_url)
        else:
            messages.error(request, 'Invalid email or password.')
    else:
        form = LoginForm()
    return render(request, 'users/login.html', {'form': form})


def logout_view(request):
    logout(request)
    messages.info(request, 'You have been logged out.')
    return redirect('/')


@login_required
def profile_view(request):
    query_count = UserQuery.objects.filter(user=request.user).count()
    recent_queries = UserQuery.objects.filter(user=request.user).order_by('-created_at')[:5]
    
    # User's actionable data
    from knowledgegraph.models import ThreatBookmark, CyberKnowledge
    bookmarked_threats = ThreatBookmark.objects.filter(user=request.user).select_related('threat').order_by('-created_at')
    submitted_threats = CyberKnowledge.objects.filter(submitted_by=request.user).order_by('-created_at')
    
    if request.method == 'POST':
        form = ProfileForm(request.POST, request.FILES, instance=request.user)
        if form.is_valid():
            try:
                form.save()
                messages.success(request, 'Profile updated successfully!')
                return redirect('users:profile')
            except Exception as e:
                logger.error(f"Profile save failure: {e}")
                messages.error(request, 'Failed to save profile changes.')
    else:
        form = ProfileForm(instance=request.user)
        
    # Calculate profile completion percentage
    fields_to_check = ['username', 'email', 'bio', 'avatar']
    completed_count = sum(1 for field in fields_to_check if getattr(request.user, field, None))
    profile_completion = int((completed_count / len(fields_to_check)) * 100)
    
    return render(request, 'users/profile.html', {
        'form': form,
        'query_count': query_count,
        'recent_queries': recent_queries,
        'bookmarked_threats': bookmarked_threats,
        'submitted_threats': submitted_threats,
        'profile_completion': profile_completion,
    })


@login_required
def settings_view(request):
    if request.method == 'POST':
        if 'update_profile' in request.POST:
            profile_form = ProfileForm(request.POST, request.FILES, instance=request.user)
            password_form = PasswordChangeForm(request.user)
            password_form.fields['old_password'].widget.attrs.pop('autofocus', None)
            if profile_form.is_valid():
                profile_form.save()
                messages.success(request, 'Profile updated successfully!')
                return redirect('users:settings')
        elif 'update_password' in request.POST:
            profile_form = ProfileForm(instance=request.user)
            password_form = PasswordChangeForm(request.user, request.POST)
            password_form.fields['old_password'].widget.attrs.pop('autofocus', None)
            if password_form.is_valid():
                user = password_form.save()
                update_session_auth_hash(request, user)
                messages.success(request, 'Password updated successfully!')
                return redirect('users:settings')
    else:
        profile_form = ProfileForm(instance=request.user)
        password_form = PasswordChangeForm(request.user)
        password_form.fields['old_password'].widget.attrs.pop('autofocus', None)
        
    return render(request, 'users/settings.html', {
        'profile_form': profile_form,
        'password_form': password_form
    })


def forgot_password_view(request):
    """Generates password reset token and outputs reset link for local environment."""
    if request.method == 'POST':
        form = ForgotPasswordForm(request.POST)
        if form.is_valid():
            email = form.cleaned_data['email'].strip()
            try:
                user = CustomUser.objects.filter(email__iexact=email).first()
                if user:
                    # Generate a signed token containing user ID
                    token = signing.dumps({"user_id": user.id}, salt="password-reset")
                    reset_link = request.build_absolute_uri(f"/users/reset-password/{token}/")
                    # Log the reset link and display on screen for easy local usage
                    logger.info(f"Password reset link generated: {reset_link}")
                    messages.success(
                        request,
                        f"A password reset link has been generated for local/offline testing: <a href='{reset_link}' class='alert-link text-break'>{reset_link}</a>"
                    )
                else:
                    messages.info(request, "If that email is registered, we have processed the reset request.")
                return render(request, 'users/forgot_password.html', {'form': form, 'done': True})
            except Exception as e:
                logger.error(f"Forgot password error: {e}")
                messages.error(request, "An error occurred while processing password reset.")
    else:
        form = ForgotPasswordForm()
    return render(request, 'users/forgot_password.html', {'form': form})


def reset_password_view(request, token):
    """Validates secure reset token and updates user password."""
    try:
        data = signing.loads(token, salt="password-reset", max_age=3600)  # Valid for 1 hour
        user = get_object_or_404(CustomUser, id=data["user_id"])
    except signing.SignatureExpired:
        messages.error(request, "The password reset link has expired.")
        return redirect('users:login')
    except signing.BadSignature:
        messages.error(request, "Invalid password reset token.")
        return redirect('users:login')

    if request.method == 'POST':
        form = ResetPasswordForm(request.POST)
        if form.is_valid():
            pwd1 = form.cleaned_data['password1']
            pwd2 = form.cleaned_data['password2']
            if pwd1 != pwd2:
                form.add_error('password2', 'Passwords do not match.')
            else:
                try:
                    user.set_password(pwd1)
                    user.save()
                    messages.success(request, "Password reset successfully. You can now log in.")
                    return redirect('users:login')
                except Exception as e:
                    logger.error(f"Password reset save error: {e}")
                    messages.error(request, "Failed to update password in database.")
    else:
        form = ResetPasswordForm()
    return render(request, 'users/reset_password.html', {'form': form, 'token': token})


@csrf_exempt
def api_login_token(request):
    """REST endpoint: Log in and return a JWT-equivalent signed authentication token."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required.'}, status=405)
    try:
        data = json.loads(request.body)
        email = data.get('email', '').strip()
        password = data.get('password', '')
        
        if not email or not password:
            return JsonResponse({'error': 'Email and password required.'}, status=400)
            
        user = authenticate(request, username=email, password=password)
        if user is not None:
            if not user.is_active:
                return JsonResponse({'error': 'User account is deactivated.'}, status=403)
            token = generate_jwt_token(user)
            return JsonResponse({
                'success': True,
                'token': token,
                'user': {
                    'username': user.username,
                    'email': user.email,
                    'role': user.role
                }
            })
        else:
            return JsonResponse({'error': 'Invalid credentials.'}, status=401)
    except Exception as e:
        logger.error(f"API login token error: {e}")
        return JsonResponse({'error': 'Internal server error.'}, status=500)


@csrf_exempt
def api_verify_token(request):
    """REST endpoint: Validate a JWT-equivalent authentication token."""
    if request.method != 'POST':
        return JsonResponse({'error': 'POST method required.'}, status=405)
    try:
        data = json.loads(request.body)
        token = data.get('token', '').strip()
        if not token:
            return JsonResponse({'error': 'Token is required.'}, status=400)
            
        try:
            payload = validate_jwt_token(token)
            return JsonResponse({
                'valid': True,
                'payload': payload
            })
        except signing.SignatureExpired:
            return JsonResponse({'valid': False, 'error': 'Token has expired.'}, status=401)
        except signing.BadSignature:
            return JsonResponse({'valid': False, 'error': 'Invalid token signature.'}, status=401)
    except Exception as e:
        logger.error(f"API token validation error: {e}")
        return JsonResponse({'error': 'Internal server error.'}, status=500)
