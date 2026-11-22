"""
Security Middleware for CyGPT
Handles:
1. Input Sanitization: Filters out dangerous HTML characters from POST parameters.
2. Request Rate Limiting: Limits clients to 60 requests per minute using LocMemCache.
3. Secure Headers: Inject security response headers.
"""
import time
import logging
import re
from django.http import JsonResponse, HttpResponse
from django.core.cache import cache
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)

# Compile dangerous patterns (e.g. script injection)
DANGEROUS_PATTERNS = [
    re.compile(r'<script.*?>.*?</script.*?>', re.IGNORECASE | re.DOTALL),
    re.compile(r'javascript:', re.IGNORECASE),
    re.compile(r'onload\s*=', re.IGNORECASE),
    re.compile(r'onerror\s*=', re.IGNORECASE),
]

class CyGPTSecurityMiddleware(MiddlewareMixin):
    def process_request(self, request):
        # Handle OPTIONS preflight requests
        if request.method == 'OPTIONS':
            response = HttpResponse()
            response['Access-Control-Allow-Origin'] = '*'
            response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
            response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, DELETE, PUT'
            return response

        # 1. Rate Limiting (exempting static files / admin panel admin uploads if needed)
        path = request.path
        if path.startswith('/chatbot/') or path.startswith('/users/'):
            # Identify user by IP or username
            ip = request.META.get('REMOTE_ADDR', '127.0.0.1')
            cache_key = f"rate_{ip}"
            
            # Get request history
            requests = cache.get(cache_key, [])
            now = time.time()
            # Keep only requests within the last 60 seconds
            requests = [r for r in requests if now - r < 60]
            
            if len(requests) >= 60:
                logger.warning(f"Rate limit exceeded for IP: {ip} on path: {path}")
                if request.headers.get('x-requested-with') == 'XMLHttpRequest' or path.endswith('/ask/'):
                    return JsonResponse({'error': 'Rate limit exceeded. Please wait 60 seconds.'}, status=429)
                return HttpResponse('Rate limit exceeded. Please try again later.', status=429)
                
            requests.append(now)
            cache.set(cache_key, requests, 60)

        # 2. Input Sanitization
        if request.method == 'POST':
            # Check if contentType is JSON or form-encoded
            if request.content_type == 'application/json':
                try:
                    # Log query checks but do not overwrite raw json to avoid breaking JSON decoder.
                    # We will sanitize the text inputs inside the query controller instead.
                    pass
                except Exception:
                    pass
            else:
                # Sanitize POST form variables
                mutable_post = request.POST.copy()
                sanitized_any = False
                for key, value in mutable_post.items():
                    original = value
                    for pattern in DANGEROUS_PATTERNS:
                        value = pattern.sub('', value)
                    if value != original:
                        mutable_post[key] = value
                        sanitized_any = True
                if sanitized_any:
                    request.POST = mutable_post

    def process_response(self, request, response):
        # 3. Inject Secure Headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        # Prevent clickjacking
        response['X-Frame-Options'] = 'DENY'
        
        # 4. CORS Support
        response['Access-Control-Allow-Origin'] = '*'
        response['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With'
        response['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS, DELETE, PUT'
        
        # Content Security Policy (CSP) for local environment
        response['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net; "
            "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com https://cdn.jsdelivr.net; "
            "img-src 'self' data:; "
            "connect-src 'self' http://localhost:11434;"
        )
        return response
