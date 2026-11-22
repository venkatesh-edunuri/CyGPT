"""
JWT-equivalent Cryptographic Token Utility
Uses Django's signing framework to generate and validate secure tokens.
Provides offline-ready JSON token generation and verification.
"""
import logging
from django.core import signing
from django.conf import settings
from users.models import CustomUser

logger = logging.getLogger(__name__)

SALT = "cygpt-jwt-salt"

def generate_jwt_token(user) -> str:
    """Generates a secure, cryptographically signed token containing user metadata."""
    payload = {
        "user_id": user.id,
        "email": user.email,
        "role": user.role,
    }
    # Generates token signed with SECRET_KEY
    return signing.dumps(payload, salt=SALT)

def validate_jwt_token(token: str) -> dict:
    """
    Validates token and returns decoded payload.
    Raises signing.SignatureExpired or signing.BadSignature on failure.
    """
    # Max age of token is set to 24 hours (86400 seconds)
    return signing.loads(token, salt=SALT, max_age=86400)

def get_user_from_token(token: str):
    """Retrieves user object from a validated token."""
    try:
        payload = validate_jwt_token(token)
        return CustomUser.objects.get(id=payload["user_id"])
    except (signing.BadSignature, signing.SignatureExpired, CustomUser.DoesNotExist) as e:
        logger.warning(f"JWT Validation failed: {e}")
        return None
