"""Password validation and verification helpers"""
from flask import current_app


def verify_password(user, password):
    """Verify password against Argon2id hash"""
    if not user:
        return False
    try:
        from argon2 import PasswordHasher
        ph = PasswordHasher()
        ph.verify(user['password_hash'], password)
        return True
    except Exception as e:
        current_app.logger.debug('Password verification failed: %s', str(e))
        return False
