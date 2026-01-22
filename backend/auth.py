from flask import Blueprint, request, jsonify, g, session, make_response, current_app
from helpers.sanitize import clean_input
from argon2 import PasswordHasher
import os
import re
import time
import sqlite3
import pyotp
import base64

# Import helper modules
from constants import *
from session_keys import SessionKeys
from db_queries import UserQueries, LoginAttemptQueries, RecoveryCodeQueries
from helpers.rate_limiter import get_block_status, apply_failed_attempt_delay, record_login_attempt, reset_failed_attempts, check_rate_limit
from helpers.qr_cleanup import cleanup_qr_file, cleanup_qr_files_for_user
from helpers.crypto_helpers import is_strong_password, generate_rsa_keypair, encrypt_private_key, decrypt_private_key
from helpers.password_helpers import verify_password
from helpers.totp_helpers import verify_totp_code, user_has_2fa_enabled, generate_totp_qr, complete_2fa_login

auth_bp = Blueprint('auth', __name__)
ph = PasswordHasher()  # Argon2id for password_hash


# ========== REGISTRATION ==========


@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = clean_input(data.get('username', '').strip())
    email = data.get('email', '').strip().lower()
    email = clean_input(email)
    password = data.get('password', '')

    # Validate input
    if not username or not email or not password:
        return jsonify({'error': 'Wszystkie pola są wymagane.'}), 400
    
    if len(username) < USERNAME_MIN_LENGTH or len(username) > USERNAME_MAX_LENGTH or not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return jsonify({'error': ERROR_INVALID_USERNAME}), 400
    
    if not re.match(r'^\S+@\S+\.\S+$', email):
        return jsonify({'error': ERROR_INVALID_EMAIL}), 400
    
    if not is_strong_password(password):
        return jsonify({'error': ERROR_WEAK_PASSWORD}), 400

    # CHECK IF USERNAME OR EMAIL ALREADY EXIST (before 2FA setup)
    if UserQueries.username_exists(username):
        return jsonify({'error': ERROR_USERNAME_EXISTS}), 409
    
    if UserQueries.email_exists(email):
        return jsonify({'error': ERROR_EMAIL_EXISTS}), 409

    try:
        # Hash password and generate encryption keys
        password_hash = ph.hash(password)
        public_key, private_key = generate_rsa_keypair()
        salt = os.urandom(16)
        private_key_encrypted = encrypt_private_key(private_key, password, salt)
        
        # Generate TOTP and QR code
        totp_secret = pyotp.random_base32()
        provisioning_uri, provisioning_qr, provisioning_qr_path = generate_totp_qr(
            totp_secret, email, username
        )
        
        # Generate recovery codes (plaintext for this registration only!)
        from db import generate_recovery_codes
        recovery_codes = generate_recovery_codes(10)
        
        # Store in session
        session[SessionKeys.REG_PENDING] = {
            'username': username,
            'email': email,
            'password_hash': password_hash,
            'salt_b64': base64.b64encode(salt).decode('ascii'),
            'public_key': public_key,
            'private_key_encrypted': private_key_encrypted,
            'totp_secret': totp_secret,
            'provisioning_qr_path': provisioning_qr_path,
            'recovery_codes': recovery_codes
        }
        
        return jsonify({
            'message': MSG_REGISTRATION_PREPARED,
            'provisioning_uri': provisioning_uri,
            'provisioning_qr': provisioning_qr,
            'provisioning_qr_path': provisioning_qr_path,
            'totp_secret': totp_secret
        }), 201
    
    except Exception as e:
        current_app.logger.warning('Registration error: %s', str(e))
        return jsonify({'error': ERROR_REGISTRATION_FAILED}), 500


# LOGIN


# Check login block status
@auth_bp.route('/api/check-login-block', methods=['POST'])
def check_login_block():
    """Check if user account is blocked due to failed login attempts"""
    data = request.get_json() or {}
    username = clean_input(data.get('username', '').strip())
    
    if not username:
        return jsonify({'blocked': False, 'remaining': 0}), 200
    
    is_blocked, remaining_seconds, block_type = get_block_status(username)
    
    if is_blocked:
        block_message = ERROR_TOO_MANY_ATTEMPTS_LONG if block_type == 'long' else ERROR_TOO_MANY_ATTEMPTS_SHORT
        return jsonify({
            'blocked': True, 
            'remaining': remaining_seconds,
            'message': block_message,
            'block_type': block_type
        }), 200
    
    return jsonify({'blocked': False, 'remaining': 0}), 200


@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = clean_input(data.get('username', '').strip())
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': ERROR_INVALID_CREDENTIALS}), 401
    
    # Check rate limit
    rate_limit_error = check_rate_limit(username)
    if rate_limit_error:
        return rate_limit_error
    
    # Find user
    user = UserQueries.get_by_username_or_email(username)
    
    # Verify password
    password_valid = verify_password(user, password)
    
    if not password_valid:
        record_login_attempt(username, 0)
        failed_count = LoginAttemptQueries.get_recent_failed_count(username, RATE_LIMIT_WINDOW_MIN)
        apply_failed_attempt_delay(failed_count)
        return jsonify({'error': ERROR_INVALID_CREDENTIALS}), 401
    
    # Password valid
    record_login_attempt(username, 1)
    
    # Check if user has 2FA enabled (disabled for test users)
    if user_has_2fa_enabled(user):
        # Require 2FA verification
        session[SessionKeys.PRE_2FA_USER_ID] = user['id']
        return jsonify({'message': MSG_LOGIN_REQUIRES_2FA, '2fa_required': True}), 200
    else:
        # Complete login for user without 2FA
        try:
            session[SessionKeys.USER_ID] = user['id']
            UserQueries.update_last_login(user['id'])
            # Reset failed login attempts after successful login
            reset_failed_attempts(username)
        except Exception as e:
            current_app.logger.error('Error during login: %s', str(e))
        return jsonify({'message': MSG_LOGIN_SUCCESS, 'id': user['id']}), 200


# PASSWORD RESET

@auth_bp.route('/api/forgot-password', methods=['POST'])
def forgot_password():
    """Start password reset process with email verification"""
    data = request.get_json() or {}
    email = clean_input(data.get('email', '').strip().lower())
    
    if not email:
        return jsonify({'error': 'Podaj email.'}), 400
    
    user = UserQueries.get_by_email(email)
    
    if not user:
        # Don't reveal if email exists (security)
        return jsonify({'message': MSG_PASSWORD_RESET_LINK_SENT}), 200
    
    # Store in session for recovery code verification
    session[SessionKeys.PASSWORD_RESET_USER_ID] = user['id']
    session[SessionKeys.PASSWORD_RESET_EMAIL] = email
    
    return jsonify({
        'message': MSG_PASSWORD_RESET_LINK_SENT,
        'requires_recovery_code': True
    }), 200


@auth_bp.route('/api/verify-recovery-for-password-reset', methods=['POST'])
def verify_recovery_for_password_reset():
    """Verify recovery code for password reset"""
    data = request.get_json() or {}
    recovery_code = clean_input(data.get('recovery_code', '').strip())
    
    # Get user from session
    user_id = session.get(SessionKeys.PASSWORD_RESET_USER_ID)
    if not user_id:
        return jsonify({'error': 'Sesja wygasła. Zacznij od nowa.'}), 401
    
    user = UserQueries.get_by_id(user_id)
    if not user:
        return jsonify({'error': ERROR_USER_NOT_FOUND}), 404
    
    # Verify recovery code
    from db import verify_recovery_code, hash_recovery_code
    recovery_codes = RecoveryCodeQueries.get_all_for_user(user_id)
    
    code_valid = False
    for row in recovery_codes:
        if verify_recovery_code(recovery_code, row['code_hash']):
            code_valid = True
            break
    
    if not code_valid:
        return jsonify({'error': ERROR_INVALID_RECOVERY_CODE}), 401
    
    # Mark recovery code as used
    RecoveryCodeQueries.mark_as_used(user_id, recovery_code)
    
    # Store in session for password change
    session[SessionKeys.CAN_RESET_PASSWORD] = True
    session[SessionKeys.PASSWORD_RESET_USER_ID] = user_id
    
    return jsonify({'message': 'Kod zweryfikowany. Teraz ustaw nowe hasło.'}), 200


@auth_bp.route('/api/reset-password', methods=['POST'])
def reset_password():
    """Reset password after recovery code verification"""
    # Check if user has verified recovery code
    if not session.get(SessionKeys.CAN_RESET_PASSWORD):
        return jsonify({'error': 'Musisz najpierw zweryfikować kod odzyskiwania.'}), 401
    
    user_id = session.get(SessionKeys.PASSWORD_RESET_USER_ID)
    if not user_id:
        return jsonify({'error': 'Sesja wygasła.'}), 401
    
    data = request.get_json() or {}
    new_password = data.get('new_password', '')
    confirm_password = data.get('confirm_password', '')
    
    if not new_password or not confirm_password:
        return jsonify({'error': 'Oba pola są wymagane.'}), 400
    
    if new_password != confirm_password:
        return jsonify({'error': ERROR_PASSWORD_MISMATCH}), 400
    
    if not is_strong_password(new_password):
        return jsonify({'error': ERROR_WEAK_PASSWORD}), 400
    
    # Update password in database
    try:
        user = UserQueries.get_by_id(user_id)
        if not user:
            return jsonify({'error': ERROR_USER_NOT_FOUND}), 404
        
        # Hash new password
        new_password_hash = ph.hash(new_password)
        
        # Get existing salt or generate new one
        salt = user['salt'] if user['salt'] else os.urandom(16)
        
        # Generate new RSA keypair encrypted with new password
        public_key, private_key = generate_rsa_keypair()
        private_key_encrypted = encrypt_private_key(private_key, new_password, salt)
        
        # Update password and re-encrypted private key
        UserQueries.update_keys_and_password(user_id, new_password_hash, public_key, private_key_encrypted)
        
        # Cleanup QR files from password reset (if any)
        cleanup_qr_files_for_user(user_id)
        
        # Clear session
        session.pop(SessionKeys.CAN_RESET_PASSWORD, None)
        session.pop(SessionKeys.PASSWORD_RESET_USER_ID, None)
        session.pop(SessionKeys.PASSWORD_RESET_EMAIL, None)
        
        return jsonify({'message': MSG_PASSWORD_RESET_SUCCESS}), 200
    except Exception as e:
        current_app.logger.error('Error resetting password: %s', str(e))
        return jsonify({'error': 'Błąd podczas zmiany hasła.'}), 500


# 2FA VERIFICATION

@auth_bp.route('/api/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json() or {}
    code = str(data.get('code', '')).strip()

    # Case A: finishing pending registration
    if session.get(SessionKeys.REG_PENDING) is not None:
        return _verify_2fa_registration(code)
    
    # Case B: existing user finishing login 2FA
    if session.get(SessionKeys.PRE_2FA_USER_ID) is not None:
        return _verify_2fa_login(code)
    
    # No valid session state
    return jsonify({'error': ERROR_2FA_FAILED}), 401


def _verify_2fa_registration(code):
    """Handle 2FA verification during registration"""
    reg = session.get(SessionKeys.REG_PENDING)
    
    if not code:
        return jsonify({'error': ERROR_2FA_FAILED}), 401
    
    totp_secret = reg.get('totp_secret')
    if not totp_secret:
        return jsonify({'error': ERROR_2FA_FAILED}), 401
    
    # Verify TOTP code
    ok = verify_totp_code(totp_secret, code)
    record_login_attempt(reg.get('username'), 1 if ok else 0)
    
    if not ok:
        time.sleep(0.5)
        return jsonify({'error': ERROR_2FA_FAILED}), 401

    # Insert user into database
    try:
        salt_bytes = base64.b64decode(reg.get('salt_b64')) if reg.get('salt_b64') else os.urandom(16)
        new_id = UserQueries.create_user(
            reg.get('username'), reg.get('email'), reg.get('password_hash'),
            salt_bytes, reg.get('public_key'), reg.get('private_key_encrypted'),
            reg.get('totp_secret')
        )
        
        # Use recovery codes from session (generated in /api/register)
        recovery_codes = reg.get('recovery_codes', [])
        RecoveryCodeQueries.save_codes(new_id, recovery_codes)

    except sqlite3.IntegrityError as e:
        m = str(e)
        try:
            if 'users.username' in m:
                return jsonify({'error': ERROR_USERNAME_EXISTS}), 409
            if 'users.email' in m:
                return jsonify({'error': ERROR_EMAIL_EXISTS}), 409
        except Exception:
            pass
        return jsonify({'error': ERROR_REGISTRATION_FAILED}), 409
    except Exception as e:
        current_app.logger.error('Registration error: %s', str(e))
        return jsonify({'error': ERROR_REGISTRATION_FAILED}), 500

    # Get recovery codes from session before clearing it
    recovery_codes = reg.get('recovery_codes', [])
    
    # Finalize session - only clear reg pending (don't create session, user needs to login)
    session.pop(SessionKeys.REG_PENDING, None)

    # Cleanup QR file from registration
    cleanup_qr_file(reg.get('provisioning_qr_path'))

    return jsonify({
        'message': MSG_REGISTRATION_SUCCESS,
        'recovery_codes': recovery_codes
    }), 201


def _verify_2fa_login(code):
    """Handle 2FA verification during login"""
    pre_id = session.get(SessionKeys.PRE_2FA_USER_ID)
    
    if not pre_id or not code:
        return jsonify({'error': ERROR_2FA_FAILED}), 401
    
    user = UserQueries.get_by_id(pre_id)
    if not user:
        return jsonify({'error': ERROR_2FA_FAILED}), 401

    # Get TOTP secret
    try:
        totp_secret = user['totp_secret']
    except Exception:
        totp_secret = None

    # Verify TOTP is configured
    if not totp_secret or totp_secret == 'TOTP_SECRET_PLACEHOLDER':
        record_login_attempt(user['username'], 0)
        return jsonify({'error': ERROR_2FA_FAILED}), 401

    # Verify TOTP code
    ok = verify_totp_code(totp_secret, code)
    record_login_attempt(user['username'], 1 if ok else 0)
    
    if not ok:
        time.sleep(0.5)
        return jsonify({'error': ERROR_2FA_FAILED}), 401

    # Complete login
    return complete_2fa_login(user)


# PRIVATE KEY RETRIEVAL 
@auth_bp.route('/api/get-private-key', methods=['POST'])
def get_private_key():
    """Get decrypted private key for logged-in user"""
    data = request.get_json() or {}
    password = data.get('password', '')
    
    user_id = session.get(SessionKeys.USER_ID)
    if not user_id:
        return jsonify({'error': ERROR_UNAUTHORIZED}), 401
    
    user = UserQueries.get_by_id(user_id)
    
    if not user:
        return jsonify({'error': ERROR_USER_NOT_FOUND}), 404
    
    # Verify password
    try:
        ph.verify(user['password_hash'], password)
    except Exception as e:
        current_app.logger.debug('Password verification failed for private key: %s', str(e))
        return jsonify({'error': 'Nieprawidłowe hasło.'}), 401
    
    # Decrypt private key
    try:
        salt = user['salt']
        encrypted_key = user['private_key_encrypted']
        private_key = decrypt_private_key(encrypted_key, password, salt)
        
        if not private_key:
            return jsonify({'error': 'Nie udało się odszyfrować klucza prywatnego.'}), 500
        
        return jsonify({'private_key': private_key}), 200
    except Exception as e:
        current_app.logger.error('Error decrypting private key: %s', str(e))
        return jsonify({'error': 'Nie udało się odszyfrować klucza prywatnego.'}), 500

@auth_bp.route('/api/logout', methods=['POST'])
def logout():
    try:
        session.pop(SessionKeys.USER_ID, None)
        session.pop(SessionKeys.PRE_2FA_USER_ID, None)
        session.pop(SessionKeys.REG_PENDING, None)
        session.pop(SessionKeys.TWO_FA_VERIFIED, None)
        session.pop(SessionKeys.IN_2FA_RECOVERY_MODE, None)
    except Exception as e:
        current_app.logger.error('Error during logout: %s', str(e))
    return jsonify({'message': MSG_LOGOUT_SUCCESS}), 200


# ========== 2FA RECOVERY - RECOVERY CODE VERIFICATION ==========

@auth_bp.route('/api/auth/2fa-recovery', methods=['POST'])
def recovery_code_verification():
    """
    Verify recovery code when user lost access to 2FA app.
    
    1. User is in 2FA verification step (pre_2fa_user_id set)
    2. User provides recovery code instead of TOTP code
    3. Verification of recovery code
    4. Removing token 2FA 
    5. New session
    6. Setting up new 2FA
    7. Generating new recovery codes
    """
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    recovery_code = data.get('recovery_code', '').strip()
    
    if not email or not recovery_code:
        return jsonify({'error': 'Email i recovery code są wymagane.'}), 400
    
    # Verify recovery code and get user
    user = RecoveryCodeQueries.get_user_by_code(email, recovery_code)
    
    if not user:
        # Security: Don't reveal if email/code is invalid
        time.sleep(0.5)
        return jsonify({'error': ERROR_INVALID_RECOVERY_CODE}), 401
    
    # Recovery code is valid! Mark it as used
    RecoveryCodeQueries.mark_as_used(user['id'], recovery_code)
    
    # Remove 2FA (force setup new one) - set to empty string instead of NULL
    UserQueries.update_totp_secret(user['id'], '')
    
    # Create session
    session[SessionKeys.USER_ID] = user['id']
    session[SessionKeys.TWO_FA_VERIFIED] = True
    session[SessionKeys.IN_2FA_RECOVERY_MODE] = True  # ← Flag to force setup new 2FA
    
    return jsonify({
        'success': True,
        'message': '2FA recovery kod zaakceptowany. Musisz teraz ustawić nowy 2FA.',
        'requires_2fa_setup': True,
        'user_id': user['id']
    }), 200

# FORCED 2FA SETUP (after recovery)

@auth_bp.route('/api/setup-2fa-forced', methods=['GET'])
def setup_2fa_forced():
    """Get 2FA setup info for forced setup after recovery code usage"""
    user_id = session.get(SessionKeys.USER_ID)
    
    if not user_id:
        return jsonify({'error': ERROR_UNAUTHORIZED}), 401
    
    # Get user info for QR generation
    user = UserQueries.get_by_id(user_id)
    
    if not user:
        return jsonify({'error': ERROR_USER_NOT_FOUND}), 401
    
    # Generate new TOTP secret
    totp_secret = pyotp.random_base32()
    
    # Generate QR code with user email
    provisioning_uri, provisioning_qr, provisioning_qr_path = generate_totp_qr(
        totp_secret, user['email'], user['username']
    )
    
    # Store in session temporarily
    session[SessionKeys.FORCE_2FA_SECRET] = totp_secret
    session[SessionKeys.FORCE_2FA_QR_PATH] = provisioning_qr_path
    
    return jsonify({
        'totp_secret': totp_secret,
        'provisioning_uri': provisioning_uri,
        'provisioning_qr': provisioning_qr,
        'provisioning_qr_path': provisioning_qr_path
    }), 200


@auth_bp.route('/api/verify-2fa-forced', methods=['POST'])
def verify_2fa_forced():
    """Verify and save 2FA setup after recovery code usage"""
    data = request.get_json() or {}
    code = str(data.get('code', '')).strip()
    user_id = session.get(SessionKeys.USER_ID)
    
    if not user_id:
        return jsonify({'error': ERROR_UNAUTHORIZED}), 401
    
    if not code:
        return jsonify({'error': 'Kod jest wymagany'}), 400
    
    totp_secret = session.get(SessionKeys.FORCE_2FA_SECRET)
    if not totp_secret:
        return jsonify({'error': 'Sesja 2FA wygasła'}), 401
    
    # Verify TOTP code
    if not verify_totp_code(totp_secret, code):
        time.sleep(0.5)
        return jsonify({'error': 'Nieprawidłowy kod 2FA'}), 401
    
    # Update user with new TOTP secret
    UserQueries.update_totp_secret(user_id, totp_secret)
    
    # Generate new recovery codes
    from db import generate_recovery_codes
    recovery_codes = generate_recovery_codes(10)
    RecoveryCodeQueries.save_codes(user_id, recovery_codes)
    
    # Cleanup session and QR file
    qr_path = session.get(SessionKeys.FORCE_2FA_QR_PATH)
    
    session.pop(SessionKeys.FORCE_2FA_SECRET, None)
    session.pop(SessionKeys.IN_2FA_RECOVERY_MODE, None)
    session.pop(SessionKeys.FORCE_2FA_QR_PATH, None)
    
    # Cleanup QR file from forced setup
    cleanup_qr_file(qr_path)
    
    return jsonify({
        'success': True,
        'message': MSG_2FA_SETUP_SUCCESS,
        'recovery_codes': recovery_codes
    }), 200