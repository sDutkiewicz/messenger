"""TOTP and 2FA related helpers"""
import io
import os
import time
import base64
import qrcode
import pyotp
from flask import current_app
from session_keys import SessionKeys
from db_queries import UserQueries
from backend.helpers.qr_cleanup import cleanup_qr_files_for_user
from constants import MSG_2FA_VERIFICATION_SUCCESS


def verify_totp_code(totp_secret, code):
    """Verify TOTP code against secret"""
    try:
        totp = pyotp.TOTP(totp_secret)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


def user_has_2fa_enabled(user):
    """Check if user has 2FA (skip for demo users: alice, bob, carol)"""
    if not user:
        return False
    if user['username'] in ('alice', 'bob', 'carol'):
        return False
    try:
        totp_secret = user['totp_secret']
        return totp_secret and totp_secret != 'TOTP_SECRET_PLACEHOLDER'
    except Exception:
        return False


def generate_totp_qr(totp_secret, email, username):
    """Generate TOTP QR code as data URL and save file"""
    try:
        provisioning_uri = pyotp.TOTP(totp_secret).provisioning_uri(
            name=email or username, 
            issuer_name='Messenger_Projekt'
        )
    except Exception:
        return None, None, None
    
    try:
        qr_img = qrcode.make(provisioning_uri)
        
        # Generate data URL for frontend
        buf = io.BytesIO()
        qr_img.save(buf, format='PNG')
        buf.seek(0)
        qr_b64 = base64.b64encode(buf.read()).decode('ascii')
        provisioning_qr = f'data:image/png;base64,{qr_b64}'
        
        # Save temporary file
        try:
            qr_dir = os.path.join(os.path.dirname(__file__), 'static', 'qrs')
            os.makedirs(qr_dir, exist_ok=True)
            filename = f'reg_{int(time.time())}_{os.urandom(4).hex()}.png'
            filepath = os.path.join(qr_dir, filename)
            qr_img.save(filepath, format='PNG')
            provisioning_qr_path = f'/static/qrs/{filename}'
        except Exception:
            provisioning_qr_path = None
        
        return provisioning_uri, provisioning_qr, provisioning_qr_path
    except Exception:
        return None, None, None


def complete_2fa_login(user):
    """Complete login after 2FA verification"""
    from flask import session, jsonify
    from db_queries import LoginAttemptQueries
    
    try:
        username = user['username']
        session.pop(SessionKeys.PRE_2FA_USER_ID, None)
        session.pop(SessionKeys.PRE_2FA_PASSWORD, None)
        session[SessionKeys.USER_ID] = user['id']
        session[SessionKeys.TWO_FA_VERIFIED] = True
        UserQueries.update_last_login(user['id'])
        
        # Reset failed login attempts
        LoginAttemptQueries.clear_failed_attempts(username)
        
        # Cleanup QR files
        cleanup_qr_files_for_user(user['id'])
        
        return jsonify({'message': MSG_2FA_VERIFICATION_SUCCESS, 'id': user['id']}), 200
    except Exception as e:
        current_app.logger.error('Error in complete_2fa_login: %s', str(e))
        return jsonify({'error': 'Błąd podczas logowania.'}), 500
