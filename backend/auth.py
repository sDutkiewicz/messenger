
from flask import Blueprint, request, jsonify, g, session, make_response, current_app
from db import get_db
from sanitize import clean_input
from argon2 import PasswordHasher
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
import os
import re
import time
import pyotp
import qrcode
import io
import base64
import glob
import sqlite3
import hashlib

auth_bp = Blueprint('auth', __name__)
ph = PasswordHasher()

def is_strong_password(password):
    # Minimum 12 chars, at least 1 upper, 1 lower, 1 digit
    if len(password) < 12:
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'\d', password):
        return False
    return True


# ========== ENCRYPTION HELPERS ==========

def generate_rsa_keypair():
    """Generate RSA 2048-bit key pair"""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    
    # Serialize public key
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')
    
    # Serialize private key (unencrypted for now)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')
    
    return public_pem, private_pem


def encrypt_private_key(private_key_pem, password, salt):
    """Encrypt private key using password-derived key"""
    # Derive encryption key from password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    
    # Encrypt private key
    cipher = Fernet(key)
    encrypted = cipher.encrypt(private_key_pem.encode())
    
    return encrypted.decode('utf-8')


def decrypt_private_key(encrypted_key_str, password, salt):
    """Decrypt private key using password-derived key"""
    try:
        # Derive decryption key from password
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        
        # Decrypt private key
        cipher = Fernet(key)
        decrypted = cipher.decrypt(encrypted_key_str.encode())
        
        return decrypted.decode('utf-8')
    except Exception:
        return None


# ========== HELPER FUNCTIONS ==========

def user_has_2fa_enabled(user):
    """Check if user has 2FA configured (skip for example users)"""
    if not user:
        return False
    
    # Example users (alice, bob, carol) skip 2FA for testing
    if user['username'] in ('alice', 'bob', 'carol'):
        return False
    
    try:
        totp_secret = user['totp_secret']
        return totp_secret and totp_secret != 'TOTP_SECRET_PLACEHOLDER'
    except Exception:
        return False


def verify_totp_code(totp_secret, code):
    """Verify TOTP code against secret"""
    try:
        totp = pyotp.TOTP(totp_secret)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


def record_login_attempt(username, success):
    """Log login attempt to database"""
    try:
        db = get_db()
        db.execute('INSERT INTO login_attempts (username, success) VALUES (?, ?)', (username, success))
        db.commit()
    except Exception:
        pass


def apply_failed_attempt_delay(failed_count):
    """Apply progressive delay on failed login attempts"""
    backoff = min(2.0, 0.25 * (failed_count + 1))
    time.sleep(backoff)


def get_recent_failed_attempts(username):
    """Get count of recent failed login attempts"""
    try:
        db = get_db()
        MAX_FAILED = 5
        WINDOW = "-15 minutes"
        
        cur = db.execute(
            "SELECT COUNT(*) as c FROM login_attempts WHERE username = ? AND success = 0 AND timestamp > datetime('now', ?)",
            (username, WINDOW)
        ).fetchone()
        
        return cur['c'] if cur is not None else 0
    except Exception:
        return 0


def check_rate_limit(username):
    """Check if user has exceeded login attempt limit"""
    failed_count = get_recent_failed_attempts(username)
    MAX_FAILED = 5
    
    if failed_count >= MAX_FAILED:
        resp = make_response(jsonify({'error': 'Zbyt wiele nieudanych prób logowania. Spróbuj później.'}), 429)
        resp.headers['Retry-After'] = str(15 * 60)
        return resp, failed_count
    
    return None, failed_count


def verify_password(user, password):
    """Verify password against hash"""
    if not user:
        return False
    try:
        ph.verify(user['password_hash'], password)
        return True
    except Exception:
        return False


def login_without_2fa(user):
    """Complete login for user without 2FA"""
    try:
        session['user_id'] = user['id']
        db = get_db()
        db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
        db.commit()
    except Exception:
        pass
    
    return jsonify({'message': 'Zalogowano pomyślnie.', 'id': user['id']}), 200


def login_with_2fa_required(user):
    """Require 2FA verification for user"""
    session['pre_2fa_user_id'] = user['id']
    return jsonify({'message': 'Wymagana weryfikacja 2FA.', '2fa_required': True}), 200


def complete_2fa_login(user):
    """Complete login after 2FA verification"""
    try:
        session.pop('pre_2fa_user_id', None)
        session.pop('pre_2fa_password', None)
        session['user_id'] = user['id']
        session['2fa_verified'] = True
        db = get_db()
        db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
        db.commit()
        
        # Cleanup temporary QR files
        try:
            qr_dir = os.path.join(os.path.dirname(__file__), 'static', 'qrs')
            pattern = os.path.join(qr_dir, f"{user['id']}_*.png")
            for p in glob.glob(pattern):
                try:
                    os.remove(p)
                except Exception:
                    pass
        except Exception:
            pass
    except Exception:
        pass
    
    return jsonify({'message': 'Weryfikacja 2FA zakończona pomyślnie.', 'id': user['id']}), 200


# ========== REGISTRATION ==========

def generate_totp_qr(totp_secret, email, username):
    """Generate TOTP QR code and return as data URL + file path"""
    try:
        # Provisioning URI format: otpauth://totp/issuer:username?secret=...
        # This is a standard format recognized by authenticator apps (Google Authenticator, Authy, etc.)
        provisioning_uri = pyotp.TOTP(totp_secret).provisioning_uri(
            name=email or username, 
            issuer_name='Messenger'
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
        
        # returning uri, data url, and file path
        return provisioning_uri, provisioning_qr, provisioning_qr_path
    except Exception:
        return None, None, None


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
    
    if len(username) < 3 or len(username) > 32 or not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return jsonify({'error': 'Nieprawidłowa nazwa użytkownika.'}), 400
    
    if not re.match(r'^\S+@\S+\.\S+$', email):
        return jsonify({'error': 'Nieprawidłowy email.'}), 400
    
    if not is_strong_password(password):
        return jsonify({'error': 'Hasło musi mieć min. 12 znaków, dużą i małą literę oraz cyfrę.'}), 400

    # CHECK IF USERNAME OR EMAIL ALREADY EXIST (before 2FA setup)
    db = get_db()
    existing_user = db.execute(
        'SELECT id FROM users WHERE username = ? OR email = ?',
        (username, email)
    ).fetchone()
    
    if existing_user:
        # Check which one is taken
        existing_by_username = db.execute(
            'SELECT id FROM users WHERE username = ?',
            (username,)
        ).fetchone()
        
        if existing_by_username:
            return jsonify({'error': 'Nazwa użytkownika już istnieje.'}), 409
        else:
            return jsonify({'error': 'Email już istnieje.'}), 409

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
        session['reg_pending'] = {
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
            'message': 'Rejestracja przygotowana. Dokończ konfigurację 2FA.',
            'provisioning_uri': provisioning_uri,
            'provisioning_qr': provisioning_qr,
            'provisioning_qr_path': provisioning_qr_path,
            'totp_secret': totp_secret
        }), 201
    
    except Exception as e:
        try:
            current_app.logger.warning('Registration error: %s', str(e))
        except Exception:
            pass
        return jsonify({'error': 'Rejestracja nie powiodła się.'}), 500


# ========== LOGIN ==========

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = clean_input(data.get('username', '').strip())
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'error': 'Nieprawidłowe dane logowania.'}), 401
    
    # Check rate limit
    rate_limit_error, failed_count = check_rate_limit(username)
    if rate_limit_error:
        return rate_limit_error
    
    db = get_db()
    
    # Find user
    user = db.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?', (username, username)
    ).fetchone()
    
    # Verify password
    password_valid = verify_password(user, password)
    
    if not password_valid:
        record_login_attempt(username, 0)
        apply_failed_attempt_delay(failed_count)
        return jsonify({'error': 'Nieprawidłowe dane logowania.'}), 401
    
    # Password valid
    record_login_attempt(username, 1)
    
    # Check if user has 2FA enabled
    if user_has_2fa_enabled(user):
        return login_with_2fa_required(user)
    else:
        return login_without_2fa(user)


# ========== 2FA VERIFICATION ==========

@auth_bp.route('/api/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json() or {}
    code = str(data.get('code', '')).strip()
    db = get_db()

    # Case A: finishing pending registration
    if session.get('reg_pending') is not None:
        return _verify_2fa_registration(code, db)
    
    # Case B: existing user finishing login 2FA
    if session.get('pre_2fa_user_id') is not None:
        return _verify_2fa_login(code, db)
    
    # No valid session state
    return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401


def _verify_2fa_registration(code, db):
    """Handle 2FA verification during registration"""
    reg = session.get('reg_pending')
    
    if not code:
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401
    
    totp_secret = reg.get('totp_secret')
    if not totp_secret:
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401
    
    # Verify TOTP code
    ok = verify_totp_code(totp_secret, code)
    record_login_attempt(reg.get('username'), 1 if ok else 0)
    
    if not ok:
        time.sleep(0.5)
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401

    # Insert user into database
    try:
        salt_bytes = base64.b64decode(reg.get('salt_b64')) if reg.get('salt_b64') else os.urandom(16)
        cur = db.execute(
            'INSERT INTO users (username, email, password_hash, salt, public_key, private_key_encrypted, totp_secret) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (reg.get('username'), reg.get('email'), reg.get('password_hash'), salt_bytes, reg.get('public_key'), reg.get('private_key_encrypted'), reg.get('totp_secret'))
        )
        db.commit()
        new_id = cur.lastrowid
        
        # Use recovery codes from session (generated in /api/register)
        recovery_codes = reg.get('recovery_codes', [])
        from db import save_recovery_codes
        save_recovery_codes(new_id, recovery_codes)

    except sqlite3.IntegrityError as e:
        m = str(e)
        try:
            if 'users.username' in m:
                return jsonify({'error': 'Nazwa użytkownika już istnieje.'}), 409
            if 'users.email' in m:
                return jsonify({'error': 'Email już istnieje.'}), 409
        except Exception:
            pass
        return jsonify({'error': 'Rejestracja nie powiodła się.'}), 409
    except Exception:
        return jsonify({'error': 'Rejestracja nie powiodła się.'}), 500

    # Get recovery codes from session before clearing it
    recovery_codes = reg.get('recovery_codes', [])
    
    # Finalize session
    session.pop('reg_pending', None)
    session['user_id'] = new_id
    session['2fa_verified'] = True

    # Cleanup QR file from registration
    try:
        qr_path = reg.get('provisioning_qr_path')
        if qr_path and qr_path.startswith('/static/qrs/'):
            # Build correct path: go up from backend/ to parent, then into static/
            fs_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), qr_path.lstrip('/'))
            if os.path.exists(fs_path):
                try:
                    os.remove(fs_path)
                except Exception:
                    pass
    except Exception:
        pass

    return jsonify({
        'message': 'Rejestracja zakończona pomyślnie.',
        'id': new_id,
        'recovery_codes': recovery_codes
    }), 201


def _verify_2fa_login(code, db):
    """Handle 2FA verification during login"""
    pre_id = session.get('pre_2fa_user_id')
    
    if not pre_id or not code:
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401
    
    user = db.execute('SELECT * FROM users WHERE id = ?', (pre_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401

    # Get TOTP secret
    try:
        totp_secret = user['totp_secret']
    except Exception:
        totp_secret = None

    # Verify TOTP is configured
    if not totp_secret or totp_secret == 'TOTP_SECRET_PLACEHOLDER':
        record_login_attempt(user['username'], 0)
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401

    # Verify TOTP code
    ok = verify_totp_code(totp_secret, code)
    record_login_attempt(user['username'], 1 if ok else 0)
    
    if not ok:
        time.sleep(0.5)
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401

    # Complete login
    password = session.get('pre_2fa_password', '')
    return complete_2fa_login(user)


# ========== PRIVATE KEY RETRIEVAL ==========
@auth_bp.route('/api/get-private-key', methods=['POST'])
def get_private_key():
    """Get decrypted private key for logged-in user"""
    data = request.get_json() or {}
    password = data.get('password', '')
    
    user_id = session.get('user_id')
    if not user_id:
        return jsonify({'error': 'Nieautoryzowany.'}), 401
    
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        return jsonify({'error': 'Użytkownik nie znaleziony.'}), 404
    
    # Verify password
    try:
        ph.verify(user['password_hash'], password)
    except Exception:
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


# ========== LOGOUT ==========

@auth_bp.route('/api/logout', methods=['POST'])
def logout():
    try:
        session.pop('user_id', None)
        session.pop('pre_2fa_user_id', None)
        session.pop('reg_pending', None)
        session.pop('2fa_verified', None)
        session.pop('2fa_recovery_mode', None)
    except Exception:
        pass
    return jsonify({'message': 'Wylogowano.'}), 200


# ========== 2FA RECOVERY - RECOVERY CODE VERIFICATION ==========

@auth_bp.route('/api/auth/2fa-recovery', methods=['POST'])
def recovery_code_verification():
    """
    Verify recovery code when user lost access to 2FA app.
    Flow:
    1. User is in 2FA verification step (pre_2fa_user_id set)
    2. User provides recovery code instead of TOTP code
    3. Backend verifies recovery code
    4. Backend removes 2FA (sets totp_secret to NULL)
    5. Backend creates session
    6. Frontend shows: FORCED 2FA SETUP (user must set up new 2FA immediately)
    """
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    recovery_code = data.get('recovery_code', '').strip()
    
    if not email or not recovery_code:
        return jsonify({'error': 'Email i recovery code są wymagane.'}), 400
    
    from db import verify_and_get_user_by_recovery_code, mark_recovery_code_used
    db = get_db()
    
    # Verify recovery code and get user
    user = verify_and_get_user_by_recovery_code(email, recovery_code)
    
    if not user:
        # Security: Don't reveal if email/code is invalid
        time.sleep(0.5)
        return jsonify({'error': 'Nieprawidłowy kod odzyskiwania lub email.'}), 401
    
    # Recovery code is valid! Mark it as used
    mark_recovery_code_used(user['id'], recovery_code)
    
    # Remove 2FA (force setup new one) - set to empty string instead of NULL
    db.execute('UPDATE users SET totp_secret = "" WHERE id = ?', (user['id'],))
    db.commit()
    
    # Create session
    session['user_id'] = user['id']
    session['2fa_verified'] = True
    session['2fa_recovery_mode'] = True  # ← Flag to force setup new 2FA
    
    return jsonify({
        'success': True,
        'message': '2FA recovery kod zaakceptowany. Musisz teraz ustawić nowy 2FA.',
        'requires_2fa_setup': True,
        'user_id': user['id']
    }), 200

# ========== FORCED 2FA SETUP (after recovery) ==========

@auth_bp.route('/api/setup-2fa-forced', methods=['GET'])
def setup_2fa_forced():
    """Get 2FA setup info for forced setup after recovery code usage"""
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Nie jesteś zalogowany'}), 401
    
    # Get user info for QR generation
    db = get_db()
    user = db.execute('SELECT email, username FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user:
        return jsonify({'error': 'Użytkownik nie znaleziony'}), 401
    
    # Generate new TOTP secret
    totp_secret = pyotp.random_base32()
    
    # Generate QR code with user email
    provisioning_uri, provisioning_qr, provisioning_qr_path = generate_totp_qr(
        totp_secret, user['email'], user['username']
    )
    
    # Store in session temporarily
    session['_force_2fa_secret'] = totp_secret
    session['_setup2fa_qr_path'] = provisioning_qr_path
    
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
    user_id = session.get('user_id')
    
    if not user_id:
        return jsonify({'error': 'Nie jesteś zalogowany'}), 401
    
    if not code:
        return jsonify({'error': 'Kod jest wymagany'}), 400
    
    totp_secret = session.get('_force_2fa_secret')
    if not totp_secret:
        return jsonify({'error': 'Sesja 2FA wygasła'}), 401
    
    # Verify TOTP code
    if not verify_totp_code(totp_secret, code):
        time.sleep(0.5)
        return jsonify({'error': 'Nieprawidłowy kod 2FA'}), 401
    
    db = get_db()
    
    # Update user with new TOTP secret
    db.execute('UPDATE users SET totp_secret = ? WHERE id = ?', (totp_secret, user_id))
    db.commit()
    
    # Generate new recovery codes
    from db import generate_recovery_codes, save_recovery_codes
    recovery_codes = generate_recovery_codes(10)
    save_recovery_codes(user_id, recovery_codes)
    
    # Cleanup session and QR file
    qr_path = session.get('_setup2fa_qr_path')
    
    session.pop('_force_2fa_secret', None)
    session.pop('2fa_recovery_mode', None)
    session.pop('_setup2fa_qr_path', None)
    
    # Cleanup QR file from forced setup
    try:
        if qr_path and qr_path.startswith('/static/qrs/'):
            # Build correct path: go up from backend/ to parent, then into static/
            fs_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), qr_path.lstrip('/'))
            if os.path.exists(fs_path):
                try:
                    os.remove(fs_path)
                except Exception:
                    pass
    except Exception:
        pass
    except Exception:
        pass
    
    return jsonify({
        'success': True,
        'message': 'Nowy 2FA i recovery codes skonfigurowane',
        'recovery_codes': recovery_codes
    }), 200