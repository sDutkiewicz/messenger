
from flask import Blueprint, request, jsonify, g, session, make_response, current_app
from db import get_db
from argon2 import PasswordHasher
import os
import re
import time
import pyotp
import qrcode
import io
import base64
import glob

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

@auth_bp.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    username = data.get('username', '').strip()
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not username or not email or not password:
        return jsonify({'error': 'Wszystkie pola są wymagane.'}), 400
    if len(username) < 3 or len(username) > 32 or not re.match(r'^[a-zA-Z0-9_.-]+$', username):
        return jsonify({'error': 'Nieprawidłowa nazwa użytkownika.'}), 400
    if not re.match(r'^\S+@\S+\.\S+$', email):
        return jsonify({'error': 'Nieprawidłowy email.'}), 400
    if not is_strong_password(password):
        return jsonify({'error': 'Hasło musi mieć min. 12 znaków, dużą i małą literę oraz cyfrę.'}), 400

    db = get_db()
    # pre-check uniqueness to provide specific UX messages
    try:
        if db.execute('SELECT 1 FROM users WHERE username = ?', (username,)).fetchone():
            return jsonify({'error': 'Nazwa użytkownika już istnieje.'}), 409
        if db.execute('SELECT 1 FROM users WHERE email = ?', (email,)).fetchone():
            return jsonify({'error': 'Email już istnieje.'}), 409
    except Exception:
        # if check fails, continue and rely on INSERT/IntegrityError handling
        pass
    try:
        password_hash = ph.hash(password)
        # generate TOTP secret for user enrollment
        totp_secret = pyotp.random_base32()
        # Placeholder for salt, public/private key
        salt = os.urandom(16)
        public_key = 'PUBLIC_KEY_PLACEHOLDER'
        private_key_encrypted = 'PRIVATE_KEY_PLACEHOLDER'
        cur = db.execute(
            'INSERT INTO users (username, email, password_hash, salt, public_key, private_key_encrypted, totp_secret) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (username, email, password_hash, salt, public_key, private_key_encrypted, totp_secret)
        )
        db.commit()
        # set session to newly created (but not fully authenticated) user
        session['pre_2fa_user_id'] = cur.lastrowid
        # build provisioning URI for authenticator apps
        try:
            provisioning_uri = pyotp.TOTP(totp_secret).provisioning_uri(name=email or username, issuer_name='Messenger')
            # generate QR PNG as data URL so frontend doesn't rely on external chart API
            try:
                qr_img = qrcode.make(provisioning_uri)
                # create data URL
                buf = io.BytesIO()
                qr_img.save(buf, format='PNG')
                buf.seek(0)
                qr_b64 = base64.b64encode(buf.read()).decode('ascii')
                provisioning_qr = f'data:image/png;base64,{qr_b64}'
                # also save a temporary file on disk and provide a static URL
                try:
                    qr_dir = os.path.join(os.path.dirname(__file__), 'static', 'qrs')
                    os.makedirs(qr_dir, exist_ok=True)
                    filename = f'{cur.lastrowid}_{int(time.time())}.png'
                    filepath = os.path.join(qr_dir, filename)
                    qr_img.save(filepath, format='PNG')
                    provisioning_qr_path = f'/static/qrs/{filename}'
                except Exception:
                    provisioning_qr_path = None
            except Exception:
                provisioning_qr = None
                provisioning_qr_path = None
        except Exception:
            provisioning_uri = None
            provisioning_qr = None
    except Exception as e:
        # Do not reveal whether username or email already exists. Log a short warning.
        try:
            current_app.logger.warning('Registration error: %s', str(e))
        except Exception:
            pass
        if 'UNIQUE constraint failed' in str(e):
            return jsonify({'error': 'Rejestracja nie powiodła się.'}), 409
        return jsonify({'error': 'Rejestracja nie powiodła się.'}), 500
    return jsonify({'message': 'Rejestracja udana. Dokończ konfigurację 2FA.', 'provisioning_uri': provisioning_uri, 'provisioning_qr': provisioning_qr, 'provisioning_qr_path': provisioning_qr_path, 'totp_secret': totp_secret}), 201

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        # Do not reveal whether fields are missing or user exists - return generic auth error
        time.sleep(0.2)
        return jsonify({'error': 'Nieprawidłowe dane logowania.'}), 401
    db = get_db()
    # rate limiting / anti-brute-force: count recent failed attempts for this username
    MAX_FAILED = 5
    WINDOW = "-15 minutes"
    cur = db.execute(
        "SELECT COUNT(*) as c FROM login_attempts WHERE username = ? AND success = 0 AND timestamp > datetime('now', ?)",
        (username, WINDOW)
    ).fetchone()
    failed_count = cur['c'] if cur is not None else 0
    if failed_count >= MAX_FAILED:
        resp = make_response(jsonify({'error': 'Zbyt wiele nieudanych prób logowania. Spróbuj później.'}), 429)
        # advise client when to retry (basic)
        resp.headers['Retry-After'] = str(15 * 60)
        return resp

    user = db.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?', (username, username)
    ).fetchone()

    success = 0
    # Always avoid revealing whether username exists
    if user:
        try:
            ph.verify(user['password_hash'], password)
            success = 1
        except Exception:
            success = 0
    else:
        # user not found, treat as failed attempt
        success = 0

    # record the password verification attempt (do not indicate existence)
    try:
        db.execute('INSERT INTO login_attempts (username, success) VALUES (?, ?)', (username, success))
        db.commit()
    except Exception:
        pass

    # apply small progressive delay on failures to slow brute-force
    if not success:
        backoff = min(2.0, 0.25 * (failed_count + 1))
        time.sleep(backoff)
        return jsonify({'error': 'Nieprawidłowe dane logowania.'}), 401

    # if user has TOTP configured, require 2FA verification step
    try:
        user_totp = user['totp_secret'] if user else None
    except Exception:
        user_totp = None
    if user and user_totp and user_totp != 'TOTP_SECRET_PLACEHOLDER':
        # set pre-auth session and ask client to verify 2FA
        session['pre_2fa_user_id'] = user['id']
        return jsonify({'message': 'Wymagana weryfikacja 2FA.', '2fa_required': True}), 200

    # successful login without 2FA
    session['user_id'] = user['id']
    try:
        db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
        db.commit()
    except Exception:
        pass
    return jsonify({'message': 'Zalogowano pomyślnie.', 'id': user['id']}), 200

@auth_bp.route('/api/verify-2fa', methods=['POST'])
def verify_2fa():
    data = request.get_json() or {}
    code = str(data.get('code', '')).strip()
    # determine user: prefer pre_2fa_user_id (set after password verify)
    pre_id = session.get('pre_2fa_user_id')
    if not pre_id or not code:
        # generic error (don't reveal reason)
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401
    db = get_db()
    user = db.execute('SELECT * FROM users WHERE id = ?', (pre_id,)).fetchone()
    if not user:
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401

    try:
        totp_secret = user['totp_secret']
    except Exception:
        totp_secret = None
    # don't reveal whether 2FA is configured
    if not totp_secret or totp_secret == 'TOTP_SECRET_PLACEHOLDER':
        # record failed attempt
        try:
            db.execute('INSERT INTO login_attempts (username, success) VALUES (?, ?)', (user['username'], 0))
            db.commit()
        except Exception:
            pass
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401

    try:
        totp = pyotp.TOTP(totp_secret)
        ok = totp.verify(code, valid_window=1)
    except Exception:
        ok = False

    # log attempt
    try:
        db.execute('INSERT INTO login_attempts (username, success) VALUES (?, ?)', (user['username'], 1 if ok else 0))
        db.commit()
    except Exception:
        pass

    if not ok:
        time.sleep(0.5)
        return jsonify({'error': 'Weryfikacja 2FA nie powiodła się.'}), 401

    # on success, finalize login: set user_id and remove pre-auth marker
    session.pop('pre_2fa_user_id', None)
    session['user_id'] = user['id']
    session['2fa_verified'] = True
    try:
        db.execute('UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?', (user['id'],))
        db.commit()
    except Exception:
        pass
    # cleanup temporary QR files for this user (if any)
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

    return jsonify({'message': 'Weryfikacja 2FA zakończona pomyślnie.', 'id': user['id']}), 200
