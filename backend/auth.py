
from flask import Blueprint, request, jsonify, g, session
from db import get_db
from argon2 import PasswordHasher
import os
import re

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
    try:
        password_hash = ph.hash(password)
        # Placeholder for salt, public/private key, totp_secret
        salt = os.urandom(16)
        public_key = 'PUBLIC_KEY_PLACEHOLDER'
        private_key_encrypted = 'PRIVATE_KEY_PLACEHOLDER'
        totp_secret = 'TOTP_SECRET_PLACEHOLDER'
        cur = db.execute(
            'INSERT INTO users (username, email, password_hash, salt, public_key, private_key_encrypted, totp_secret) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (username, email, password_hash, salt, public_key, private_key_encrypted, totp_secret)
        )
        db.commit()
        # set session to newly created user
        session['user_id'] = cur.lastrowid
    except Exception as e:
        if 'UNIQUE constraint failed: users.username' in str(e):
            return jsonify({'error': 'Nazwa użytkownika już istnieje.'}), 409
        if 'UNIQUE constraint failed: users.email' in str(e):
            return jsonify({'error': 'Email już istnieje.'}), 409
        return jsonify({'error': 'Błąd rejestracji.'}), 500
    return jsonify({'message': 'Rejestracja udana.'}), 201

@auth_bp.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    username = data.get('username', '').strip()
    password = data.get('password', '')
    if not username or not password:
        return jsonify({'error': 'Wszystkie pola są wymagane.'}), 400
    db = get_db()
    user = db.execute(
        'SELECT * FROM users WHERE username = ? OR email = ?', (username, username)
    ).fetchone()
    if not user:
        return jsonify({'error': 'Nieprawidłowe dane logowania.'}), 401
    try:
        ph.verify(user['password_hash'], password)
    except Exception:
        return jsonify({'error': 'Nieprawidłowe dane logowania.'}), 401
    # set session for logged in user
    session['user_id'] = user['id']
    return jsonify({'message': 'Zalogowano pomyślnie.', 'id': user['id']}), 200

@auth_bp.route('/api/verify-2fa', methods=['POST'])
def verify_2fa():
    #TODO
    return jsonify({'message': '2FA verification endpoint'}), 200
