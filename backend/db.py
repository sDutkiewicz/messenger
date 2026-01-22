import sqlite3
from flask import g
import os


# database path configuration
DATABASE = os.getenv('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'data', 'messenger.db'))

def get_db(): # connect to the database
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database and create tables if 
    they do not exist. Insert example users if empty."""
    #
    #  ensure directory exists
    db_dir = os.path.dirname(DATABASE)
    
    if not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    

    # creating tables
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    cursor.executescript('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt BLOB NOT NULL,
        public_key TEXT NOT NULL,
        private_key_encrypted TEXT NOT NULL,
        totp_secret TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS messages (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sender_id INTEGER,
        recipient_id INTEGER,
        encrypted_content TEXT NOT NULL,
        session_key_encrypted TEXT NOT NULL,
        signature TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (sender_id) REFERENCES users(id),
        FOREIGN KEY (recipient_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS attachments (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        message_id INTEGER,
        filename TEXT NOT NULL,
        encrypted_data BLOB NOT NULL,
        FOREIGN KEY (message_id) REFERENCES messages(id)
    );

    CREATE TABLE IF NOT EXISTS login_attempts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        success INTEGER
    );

    CREATE TABLE IF NOT EXISTS two_fa_recovery_codes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        code_hash TEXT NOT NULL,
        used BOOLEAN DEFAULT FALSE,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        used_at TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );
    ''')
    db.commit()
    db.close()
    add_example_users()

# Add example users (alice, bob, carol) for testing
def add_example_users():
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    from argon2 import PasswordHasher
    from helpers.crypto_helpers import generate_rsa_keypair, encrypt_private_key
    ph = PasswordHasher()
    
    users = [
        ('alice', 'alice@example.com', 'TestHaslo123'),
        ('bob', 'bob@example.com', 'TestHaslo123'),
        ('carol', 'carol@example.com', 'TestHaslo123'),
    ]
    
    for username, email, password in users:
        cursor.execute('SELECT 1 FROM users WHERE username = ?', (username,))
        if cursor.fetchone() is None:
            password_hash = ph.hash(password)
            salt = os.urandom(16)
            
            # Generate RSA keys
            public_key, private_key = generate_rsa_keypair()
            private_key_encrypted = encrypt_private_key(private_key, password, salt)
            
            # No TOTP secret for example users - they login without 2FA
            totp_secret = ''
            
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, salt, public_key, private_key_encrypted, totp_secret) VALUES (?, ?, ?, ?, ?, ?, ?)',
                (username, email, password_hash, salt, public_key, private_key_encrypted, totp_secret)
            )
    db.commit()
    db.close()


# ========== 2FA RECOVERY CODES ==========

def generate_recovery_codes(count=10):
    """Generate random recovery codes"""
    import secrets
    codes = []
    for _ in range(count):
        # Format: "XXXX-XXXX-XXXX" (12 chars + dashes, no prefix)
        random_part = secrets.token_hex(6).upper()  # 12 hex chars
        code = f"{random_part[:4]}-{random_part[4:8]}-{random_part[8:]}"
        codes.append(code)
    return codes


def hash_recovery_code(code):
    """Hash recovery code using Argon2 (same as password hashing)"""
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    return ph.hash(code)


def verify_recovery_code(code, code_hash):
    """Verify recovery code against hash"""
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    try:
        ph.verify(code_hash, code)
        return True
    except Exception:
        return False
