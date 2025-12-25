import sqlite3
from flask import g
import os

DATABASE = os.getenv('DATABASE_PATH', os.path.join(os.path.dirname(__file__), 'data', 'messenger.db'))

def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    """Initialize the database and create tables if they do not exist. Insert example users if empty."""
    # ensure directory exists
    db_dir = os.path.dirname(DATABASE)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
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
    ''')
    db.commit()
    db.close()
    add_example_users()

# Add example users (alice, bob, carol) if they do not exist
def add_example_users():
    db = sqlite3.connect(DATABASE)
    cursor = db.cursor()
    from argon2 import PasswordHasher
    ph = PasswordHasher()
    users = [
        ('alice', 'alice@example.com', ph.hash('TestHaslo123'), os.urandom(16), 'PUBKEY', 'PRIVKEY', 'TOTP'),
        ('bob', 'bob@example.com', ph.hash('TestHaslo123'), os.urandom(16), 'PUBKEY', 'PRIVKEY', 'TOTP'),
        ('carol', 'carol@example.com', ph.hash('TestHaslo123'), os.urandom(16), 'PUBKEY', 'PRIVKEY', 'TOTP'),
    ]
    for u in users:
        cursor.execute('SELECT 1 FROM users WHERE username = ?', (u[0],))
        if cursor.fetchone() is None:
            cursor.execute(
                'INSERT INTO users (username, email, password_hash, salt, public_key, private_key_encrypted, totp_secret) VALUES (?, ?, ?, ?, ?, ?, ?)',
                u
            )
    db.commit()
    db.close()
    
