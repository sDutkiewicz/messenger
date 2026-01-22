"""
Database query helpers to centralize SQL queries.
Reduces code duplication and makes schema changes easier.
"""

from db import get_db


class UserQueries:
    """Queries related to user management"""
    
    @staticmethod
    def get_by_id(user_id):
        """Get user by ID"""
        from flask import current_app
        from helpers.crypto_helpers import decrypt_totp_secret
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        
        # Decrypt TOTP secret if present
        if user and user['totp_secret']:
            try:
                decrypted_totp = decrypt_totp_secret(user['totp_secret'], current_app.config['SECRET_KEY'], user['salt'])
                if decrypted_totp:
                    user = dict(user)
                    user['totp_secret'] = decrypted_totp
            except Exception:
                pass
        
        return user
    
    @staticmethod
    def get_by_username(username):
        """Get user by username"""
        from flask import current_app
        from helpers.crypto_helpers import decrypt_totp_secret
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        
        # Decrypt TOTP secret if present
        if user and user['totp_secret']:
            try:
                decrypted_totp = decrypt_totp_secret(user['totp_secret'], current_app.config['SECRET_KEY'], user['salt'])
                if decrypted_totp:
                    user = dict(user)
                    user['totp_secret'] = decrypted_totp
            except Exception:
                pass
        
        return user
    
    @staticmethod
    def get_by_email(email):
        """Get user by email"""
        from flask import current_app
        from helpers.crypto_helpers import decrypt_totp_secret
        
        db = get_db()
        user = db.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
        # Decrypt TOTP secret if present
        if user and user['totp_secret']:
            try:
                decrypted_totp = decrypt_totp_secret(user['totp_secret'], current_app.config['SECRET_KEY'], user['salt'])
                if decrypted_totp:
                    user = dict(user)
                    user['totp_secret'] = decrypted_totp
            except Exception:
                pass
        
        return user
    
    @staticmethod
    def get_by_username_or_email(username):
        """Get user by username OR email"""
        from flask import current_app
        from helpers.crypto_helpers import decrypt_totp_secret
        
        db = get_db()
        user = db.execute(
            'SELECT * FROM users WHERE username = ? OR email = ?',
            (username, username)
        ).fetchone()
        
        # Decrypt TOTP secret if present
        if user and user['totp_secret']:
            try:
                decrypted_totp = decrypt_totp_secret(user['totp_secret'], current_app.config['SECRET_KEY'], user['salt'])
                if decrypted_totp:
                    user = dict(user)
                    user['totp_secret'] = decrypted_totp
            except Exception:
                pass
        
        return user
    
    @staticmethod
    def get_all_except(exclude_id):
        """Get all users except specified ID"""
        db = get_db()
        return db.execute(
            'SELECT id, username FROM users WHERE id != ?',
            (exclude_id,)
        ).fetchall()
    
    @staticmethod
    def exists(username, email):
        """Check if username or email already exists"""
        db = get_db()
        return db.execute(
            'SELECT id FROM users WHERE username = ? OR email = ?',
            (username, email)
        ).fetchone()
    
    @staticmethod
    def username_exists(username):
        """Check if username exists"""
        db = get_db()
        return db.execute(
            'SELECT id FROM users WHERE username = ?',
            (username,)
        ).fetchone()
    
    @staticmethod
    def email_exists(email):
        """Check if email exists"""
        db = get_db()
        return db.execute(
            'SELECT id FROM users WHERE email = ?',
            (email,)
        ).fetchone()
    
    @staticmethod
    def create_user(username, email, password_hash, salt, public_key, private_key_encrypted, totp_secret):
        """Create new user, return user ID"""
        from flask import current_app
        from helpers.crypto_helpers import encrypt_totp_secret
        
        db = get_db()
        # Encrypt TOTP secret before storing
        encrypted_totp = encrypt_totp_secret(totp_secret, current_app.config['SECRET_KEY'], salt)
        
        cur = db.execute(
            'INSERT INTO users (username, email, password_hash, salt, public_key, private_key_encrypted, totp_secret) VALUES (?, ?, ?, ?, ?, ?, ?)',
            (username, email, password_hash, salt, public_key, private_key_encrypted, encrypted_totp)
        )
        db.commit()
        return cur.lastrowid
    
    @staticmethod
    def update_last_login(user_id):
        """Update last login timestamp"""
        db = get_db()
        db.execute(
            'UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?',
            (user_id,)
        )
        db.commit()
    
    @staticmethod
    def update_password_hash(user_id, password_hash):
        """Update user password hash"""
        db = get_db()
        db.execute(
            'UPDATE users SET password_hash = ? WHERE id = ?',
            (password_hash, user_id)
        )
        db.commit()
    
    @staticmethod
    def update_totp_secret(user_id, totp_secret):
        """Update TOTP secret (encrypts before storing)"""
        from flask import current_app
        from helpers.crypto_helpers import encrypt_totp_secret
        
        db = get_db()
        user = db.execute('SELECT salt FROM users WHERE id = ?', (user_id,)).fetchone()
        
        if not user:
            return
        
        # Encrypt TOTP secret before storing
        encrypted_totp = encrypt_totp_secret(totp_secret, current_app.config['SECRET_KEY'], user['salt'])
        
        db.execute(
            'UPDATE users SET totp_secret = ? WHERE id = ?',
            (encrypted_totp, user_id)
        )
        db.commit()
    
    @staticmethod
    def update_keys_and_password(user_id, password_hash, public_key, private_key_encrypted):
        """Update password and re-encrypted keys (used in password reset)"""
        db = get_db()
        db.execute(
            'UPDATE users SET password_hash = ?, public_key = ?, private_key_encrypted = ? WHERE id = ?',
            (password_hash, public_key, private_key_encrypted, user_id)
        )
        db.commit()


class MessageQueries:
    """Queries related to messages"""
    
    @staticmethod
    def get_conversation(user1_id, user2_id):
        """Get all messages in conversation between two users"""
        db = get_db()
        return db.execute('''
            SELECT m.id, m.sender_id, m.recipient_id, m.encrypted_content, 
                   m.session_key_encrypted, m.signature, m.is_read, u.username as sender
            FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE (m.sender_id = ? AND m.recipient_id = ?)
               OR (m.sender_id = ? AND m.recipient_id = ?)
            ORDER BY m.created_at ASC
        ''', (user1_id, user2_id, user2_id, user1_id)).fetchall()
    
    @staticmethod
    def mark_as_read(sender_id, recipient_id):
        """Mark messages as read"""
        db = get_db()
        db.execute(
            'UPDATE messages SET is_read = 1 WHERE sender_id = ? AND recipient_id = ? AND is_read = 0',
            (sender_id, recipient_id)
        )
        db.commit()
    
    @staticmethod
    def get_by_id(msg_id):
        """Get message by ID"""
        db = get_db()
        return db.execute(
            'SELECT sender_id, recipient_id FROM messages WHERE id = ?',
            (msg_id,)
        ).fetchone()
    
    @staticmethod
    def send(sender_id, recipient_id, encrypted_content, session_key_encrypted, signature):
        """Send new message, return message ID"""
        db = get_db()
        cur = db.execute(
            'INSERT INTO messages (sender_id, recipient_id, encrypted_content, session_key_encrypted, signature) VALUES (?, ?, ?, ?, ?)',
            (sender_id, recipient_id, encrypted_content, session_key_encrypted, signature)
        )
        msg_id = cur.lastrowid
        db.commit()
        return msg_id
    
    @staticmethod
    def delete(msg_id):
        """Delete message by ID"""
        db = get_db()
        db.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
        db.commit()


class AttachmentQueries:
    """Queries related to attachments"""
    
    @staticmethod
    def get_by_id(att_id):
        """Get attachment by ID"""
        db = get_db()
        return db.execute(
            'SELECT message_id, filename, encrypted_data FROM attachments WHERE id = ?',
            (att_id,)
        ).fetchone()
    
    @staticmethod
    def get_by_message(msg_id):
        """Get all attachments for a message"""
        db = get_db()
        return db.execute(
            'SELECT id, filename FROM attachments WHERE message_id = ?',
            (msg_id,)
        ).fetchall()
    
    @staticmethod
    def add(message_id, filename, encrypted_data):
        """Add attachment to message"""
        db = get_db()
        db.execute(
            'INSERT INTO attachments (message_id, filename, encrypted_data) VALUES (?, ?, ?)',
            (message_id, filename, encrypted_data)
        )
        db.commit()


class LoginAttemptQueries:
    """Queries related to login attempt tracking"""
    
    @staticmethod
    def record(username, success):
        """Record login attempt"""
        db = get_db()
        db.execute(
            'INSERT INTO login_attempts (username, success) VALUES (?, ?)',
            (username, success)
        )
        db.commit()
    
    @staticmethod
    def get_recent_failed_count(username, window_min):
        """Get count of recent failed login attempts"""
        db = get_db()
        cur = db.execute(
            f"SELECT COUNT(*) as c FROM login_attempts WHERE username = ? AND success = 0 AND timestamp > datetime('now', '-{window_min} minutes')",
            (username,)
        ).fetchone()
        return cur['c'] if cur is not None else 0
    
    @staticmethod
    def get_last_failed_timestamp(username):
        """Get timestamp of last failed login attempt"""
        db = get_db()
        return db.execute(
            "SELECT timestamp FROM login_attempts WHERE username = ? AND success = 0 ORDER BY timestamp DESC LIMIT 1",
            (username,)
        ).fetchone()
    
    @staticmethod
    def clear_failed_attempts(username):
        """Clear all failed login attempts for user"""
        db = get_db()
        db.execute(
            'DELETE FROM login_attempts WHERE username = ? AND success = 0',
            (username,)
        )
        db.commit()


class RecoveryCodeQueries:
    """Queries related to 2FA recovery codes"""
    
    @staticmethod
    def get_all_for_user(user_id):
        """Get all unused recovery code hashes for user"""
        db = get_db()
        return db.execute(
            'SELECT code_hash FROM two_fa_recovery_codes WHERE user_id = ? AND used = FALSE',
            (user_id,)
        ).fetchall()
    
    @staticmethod
    def save_codes(user_id, codes):
        """Save hashed recovery codes to database"""
        from db import hash_recovery_code
        db = get_db()
        
        # Delete old codes for this user
        db.execute('DELETE FROM two_fa_recovery_codes WHERE user_id = ?', (user_id,))
        
        # Insert new codes
        for code in codes:
            code_hash = hash_recovery_code(code)
            db.execute(
                'INSERT INTO two_fa_recovery_codes (user_id, code_hash, used) VALUES (?, ?, FALSE)',
                (user_id, code_hash)
            )
        
        db.commit()
    
    @staticmethod
    def mark_as_used(user_id, code):
        """Mark recovery code as used"""
        from datetime import datetime
        from db import hash_recovery_code
        db = get_db()
        code_hash = hash_recovery_code(code)
        
        db.execute(
            '''UPDATE two_fa_recovery_codes 
               SET used = TRUE, used_at = ? 
               WHERE user_id = ? AND code_hash = ? AND used = FALSE''',
            (datetime.now(), user_id, code_hash)
        )
        db.commit()
        
        # Return how many codes were updated (should be 1 if valid)
        return db.execute('SELECT changes() as changes', ()).fetchone()['changes']
    
    @staticmethod
    def get_user_by_code(email, code):
        """Verify recovery code and return user if valid"""
        from db import verify_recovery_code
        db = get_db()
        
        # Get user by email
        user = db.execute('SELECT id, totp_secret FROM users WHERE email = ?', (email,)).fetchone()
        
        if not user:
            return None
        
        # Get recovery codes for this user
        codes = db.execute(
            '''SELECT code_hash FROM two_fa_recovery_codes 
               WHERE user_id = ? AND used = FALSE''',
            (user['id'],)
        ).fetchall()
        
        if not codes:
            return None
        
        # Check if provided code matches any hash
        for row in codes:
            if verify_recovery_code(code, row['code_hash']):
                return user
        
        return None
