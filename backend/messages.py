from flask import Blueprint, request, jsonify
from db import get_db
from flask import session
from sanitize import clean_input
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import base64
import hashlib


# Blueprint for message-related routes
messages_bp = Blueprint('messages', __name__)


def get_current_user_id():
    """Return logged-in user ID from session"""
    user_id = session.get('user_id')
    if user_id is None:
        # For demo: return 1 (alice) if not logged in
        return 1
    return user_id


def check_message_permission(user_id, msg_id, db):
    """Check if user has permission to access message (sender or recipient)"""
    if user_id is None:
        return False, {'error': 'Unauthorized'}, 401
    
    msg = db.execute('SELECT sender_id, recipient_id FROM messages WHERE id = ?', (msg_id,)).fetchone()
    if not msg:
        return False, {'error': 'Message not found'}, 404
    
    if user_id != msg['sender_id'] and user_id != msg['recipient_id']:
        return False, {'error': 'No permission'}, 403
    
    return True, msg, 200


def get_user_public_key(user_id):
    """Get public key for user"""
    db = get_db()
    user = db.execute('SELECT public_key FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user or not user['public_key']:
        return None
    
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        public_key = load_pem_public_key(
            user['public_key'].encode(),
            backend=default_backend()
        )
        return public_key
    except Exception:
        pass
    
    return None


def verify_message_signature(encrypted_content, signature, public_key):
    """Verify message signature with RSA public key"""
    try:
        if not signature:
            return False
        message_hash = hashlib.sha256(encrypted_content.encode()).digest()
        signature_bytes = base64.b64decode(signature)
        public_key.verify(
            signature_bytes,
            message_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False


@messages_bp.route('/api/users', methods=['GET']) # show list of users
def list_users():
    db = get_db()
    my_id = get_current_user_id()
    users = db.execute('SELECT id, username FROM users WHERE id != ?', (my_id,)).fetchall()
    return jsonify([{'id': u['id'], 'username': u['username']} for u in users])


@messages_bp.route('/api/me', methods=['GET']) # get current user info
def get_me():
    db = get_db()
    my_id = get_current_user_id()
    if my_id is None:
        return jsonify({'id': None, 'username': None}), 200
    user = db.execute('SELECT id, username FROM users WHERE id = ?', (my_id,)).fetchone()
    if not user:
        return jsonify({'id': None, 'username': None}), 200
    return jsonify({'id': user['id'], 'username': user['username']})



# Get conversation with another user
@messages_bp.route('/api/messages/conversation/<int:user_id>', methods=['GET'])
def get_conversation(user_id):
    db = get_db()
    my_id = get_current_user_id()


    # mark messages sent to me by this user as read
    try:
        db.execute(
            'UPDATE messages SET is_read = 1 WHERE sender_id = ? AND recipient_id = ? AND is_read = 0',
            (user_id, my_id)
        )
        db.commit()
    except Exception:
        pass

    # fetch messages between me and the other user
    messages = db.execute('''
        SELECT m.id, m.sender_id, m.recipient_id, m.encrypted_content, m.session_key_encrypted, m.signature, m.is_read, u.username as sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.recipient_id = ?)
           OR (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.created_at ASC
    ''', (my_id, user_id, user_id, my_id)).fetchall()
    result = []

    # sanitize outgoing messages and attachments
    for m in messages:
        # fetch attachments for this message
        atts = db.execute('SELECT id, filename FROM attachments WHERE message_id = ?', (m['id'],)).fetchall()
        attachments = []
        for a in atts:
            fname = a['filename']
            try:
                if fname:
                    fname = clean_input(fname)
            except Exception:
                pass
            attachments.append({'id': a['id'], 'filename': fname})
        # Return encrypted content as-is (don't sanitize encrypted data)
        result.append({
            'id': m['id'], 
            'sender': m['sender'], 
            'sender_id': m['sender_id'], 
            'encrypted_content': m['encrypted_content'],
            'session_key_encrypted': m['session_key_encrypted'],
            'signature': m['signature'],
            'is_read': m['is_read'], 
            'attachments': attachments
        })
    return jsonify({'messages': result})


# send a new message
@messages_bp.route('/api/messages/send', methods=['POST'])
def send_message():
    try:
        db = get_db()
        my_id = get_current_user_id()
        if my_id is None:
            return jsonify({'error': 'Nieautoryzowany'}), 401

        # Support both JSON and multipart/form-data (for attachments)
        if request.content_type and request.content_type.startswith('multipart/form-data'):
            recipient_id = request.form.get('recipient_id')
            encrypted_content = request.form.get('encrypted_content')
            session_key_encrypted = request.form.get('session_key_encrypted')
            signature = request.form.get('signature', '')
        else:
            data = request.get_json() or {}
            recipient_id = data.get('recipient_id')
            encrypted_content = data.get('encrypted_content')
            session_key_encrypted = data.get('session_key_encrypted')
            signature = data.get('signature', '')

        if not recipient_id or not encrypted_content or not session_key_encrypted:
            return jsonify({'error': 'Brak wymaganych pól szyfrowanej wiadomości.'}), 400
        
        try:
            recipient_id = int(recipient_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'Nieprawidłowy odbiorca.'}), 400

        # Verify recipient exists
        recipient = db.execute('SELECT id FROM users WHERE id = ?', (recipient_id,)).fetchone()
        if not recipient:
            return jsonify({'error': 'Odbiorca nie istnieje.'}), 400

        # Verify signature if provided
        if signature:
            sender_public_key = get_user_public_key(my_id)
            if sender_public_key:
                if not verify_message_signature(encrypted_content, signature, sender_public_key):
                    return jsonify({'error': 'Signature verification failed'}), 400

        # Insert message into database (already encrypted from frontend)
        cur = db.execute(
            'INSERT INTO messages (sender_id, recipient_id, encrypted_content, session_key_encrypted, signature) VALUES (?, ?, ?, ?, ?)',
            (my_id, recipient_id, encrypted_content, session_key_encrypted, signature)
        )
        msg_id = cur.lastrowid
        db.commit()

        # handle file attachments if any (multipart)
        if request.files:
            files = request.files.getlist('attachments')
            for f in files:
                filename = f.filename
                try:
                    if filename:
                        filename = clean_input(filename)
                except Exception:
                    pass
                data = f.read()
                # limit file size (25MB)
                if len(data) > 25 * 1024 * 1024:
                    continue
                db.execute('INSERT INTO attachments (message_id, filename, encrypted_data) VALUES (?, ?, ?)', (msg_id, filename, data))
            db.commit()

        return jsonify({'message': 'Wysłano.', 'id': msg_id}), 201
    except Exception as e:
        return jsonify({'error': 'Server error', 'details': str(e)}), 500



# Delete a message

# Get public key for a user
@messages_bp.route('/api/users/<int:user_id>/public-key', methods=['GET'])
def get_user_public_key_route(user_id):
    """Get public key for a user"""
    db = get_db()
    user = db.execute('SELECT public_key FROM users WHERE id = ?', (user_id,)).fetchone()
    
    if not user or not user['public_key']:
        return jsonify({'error': 'Nie znaleziono klucza publicznego.'}), 404
    
    return jsonify({'public_key': user['public_key']}), 200


@messages_bp.route('/api/messages/<int:msg_id>', methods=['DELETE'])
def delete_message(msg_id):
    """Delete a message if requester is sender or recipient."""
    db = get_db()
    my_id = get_current_user_id()
    
    has_permission, result, status_code = check_message_permission(my_id, msg_id, db)
    if not has_permission:
        return jsonify(result), status_code
    
    db.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
    db.commit()
    return '', 204



@messages_bp.route('/api/attachments/<int:att_id>', methods=['GET'])
def download_attachment(att_id):
    db = get_db()
    my_id = get_current_user_id()
    
    att = db.execute('SELECT message_id, filename, encrypted_data FROM attachments WHERE id = ?', (att_id,)).fetchone()
    if not att:
        return jsonify({'error': 'Attachment not found'}), 404
    
    has_permission, _, status_code = check_message_permission(my_id, att['message_id'], db)
    if not has_permission:
        return jsonify({'error': 'No permission'}), status_code
    
    # Return encrypted file data as base64 (frontend will decrypt it)
    encrypted_data_b64 = base64.b64encode(att['encrypted_data']).decode('utf-8')
    return jsonify({
        'id': att_id,
        'filename': att['filename'],
        'encrypted_data': encrypted_data_b64
    }), 200

