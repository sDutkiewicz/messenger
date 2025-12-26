from flask import Blueprint, request, jsonify
from db import get_db
from flask import session
messages_bp = Blueprint('messages', __name__)


def get_current_user_id():
    user_id = session.get('user_id')
    if user_id is None:
        # For demo: return 1 (alice) if not logged in
        return 1
    return user_id

@messages_bp.route('/api/users', methods=['GET'])
def list_users():
    db = get_db()
    my_id = get_current_user_id()
    users = db.execute('SELECT id, username FROM users WHERE id != ?', (my_id,)).fetchall()
    return jsonify([{'id': u['id'], 'username': u['username']} for u in users])


@messages_bp.route('/api/me', methods=['GET'])
def get_me():
    db = get_db()
    my_id = get_current_user_id()
    if my_id is None:
        return jsonify({'id': None, 'username': None}), 200
    user = db.execute('SELECT id, username FROM users WHERE id = ?', (my_id,)).fetchone()
    if not user:
        return jsonify({'id': None, 'username': None}), 200
    return jsonify({'id': user['id'], 'username': user['username']})

@messages_bp.route('/api/messages/conversation/<int:user_id>', methods=['GET'])
def get_conversation(user_id):
    db = get_db()
    my_id = get_current_user_id()
    messages = db.execute('''
        SELECT m.id, m.sender_id, m.recipient_id, m.encrypted_content as content, u.username as sender
        FROM messages m
        JOIN users u ON m.sender_id = u.id
        WHERE (m.sender_id = ? AND m.recipient_id = ?)
           OR (m.sender_id = ? AND m.recipient_id = ?)
        ORDER BY m.created_at ASC
    ''', (my_id, user_id, user_id, my_id)).fetchall()
    return jsonify({'messages': [
        {'id': m['id'], 'sender': m['sender'], 'sender_id': m['sender_id'], 'content': m['content']} for m in messages
    ]})

@messages_bp.route('/api/messages/send', methods=['POST'])
def send_message():
    try:
        data = request.get_json() or {}
        recipient_id = data.get('recipient_id')
        content = (data.get('content') or '').strip()
        if not recipient_id or not content:
            return jsonify({'error': 'Brak odbiorcy lub treści.'}), 400
        db = get_db()
        my_id = get_current_user_id()
        if my_id is None:
            return jsonify({'error': 'Nieautoryzowany'}), 401
        cur = db.execute(
            'INSERT INTO messages (sender_id, recipient_id, encrypted_content, session_key_encrypted, signature) VALUES (?, ?, ?, ?, ?)',
            (my_id, recipient_id, content, '', '')
        )
        db.commit()
        return jsonify({'message': 'Wysłano.', 'id': cur.lastrowid}), 201
    except Exception as e:
        return jsonify({'error': 'Server error', 'details': str(e)}), 500

