from flask import Blueprint, request, jsonify, send_file
from db import get_db
from flask import session
from sanitize import clean_input
import io


# Blueprint for message-related routes
messages_bp = Blueprint('messages', __name__)


def get_current_user_id(): # return logged-in user ID from session
    user_id = session.get('user_id')
    if user_id is None:
        # For demo: return 1 (alice) if not logged in
        return 1
    return user_id

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
        SELECT m.id, m.sender_id, m.recipient_id, m.encrypted_content as content, m.is_read, u.username as sender
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
        # sanitize outgoing content
        content_out = m['content']
        try:
            if content_out:
                content_out = clean_input(content_out)
        except Exception:
            pass
        result.append({'id': m['id'], 'sender': m['sender'], 'sender_id': m['sender_id'], 'content': content_out, 'is_read': m['is_read'], 'attachments': attachments})
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
            content = (request.form.get('content') or '').strip()
            try:
                if content:
                    content = clean_input(content)
            except Exception:
                pass
        else:
            data = request.get_json() or {}
            recipient_id = data.get('recipient_id')
            content = (data.get('content') or '').strip()
            try:
                if content:
                    content = clean_input(content)
            except Exception:
                pass

        if not recipient_id or not content:
            return jsonify({'error': 'Brak odbiorcy lub treści.'}), 400
        
        try:
            recipient_id = int(recipient_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'Nieprawidłowy odbiorca.'}), 400

        cur = db.execute(
            'INSERT INTO messages (sender_id, recipient_id, encrypted_content, session_key_encrypted, signature) VALUES (?, ?, ?, ?, ?)',
            (my_id, recipient_id, content, '', '')
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
@messages_bp.route('/api/messages/<int:msg_id>', methods=['DELETE'])
def delete_message(msg_id):
    """Delete a message if requester is sender or recipient."""
    db = get_db()
    my_id = get_current_user_id()


    if my_id is None:
        return jsonify({'error': 'Non-authorized'}), 401
    

    msg = db.execute('SELECT sender_id, recipient_id FROM messages WHERE id = ?', (msg_id,)).fetchone()
    if not msg:
        return jsonify({'error': 'Message not found.'}), 404
    
    if my_id != msg['sender_id'] and my_id != msg['recipient_id']:
        return jsonify({'error': 'No permission.'}), 403
    
    db.execute('DELETE FROM messages WHERE id = ?', (msg_id,))
    db.commit()
    return '', 204 # No Content



# Download attachment
@messages_bp.route('/api/attachments/<int:att_id>', methods=['GET'])
def download_attachment(att_id):
    db = get_db()
    my_id = get_current_user_id()
    if my_id is None:
        return jsonify({'error': 'Non-authorized'}), 401
    att = db.execute('SELECT message_id, filename, encrypted_data FROM attachments WHERE id = ?', (att_id,)).fetchone()
    if not att:
        return jsonify({'error': 'Attachment not found.'}), 404
    
    # check permission: user must be sender or recipient of message
    msg = db.execute('SELECT sender_id, recipient_id FROM messages WHERE id = ?', (att['message_id'],)).fetchone()
    if not msg:
        return jsonify({'error': 'Related message not found.'}), 404
    if my_id != msg['sender_id'] and my_id != msg['recipient_id']:
        return jsonify({'error': 'No permission.'}), 403
    data = att['encrypted_data']
    # return as attachment

    
    return send_file(io.BytesIO(data), download_name=att['filename'], as_attachment=True)

