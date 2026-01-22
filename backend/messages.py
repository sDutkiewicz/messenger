from flask import Blueprint, request, jsonify
from flask import session, current_app
from helpers.sanitize import clean_input
import base64

# Import helper modules
from session_keys import SessionKeys
from db_queries import UserQueries, MessageQueries, AttachmentQueries, LoginAttemptQueries
from constants import MAX_FILE_SIZE_BYTES, ERROR_UNAUTHORIZED, ERROR_USER_NOT_FOUND

# Blueprint for message-related routes
messages_bp = Blueprint('messages', __name__)


def sanitize_filename(filename):
    """Safely sanitize attachment filename"""
    try:
        return clean_input(filename) if filename else None
    except Exception:
        return None


def get_current_user_id():
    """
    Return logged-in user ID from session.
    
    returns user_id=1 (alice) if not logged in.
    In production, should return None and endpoints should return 401.
    """
    user_id = session.get(SessionKeys.USER_ID)
    if user_id is None:
        return 1  # Demo user - change in production
    return user_id


def check_message_permission(user_id, msg_id):
    """Check if user has permission to access message (sender or recipient)"""
    if user_id is None:
        return False, {'error': ERROR_UNAUTHORIZED}, 401
    
    msg = MessageQueries.get_by_id(msg_id)
    if not msg:
        return False, {'error': 'Message not found'}, 404
    
    if user_id != msg['sender_id'] and user_id != msg['recipient_id']:
        return False, {'error': 'No permission'}, 403
    
    return True, msg, 200


def get_user_public_key(user_id):
    """
    Retrieve user's RSA public key from database.
    Used for encrypting AES key for message recipients.
    """
    user = UserQueries.get_by_id(user_id)
    
    if not user or not user['public_key']:
        return None
    
    try:
        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        public_key = load_pem_public_key(
            user['public_key'].encode()
        )
        return public_key
    except Exception as e:
        current_app.logger.error('Error loading public key: %s', str(e))
        return None



@messages_bp.route('/api/users', methods=['GET'])
def list_users():
    """
    Download list of all users (id and username) except self
    """
    my_id = get_current_user_id()
    users = UserQueries.get_all_except(my_id)
    return jsonify([{'id': u['id'], 'username': clean_input(u['username'])} for u in users])


@messages_bp.route('/api/me', methods=['GET'])
def get_me():
    """
    Retrieve current user information.
    Returns user ID, username, and 2FA recovery mode status.
    """
    my_id = get_current_user_id()
    if my_id is None:
        return jsonify({'id': None, 'username': None, 'in_2fa_recovery_mode': False}), 200
    
    user = UserQueries.get_by_id(my_id)
    if not user:
        return jsonify({'id': None, 'username': None, 'in_2fa_recovery_mode': False}), 200
    
    # Check if user is in 2FA recovery mode (forced new 2FA setup)
    in_recovery = session.get(SessionKeys.IN_2FA_RECOVERY_MODE, False)
    
    return jsonify({
        'id': user['id'], 
        'username': clean_input(user['username']),
        'in_2fa_recovery_mode': in_recovery
    })

@messages_bp.route('/api/messages/conversation/<int:user_id>', methods=['GET'])
def get_conversation(user_id):
    """
    Retrieve conversation with another user.
    Loads all messages (sent and received), marks partner messages as read.
    Returns encrypted_content and session_key_encrypted for frontend decryption.
    """
    my_id = get_current_user_id()

    # Mark all messages from this user as read
    try:
        MessageQueries.mark_as_read(user_id, my_id)
    except Exception as e:
        current_app.logger.error('Error marking messages as read: %s', str(e))

    # Retrieve all messages between current user and this user
    messages = MessageQueries.get_conversation(my_id, user_id)
    
    result = []

    # Return messages with attachments (data is encrypted - do not sanitize!)
    for m in messages:
        # Retrieve attachments for this message
        atts = AttachmentQueries.get_by_message(m['id'])
        attachments = []
        for a in atts:
            fname = sanitize_filename(a['filename'])
            attachments.append({'id': a['id'], 'filename': fname})
        
        # Return encrypted content as-is (do not sanitize encrypted data!)
        result.append({
            'id': m['id'], 
            'sender': clean_input(m['sender']),
            'sender_id': m['sender_id'], 
            'encrypted_content': m['encrypted_content'],
            'session_key_encrypted': m['session_key_encrypted'],
            'signature': m['signature'],
            'is_read': m['is_read'], 
            'attachments': attachments
        })
    return jsonify({'messages': result})


# Send a new message
@messages_bp.route('/api/messages/send', methods=['POST'])
def send_message():
    try:
        my_id = get_current_user_id()
        if my_id is None:
            return jsonify({'error': ERROR_UNAUTHORIZED}), 401

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
            return jsonify({'error': 'Missing required encrypted message fields.'}), 400
        
        try:
            recipient_id = int(recipient_id)
        except (ValueError, TypeError):
            return jsonify({'error': 'Invalid recipient.'}), 400

        # Verify recipient exists
        if not UserQueries.get_by_id(recipient_id):
            return jsonify({'error': 'Recipient does not exist.'}), 400
       
        # Insert message into database (already encrypted from frontend)
        msg_id = MessageQueries.send(my_id, recipient_id, encrypted_content, session_key_encrypted, signature)

        # Handle attachments from JSON if any
        attachments = data.get('attachments', [])
        for att in attachments:
            if isinstance(att, dict):
                filename = sanitize_filename(att.get('filename', 'file'))
                encrypted_data_b64 = att.get('encrypted_data', '')
                
                # encrypted_data is already a base64 string from frontend (format "U2FsdGVk...")
                # Convert it to bytes for storage
                try:
                    encrypted_data = encrypted_data_b64.encode('utf-8')
                    if len(encrypted_data) > MAX_FILE_SIZE_BYTES:
                        continue
                    AttachmentQueries.add(msg_id, filename, encrypted_data)
                except Exception:
                    continue

        return jsonify({'message': 'Sent.', 'id': msg_id}), 201
    except Exception as e:
        current_app.logger.error('Error sending message: %s', str(e))
        return jsonify({'error': 'Server error', 'details': str(e)}), 500



# Get public key for a user
@messages_bp.route('/api/users/<int:user_id>/public-key', methods=['GET'])
def get_user_public_key_route(user_id):
    """Retrieve RSA public key for specified user."""
    user = UserQueries.get_by_id(user_id)
    
    if not user or not user['public_key']:
        return jsonify({'error': 'Public key not found.'}), 404
    
    return jsonify({'public_key': user['public_key']}), 200



# Delete a message
@messages_bp.route('/api/messages/<int:msg_id>', methods=['DELETE'])
def delete_message(msg_id):
    """Delete a message if requester is sender or recipient."""
    my_id = get_current_user_id()
    
    has_permission, result, status_code = check_message_permission(my_id, msg_id)
    if not has_permission:
        return jsonify(result), status_code
    
    MessageQueries.delete(msg_id)
    return '', 204




# Download attachment
@messages_bp.route('/api/attachments/<int:att_id>', methods=['GET'])
def download_attachment(att_id):
    my_id = get_current_user_id()
    
    att = AttachmentQueries.get_by_id(att_id)
    if not att:
        return jsonify({'error': 'Attachment not found'}), 404
    
    has_permission, _, status_code = check_message_permission(my_id, att['message_id'])
    if not has_permission:
        return jsonify({'error': 'No permission'}), status_code
    
    # Return encrypted file data
    # encrypted_data is the raw UTF-8 bytes of the "U2FsdGVk..." string
    encrypted_data_str = att['encrypted_data'].decode('utf-8')
    return jsonify({
        'id': att_id,
        'filename': att['filename'],
        'encrypted_data': encrypted_data_str
    }), 200

