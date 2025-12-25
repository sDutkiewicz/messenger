from flask import Blueprint, request, jsonify

messages_bp = Blueprint('messages', __name__)

@messages_bp.route('/api/messages/send', methods=['POST'])
def send_message():
    # TODO
    return jsonify({'message': 'Send message endpoint'}), 200

@messages_bp.route('/api/messages/inbox', methods=['GET'])
def inbox():
    # TODO
    return jsonify({'messages': []}), 200

@messages_bp.route('/api/messages/<int:msg_id>', methods=['GET'])
def get_message(msg_id):
    # TODO
    return jsonify({'message': f'Message {msg_id} details'}), 200
