
from flask import Flask, jsonify
from werkzeug.middleware.proxy_fix import ProxyFix
import os


from auth import auth_bp
from messages import messages_bp
from db import get_db, close_db, init_db


app = Flask(__name__)


# ProxyFix for NGINX reverse proxy headers
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Initialize database on app startup
with app.app_context():
    init_db()

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
app.config['DATABASE'] = os.getenv('DATABASE_PATH', '/app/data/messenger.db')

# Register blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(messages_bp)

# Database connection hooks
@app.before_request
def before_request():
    get_db()

@app.teardown_appcontext
def teardown_db(exception):
    close_db(exception)

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'version': '1.0.0'}), 200

@app.route('/api/health', methods=['GET'])
def api_health():
    """API health check"""
    return jsonify({'status': 'ok'}), 200

@app.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=8000)
