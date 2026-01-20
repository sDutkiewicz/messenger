from flask import Flask, jsonify, send_from_directory, request
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime
import os
from auth import auth_bp
from messages import messages_bp
from db import get_db, close_db, init_db


def get_client_ip():
    """Get real client IP address from reverse proxy headers"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    if request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    return request.remote_addr


def get_request_info():
    """Detailed request and reverse proxy information"""
    return {
        'client_ip': get_client_ip(),
        'remote_addr': request.remote_addr,
        'x_forwarded_for': request.headers.get('X-Forwarded-For'),
        'x_real_ip': request.headers.get('X-Real-IP'),
        'x_forwarded_proto': request.headers.get('X-Forwarded-Proto'),
        'x_forwarded_host': request.headers.get('X-Forwarded-Host'),
        'host': request.host,
        'user_agent': request.user_agent.string,
        'method': request.method,
        'scheme': request.scheme,
        'path': request.path,
    }


# Directory path for frontend static files
FRONTEND_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'frontend')) 
app = Flask(__name__)


# ProxyFix for NGINX reverse proxy headers
# Creates chain of trusted proxies for secure IP/protocol detection
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Initialize database on app startup
with app.app_context():
    init_db()

# Application configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production') 
app.config['DATABASE'] = os.getenv('DATABASE_PATH', '/app/data/messenger.db')

# Register blueprints (auth and messages endpoints)
app.register_blueprint(auth_bp)
app.register_blueprint(messages_bp)

# === API ENDPOINTS - System Information ===

@app.route('/api/info')
def api_info():
    """Application information and encryption details"""
    return jsonify({
        'app': 'Messenger - Encrypted Communication',
        'service': 'Flask API',
        'server': 'Gunicorn WSGI',
        'proxy': 'Nginx HTTPS Reverse Proxy',
        'encryption': {
            'messages': 'AES-256-GCM (hybrid)',
            'keys': 'RSA-2048 OAEP',
            'passwords': 'Argon2id',
            'key_derivation': 'PBKDF2-SHA256'
        },
        'auth_2fa': 'TOTP RFC 6238',
        'database': 'SQLite3',
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/health')
def api_health():
    """Health check endpoint - confirms service is running"""
    return jsonify({
        'status': 'ok',
        'service': 'Flask + Gunicorn + Nginx',
        'timestamp': datetime.now().isoformat()
    }), 200


@app.route('/api/client-info')
def api_client_info():
    """Client and request information (for reverse proxy debugging)"""
    return jsonify({
        'client': get_request_info(),
        'connection': {
            'real_ip': get_client_ip(),
            'is_secure': request.is_secure,
            'is_proxied': bool(request.headers.get('X-Forwarded-For')),
        },
        'timestamp': datetime.now().isoformat()
    }), 200

# === STATIC FILES SERVING ===

@app.route('/')
def serve_index():
    return send_from_directory(FRONTEND_DIR, 'index.html')

@app.route('/login.html')
def serve_login():
    return send_from_directory(FRONTEND_DIR, 'login.html')

@app.route('/register.html')
def serve_register():
    return send_from_directory(FRONTEND_DIR, 'register.html')

@app.route('/dashboard.html')
def serve_dashboard():
    return send_from_directory(FRONTEND_DIR, 'dashboard.html')

@app.route('/<path:filename>')
def serve_static(filename):
    """Serve other static files (CSS, JS, images)"""
    return send_from_directory(FRONTEND_DIR, filename)


# === ERROR HANDLERS ===

@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500


# === DATABASE HOOKS ===

@app.before_request
def before_request():
    """Initialize database connection before each request"""
    get_db()

@app.teardown_appcontext
def teardown_db(exception):
    """Close database connection after each request"""
    close_db(exception)


if __name__ == '__main__':
    print("=" * 70)
    print("Messenger - Encrypted Communication Application")
    print("=" * 70)
    print("Run with Gunicorn (as non-root user):")
    print("  gunicorn -w 4 -b 0.0.0.0:8000 --timeout 120 wsgi:app")
    print("")
    print("In Docker (automatically):")
    print("  docker-compose up")
    print("")
    print("Reverse Proxy: Nginx on https://localhost")
    print("API Health: GET /api/health")
    print("Application: GET /")
    print("=" * 70)
    app.run(host='127.0.0.1', port=8000, debug=False)
