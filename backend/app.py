from flask import Flask, jsonify, send_from_directory, request
from werkzeug.middleware.proxy_fix import ProxyFix
from datetime import datetime, timedelta
import os
import hmac
import secrets
from auth import auth_bp
from messages import messages_bp
from db import get_db, close_db, init_db


def get_client_ip():
    """Get real client IP address from reverse proxy headers"""
    # ProxyFix has already interpreted the single trusted proxy hop.  Reading
    # X-Forwarded-For directly would allow a client to spoof its address.
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

secret_key = os.getenv('SECRET_KEY')
if not secret_key:
    if os.getenv('FLASK_ENV', 'development').lower() == 'production':
        raise RuntimeError('SECRET_KEY must be set in production')
    secret_key = secrets.token_urlsafe(48)


# ProxyFix for NGINX reverse proxy headers
# Creates chain of trusted proxies for secure IP/protocol detection
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)

# Initialize database on app startup
with app.app_context():
    init_db()

# Application configuration
app.config.update(
    SECRET_KEY=secret_key,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=os.getenv(
        'SESSION_COOKIE_SECURE',
        'true' if os.getenv('FLASK_ENV', 'development').lower() == 'production' else 'false'
    ).lower() == 'true',
    SESSION_COOKIE_SAMESITE='Strict',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
    MAX_CONTENT_LENGTH=35 * 1024 * 1024,
)
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
    # This endpoint is intentionally available only outside production; proxy
    # and client metadata is useful for debugging but should not be public.
    if os.getenv('FLASK_ENV', 'development').lower() == 'production':
        return jsonify({'error': 'Not found'}), 404
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
    if request.method in {'POST', 'PUT', 'PATCH', 'DELETE'}:
        cookie_token = request.cookies.get('csrf_token', '')
        header_token = request.headers.get('X-CSRF-Token', '')
        if not cookie_token or not header_token or not hmac.compare_digest(cookie_token, header_token):
            return jsonify({'error': 'Invalid CSRF token'}), 403

@app.after_request
def set_security_response_headers(response):
    # Double-submit CSRF token: readable by same-origin JavaScript, but still
    # protected from cross-site form/fetch requests by the matching header.
    if not request.cookies.get('csrf_token'):
        response.set_cookie(
            'csrf_token', secrets.token_urlsafe(32), secure=app.config['SESSION_COOKIE_SECURE'],
            httponly=False, samesite='Strict', path='/'
        )
    response.headers['Cache-Control'] = 'no-store' if request.path.startswith('/api/') else response.headers.get('Cache-Control', 'no-cache')
    return response

@app.teardown_appcontext
def teardown_db(exception):
    """Close database connection after each request"""
    close_db(exception)


if __name__ == '__main__':
    print("Messenger aplikacja")

    
    
    print("Reverse Proxy: Nginx on https://localhost")
    print("API Health: GET /api/health")
    print("Application: GET /")
    print("=" * 70)
    app.run(host='127.0.0.1', port=8000, debug=False)
