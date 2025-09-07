from flask import Flask, render_template, request, make_response, redirect, url_for, abort
import jwt
import os
from functools import wraps
from datetime import datetime, timedelta
import logging

# --- Basic Configuration ---
app = Flask(__name__, template_folder='templates', static_folder='static')
logging.basicConfig(level=logging.INFO)

# --- Security Configuration ---
# This securely reads your secret key from Render's environment variables.
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET', 'a-very-secret-key-that-you-should-change')

# --- User Management ---
# This is where you add and remove users for your closed alpha.
USERS = {
    "dnavas": "Almanueva1!",
    "user2": "anotherSecurePassword",
}

# --- Decorator for Token Authentication ---
# This function is the "gatekeeper" for your protected pages.
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        app.logger.info(f"Checking token for protected path: {request.path}")
        if not token:
            app.logger.warning("No token found. Redirecting to login.")
            return redirect(url_for('login_page'))
        try:
            # CRITICAL FIX: Ensures the token is validated with the correct algorithm.
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            app.logger.info("Token is valid.")
        except Exception as e:
            app.logger.error(f"Token validation failed: {e}. Redirecting to login.")
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# --- API Route for Login ---
# This handles the form submission from your login page.
@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return {"error": "Username and password are required"}, 400
    username = data.get('username')
    password = data.get('password')
    if username in USERS and USERS[username] == password:
        token = jwt.encode({
            'user': username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        response = make_response({"message": "Login successful"})
        response.set_cookie('token', token, httponly=True, secure=True, samesite='Lax')
        return response
    else:
        return {"error": "Invalid credentials"}, 401

# --- Page Routes ---

@app.route('/login')
def login_page():
    app.logger.info("Request received for /login route.")
    return render_template('login.html')

@app.route('/apply')
def apply_page():
    app.logger.info("Request received for /apply route.")
    return render_template('apply.html')

# The main route is now the protected homepage.
@app.route('/')
@token_required
def index():
    app.logger.info("Request received for protected / route. Serving index.html.")
    try:
        return render_template('index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find or render 'templates/index.html'. Error: {e}")
        abort(500)

@app.route('/session-scribe')
@token_required
def session_scribe():
    app.logger.info("Request for /session-scribe. Trying 'templates/session-scribe/index.html'.")
    try:
        return render_template('session-scribe/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find 'templates/session-scribe/index.html'. Error: {e}")
        abort(500)

# --- Add new routes for your other pages here ---
# EXAMPLE: To add a new protected page for a "Character Sheet" app
# The URL will be navacite.com/character-sheet
@app.route('/character-sheet')
@token_required
def character_sheet():
    app.logger.info("Request for /character-sheet. Trying 'templates/character-sheet/index.html'.")
    try:
        return render_template('character-sheet/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find 'templates/character-sheet/index.html'. Error: {e}")
        abort(500)

# --- Redirects to enforce clean URLs ---
# These catch old links and point them to the correct, clean URL.
@app.route('/index.html')
def index_html_redirect():
    return redirect(url_for('index'), 301)

@app.route('/apply.html')
def apply_html_redirect():
    return redirect(url_for('apply_page'), 301)


# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    app.logger.warning(f"404 Not Found error triggered for path: {request.path}")
    return "This page was not found in the application.", 404

if __name__ == '__main__':
    app.run(debug=True)

