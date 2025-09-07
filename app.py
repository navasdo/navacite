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
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET', 'a-very-secret-key-that-you-should-change')

# --- User Management ---
USERS = {
    "user1": "password123",
    "user2": "anotherSecurePassword",
}

# --- Decorator for Token Authentication ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        app.logger.info(f"Checking token for protected path: {request.path}")
        if not token:
            app.logger.warning("No token found. Redirecting to login.")
            return redirect(url_for('login_page'))
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            app.logger.info("Token is valid.")
        except Exception as e:
            app.logger.error(f"Token validation failed: {e}. Redirecting to login.")
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# --- API Route for Login ---
@app.route('/api/login', methods=['POST'])
def login_api():
    # (No changes to this function)
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

# --- Page Routes with Logging ---

@app.route('/login')
def login_page():
    app.logger.info("Request received for /login route.")
    return render_template('login.html')

@app.route('/apply')
def apply_page():
    app.logger.info("Request received for /apply route.")
    return render_template('apply.html')

# NEW: This is now a "gatekeeper" route. It decides where the user should go.
@app.route('/')
def index():
    token = request.cookies.get('token')
    app.logger.info("Root path '/' accessed. Checking for token.")
    if not token:
        app.logger.warning("No token found at root. Redirecting to login.")
        return redirect(url_for('login_page'))
    try:
        # Check if the token is valid
        jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        app.logger.info("Valid token found at root. Redirecting to home page.")
        # If token is valid, send them to the actual protected home page
        return redirect(url_for('home_page'))
    except:
        # If token is invalid for any reason, send them to login
        app.logger.error("Invalid token found at root. Redirecting to login.")
        return redirect(url_for('login_page'))

# NEW: This is the actual homepage, which is protected.
@app.route('/home')
@token_required
def home_page():
    app.logger.info("Request received for protected /home route. Serving index.html.")
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

# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    app.logger.warning(f"404 Not Found error triggered for path: {request.path}")
    return "This page was not found in the application.", 404

if __name__ == '__main__':
    app.run(debug=True)

