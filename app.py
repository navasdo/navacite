from flask import Flask, render_template, request, make_response, redirect, url_for
import jwt
import os
from functools import wraps
from datetime import datetime, timedelta

app = Flask(__name__, template_folder='templates', static_folder='static')

# --- Configuration ---
# It's crucial to set a secret key for signing the JWTs.
# On Render, set this as an environment variable named JWT_SECRET.
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET', 'a-very-secret-key-that-you-should-change')

# --- User Management ---
# For your closed alpha, you can hardcode the approved users here.
# To add/remove users, just edit this dictionary and redeploy.
USERS = {
    "dnavas": "Almanueva1!",
    "user2": "anotherSecurePassword",
    # Example for a new user:
    # "new_user": "their_password"
}

# --- Decorator for Token Authentication ---
# This is the "gatekeeper" that protects your pages.
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            # If no token is found, redirect to the login page.
            return redirect(url_for('login_page'))
        try:
            # Verify the token is valid and not expired.
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            # If the token is invalid for any reason, send them to login.
            return redirect(url_for('login_page'))
        # If the token is valid, let them see the page they requested.
        return f(*args, **kwargs)
    return decorated

# --- API Route for Login ---
@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return {"error": "Username and password are required"}, 400

    username = data.get('username')
    password = data.get('password')

    # Check if the submitted username and password match our USERS list.
    if username in USERS and USERS[username] == password:
        # If they match, create a secure token that expires in 24 hours.
        token = jwt.encode({
            'user': username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")

        # Send a success message and set the token in a secure, http-only cookie.
        response = make_response({"message": "Login successful"})
        response.set_cookie('token', token, httponly=True, secure=True, samesite='Lax')
        return response
    else:
        # If credentials are wrong, return an error.
        return {"error": "Invalid credentials"}, 401

# --- Page Routes ---

# Serves the login page. This route is public.
@app.route('/login')
def login_page():
    return render_template('login.html')

# Serves the application info page. This route is public.
@app.route('/apply')
def apply_page():
    return render_template('apply.html')

# This is your main landing page. The @token_required decorator protects it.
@app.route('/index')
@token_required
def index():
    return render_template('index.html')

# Example of another protected route for a sub-page.
@app.route('/session-scribe')
@token_required
def session_scribe():
    # This serves the index.html file from the templates/session-scribe/ directory.
    try:
        return render_template('session-scribe/index.html')
    except:
        return "Page not found", 404


# This allows the app to run when you execute `python app.py` on your own computer.
if __name__ == '__main__':
    app.run(debug=True)

