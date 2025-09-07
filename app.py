from flask import Flask, render_template, request, make_response, redirect, url_for
import jwt
import os
from datetime import datetime, timedelta, timezone
from functools import wraps

# Initialize the Flask application.
# By default, Flask looks for a 'static' folder for assets (CSS, JS, images)
# and we explicitly tell it that our HTML files are in the 'templates' folder.
app = Flask(__name__, template_folder='templates')

# --- Configuration ---
# On Render, you will set this as an environment variable for security.
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET', 'a-default-fallback-secret-key-for-local-dev')

# This is your hardcoded user for the closed alpha.
# In a real app, these would also be environment variables or come from a database.
VALID_USERNAME = "alpha-user"
VALID_PASSWORD = "invite-password"

# --- Login Protection (Decorator) ---
# This is the replacement for your middleware.js. It's a Python "decorator"
# that we can place above any route we want to protect.
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        # If no token is found, redirect to the login page.
        if not token:
            return redirect(url_for('login_page'))
        try:
            # Try to decode the token. If it's expired or invalid, it will raise an error.
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except:
            # If decoding fails, the token is bad. Redirect to login and clear the bad cookie.
            resp = make_response(redirect(url_for('login_page')))
            resp.set_cookie('token', '', expires=0)
            return resp
        # If the token is valid, run the original function (e.g., show the requested page).
        return f(*args, **kwargs)
    return decorated

# --- Public Routes (No Login Required) ---

@app.route('/login.html')
def login_page():
    """Serves the login.html page."""
    return render_template('login.html')

@app.route('/apply.html')
def apply_page():
    """Serves the apply.html page."""
    return render_template('apply.html')

@app.route('/api/login', methods=['POST'])
def login_api():
    """
    This handles the form submission from the login page, verifies credentials,
    and sets the authentication cookie.
    """
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

    if data['username'] == VALID_USERNAME and data['password'] == VALID_PASSWORD:
        # Create a token that expires in 30 days
        token = jwt.encode({
            'user': data['username'],
            'exp': datetime.now(timezone.utc) + timedelta(days=30)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        
        resp = make_response({'message': 'Login successful!'})
        # Set the cookie with security best practices
        resp.set_cookie('token', token, httponly=True, secure=True, samesite='Lax', max_age=30*24*60*60)
        return resp

    return make_response('Could not verify', 401, {'WWW-Authenticate': 'Basic realm="Login required!"'})

# --- Protected Routes (Login IS Required) ---

@app.route('/')
@token_required # This decorator protects the route
def index():
    """Serves the main index.html landing page."""
    return render_template('index.html')

@app.route('/session-scribe')
@token_required # This decorator protects the route
def session_scribe():
    """Serves the session-scribe app page."""
    return render_template('session-scribe/index.html')

# You can add more protected routes here following the same pattern.
# For example, if you had a page at /character-creator/index.html:
#
# @app.route('/character-creator')
# @token_required
# def character_creator():
#     return render_template('character-creator/index.html')

# --- Running the App ---
if __name__ == '__main__':
    # This block is for running the app locally for testing purposes.
    # Render will use the 'gunicorn' command specified in the guide instead.
    app.run(debug=True, port=5000)


