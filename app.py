from flask import Flask, render_template, request, make_response, redirect, url_for, abort, g
import jwt
import os
from functools import wraps
from datetime import datetime, timedelta
import logging
import requests
import json
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import click
import base64
import re
from sqlalchemy import desc

# --- Basic Configuration ---
app = Flask(__name__, template_folder='templates', static_folder='static')
logging.basicConfig(level=logging.INFO)

# --- Security Configuration ---
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET', 'a-very-secret-key-that-you-should-change')
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///default.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['GEMINI_API_KEY_COGNITION'] = os.environ.get('GEMINI_API_KEY_COGNITION')
app.config['GEMINI_API_KEY_SLP'] = os.environ.get('GEMINI_API_KEY_SLP')

# --- Database and Encryption Setup ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Database Models ---
class User(db.Model):
    __tablename__ = 'user'  # EXPLICITLY DEFINE the table name as lowercase 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    
    # NEW FIELDS FOR REGISTRATION
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    # UPDATED: Made email required for all new accounts
    email = db.Column(db.String(120), unique=True, nullable=False)
    
    # Existing fields
    display_name = db.Column(db.String(100)) 
    real_name = db.Column(db.String(100))
    location = db.Column(db.String(100))
    profile_photo_url = db.Column(db.Text) 
    about_me = db.Column(db.Text)
    fields = db.Column(db.JSON)
    interests = db.Column(db.JSON)
    hobbies = db.Column(db.JSON)
    specializations = db.Column(db.JSON)
    display_preference = db.Column(db.String(20), default='username')
    notifications_received = db.relationship('Notification', foreign_keys='Notification.recipient_id', backref='recipient', lazy='dynamic')

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    sender = db.relationship('User', foreign_keys=[sender_id])

# --- Custom CLI Command to Initialize DB ---
@app.cli.command("init-db")
def init_db_command():
    """Creates the database tables."""
    db.create_all()
    print("Initialized the database.")

# --- Session Management ---
@app.teardown_appcontext
def shutdown_session(exception=None):
    db.session.remove()

# --- App Context Processor ---
@app.context_processor
def inject_user_and_notifications():
    notification_count = 0
    if g.user:
        notification_count = Notification.query.filter_by(recipient_id=g.user.id, is_read=False).count()
    return dict(current_user=g.user, notification_count=notification_count)

# --- App Context Processor ---
@app.before_request
def load_logged_in_user():
    token = request.cookies.get('token')
    g.user = None
    if token:
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            g.user = User.query.filter_by(username=data['user']).first()
        except Exception as e:
            g.user = None

# --- Decorator for Token Authentication ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if g.user is None:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# --- API Routes ---
@app.route('/api/register', methods=['POST'])
def register_api():
    data = request.get_json()
    # UPDATED: Check for all new required fields from the multi-step form
    required_fields = ['username', 'password', 'email', 'firstName', 'lastName']
    if not data or not all(field in data and data[field] for field in required_fields):
        return jsonify({"error": "All fields are required"}), 400
    
    # Check if username or email is already taken
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username is already taken"}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "An account with that email already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    # UPDATED: Create new user with all the new details
    new_user = User(
        username=data['username'],
        password=hashed_password,
        email=data['email'],
        first_name=data['firstName'],
        last_name=data['lastName'],
        real_name=f"{data['firstName']} {data['lastName']}" # Set real_name by default
    )
    
    db.session.add(new_user)
    db.session.commit()
    
    # This is where the email verification process will be triggered in the future.
    return jsonify({"message": "User registered successfully. Please verify your email."}), 201


@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return {"error": "Username and password are required"}, 400
    
    try:
        user = User.query.filter_by(username=data.get('username')).first()
        if user and bcrypt.check_password_hash(user.password, data.get('password')):
            token = jwt.encode({
                'user': user.username,
                'exp': datetime.utcnow() + timedelta(hours=24)
            }, app.config['SECRET_KEY'], algorithm="HS256")
            response = make_response(jsonify({"message": "Login successful"}))
            response.set_cookie('token', token, httponly=True, secure=True, samesite='Lax')
            return response
        else:
            return jsonify({"error": "Invalid credentials"}), 401
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Database error during login: {e}")
        return jsonify({"error": "A server error occurred during login. Please try again."}), 500

@app.route('/api/profile', methods=['POST'])
@token_required
def update_profile_api():
    data = request.get_json()
    user = g.user

    forbidden_keywords = ['politics', 'religion', 'racism', 'bigotry']
    about_me_text = data.get('about_me', '').lower()
    if any(keyword in about_me_text for keyword in forbidden_keywords):
        return jsonify({"error": "Profile contains forbidden topics. Please revise."}), 400

    user.real_name = data.get('real_name', user.real_name)
    user.location = data.get('location', user.location)
    user.email = data.get('email', user.email)
    user.about_me = data.get('about_me', user.about_me)
    user.fields = data.get('fields', user.fields)
    user.interests = data.get('interests', user.interests)
    user.hobbies = data.get('hobbies', user.hobbies)
    user.specializations = data.get('specializations', user.specializations)
    
    preference = data.get('display_preference', user.display_preference)
    user.display_preference = preference
    if preference == 'real_name':
        user.display_name = data.get('real_name', user.username)
    else:
        user.display_name = user.username

    photo_b64 = data.get('profile_photo_b64')
    if photo_b64:
        user.profile_photo_url = photo_b64
    
    db.session.commit()
    return jsonify({"message": "Profile updated successfully"})

@app.route('/api/collaborate', methods=['POST'])
@token_required
def request_collaboration():
    data = request.get_json()
    recipient_username = data.get('recipient_username')
    if not recipient_username:
        return jsonify({"error": "Recipient username is required"}), 400

    recipient = User.query.filter_by(username=recipient_username).first()
    if not recipient:
        return jsonify({"error": "Recipient not found"}), 404
    
    if recipient.id == g.user.id:
        return jsonify({"error": "You cannot send a collaboration request to yourself."}), 400

    existing_notification = Notification.query.filter_by(
        sender_id=g.user.id,
        recipient_id=recipient.id,
        type='collaboration_request'
    ).first()

    if existing_notification:
        return jsonify({"message": "Collaboration request already sent."}), 200

    new_notification = Notification(
        recipient_id=recipient.id,
        sender_id=g.user.id,
        type='collaboration_request'
    )
    db.session.add(new_notification)
    db.session.commit()
    
    return jsonify({"message": "Collaboration request sent successfully."}), 201

@app.route('/api/notifications', methods=['GET'])
@token_required
def get_notifications():
    notifications = Notification.query.filter_by(recipient_id=g.user.id).order_by(desc(Notification.timestamp)).all()
    
    output = []
    for notification in notifications:
        output.append({
            'id': notification.id,
            'sender_username': notification.sender.username,
            'sender_photo': notification.sender.profile_photo_url or f"https://placehold.co/40x40/1e293b/a78bfa?text={notification.sender.username[0].upper()}",
            'type': notification.type,
            'is_read': notification.is_read,
            'timestamp': notification.timestamp.isoformat() + "Z"
        })
    return jsonify(output)

@app.route('/api/notifications/mark-read', methods=['POST'])
@token_required
def mark_notifications_as_read():
    try:
        Notification.query.filter_by(recipient_id=g.user.id, is_read=False).update({'is_read': True})
        db.session.commit()
        return jsonify({"message": "Notifications marked as read."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error marking notifications as read: {e}")
        return jsonify({"error": "An internal error occurred."}), 500

# --- (The rest of your page routes and other API endpoints remain the same) ---

# --- Page Routes ---
@app.route('/')
def landing_page():
    if g.user:
        return redirect(url_for('library_page'))
    return render_template('landing.html')

@app.route('/login')
def login_page():
    return render_template('login.html')

@app.route('/register')
def register_page():
    return render_template('register.html')
    
@app.route('/apply')
def apply_page():
    return render_template('apply.html')

@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login_page')))
    response.set_cookie('token', '', expires=0)
    return response

@app.route('/library')
@token_required
def library_page():
    return render_template('index.html')

@app.route('/profile')
@token_required
def my_profile_page():
    if g.user:
        return redirect(url_for('profile_page', username=g.user.username))
    else:
        return redirect(url_for('login_page'))

@app.route('/profile/<username>')
@token_required
def profile_page(username):
    profile_user = User.query.filter_by(username=username).first_or_404()
    
    is_own_profile = False
    if g.user and g.user.id == profile_user.id:
        is_own_profile = True
        
    return render_template('profile.html', user=profile_user, is_own_profile=is_own_profile)


@app.route('/session-scribe')
@token_required
def session_scribe():
    return render_template('session-scribe/index.html')

# --- Articulation Tools ---
@app.route('/articulation-tools')
@token_required
def articulation_tools():
    return render_template('articulation-tools/index.html')

# --- Dynamic Route for Individual Phoneme Pages ---
@app.route('/articulation-tools/<phoneme_slug>')
@token_required
def phoneme_page(phoneme_slug):
    return render_template(f'articulation-tools/{phoneme_slug}/index.html')

# --- Language Tools ---
@app.route('/language-tools')
@token_required
def language_tools():
    return render_terender_template('language-tools/index.html')

# --- Dynamic Route for Individual Language Pages ---
@app.route('/language-tools/<languageTools_slug>')
@token_required
def language_page(languageTools_slug):
    return render_template(f'language-tools/{languageTools_slug}/index.html')

# --- Fluency Tools ---
@app.route('/fluency-tools')
@token_required
def fluency_tools():
    return render_template('fluency-tools/index.html')

# --- Dynamic Route for Individual Fluency-Tool Pages ---
@app.route('/fluency-tools/<fluencyTools_slug>')
@token_required
def fluency_page(fluencyTools_slug):
    return render_template(f'fluency-tools/{fluencyTools_slug}/index.html')

# --- SLP Tools ---
@app.route('/slp-tools')
@token_required
def slp_tools():
    return render_template('slp-tools/index.html')

# --- Dynamic Route for Individual SLP-Tool Pages ---
@app.route('/slp-tools/<slpTools_slug>')
@token_required
def slp_page(slpTools_slug):
    return render_template(f'slp-tools/{slpTools_slug}/index.html')

# --- Cognition Tools ---
@app.route('/cognition-tools')
@token_required
def cognition_tools():
    return render_template('cognition-tools/index.html')

# --- Dynamic Route for Individual Cognition-Tool Pages ---
@app.route('/cognition-tools/<cognitionTools_slug>')
@token_required
def cognition_page(cognitionTools_slug):
    return render_template(f'cognition-tools/{cognitionTools_slug}/index.html')


# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# --- This block should be the VERY LAST thing in your file ---
if __name__ == '__main__':
    app.run(debug=True)


