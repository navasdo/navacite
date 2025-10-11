from flask import Flask, render_template, request, make_response, redirect, url_for, abort, g
import jwt
import os
from functools import wraps
from datetime import datetime, timedelta, date
from dateutil.relativedelta import relativedelta
import logging
import requests
import json
from flask import jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import click
import base64
import re
from sqlalchemy import desc, func, not_
from sqlalchemy.dialects.postgresql import JSONB
import random

# --- Basic Configuration ---
app = Flask(__name__, template_folder='templates', static_folder='static')
logging.basicConfig(level=logging.INFO)

# --- Security Configuration ---
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET', 'a-very-secret-key-that-you-should-change')
db_url = os.environ.get('DATABASE_URL', 'sqlite:///default.db')
if db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
app.config['SQLALCHEMY_DATABASE_URI'] = db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['GEMINI_API_KEY_COGNITION'] = os.environ.get('GEMINI_API_KEY_COGNITION')
app.config['GEMINI_API_KEY_SLP'] = os.environ.get('GEMINI_API_KEY_SLP')
app.config['LITERACY_LAUNCHPAD_API_KEY'] = os.environ.get('LITERACY-LAUNCHPAD')
app.config['LEADERBOARD_RESET_SECRET'] = os.environ.get('LEADERBOARD_RESET_SECRET', 'change-this-secret-key')
app.config['GEMINI_LITERACY_LAUNCHPAD_ALE'] = os.environ.get('GEMINI_LITERACY_LAUNCHPAD_ALE')


# --- Database and Encryption Setup ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

@app.route('/api/literacy-launchpad/next-level', methods=['POST'])
@token_required
def get_next_level():
    data = request.get_json()
    current_level = data.get('current_level')
    accuracy = data.get('accuracy')

    if current_level is None or accuracy is None:
        return jsonify({"error": "current_level and accuracy are required"}), 400

    api_key = app.config.get('GEMINI_LITERACY_LAUNCHPAD_ALE')
    if not api_key:
        return jsonify({"error": "Adaptive Learning Engine API key not configured"}), 500

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={api_key}"
    
    system_prompt = """
    You are an adaptive learning engine for a literacy application. Your task is to determine the next difficulty level for a student based on their performance. The difficulty levels range from 1 to 10. You must follow the provided rules precisely. Respond ONLY with a JSON object containing a single key, 'next_level', which must be an integer.
    """
    
    user_prompt = f"""
    The student is currently at difficulty level {current_level}.
    Their accuracy on the last passage was {accuracy}%.

    Apply these rules to determine the next level:
    1. If accuracy is greater than 80%, increase the level by 1. The maximum level is 10.
    2. If accuracy is less than 50%, decrease the level by 1. The minimum level is 1.
    3. If accuracy is between 50% and 80% (inclusive), the level remains the same.
    """

    schema = {
        "type": "OBJECT",
        "properties": { "next_level": { "type": "INTEGER" } }
    }

    payload = {
        "contents": [{"parts": [{"text": user_prompt}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": { "responseMimeType": "application/json", "responseSchema": schema }
    }

    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        # The response from Gemini comes wrapped in its own structure, so we need to parse it.
        gemini_response = response.json()
        
        # Extract the text part which contains our JSON string
        if 'candidates' in gemini_response and len(gemini_response['candidates']) > 0:
            content_part = gemini_response['candidates'][0].get('content', {}).get('parts', [{}])[0]
            if 'text' in content_part:
                # The 'text' is a JSON string, so we parse it again
                next_level_data = json.loads(content_part['text'])
                return jsonify(next_level_data)

        # Fallback to simple logic if API response is not as expected
        raise ValueError("Unexpected API response structure")

    except (requests.exceptions.RequestException, ValueError, json.JSONDecodeError) as e:
        app.logger.error(f"ALE API call failed or returned invalid data: {e}. Using fallback logic.")
        # Fallback logic if the API fails
        next_level = current_level
        if accuracy > 80:
            next_level = min(10, current_level + 1)
        elif accuracy < 50:
            next_level = max(1, current_level - 1)
        return jsonify({"next_level": next_level})

# --- Database Models ---
class User(db.Model):
    __tablename__ = 'user'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    first_name = db.Column(db.String(100))
    last_name = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True, nullable=False)
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
    
    notifications_received = db.relationship(
        'Notification',
        primaryjoin="User.id == Notification.recipient_id",
        back_populates='recipient',
        lazy='dynamic'
    )
    notifications_sent = db.relationship(
        'Notification',
        primaryjoin="User.id == Notification.sender_id",
        back_populates='sender',
        lazy='dynamic'
    )

class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    type = db.Column(db.String(50), nullable=False)
    is_read = db.Column(db.Boolean, default=False, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    
    sender = db.relationship(
        'User',
        primaryjoin="Notification.sender_id == User.id",
        back_populates='notifications_sent'
    )
    recipient = db.relationship(
        'User',
        primaryjoin="Notification.recipient_id == User.id",
        back_populates='notifications_received'
    )

# Database model for the Literacy Launchpad Leaderboard
class Leaderboard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    pseudonym = db.Column(db.String(100), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# NEW: Database model for the Literacy Launchpad Passages
class Passage(db.Model):
    __tablename__ = 'passage'
    id = db.Column(db.Integer, primary_key=True)
    difficulty = db.Column(db.Integer, nullable=False, index=True)
    content = db.Column(JSONB, nullable=False)

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

# --- API Routes (User, Profile, etc.) ---
@app.route('/api/register', methods=['POST'])
def register_api():
    data = request.get_json()
    required_fields = ['username', 'password', 'email', 'firstName', 'lastName']
    if not data or not all(field in data and data[field] for field in required_fields):
        return jsonify({"error": "All fields are required"}), 400
    
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username is already taken"}), 400
    if User.query.filter_by(email=data['email']).first():
        return jsonify({"error": "An account with that email already exists"}), 400

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    
    new_user = User(
        username=data['username'],
        password=hashed_password,
        email=data['email'],
        first_name=data['firstName'],
        last_name=data['lastName'],
        real_name=f"{data['firstName']} {data['lastName']}"
    )
    
    db.session.add(new_user)
    db.session.commit()
    
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

# --- NEW SESSION SCRIBE API ROUTES ---
@app.route('/api/compliance-check', methods=['POST'])
@token_required
def handle_compliance_check():
    data = request.get_json()
    user_input = data.get('userInput')
    if not user_input:
        return jsonify({"error": "No input provided"}), 400

    api_key = app.config.get('GEMINI_API_KEY_SLP')
    if not api_key:
        return jsonify({"error": "API key not configured"}), 500
    
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={api_key}"
    
    system_prompt = "You are a compliance officer reviewing therapy notes for FERPA and HIPAA. Identify any potential personally identifiable information (PII) like names, specific locations, or other identifying details. Do NOT flag common acronyms used in the field. Respond ONLY with a JSON object. The JSON object should have a single key, 'violations', which is an array of strings. Each string should be a word or phrase you identified as a potential violation. If there are no violations, return an empty array: {\"violations\": []}."
    
    schema = {
        "type": "OBJECT",
        "properties": { "violations": { "type": "ARRAY", "items": { "type": "STRING" } } }
    }

    payload = {
        "contents": [{"parts": [{"text": user_input}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": { "responseMimeType": "application/json", "responseSchema": schema }
    }

    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        app.logger.error(f"API call failed: {e}")
        return jsonify({"error": "Failed to communicate with AI service"}), 500

@app.route('/api/generate-note', methods=['POST'])
@token_required
def handle_generate_note():
    data = request.get_json()
    user_input = data.get('userInput')
    glossary = data.get('glossary', {})
    if not user_input:
        return jsonify({"error": "No input provided"}), 400

    api_key = app.config.get('GEMINI_API_KEY_SLP')
    if not api_key:
        return jsonify({"error": "API key not configured"}), 500

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={api_key}"
    
    glossary_text = "\n".join([f"- {key}: {value}" for key, value in glossary.items()])
    
    prompt = f"""
    Based on the following shorthand notes and glossary, please generate a professional therapy note.
    Shorthand Notes: "{user_input}"
    Glossary of Terms: {glossary_text}
    """
    
    system_prompt = "You are an expert Speech-Language Pathologist. Your task is to expand shorthand clinical notes into a complete, professional, and compliant therapy note. Write the note in the third-person, past tense. Ensure the output is a single, concise paragraph. Do not add a date."

    payload = { "contents": [{"parts": [{"text": prompt}]}], "systemInstruction": {"parts": [{"text": system_prompt}]} }

    try:
        response = requests.post(url, json=payload)
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        app.logger.error(f"API call failed: {e}")
        return jsonify({"error": "Failed to communicate with AI service"}), 500

# --- NEW LITERACY LAUNCHPAD API ROUTES ---
@app.route('/api/literacy-launchpad/leaderboard', methods=['GET'])
def get_leaderboard():
    entries = Leaderboard.query.order_by(desc(Leaderboard.score)).limit(10).all()
    today = date.today()
    next_reset_date = (today + relativedelta(months=1)).replace(day=1)
    
    return jsonify({
        'entries': [{'pseudonym': e.pseudonym, 'score': e.score} for e in entries],
        'nextReset': next_reset_date.isoformat()
    })

@app.route('/api/literacy-launchpad/leaderboard', methods=['POST'])
@token_required
def add_to_leaderboard():
    data = request.get_json()
    pseudonym = data.get('pseudonym')
    score = data.get('score')
    password = data.get('password')

    if not all([pseudonym, score, password]):
        return jsonify({"error": "Missing data"}), 400

    if not g.user or not bcrypt.check_password_hash(g.user.password, password):
        return jsonify({"error": "Invalid credentials"}), 401

    new_entry = Leaderboard(pseudonym=pseudonym, score=score)
    db.session.add(new_entry)
    
    entry_count = Leaderboard.query.count()
    if entry_count > 10:
        lowest_entry = Leaderboard.query.order_by(Leaderboard.score.asc()).first()
        db.session.delete(lowest_entry)
        
    db.session.commit()
    return jsonify({"message": "Leaderboard updated successfully"}), 201

@app.route('/api/literacy-launchpad/reset-leaderboard', methods=['POST'])
def reset_leaderboard():
    if request.headers.get('X-Admin-Secret') != app.config['LEADERBOARD_RESET_SECRET']:
        abort(403)
    try:
        db.session.query(Leaderboard).delete()
        db.session.commit()
        return jsonify({"message": "Leaderboard has been reset successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error resetting leaderboard: {e}")
        return jsonify({"error": "An internal server error occurred while resetting the leaderboard."}), 500

# NEW: API endpoint to fetch a passage from the database
@app.route('/api/literacy-launchpad/passage', methods=['GET'])
@token_required
def get_passage():
    level = request.args.get('level', type=int)
    exclude_ids_str = request.args.get('exclude', '')
    
    if not level:
        return jsonify({"error": "Level parameter is required"}), 400
        
    exclude_ids = []
    if exclude_ids_str:
        try:
            exclude_ids = [int(id_str) for id_str in exclude_ids_str.split(',')]
        except ValueError:
            return jsonify({"error": "Invalid exclude IDs format"}), 400

    # Query for passages at the specified level, excluding used IDs
    query = Passage.query.filter_by(difficulty=level).filter(not_(Passage.id.in_(exclude_ids)))
    passages = query.all()

    # Fallback: if no passages at the current level, try any other level
    if not passages:
        fallback_query = Passage.query.filter(not_(Passage.id.in_(exclude_ids)))
        passages = fallback_query.all()
        
    if not passages:
        return jsonify({"error": "No more passages available"}), 404

    # Select a random passage from the fetched list
    passage = random.choice(passages)

    return jsonify({
        "passage_id": passage.id,
        "passage_difficulty": passage.difficulty,
        "content_json": passage.content
    })

@app.route('/api/literacy-launchpad/next-level', methods=['POST'])
@token_required
def get_next_level():
    data = request.get_json()
    current_level = data.get('currentLevel')
    accuracy = data.get('accuracy')

    if current_level is None or accuracy is None:
        return jsonify({"error": "Missing currentLevel or accuracy"}), 400
    
    api_key = app.config.get('GEMINI_LITERACY_LAUNCHPAD_ALE')
    if not api_key:
        # Fallback logic if API key is not configured
        if accuracy >= 80:
            next_level = min(10, current_level + 1)
        elif accuracy < 50:
            next_level = max(1, current_level - 1)
        else:
            next_level = current_level
        return jsonify({"nextLevel": next_level})

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={api_key}"
    
    system_prompt = """
    You are an adaptive learning engine. Your only job is to determine the next difficulty level for a student based on their performance.
    - The levels are integers from 1 to 10.
    - If accuracy is >= 80%, increase level by 1.
    - If accuracy is < 50%, decrease level by 1.
    - Otherwise, the level stays the same.
    - Do not go below level 1 or above level 10.
    Respond ONLY with a JSON object with a single key: "nextLevel". Example: {"nextLevel": 5}
    """
    
    user_prompt = f"The student is at level {current_level} and scored {accuracy}%."

    schema = {
        "type": "OBJECT",
        "properties": { "nextLevel": { "type": "NUMBER" } }
    }

    payload = {
        "contents": [{"parts": [{"text": user_prompt}]}],
        "systemInstruction": {"parts": [{"text": system_prompt}]},
        "generationConfig": { "responseMimeType": "application/json", "responseSchema": schema }
    }

    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
        api_response = response.json()
        
        # Extracting the text part which contains the JSON string
        json_string = api_response.get('candidates')[0].get('content').get('parts')[0].get('text')
        # Parsing the JSON string to a Python dictionary
        result_json = json.loads(json_string)
        next_level = result_json.get('nextLevel')

        if next_level is not None:
            return jsonify({"nextLevel": int(next_level)})
        else:
            raise ValueError("API did not return nextLevel")

    except (requests.exceptions.RequestException, ValueError, IndexError, KeyError) as e:
        app.logger.error(f"ALE API call failed: {e}. Using fallback logic.")
        # Fallback logic in case of API error or timeout
        if accuracy >= 80:
            next_level = min(10, current_level + 1)
        elif accuracy < 50:
            next_level = max(1, current_level - 1)
        else:
            next_level = current_level
        return jsonify({"nextLevel": next_level})

@app.route('/api/literacy-launchpad/scaffold', methods=['POST'])
@token_required
# ... existing code ...
def get_scaffold():
    data = request.get_json()
    passage = data.get('passage')
    incorrect_word = data.get('incorrect_word')
# ... existing code ...
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Literacy Launchpad API call failed: {e}")
        return jsonify({"error": "Failed to get help from the AI service"}), 500    
    
@app.route('/api/literacy-launchpad/scaffold', methods=['POST'])
@token_required
def get_scaffold():
    data = request.get_json()
    passage = data.get('passage')
    incorrect_word = data.get('incorrect_word')
    
    api_key = app.config.get('LITERACY_LAUNCHPAD_API_KEY')
    if not api_key:
        return jsonify({"error": "API key not configured for Literacy Launchpad"}), 500

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash-preview-05-20:generateContent?key={api_key}"
    
    prompt = f"""
    A student was reading the following passage and made an error.
    Passage: "{passage}"
    The student incorrectly chose the word "{incorrect_word}".
    Provide a brief, student-friendly explanation of why that word does not fit grammatically or semantically.
    Also, identify the contextual clue in the passage that points to the correct answer.
    Respond ONLY with a JSON object with two keys: "explanation" and "clue".
    Example: {{"explanation": "The word 'running' is an action, but the sentence needs a describing word for the apple.", "clue": "The apple was..."}}
    """
    
    try:
        response = requests.post(url, json={"contents": [{"parts": [{"text": prompt}]}]})
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.RequestException as e:
        app.logger.error(f"Literacy Launchpad API call failed: {e}")
        return jsonify({"error": "Failed to get help from the AI service"}), 500   

# --- NEW LITERACY LAUNCHPAD API ROUTES ---
@app.route('/api/literacy-launchpad/leaderboard', methods=['GET'])
# ... existing code ...
def get_leaderboard():
    entries = Leaderboard.query.order_by(desc(Leaderboard.score)).limit(10).all()
    today = date.today()
    next_reset_date = (today + relativedelta(months=1)).replace(day=1)
# ... existing code ...
        'entries': [{'pseudonym': e.pseudonym, 'score': e.score} for e in entries],
        'nextReset': next_reset_date.isoformat()



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

# --- Tool Page Routes ---
@app.route('/articulation-tools')
@token_required
def articulation_tools(): return render_template('articulation-tools/index.html')

@app.route('/articulation-tools/<phoneme_slug>')
@token_required
def phoneme_page(phoneme_slug):
    if '..' in phoneme_slug or '/' in phoneme_slug: abort(404)
    return render_template(f'articulation-tools/{phoneme_slug}/index.html')

@app.route('/language-tools')
@token_required
def language_tools(): return render_template('language-tools/index.html')

@app.route('/language-tools/<languageTools_slug>')
@token_required
def language_page(languageTools_slug):
    if '..' in languageTools_slug or '/' in languageTools_slug: abort(404)
    return render_template(f'language-tools/{languageTools_slug}/index.html')

@app.route('/fluency-tools')
@token_required
def fluency_tools(): return render_template('fluency-tools/index.html')

@app.route('/fluency-tools/<fluencyTools_slug>')
@token_required
def fluency_page(fluencyTools_slug):
    if '..' in fluencyTools_slug or '/' in fluencyTools_slug: abort(404)
    return render_template(f'fluency-tools/{fluencyTools_slug}/index.html')

@app.route('/slp-tools')
@token_required
def slp_tools(): return render_template('slp-tools/index.html')

@app.route('/slp-tools/<slpTools_slug>')
@token_required
def slp_page(slpTools_slug):
    if '..' in slpTools_slug or '/' in slpTools_slug: abort(404)
    return render_template(f'slp-tools/{slpTools_slug}/index.html')

@app.route('/cognition-tools')
@token_required
def cognition_tools(): return render_template('cognition-tools/index.html')

@app.route('/cognition-tools/<cognitionTools_slug>')
@token_required
def cognition_page(cognitionTools_slug):
    if '..' in cognitionTools_slug or '/' in cognitionTools_slug: abort(404)
    return render_template(f'cognition-tools/{cognitionTools_slug}/index.html')


# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

# --- This block should be the VERY LAST thing in your file ---
if __name__ == '__main__':
    app.run(debug=True)

