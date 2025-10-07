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
app.config['LITERACY_LAUNCHPAD_API_KEY'] = os.environ.get('LITERACY-LAUNCHPAD')
# NEW: Add a secret key for leaderboard resets
app.config['LEADERBOARD_RESET_SECRET'] = os.environ.get('LEADERBOARD_RESET_SECRET', 'change-this-secret-key')


# --- Database and Encryption Setup ---
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

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
# ... (existing user, profile, notification routes are unchanged) ...

# --- NEW LITERACY LAUNCHPAD API ROUTES ---
@app.route('/api/literacy-launchpad/leaderboard', methods=['GET'])
def get_leaderboard():
    entries = Leaderboard.query.order_by(desc(Leaderboard.score)).limit(10).all()
    
    # Calculate the next reset date (first day of the next month)
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

    # Authenticate the clinician
    if not g.user or not bcrypt.check_password_hash(g.user.password, password):
        return jsonify({"error": "Invalid credentials"}), 401

    # Add the new entry
    new_entry = Leaderboard(pseudonym=pseudonym, score=score)
    db.session.add(new_entry)
    
    # Keep only the top 10 scores
    entry_count = Leaderboard.query.count()
    if entry_count > 10:
        lowest_entry = Leaderboard.query.order_by(Leaderboard.score.asc()).first()
        db.session.delete(lowest_entry)
        
    db.session.commit()
    return jsonify({"message": "Leaderboard updated successfully"}), 201

# NEW: Route to handle resetting the leaderboard
@app.route('/api/literacy-launchpad/reset-leaderboard', methods=['POST'])
def reset_leaderboard():
    # Protect this endpoint with a secret key
    if request.headers.get('X-Admin-Secret') != app.config['LEADERBOARD_RESET_SECRET']:
        abort(403) # Forbidden
    try:
        db.session.query(Leaderboard).delete()
        db.session.commit()
        return jsonify({"message": "Leaderboard has been reset successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error resetting leaderboard: {e}")
        return jsonify({"error": "An internal server error occurred while resetting the leaderboard."}), 500
    
@app.route('/api/literacy-launchpad/scaffold', methods=['POST'])
@token_required
def get_scaffold():
    # ... (existing scaffold route is unchanged) ...
    pass

# --- Page Routes ---
# ... (existing page routes are unchanged) ...

# --- This block should be the VERY LAST thing in your file ---
if __name__ == '__main__':
    app.run(debug=True)
