import base64
import re
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
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    display_name = db.Column(db.String(100)) # This will now store the user's preferred display name
    real_name = db.Column(db.String(100))
    location = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    profile_photo_url = db.Column(db.Text) # Changed to Text to accommodate base64 URLs
    about_me = db.Column(db.Text)
    fields = db.Column(db.JSON)
    interests = db.Column(db.JSON)
    hobbies = db.Column(db.JSON)
    specializations = db.Column(db.JSON)
    display_preference = db.Column(db.String(20), default='username') # NEW: 'username' or 'real_name'

    real_name = db.Column(db.String(100))
    location = db.Column(db.String(100))
    email = db.Column(db.String(120), unique=True)
    profile_photo_url = db.Column(db.String(255))
    about_me = db.Column(db.Text)
    fields = db.Column(db.JSON)
    interests = db.Column(db.JSON)
    hobbies = db.Column(db.JSON)
    specializations = db.Column(db.JSON) # UPDATED to match your database

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
# Makes the current user available to all templates
@app.context_processor
def inject_user():
    return dict(current_user=g.user)

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
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password are required"}), 400
    
    username = data.get('username')
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username is already taken"}), 400

    hashed_password = bcrypt.generate_password_hash(data.get('password')).decode('utf-8')
    new_user = User(username=username, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully"}), 201

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

    # Forbidden content check
    forbidden_keywords = ['politics', 'religion', 'racism', 'bigotry']
    about_me_text = data.get('about_me', '').lower()
    if any(keyword in about_me_text for keyword in forbidden_keywords):
        return jsonify({"error": "Profile contains forbidden topics. Please revise."}), 400

    # Update standard fields
    user.real_name = data.get('real_name', user.real_name)
    user.location = data.get('location', user.location)
    user.email = data.get('email', user.email)
    user.about_me = data.get('about_me', user.about_me)
    user.fields = data.get('fields', user.fields)
    user.interests = data.get('interests', user.interests)
    user.hobbies = data.get('hobbies', user.hobbies)
    user.specializations = data.get('specializations', user.specializations)
    
    # NEW: Update display preference and the display_name field itself
    preference = data.get('display_preference', user.display_preference)
    user.display_preference = preference
    if preference == 'real_name':
        user.display_name = data.get('real_name', user.username)
    else: # Default to username
        user.display_name = user.username

    # NEW: Handle profile photo upload (Base64)
    photo_b64 = data.get('profile_photo_b64')
    if photo_b64:
        # The string comes in as 'data:image/png;base64,iVBORw0KGgo...'. We need to keep this format.
        user.profile_photo_url = photo_b64
    
    db.session.commit()
    return jsonify({"message": "Profile updated successfully"})

# ... (The rest of your app.py file remains the same) ...
# SESSION SCRIBE --- Waiter #1: Handles the compliance check
@app.route('/api/compliance-check', methods=['POST'])
def handle_compliance_check():
    data = request.get_json()
    user_input = data.get('userInput')
    if not user_input:
        return jsonify({"error": "No user input provided"}), 400

    try:
        api_key = app.config['GEMINI_API_KEY_SLP'] 
        google_api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={api_key}"
        
        payload = {
            "contents": [{ "parts": [{ "text": f"Analyze the following text for potential PII and return the result as a JSON object: \"{user_input}\"" }] }],
            "systemInstruction": { "parts": [{ "text": "You are a compliance-checking AI. Your task is to identify potential personally identifiable information (PII) or FERPA violations in a given text. Return a JSON object with a single key \"violations\" which is an array of strings. Each string in the array should be a word or phrase you've identified as a potential violation. Focus on names of people, specific non-school locations, or titles of works that could be misinterpreted as names. If there are no potential violations, return an empty array. Do not explain your reasoning, just return the JSON object." }] },
            "generationConfig": { "responseMimeType": "application/json", "responseSchema": { "type": "OBJECT", "properties": { "violations": { "type": "ARRAY", "items": { "type": "STRING" } } } } }
        }
        
        app.logger.info("Sending compliance-check payload to Google...")
        response = requests.post(google_api_url, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        response.raise_for_status()
        return jsonify(response.json())

    except requests.exceptions.HTTPError as http_err:
        error_message = f"HTTP error occurred while calling Google API: {http_err}"
        app.logger.error(error_message)
        app.logger.error(f"Response Body: {http_err.response.text}")
        return jsonify({"error": "The AI service returned an error.", "details": http_err.response.text}), 500
    except Exception as e:
        error_message = f"An unexpected error occurred in compliance-check: {e}"
        app.logger.error(error_message)
        return jsonify({"error": "An unexpected internal error occurred.", "details": str(e)}), 500

# Waiter #2: Handles generating the final note
@app.route('/api/generate-note', methods=['POST'])
def handle_generate_note():
    data = request.get_json()
    user_input = data.get('userInput')
    glossary = data.get('glossary')
    if not user_input or not glossary:
        return jsonify({"error": "Missing user input or glossary"}), 400

    try:
        api_key = app.config['GEMINI_API_KEY_SLP']
        google_api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={api_key}"
        
        payload = {
            "contents": [{ "parts": [{ "text": f"Using the following glossary, please expand the shorthand note below into a professional therapy note.\n\nGlossary:\n{json.dumps(glossary, indent=2)}\n\nShorthand Note:\n\"{user_input}\"" }] }],
            "systemInstruction": { "parts": [{ "text": "You are a Speech-Language Pathologist’s assistant. Your only task is to take shorthand prompts (fragments, abbreviations, or incomplete sentences) and expand them into full, professional attendance notes for school-based therapy. Write in a clear, concise, professional tone appropriate for clinical documentation. Crucially, all notes must be de-identified. Always refer to individuals as \"the student\" or \"the students\" and use neutral pronouns (they/them/their) to ensure anonymity and FERPA compliance. Use the provided glossary to expand shorthand. For terms not in the glossary, expand them logically." }] }
        }

        app.logger.info("Sending generate-note payload to Google...")
        response = requests.post(google_api_url, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        response.raise_for_status()
        return jsonify(response.json())

    except requests.exceptions.HTTPError as http_err:
        error_message = f"HTTP error occurred while calling Google API: {http_err}"
        app.logger.error(error_message)
        app.logger.error(f"Response Body: {http_err.response.text}")
        return jsonify({"error": "The AI service returned an error.", "details": http_err.response.text}), 500
    except Exception as e:
        error_message = f"An unexpected error occurred in generate-note: {e}"
        app.logger.error(error_message)
        return jsonify({"error": "An unexpected internal error occurred.", "details": str(e)}), 500
    
# MIND SHIFTER Waiter for checking a student's solution in Mind Shifter
@app.route('/api/check-solution', methods=['POST'])
def handle_check_solution():
    data = request.get_json()
    student_answer = data.get('studentAnswer')
    solution_keywords = data.get('solutionKeywords')
    
    if not student_answer or not solution_keywords:
        return jsonify({"error": "Missing required data"}), 400

    try:
        api_key = app.config['GEMINI_API_KEY_COGNITION']
        google_api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={api_key}"
        
        inappropriate_prompt = f"Is the following text inappropriate, offensive, or off-topic for a school assignment? Answer only \"Yes\" or \"No\". Text: \"{student_answer}\""
        inappropriate_payload = {"contents": [{"parts": [{"text": inappropriate_prompt}]}]}
        inappropriate_response = requests.post(google_api_url, headers={"Content-Type": "application/json"}, data=json.dumps(inappropriate_payload))
        inappropriate_response.raise_for_status()
        inappropriate_result = inappropriate_response.json().get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
        
        if 'yes' in inappropriate_result.strip().lower():
            return jsonify({"match": False, "inappropriate": True})

        concept_prompt = f"You are an AI assistant. Compare a student's answer to a list of keywords. Is the student's answer conceptually similar to any of the keywords? Answer only \"Yes\" or \"No\".\nStudent Answer: \"{student_answer}\"\nKeywords: \"{', '.join(solution_keywords)}\""
        concept_payload = {"contents": [{"parts": [{"text": concept_prompt}]}]}
        concept_response = requests.post(google_api_url, headers={"Content-Type": "application/json"}, data=json.dumps(concept_payload))
        concept_response.raise_for_status()
        concept_result = concept_response.json().get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
        is_match = 'yes' in concept_result.strip().lower()
        
        return jsonify({"match": is_match, "inappropriate": False})

    except Exception as e:
        is_match = any(keyword in student_answer.lower() for keyword in solution_keywords)
        return jsonify({"match": is_match, "inappropriate": False})


# Waiter for getting a helpful hint in Mind Shifter
@app.route('/api/get-scaffolding', methods=['POST'])
def handle_get_scaffolding():
    data = request.get_json()
    student_answer = data.get('studentAnswer')
    
    if not student_answer:
        return jsonify({"error": "Missing student answer"}), 400
        
    try:
        api_key = app.config['GEMINI_API_KEY_COGNITION']
        google_api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-pro:generateContent?key={api_key}"

        prompt = f"A student's answer isn't quite right: \"{student_answer}\". Provide a short, encouraging, one-sentence question to help them think of a better solution. Do not give the answer."
        payload = {"contents": [{"parts": [{"text": prompt}]}]}

        response = requests.post(google_api_url, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        response.raise_for_status()
        
        scaffold_text = response.json().get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', "Good start! How might someone else see this situation?")
        
        return jsonify({"scaffoldText": scaffold_text})

    except Exception as e:
        return jsonify({"scaffoldText": "Good start! How might someone else see this situation?"})


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

# --- Profile Routes ---
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

# ... (The rest of your tool routes remain the same) ...
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
    return render_template('language-tools/index.html')

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
    # Note: We are now rendering a real template for 404 errors
    return render_template('404.html'), 404

# --- This block should be the VERY LAST thing in your file ---
if __name__ == '__main__':
    app.run(debug=True)



