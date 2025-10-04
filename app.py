from flask import Flask, render_template, request, make_response, redirect, url_for, abort
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
import json # Ensure json is imported

# --- Basic Configuration ---
app = Flask(__name__, template_folder='templates', static_folder='static')
logging.basicConfig(level=logging.INFO)

# --- Security Configuration ---
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET', 'a-very-secret-key-that-you-should-change')
app.config['GEMINI_API_KEY_COGNITION'] = os.environ.get('GEMINI_API_KEY_COGNITION')
app.config['GEMINI_API_KEY_SLP'] = os.environ.get('GEMINI_API_KEY_SLP')

# --- Database Configuration ---
# This reads the database connection string from a new 'DATABASE_URL' environment variable.
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///default.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

# --- Database Model ---
# This defines the 'User' table in your database with new profile fields.
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    
    # New Profile Fields
    display_name = db.Column(db.String(100), nullable=True)
    real_name = db.Column(db.String(100), nullable=True)
    location = db.Column(db.String(100), nullable=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    profile_photo_url = db.Column(db.String(255), nullable=True, default='default.jpg')
    about_me = db.Column(db.Text, nullable=True)
    
    # Storing lists as JSON strings
    fields = db.Column(db.Text, nullable=True) # JSON string of a list
    interests = db.Column(db.Text, nullable=True) # JSON string of a list
    hobbies = db.Column(db.Text, nullable=True) # JSON string of a list
    research_areas = db.Column(db.Text, nullable=True) # JSON string of a list

    def __repr__(self):
        return f'<User {self.username}>'

# --- Decorator for Token Authentication ---
def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return redirect(url_for('login_page'))
        try:
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            # You can pass the current user's data to the route if needed
            kwargs['current_user_data'] = data
        except Exception as e:
            return redirect(url_for('login_page'))
        return f(*args, **kwargs)
    return decorated

# --- API Route for Login ---
# This now checks the database instead of the hard-coded dictionary.
@app.route('/api/login', methods=['POST'])
def login_api():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return {"error": "Username and password are required"}, 400
    
    user = User.query.filter_by(username=data.get('username')).first()
    
    if user and bcrypt.check_password_hash(user.password, data.get('password')):
        token = jwt.encode({
            'user': user.username,
            'exp': datetime.utcnow() + timedelta(hours=24)
        }, app.config['SECRET_KEY'], algorithm="HS256")
        response = make_response({"message": "Login successful"})
        response.set_cookie('token', token, httponly=True, secure=True, samesite='Lax')
        return response
    else:
        return {"error": "Invalid credentials"}, 401

# --- NEW API Route for Registration ---
@app.route('/api/register', methods=['POST'])
def register_api():
    data = request.get_json()
    if not data or not data.get('username') or not data.get('password'):
        return jsonify({"error": "Username and password are required"}), 400

    # Check if user already exists
    if User.query.filter_by(username=data['username']).first():
        return jsonify({"error": "Username already exists"}), 409

    hashed_password = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    new_user = User(username=data['username'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    
    return jsonify({"message": "User registered successfully"}), 201

# --- Page Routes ---

@app.route('/login')
def login_page():
    return render_template('login.html')

# --- NEW Registration Page Route ---
@app.route('/register')
def register_page():
    return render_template('register.html')
    
# --- NEW Logout Route ---
@app.route('/logout')
def logout():
    response = make_response(redirect(url_for('login_page')))
    response.set_cookie('token', '', expires=0) # Clear the cookie
    return response

# --- NEW Profile Page Route ---
@app.route('/profile')
@token_required
def profile_page(current_user_data):
    username = current_user_data['user']
    user = User.query.filter_by(username=username).first_or_404()
    
    # This is a placeholder to demonstrate the "Collaborate" button logic.
    # In a real app, you'd check if the logged-in user is viewing another's profile.
    is_own_profile = True 

    return render_template('profile.html', user=user, is_own_profile=is_own_profile)

# --- NEW API Route to Update Profile ---
@app.route('/api/profile', methods=['POST'])
@token_required
def update_profile(current_user_data):
    username = current_user_data['user']
    user = User.query.filter_by(username=username).first_or_404()
    data = request.get_json()

    # Basic validation for 'about_me'
    forbidden_words = ['politics', 'religion', 'racism', 'bigotry']
    if 'about_me' in data and any(word in data['about_me'].lower() for word in forbidden_words):
        return jsonify({"error": "Profile summary contains prohibited content."}), 400

    # Update fields from the request data
    user.display_name = data.get('display_name', user.display_name)
    user.real_name = data.get('real_name', user.real_name)
    user.location = data.get('location', user.location)
    user.about_me = data.get('about_me', user.about_me)
    user.email = data.get('email', user.email)

    # Update list fields by storing them as JSON strings
    if 'fields' in data: user.fields = json.dumps(data['fields'])
    if 'interests' in data: user.interests = json.dumps(data['interests'])
    if 'hobbies' in data: user.hobbies = json.dumps(data['hobbies'])
    if 'research_areas' in data: user.research_areas = json.dumps(data['research_areas'])

    db.session.commit()
    return jsonify({"message": "Profile updated successfully"}), 200

    username = current_user_data['user']
    user = User.query.filter_by(username=username).first()
    if not user:
        # This case should be rare if the token is valid
        return redirect(url_for('logout'))
    # Pass the user object to the template
    return render_template('profile.html', user=user)

@app.route('/apply')
def apply_page():
    return render_template('apply.html')

@app.route('/')
def landing_page():
    token = request.cookies.get('token')
    if token:
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            return redirect(url_for('library_page'))
        except Exception:
            pass # Invalid token, fall through to landing page
    return render_template('landing.html')


@app.route('/library')
@token_required
def library_page(**kwargs):
    return render_template('index.html')

@app.route('/session-scribe')
@token_required
def session_scribe(**kwargs):
    return render_template('session-scribe/index.html')

@app.route('/character-sheet')
@token_required
def character_sheet(**kwargs):
    return render_template('character-sheet/index.html')

@app.route('/articulation-tools')
@token_required
def articulation_tools(**kwargs):
    return render_template('articulation-tools/index.html')

@app.route('/articulation-tools/<phoneme_slug>')
@token_required
def phoneme_page(phoneme_slug, **kwargs):
    return render_template(f'articulation-tools/{phoneme_slug}/index.html')

@app.route('/language-tools')
@token_required
def language_tools(**kwargs):
    return render_template('language-tools/index.html')

@app.route('/language-tools/<languageTools_slug>')
@token_required
def language_page(languageTools_slug, **kwargs):
    return render_template(f'/language-tools/{languageTools_slug}/index.html')

@app.route('/fluency-tools')
@token_required
def fluency_tools(**kwargs):
    return render_template('fluency-tools/index.html')

@app.route('/fluency-tools/<fluencyTools_slug>')
@token_required
def fluency_page(fluencyTools_slug, **kwargs):
    return render_template(f'/fluency-tools/{fluencyTools_slug}/index.html')

@app.route('/slp-tools')
@token_required
def slp_tools(**kwargs):
    return render_template('slp-tools/index.html')

@app.route('/slp-tools/<slpTools_slug>')
@token_required
def slp_page(slpTools_slug, **kwargs):
    return render_template(f'/slp-tools/{slpTools_slug}/index.html')

@app.route('/cognition-tools')
@token_required
def cognition_tools(**kwargs):
    return render_template('cognition-tools/index.html')

@app.route('/cognition-tools/<cognitionTools_slug>')
@token_required
def cognition_page(cognitionTools_slug, **kwargs):
    return render_template(f'/cognition-tools/{cognitionTools_slug}/index.html')
        
@app.route('/index.html')
def index_html_redirect():
    return redirect(url_for('library_page'), 301)

@app.route('/apply.html')
def apply_html_redirect():
    return redirect(url_for('apply_page'), 301)

@app.errorhandler(404)
def page_not_found(e):
    return "This page was not found in the application.", 404

# --- ALL API ROUTES GO HERE ---

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
        response = requests.post(google_api_url, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.HTTPError as http_err:
        return jsonify({"error": "The AI service returned an error.", "details": http_err.response.text}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected internal error occurred.", "details": str(e)}), 500

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
        response = requests.post(google_api_url, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        response.raise_for_status()
        return jsonify(response.json())
    except requests.exceptions.HTTPError as http_err:
        return jsonify({"error": "The AI service returned an error.", "details": http_err.response.text}), 500
    except Exception as e:
        return jsonify({"error": "An unexpected internal error occurred.", "details": str(e)}), 500
    
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

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)

