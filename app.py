from flask import Flask, render_template, request, make_response, redirect, url_for, abort
import jwt
import os
from functools import wraps
from datetime import datetime, timedelta
import logging
import requests
import json
from flask import jsonify

# --- Basic Configuration ---
app = Flask(__name__, template_folder='templates', static_folder='static')
logging.basicConfig(level=logging.INFO)

# --- Security Configuration ---
# This securely reads your secret key from Render's environment variables.
app.config['SECRET_KEY'] = os.environ.get('JWT_SECRET', 'a-very-secret-key-that-you-should-change')
app.config['GEMINI_API_KEY_COGNITION'] = os.environ.get('GEMINI_API_KEY_COGNITION')
app.config['GEMINI_API_KEY_SLP'] = os.environ.get('GEMINI_API_KEY_SLP')


# --- User Management ---
# This is where you add and remove users for your closed alpha.
USERS = {
    "dnavas": "Almanueva1!",
    "user2": "anotherSecurePassword",
    "mburk": "Rockets25",
    "annahower": "Falcons25!",
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

# The NEW main route is now the public landing page.
@app.route('/')
def landing_page():
    token = request.cookies.get('token')
    app.logger.info("Request received for public / route.")
    if token:
        try:
            # Check if the token is valid without protecting the page
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
            app.logger.info("Valid token found. Redirecting to /library.")
            # If token is valid, redirect to the library
            return redirect(url_for('library_page'))
        except Exception as e:
            # If token is invalid (e.g., expired), just log it and show the landing page
            app.logger.warning(f"Invalid token found on landing page access: {e}. Serving landing page.")
            # Fall through to render the landing page
    
    # If no token or invalid token, show the public landing page
    app.logger.info("No valid token. Serving landing.html.")
    return render_template('landing.html')


# The OLD main route is moved to /library and remains protected.
@app.route('/library')
@token_required
def library_page():
    app.logger.info("Request received for protected /library route. Serving index.html.")
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

# --- Articulation Tools ---
@app.route('/articulation-tools')
@token_required
def articulation_tools():
    app.logger.info("Request for /articulation-tools. Trying 'templates/articulation-tools/index.html'.")
    try:
        return render_template('articulation-tools/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find 'templates/articulation-tools/index.html'. Error: {e}")
        abort(500)

# --- Dynamic Route for Individual Phoneme Pages ---
@app.route('/articulation-tools/<phoneme_slug>')
@token_required
def phoneme_page(phoneme_slug):
    app.logger.info(f"Request received for phoneme page: /articulation-tools/{phoneme_slug}")
    try:
        # This is the correct path, starting from inside the 'templates' folder.
        return render_template(f'articulation-tools/{phoneme_slug}/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find template for phoneme '{phoneme_slug}'. Error: {e}")
        abort(404)

# --- Language Tools ---
@app.route('/language-tools')
@token_required
def language_tools():
    app.logger.info("Request for /language-tools. Trying 'templates/language-tools/index.html'.")
    try:
        return render_template('language-tools/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find 'templates/language-tools/index.html'. Error: {e}")
        abort(500)

# --- Dynamic Route for Individual Language Pages ---
@app.route('/language-tools/<languageTools_slug>')
@token_required
def language_page(languageTools_slug):
    app.logger.info(f"Request received for language tools page: /language-tools/{languageTools_slug}")
    try:
        # This is the correct path, starting from inside the 'templates' folder.
        return render_template(f'/language-tools/{languageTools_slug}/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find template for '{languageTools_slug}'. Error: {e}")
        abort(404)

# --- Fluency Tools ---
@app.route('/fluency-tools')
@token_required
def fluency_tools():
    app.logger.info("Request for /fluency-tools. Trying 'templates/fluency-tools/index.html'.")
    try:
        return render_template('fluency-tools/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find 'templates/fluency-tools/index.html'. Error: {e}")
        abort(500)

# --- Dynamic Route for Individual Fluency-Tool Pages ---
@app.route('/fluency-tools/<fluencyTools_slug>')
@token_required
def fluency_page(fluencyTools_slug):
    app.logger.info(f"Request received for Fluency tools page: /fluency-tools/{fluencyTools_slug}")
    try:
        # This is the correct path, starting from inside the 'templates' folder.
        return render_template(f'/fluency-tools/{fluencyTools_slug}/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find template for '{fluencyTools_slug}'. Error: {e}")
        abort(404)

# --- SLP Tools ---
@app.route('/slp-tools')
@token_required
def slp_tools():
    app.logger.info("Request for /slp-tools. Trying 'templates/slp-tools/index.html'.")
    try:
        return render_template('slp-tools/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find 'templates/slp-tools/index.html'. Error: {e}")
        abort(500)

# --- Dynamic Route for Individual SLP-Tool Pages ---
@app.route('/slp-tools/<slpTools_slug>')
@token_required
def slp_page(slpTools_slug):
    app.logger.info(f"Request received for SLP tools page: /slp-tools/{slpTools_slug}")
    try:
        # This is the correct path, starting from inside the 'templates' folder.
        return render_template(f'/slp-tools/{slpTools_slug}/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find template for '{slpTools_slug}'. Error: {e}")
        abort(404)

# --- Cognition Tools ---
@app.route('/cognition-tools')
@token_required
def cognition_tools():
    app.logger.info("Request for /cognition-tools. Trying 'templates/cognition-tools/index.html'.")
    try:
        return render_template('cognition-tools/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find 'templates/cognition-tools/index.html'. Error: {e}")
        abort(500)

# --- Dynamic Route for Individual Cognition-Tool Pages ---
@app.route('/cognition-tools/<cognitionTools_slug>')
@token_required
def cognition_page(cognitionTools_slug):
    app.logger.info(f"Request received for cognition tools page: /cognition-tools/{cognitionTools_slug}")
    try:
        # This is the correct path, starting from inside the 'templates' folder.
        return render_template(f'/cognition-tools/{cognitionTools_slug}/index.html')
    except Exception as e:
        app.logger.error(f"CRITICAL: Could not find template for '{cognitionTools_slug}'. Error: {e}")
        abort(404)
        
# --- Redirects to enforce clean URLs ---
# These catch old links and point them to the correct, clean URL.
@app.route('/index.html')
def index_html_redirect():
    return redirect(url_for('library_page'), 301)

@app.route('/apply.html')
def apply_html_redirect():
    return redirect(url_for('apply_page'), 301)


# --- Error Handling ---
@app.errorhandler(404)
def page_not_found(e):
    app.logger.warning(f"404 Not Found error triggered for path: {request.path}")
    return "This page was not found in the application.", 404

# --- ALL API ROUTES GO HERE, OUTSIDE THE MAIN BLOCK ---

# SESSION SCRIBE --- Waiter #1: Handles the compliance check
@app.route('/api/compliance-check', methods=['POST'])
def handle_compliance_check():
    data = request.get_json()
    user_input = data.get('userInput')
    
    if not user_input:
        return jsonify({"error": "No user input provided"}), 400

    try:
        # Securely gets the key from your Render environment variables
        api_key = app.config['SLP_KEY'] 
        google_api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
        # This is the same payload your JavaScript was creating
        payload = {
            "contents": [{ "parts": [{ "text": f"Analyze the following text for potential PII and return the result as a JSON object: \"{user_input}\"" }] }],
            "systemInstruction": { "parts": [{ "text": "You are a compliance-checking AI. Your task is to identify potential personally identifiable information (PII) or FERPA violations in a given text. Return a JSON object with a single key \"violations\" which is an array of strings. Each string in the array should be a word or phrase you've identified as a potential violation. Focus on names of people, specific non-school locations, or titles of works that could be misinterpreted as names. If there are no potential violations, return an empty array. Do not explain your reasoning, just return the JSON object." }] },
            "generationConfig": {
                "responseMimeType": "application/json",
                "responseSchema": { "type": "OBJECT", "properties": { "violations": { "type": "ARRAY", "items": { "type": "STRING" } } } }
            }
        }
        
        response = requests.post(google_api_url, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        response.raise_for_status() # Check for errors
        
        # Send Google's response back to the browser
        return response.json()

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# Waiter #2: Handles generating the final note
@app.route('/api/generate-note', methods=['POST'])
def handle_generate_note():
    data = request.get_json()
    user_input = data.get('userInput')
    glossary = data.get('glossary')

    if not user_input or not glossary:
        return jsonify({"error": "Missing user input or glossary"}), 400

    try:
        # Securely gets the key from your Render environment variables
        api_key = app.config['SLP_KEY']
        google_api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
        # This is the same payload your JavaScript was creating
        payload = {
            "contents": [{ "parts": [{ "text": f"Using the following glossary, please expand the shorthand note below into a professional therapy note.\n\nGlossary:\n{json.dumps(glossary, indent=2)}\n\nShorthand Note:\n\"{user_input}\"" }] }],
            "systemInstruction": { "parts": [{ "text": "You are a Speech-Language Pathologist’s assistant. Your only task is to take shorthand prompts (fragments, abbreviations, or incomplete sentences) and expand them into full, professional attendance notes for school-based therapy. Write in a clear, concise, professional tone appropriate for clinical documentation. Crucially, all notes must be de-identified. Always refer to individuals as \"the student\" or \"the students\" and use neutral pronouns (they/them/their) to ensure anonymity and FERPA compliance. Use the provided glossary to expand shorthand. For terms not in the glossary, expand them logically." }] }
        }

        response = requests.post(google_api_url, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        response.raise_for_status() # Check for errors
        
        # Send Google's response back to the browser
        return response.json()

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    app.run(debug=True)

    # MIND SHIFTER Waiter for checking a student's solution in Mind Shifter
@app.route('/api/check-solution', methods=['POST'])
def handle_check_solution():
    data = request.get_json()
    student_answer = data.get('studentAnswer')
    solution_keywords = data.get('solutionKeywords')
    
    if not student_answer or not solution_keywords:
        return jsonify({"error": "Missing required data"}), 400

    try:
        # Securely uses the COGNITION key from your app config
        api_key = app.config['GEMINI_API_KEY_COGNITION']
        google_api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
        
        # This part runs two checks: one for inappropriate content and one for conceptual match
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
        # A fallback in case the API call fails
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
        # Securely uses the COGNITION key from your app config
        api_key = app.config['GEMINI_API_KEY_COGNITION']
        google_api_url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"

        prompt = f"A student's answer isn't quite right: \"{student_answer}\". Provide a short, encouraging, one-sentence question to help them think of a better solution. Do not give the answer."
        payload = {"contents": [{"parts": [{"text": prompt}]}]}

        response = requests.post(google_api_url, headers={"Content-Type": "application/json"}, data=json.dumps(payload))
        response.raise_for_status()
        
        scaffold_text = response.json().get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', "Good start! How might someone else see this situation?")
        
        return jsonify({"scaffoldText": scaffold_text})

    except Exception as e:
        return jsonify({"scaffoldText": "Good start! How might someone else see this situation?"})

# --- This block should be the VERY LAST thing in your file ---
if __name__ == '__main__':
    # This line MUST be indented with 4 spaces
                app.run(debug=True)
