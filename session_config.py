"""
This script checks if the Flask session configuration is working correctly.
Run this before your main app to test session storage.
"""
from flask import Flask, session, request, jsonify
import os
import secrets
from datetime import timedelta

app = Flask(__name__)

# Generate a secure random key for testing
app.secret_key = secrets.token_hex(16)
app.config['SESSION_TYPE'] = 'filesystem'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'

try:
    from flask_session import Session
    Session(app)
    print("Using Flask-Session for server-side sessions")
except ImportError:
    print("Flask-Session not installed, using default client-side sessions")

@app.route('/')
def index():
    # Count visits
    if 'visits' in session:
        session['visits'] = session.get('visits') + 1
    else:
        session['visits'] = 1
    
    # Set some test data
    session['test_value'] = 'This is a test'
    
    # Make sure changes are saved
    session.modified = True
    
    return jsonify({
        'session_working': True,
        'session_id': request.cookies.get('session'),
        'visits': session.get('visits'),
        'test_value': session.get('test_value'),
        'full_session': dict(session)
    })

@app.route('/clear')
def clear():
    session.clear()
    return jsonify({'session_cleared': True})

if __name__ == '__main__':
    print(f"Session configuration:")
    print(f"- Secret key length: {len(app.secret_key)} bytes")
    print(f"- Session type: {app.config.get('SESSION_TYPE', 'client-side')}")
    print(f"- Session lifetime: {app.config.get('PERMANENT_SESSION_LIFETIME')}")
    print(f"- Cookie secure: {app.config.get('SESSION_COOKIE_SECURE')}")
    print(f"- Cookie httponly: {app.config.get('SESSION_COOKIE_HTTPONLY')}")
    print(f"- Cookie samesite: {app.config.get('SESSION_COOKIE_SAMESITE')}")
    print(f"- Session file path: {app.config.get('SESSION_FILE_DIR', 'Not configured')}")
    
    print("\nStarting test server on http://127.0.0.1:5001")
    print("- Visit / to test session creation")
    print("- Visit /clear to clear the session")
    app.run(debug=True, port=5001)