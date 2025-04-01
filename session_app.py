#!/usr/bin/env python3

"""
Standalone session test app for PropIntel
Run this to verify session functionality works
"""

import os
import datetime
import uuid
from flask import Flask, session, redirect, url_for, request, render_template_string

# Create temporary directory for sessions
SESSION_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'test_sessions')
if not os.path.exists(SESSION_DIR):
    os.makedirs(SESSION_DIR)

# Create Flask app
app = Flask(__name__)

# Configure sessions WITHOUT Flask-Session (using Flask's built-in sessions)
app.config["SESSION_PERMANENT"] = True
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(days=1)
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Set a strong secret key
app.secret_key = str(uuid.uuid4())
print(f"Using secret key: {app.secret_key}")

@app.route('/')
def index():
    # Count visits in this session
    visits = session.get('visits', 0) + 1
    session['visits'] = visits
    
    # Get current user from session
    user_id = session.get('user_id', 'Not logged in')
    
    # Debug the session
    session_debug = dict(session)
    
    # Create HTML template
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Session Test</title>
        <style>
            body { font-family: Arial, sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
            .debug { background: #f8f9fa; padding: 10px; border-radius: 4px; }
            .card { border: 1px solid #ddd; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
            .btn { background: #007bff; color: white; border: none; padding: 10px 15px; 
                   border-radius: 4px; text-decoration: none; display: inline-block; margin-right: 10px; }
            .btn-logout { background: #dc3545; }
        </style>
    </head>
    <body>
        <h1>Session Test App</h1>
        
        <div class="card">
            <h2>Session Status</h2>
            <p><strong>Visits:</strong> {{ visits }}</p>
            <p><strong>User ID:</strong> {{ user_id }}</p>
            <p><strong>Cookie Settings:</strong></p>
            <ul>
                <li>SESSION_PERMANENT: {{ app.config['SESSION_PERMANENT'] }}</li>
                <li>PERMANENT_SESSION_LIFETIME: {{ app.config['PERMANENT_SESSION_LIFETIME'] }}</li>
                <li>SESSION_COOKIE_HTTPONLY: {{ app.config['SESSION_COOKIE_HTTPONLY'] }}</li>
                <li>SESSION_COOKIE_SAMESITE: {{ app.config['SESSION_COOKIE_SAMESITE'] }}</li>
            </ul>
        </div>
        
        <div class="card">
            <h2>Actions</h2>
            <a href="{{ url_for('login_admin') }}" class="btn">Login as Admin</a>
            <a href="{{ url_for('login_guest') }}" class="btn">Login as Guest</a>
            <a href="{{ url_for('logout') }}" class="btn btn-logout">Logout</a>
        </div>
        
        <div class="card">
            <h2>Session Debug</h2>
            <div class="debug">
                <pre>{{ session_debug }}</pre>
            </div>
        </div>
    </body>
    </html>
    """
    
    return render_template_string(template, 
                                 visits=visits, 
                                 user_id=user_id, 
                                 session_debug=session_debug,
                                 app=app)

@app.route('/login-admin')
def login_admin():
    """Admin login route"""
    # Clear existing session
    session.clear()
    
    # Set user_id in session
    session['user_id'] = '1'
    
    # Set session as permanent
    session.permanent = True
    
    # Print debug info
    print(f"Login admin: Session = {session}")
    
    return redirect(url_for('index'))

@app.route('/login-guest')
def login_guest():
    """Guest login route"""
    # Clear existing session
    session.clear()
    
    # Set user_id in session
    session['user_id'] = 'guest'
    
    # Set session as permanent
    session.permanent = True
    
    # Print debug info
    print(f"Login guest: Session = {session}")
    
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Logout route"""
    # Save the visits count
    visits = session.get('visits', 0)
    
    # Clear the session
    session.clear()
    
    # Restore the visits count
    session['visits'] = visits
    
    # Print debug info
    print(f"Logout: Session = {session}")
    
    return redirect(url_for('index'))

@app.after_request
def after_request(response):
    """Add debugging headers to the response"""
    response.headers['X-Session-Debug'] = str(dict(session))
    
    # Check for Set-Cookie header
    cookies = [h for h in response.headers.getlist('Set-Cookie') if 'session=' in h]
    if cookies:
        print(f"Set-Cookie headers: {cookies}")
    else:
        print("No session cookie set in response")
    
    return response

if __name__ == '__main__':
    app.run(debug=True, port=5001)
