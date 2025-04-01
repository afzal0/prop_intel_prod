#!/usr/bin/env python3

"""
Direct fix for PropIntel session issues - creates standalone test app
This app demonstrates working session management separate from your main app
"""

import os
import datetime
from flask import Flask, session, redirect, url_for, request, render_template_string
import flask_session
import tempfile

def create_standalone_app():
    """Creates a standalone test app that demonstrates working sessions"""
    app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'session_app.py')
    
    with open(app_path, 'w') as f:
        f.write('''#!/usr/bin/env python3

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
    app.run(debug=True, port=5000)
''')
    
    # Make the file executable
    os.chmod(app_path, 0o755)
    
    print(f"Created standalone app: {app_path}")
    print("Run with: python session_app.py")
    print("Visit: http://localhost:5000/")
    
    # Also create a version with the simplest possible fix
    simple_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'simple_session_fix.txt')
    with open(simple_path, 'w') as f:
        f.write('''
====== SIMPLEST SESSION FIX FOR PROPINTEL ======

1. Open app.py and add this near the top (after imports):

# Set a secure secret key
app.secret_key = "propintel-secure-key-change-this"

# Configure cookie session settings
app.config["SESSION_COOKIE_SECURE"] = False  # Change to True in production with HTTPS
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"

# Set longer session lifetime
app.config["PERMANENT_SESSION_LIFETIME"] = 2592000  # 30 days in seconds


2. Replace your login function with this simplified version:

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    # If already logged in, redirect
    if g.user:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Special handling for guest
        if username.lower() == 'guest':
            session.clear()
            session['user_id'] = 'guest'
            session.permanent = True
            return redirect(url_for('index'))
        
        # Special handling for admin
        if username.lower() == 'admin' and password == 'admin123':
            session.clear()
            session['user_id'] = '1'  # Store as string
            session.permanent = True
            return redirect(url_for('index'))
        
        # Regular login (database checks)
        flash('Login failed', 'danger')
        
    return render_template('login.html')


3. Replace your before_request function with this simplified version:

@app.before_request
def before_request():
    """Load logged in user"""
    g.user = None
    
    # Skip for static files
    if request.path.startswith('/static/'):
        return
    
    # Check for user_id in session
    if 'user_id' in session:
        user_id = session['user_id']
        
        # Handle guest user
        if user_id == 'guest':
            g.user = {'user_id': 'guest', 'role': 'guest'}
            return
            
        # Handle admin user
        if user_id == '1':
            g.user = {'user_id': 1, 'username': 'admin', 'role': 'admin'}
            return
            
        # Regular users (database lookup)
        # your existing code...


4. Add a simple login check in index.html:

<p>Current user: {{ g.user.username if g.user else "Not logged in" }}</p>


5. Make sure your templates don't have HTML syntax errors
''')
    
    print(f"Created simple fix instructions: {simple_path}")

if __name__ == '__main__':
    create_standalone_app()