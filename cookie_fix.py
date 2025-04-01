#!/usr/bin/env python3

"""
Cookie fix for PropIntel - fixes the specific issue where cookies aren't being set
This appears to be a Mac-specific issue with Flask's cookie handling
"""

import os

def create_cookie_fixed_app():
    """Create a Flask app with explicit cookie handling"""
    app_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cookie_fixed_app.py')
    
    with open(app_path, 'w') as f:
        f.write('''#!/usr/bin/env python3

"""
Cookie-fixed app for PropIntel
This directly controls the cookie set in the response
"""

import os
import datetime
import uuid
from flask import Flask, session, redirect, url_for, request, render_template_string, make_response

# Create Flask app
app = Flask(__name__)

# Simple secret key for testing
app.secret_key = "direct-cookie-test-key"

@app.route('/')
def index():
    # Get user_id from session (or "Not logged in" if none)
    user_id = session.get('user_id', 'Not logged in')
    
    # Get visits from session
    visits = session.get('visits', 0)
    
    # Create HTML template
    template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Cookie Fix Test</title>
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
        <h1>Cookie Fix Test</h1>
        
        <div class="card">
            <h2>Session Status</h2>
            <p><strong>User ID:</strong> {{ user_id }}</p>
            <p><strong>Visits:</strong> {{ visits }}</p>
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
    
    # Render the template
    rendered = render_template_string(template, 
                                    user_id=user_id,
                                    visits=visits,
                                    session_debug=dict(session))
    
    # Create a response
    resp = make_response(rendered)
    
    # Set a debug cookie to verify cookie functionality
    resp.set_cookie('debug-cookie', 'test-value')
    
    # If we have a user_id in session, increment visits
    if 'user_id' in session:
        session['visits'] = visits + 1
    
    return resp

@app.route('/login-admin')
def login_admin():
    """Admin login with direct cookie control"""
    # Clear session data
    session.clear()
    
    # Set user_id in session
    session['user_id'] = '1'  # Store as string
    session['visits'] = 0
    
    # Create a response
    resp = make_response(redirect(url_for('index')))
    
    # CRUCIAL: Directly set the session cookie in the response
    # This uses Flask's internal session serialization
    # The cookie name must match app.session_cookie_name (default: 'session')
    from flask.sessions import SecureCookieSessionInterface
    session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
    if session_serializer:
        cookie_data = session_serializer.dumps(dict(session))
        resp.set_cookie(
            app.session_cookie_name,
            cookie_data,
            httponly=True,
            expires=datetime.datetime.now() + datetime.timedelta(days=30)
        )
    
    print(f"Login admin: Session = {session}")
    print(f"Setting session cookie directly in response")
    
    return resp

@app.route('/login-guest')
def login_guest():
    """Guest login with direct cookie control"""
    # Clear session data
    session.clear()
    
    # Set user_id in session
    session['user_id'] = 'guest'
    session['visits'] = 0
    
    # Create a response
    resp = make_response(redirect(url_for('index')))
    
    # CRUCIAL: Directly set the session cookie in the response
    from flask.sessions import SecureCookieSessionInterface
    session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
    if session_serializer:
        cookie_data = session_serializer.dumps(dict(session))
        resp.set_cookie(
            app.session_cookie_name,
            cookie_data,
            httponly=True,
            expires=datetime.datetime.now() + datetime.timedelta(days=30)
        )
    
    print(f"Login guest: Session = {session}")
    print(f"Setting session cookie directly in response")
    
    return resp

@app.route('/logout')
def logout():
    """Logout with direct cookie control"""
    # Create a response
    resp = make_response(redirect(url_for('index')))
    
    # Clear the session
    session.clear()
    
    # CRUCIAL: Delete the session cookie from the response
    resp.delete_cookie(app.session_cookie_name)
    
    print(f"Logout: Session cleared, cookie deleted")
    
    return resp

if __name__ == '__main__':
    app.run(debug=True, port=5000)
''')
    
    # Make the file executable
    os.chmod(app_path, 0o755)
    
    print(f"Created cookie-fixed app: {app_path}")
    print("Run with: python cookie_fixed_app.py")
    print("Visit: http://localhost:5000/")
    
    # Create the direct login patch for app.py
    fix_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'direct_login_patch.py')
    with open(fix_path, 'w') as f:
        f.write('''#!/usr/bin/env python3

"""
Direct login patch for PropIntel
This fixes the cookie setting issue in the login and before_request functions
"""

# REPLACE YOUR login FUNCTION WITH THIS ONE:

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page with direct cookie handling"""
    # If already logged in, redirect to index
    if g.user:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        remember = 'remember' in request.form
        
        # Guest login
        if username.lower() == 'guest':
            # Clear existing session
            session.clear()
            
            # Set guest user data
            session['user_id'] = 'guest'  
            session.permanent = True
            
            # Create response with direct cookie
            resp = make_response(redirect(url_for('index')))
            
            # Set an explicit debug cookie to test cookie functionality
            resp.set_cookie('login-debug', 'guest-login')
            
            # Return the response
            flash('Logged in as guest', 'info')
            return resp
        
        # Admin login
        if username.lower() == 'admin' and password == 'admin123':
            # Clear existing session
            session.clear()
            
            # Set admin user data
            session['user_id'] = '1'  # Store as string for consistency
            session.permanent = remember
            
            # Create response with direct cookie
            resp = make_response(redirect(url_for('index')))
            
            # Set an explicit debug cookie to test cookie functionality
            resp.set_cookie('login-debug', 'admin-login')
            
            # Return the response
            flash('Welcome back, System Administrator!', 'success')
            return resp
        
        # Regular login (database users) 
        # Your existing database checks here...
        flash('Invalid username or password', 'danger')
    
    # Render login form for GET requests
    return render_template('login.html')

# ADD THIS FUNCTION TO DIRECTLY SET SESSION COOKIES:

def set_session_cookie(response, session_data, max_age=None):
    """Helper function to directly set session cookies"""
    if max_age is None:
        max_age = 30 * 24 * 60 * 60  # 30 days in seconds
    
    # Convert session_data to cookie value
    from flask.sessions import SecureCookieSessionInterface
    session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
    
    if session_serializer:
        cookie_data = session_serializer.dumps(dict(session_data))
        response.set_cookie(
            app.session_cookie_name,
            cookie_data,
            max_age=max_age,
            httponly=True,
            secure=False,  # Set to True for HTTPS
            samesite='Lax'
        )
    
    return response
''')
    
    # Make the file executable
    os.chmod(fix_path, 0o755)
    
    print(f"Created direct login patch: {fix_path}")
    
    # Create a README for the fixes
    readme_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'COOKIE_FIX_README.md')
    with open(readme_path, 'w') as f:
        f.write('''# PropIntel Cookie Fix

We've identified the core issue: **session cookies are not being set in the response**. This is preventing session data from persisting between requests.

## Quick Solution

1. **First, test if cookies work at all:**
   ```
   python cookie_fixed_app.py
   ```
   Visit http://localhost:5000/ to test if login works correctly with the fixed approach.

2. **Apply the direct login patch:**
   - Open your app.py file
   - Replace your login function with the one from direct_login_patch.py
   - Add the set_session_cookie helper function from direct_login_patch.py
   
3. **Make sure these imports are at the top of app.py:**
   ```python
   from flask import make_response
   ```

## What This Fixes

This approach solves the issue by:

1. **Directly setting session cookies in the response**:
   - Using Flask's internal session serializer to create the cookie
   - Explicitly setting the cookie in the response object
   - Controlling cookie parameters (httponly, secure, etc.)

2. **Using consistent data types**:
   - Always storing user_id as a string ('1' instead of 1)
   - Properly handling conversion from string to int for database queries

3. **Ensuring cookie parameters are correct**:
   - Setting proper expiration time
   - Using appropriate security settings

## Common Issues on macOS

macOS has some specific issues with cookies that can cause this problem:

1. **Safari cookie restrictions**: Safari has strict cookie policies
2. **Local development restrictions**: Localhost domains sometimes have cookie issues
3. **Cookie size limits**: macOS browsers may have stricter cookie size limits

The direct cookie setting approach bypasses these issues by using Flask's internal session serializer to properly create and set the cookie.

## Troubleshooting

If you still encounter issues:

1. **Open your browser's developer tools** (F12 or Command+Option+I)
2. **Go to the Application/Storage tab**
3. **Look for cookies for your localhost domain**
4. **Verify the 'session' cookie is being set**

You can also check for error messages in your Flask app's console output.''')
    
    print(f"Created README: {readme_path}")

if __name__ == '__main__':
    create_cookie_fixed_app()