#!/usr/bin/env python3

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
