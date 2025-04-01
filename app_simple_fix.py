#!/usr/bin/env python3

"""
Simplified app with hardcoded login to debug session management issues
Run this instead of app.py to test the basic functionality
"""

import os
import sys
import datetime
from flask import (
    Flask, render_template, request, redirect, url_for, session, g, 
    flash, jsonify, send_from_directory, send_file
)
from werkzeug.utils import secure_filename
from functools import wraps

# Create the Flask app
app = Flask(__name__)

# Configure the app
app.secret_key = 'hardcoded_secret_key_for_testing'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=30)

# Create upload directory
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

# Global user database (for debugging)
USERS = {
    'admin': {
        'user_id': 1,
        'username': 'admin',
        'password': 'admin123',
        'email': 'admin@propintel.com',
        'full_name': 'System Administrator',
        'role': 'admin'
    },
    'guest': {
        'user_id': 2,
        'username': 'guest',
        'password': '',
        'email': 'guest@example.com',
        'full_name': 'Guest User',
        'role': 'guest'
    }
}

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        print(f"login_required: session = {session}")
        print(f"login_required: g.user = {g.user}")
        
        if g.user is None:
            session['next_url'] = request.url
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

@app.before_request
def before_request():
    """Load user before each request"""
    g.user = None
    
    print(f"before_request: session = {session}")
    
    if 'user_id' in session:
        user_id = session['user_id']
        print(f"before_request: user_id = {user_id}")
        
        # Check hardcoded users
        for user in USERS.values():
            if user['user_id'] == user_id:
                g.user = user
                print(f"before_request: found user = {g.user}")
                break
        
        if g.user is None:
            # Special case for "admin" string
            if user_id == 'admin':
                g.user = USERS['admin']
                print(f"before_request: using admin user")
            # Special case for "guest" string
            elif user_id == 'guest':
                g.user = USERS['guest']
                print(f"before_request: using guest user")

@app.route('/')
def index():
    """Home page"""
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Login page"""
    # Redirect if already logged in
    if g.user:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        remember = 'remember' in request.form
        
        # Validate inputs
        if not username:
            flash('Username is required', 'danger')
            return render_template('login.html')
            
        # Check login against hardcoded users
        if username in USERS:
            user = USERS[username]
            
            # Guest login (no password needed)
            if username == 'guest':
                session.clear()
                session['user_id'] = user['user_id']
                session.permanent = True
                flash('Logged in as guest', 'info')
                next_page = session.pop('next_url', url_for('index'))
                print(f"login: guest success, redirecting to {next_page}")
                return redirect(next_page)
            
            # Regular login
            if password == user['password']:
                session.clear()
                session['user_id'] = user['user_id']
                session.permanent = remember
                flash(f'Welcome back, {user["full_name"]}!', 'success')
                next_page = session.pop('next_url', url_for('index'))
                print(f"login: {username} success, redirecting to {next_page}")
                return redirect(next_page)
            else:
                flash('Invalid password', 'danger')
        else:
            flash('Username not found', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """Logout user"""
    print(f"logout: session before = {session}")
    session.clear()
    print(f"logout: session after = {session}")
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """Upload file page"""
    print(f"upload_file: session = {session}")
    print(f"upload_file: g.user = {g.user}")
    
    if g.user['role'] == 'guest':
        flash('Guest users cannot upload files', 'warning')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If user does not select file, browser also
        # submits an empty part without filename
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            flash(f'Successfully uploaded {filename}', 'success')
            return redirect(url_for('index'))
    
    return render_template('upload.html')

@app.route('/download_template')
def download_template():
    """Download sample template"""
    # Create a simple text file as placeholder
    template_path = os.path.join(app.config['UPLOAD_FOLDER'], 'sample_template.txt')
    with open(template_path, 'w') as f:
        f.write('This is a sample template file')
    
    return send_file(template_path, as_attachment=True, download_name='sample_template.txt')

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)