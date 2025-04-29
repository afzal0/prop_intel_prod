#!/usr/bin/env python3

'''
App initialization file for PropIntel with server-side sessions
Add this code to the top of app.py after importing Flask
'''

from datetime import datetime, timedelta

# Initialize server-side sessions
from session_manager import session_manager
session_manager.init_app(app)

# Create uploads directory
import os
uploads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
if not os.path.exists(uploads_dir):
    os.makedirs(uploads_dir)
app.config['UPLOAD_FOLDER'] = uploads_dir

# Set a strong secret key
secret_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secret_key.txt')
if os.path.exists(secret_key_path):
    with open(secret_key_path, 'r') as f:
        app.secret_key = f.read().strip()
else:
    import hashlib
    app.secret_key = hashlib.sha256(os.urandom(32)).hexdigest()
    with open(secret_key_path, 'w') as f:
        f.write(app.secret_key)

# Additional security settings
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') != 'development'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=30)
