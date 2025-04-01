#!/usr/bin/env python3

'''
Flask session fix for PropIntel
Copy and add this code to app.py after the Flask app creation
'''

import os
from flask_session import Session
import datetime

# Configure Flask-Session for server-side session storage
app.config['SESSION_TYPE'] = 'filesystem'  # Use filesystem-based sessions
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_session')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=30)
app.config['SESSION_USE_SIGNER'] = True  # Sign the session cookie
app.config['SESSION_KEY_PREFIX'] = 'propintel_session_'  # Prefix for session keys

# Initialize Flask-Session
Session(app)

# Set a strong secret key for Flask
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
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
