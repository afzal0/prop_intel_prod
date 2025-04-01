#!/usr/bin/env python3

"""
Minimal session test for PropIntel
Run this to test if sessions work correctly
"""

from flask import Flask, session, redirect, url_for, request
from flask_session import Session
import os
import datetime

app = Flask(__name__)

# Configure Flask-Session
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flask_session")
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(days=31)
app.secret_key = "session-test-key"

# Initialize Flask-Session
Session(app)

@app.route('/')
def index():
    visits = session.get('visits', 0)
    session['visits'] = visits + 1
    
    current_user = session.get('user_id', 'Not logged in')
    
    return f"""
    <h1>Session Test</h1>
    <p>Visits: {visits}</p>
    <p>User ID: {current_user}</p>
    <p>Session data: {session}</p>
    <p><a href="/login">Log in as admin</a></p>
    <p><a href="/guest">Log in as guest</a></p>
    <p><a href="/logout">Log out</a></p>
    """

@app.route('/login')
def login():
    session.clear()
    session['user_id'] = '1'  # Admin user ID as string
    session.permanent = True
    return redirect(url_for('index'))

@app.route('/guest')
def guest():
    session.clear()
    session['user_id'] = 'guest'
    session.permanent = True
    return redirect(url_for('index'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

if __name__ == '__main__':
    # Create session directory if it doesn't exist
    if not os.path.exists(app.config["SESSION_FILE_DIR"]):
        os.makedirs(app.config["SESSION_FILE_DIR"])
        
    app.run(debug=True, port=5050)
