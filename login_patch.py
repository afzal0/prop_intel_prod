#!/usr/bin/env python3

"""
Login patch for PropIntel app.py
Apply this to fix the session saving issue
"""

# === Add these imports at the top of your file if not already there ===
from flask import Flask, session, request, redirect, url_for, flash, render_template, g
from werkzeug.security import check_password_hash
from functools import wraps
import datetime
import json
import uuid
import os

# === Make sure Flask-Session is installed and imported ===
# pip install Flask-Session
from flask_session import Session

# === Add this right after creating your Flask app ===
# app = Flask(__name__)

# Configure Flask-Session
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flask_session")
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(days=31)

# Initialize Flask-Session
Session(app)

# Set a strong secret key
secret_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secret_key.txt')
if os.path.exists(secret_key_path):
    with open(secret_key_path, 'r') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = str(uuid.uuid4())
    with open(secret_key_path, 'w') as f:
        f.write(app.secret_key)

# === Replace your login route with this one ===
@app.route("/login", methods=["GET", "POST"])
def login():
    """User login page"""
    # Debug session state
    print(f"login: method = {request.method}, session = {session}")
    
    # If user is already logged in, redirect to index
    if g.user:
        print(f"login: user already logged in: {g.user}")
        return redirect(url_for("index"))
    
    # Handle login form submission
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")
        remember = "remember" in request.form
        
        print(f"login: login attempt for username '{username}'")
        
        # Check for missing username
        if not username:
            flash("Username is required", "danger")
            return render_template("login.html")
        
        # Special handling for guest login
        if username.lower() == "guest":
            # Clear existing session
            session.clear()
            
            # Set new session data as string
            session["user_id"] = "guest"
            session["is_guest"] = True
            
            # Set session as permanent
            session.permanent = True
            
            flash("Logged in as guest", "info")
            
            # Ensure session data is saved
            resp = redirect(url_for("index"))
            return resp
        
        # Special handling for admin login
        if username.lower() == "admin" and password == "admin123":
            # Clear existing session
            session.clear()
            
            # Set new session data
            session["user_id"] = "1"  # Store as string for consistency
            
            # Set session as permanent if remember is checked
            session.permanent = remember
            
            # Debug session data
            print(f"login: admin session data = {session}")
            
            flash("Welcome back, System Administrator!", "success")
            
            # Ensure session data is saved
            resp = redirect(url_for("index"))
            return resp
        
        # Regular user login with database validation
        # (Your existing database validation code...)
        # Just make sure to store session["user_id"] as a string:
        # session["user_id"] = str(user["user_id"])
        
    # Render login form for GET requests
    return render_template("login.html")

# === Replace your before_request function with this one ===
@app.before_request
def before_request():
    """Load user before each request"""
    # Initialize g.user
    g.user = None
    
    # Debug session data
    print(f"before_request: session = {session}")
    print(f"before_request: path = {request.path}")
    
    # Skip session check for static files
    if request.path.startswith("/static/"):
        return
    
    # If user_id is in session, try to load user
    if "user_id" in session:
        user_id = session["user_id"]
        print(f"before_request: user_id = {user_id}")
        
        # Handle special case for guest user
        if user_id == "guest":
            g.user = {
                "user_id": "guest",
                "username": "guest",
                "email": "guest@example.com",
                "full_name": "Guest User",
                "role": "guest"
            }
            print("before_request: loaded guest user")
            return
        
        # Handle special case for admin user
        if user_id == "1" or user_id == 1:
            g.user = {
                "user_id": 1,
                "username": "admin",
                "email": "admin@propintel.com",
                "full_name": "System Administrator",
                "role": "admin"
            }
            print("before_request: loaded admin user")
            return
            
        # For regular users, try to get user from database
        # (Your existing database code...)
        # Make sure to handle cases where user_id is a string but
        # needs to be converted to int for database lookup
