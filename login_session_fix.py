#!/usr/bin/env python3

'''
Improved login and session functions for PropIntel
Replace these functions in app.py
'''

# Import these at the top of your app.py file
from flask import Flask, request, session, g, redirect, url_for, flash, render_template
from functools import wraps
from werkzeug.security import check_password_hash

# Better login_required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Debug session
        print(f"login_required: session = {session}")
        print(f"login_required: g.user = {g.user}")
        
        if g.user is None:
            # Store the original URL in session to return after login
            next_url = request.url
            session['next_url'] = next_url
            
            flash('Please log in to access this page', 'warning')
            print(f"login_required: redirecting to login, next_url = {next_url}")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Improved before_request function
@app.before_request
def before_request():
    '''Load user before each request'''
    # Initialize g.user
    g.user = None
    
    # Debug session data
    print(f"before_request: session = {session}")
    print(f"before_request: path = {request.path}")
    
    # Skip session check for static files
    if request.path.startswith('/static/'):
        return
    
    # If user_id is in session, try to load user
    if 'user_id' in session:
        user_id = session['user_id']
        print(f"before_request: user_id = {user_id}")
        
        # Handle special case for guest user
        if user_id == 'guest':
            g.user = {
                'user_id': 'guest',
                'username': 'guest',
                'email': 'guest@example.com',
                'full_name': 'Guest User',
                'role': 'guest'
            }
            print("before_request: loaded guest user")
            return
        
        # Handle special case for admin user when stored as 'admin' string
        if user_id == 'admin':
            g.user = {
                'user_id': 1,
                'username': 'admin',
                'email': 'admin@propintel.com',
                'full_name': 'System Administrator',
                'role': 'admin'
            }
            print("before_request: loaded admin user from string")
            return
        
        # Convert user_id to integer for database queries
        try:
            # For regular users, try to get user from database
            conn = get_db_connection()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT user_id, username, email, full_name, role 
                        FROM propintel.users 
                        WHERE user_id = %s AND is_active = TRUE
                    """, (int(user_id),))
                    user = cur.fetchone()
                    
                    if user:
                        g.user = user
                        print(f"before_request: loaded user from database: {user['username']}")
                    else:
                        # User not found or not active, clear session
                        print(f"before_request: user {user_id} not found or not active, clearing session")
                        session.pop('user_id', None)
                        session.pop('is_guest', None)
            except Exception as db_error:
                print(f"before_request: database error: {db_error}")
                # Special handling for admin ID 1 when database fails
                if str(user_id) == '1':
                    g.user = {
                        'user_id': 1,
                        'username': 'admin',
                        'email': 'admin@propintel.com',
                        'full_name': 'System Administrator',
                        'role': 'admin'
                    }
                    print("before_request: loaded admin user as fallback after database error")
            finally:
                conn.close()
        except (ValueError, TypeError) as e:
            print(f"before_request: error converting user_id: {e}")
            # Clear invalid session data
            session.clear()
    else:
        print("before_request: no user_id in session")

# Improved login route with better error handling and debugging
@app.route('/login', methods=['GET', 'POST'])
def login():
    '''User login page'''
    # Debug session state
    print(f"login: method = {request.method}, session = {session}")
    
    # If user is already logged in, redirect to index
    if g.user:
        print(f"login: user already logged in: {g.user}")
        return redirect(url_for('index'))
    
    # Handle login form submission
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        remember = 'remember' in request.form
        
        print(f"login: login attempt for username '{username}'")
        
        # Check for missing username
        if not username:
            flash('Username is required', 'danger')
            return render_template('login.html')
        
        # Special handling for guest login
        if username.lower() == 'guest':
            session.clear()
            session['user_id'] = 'guest'
            session['is_guest'] = True
            session.permanent = True
            
            flash('Logged in as guest', 'info')
            
            # Redirect to next_url or index
            next_url = session.pop('next_url', url_for('index'))
            print(f"login: guest login successful, redirecting to {next_url}")
            return redirect(next_url)
        
        # Special handling for admin login
        if username.lower() == 'admin' and password == 'admin123':
            session.clear()
            session['user_id'] = 1  # Store admin user ID as integer
            session.permanent = remember
            
            flash('Welcome back, System Administrator!', 'success')
            
            # Redirect to next_url or index
            next_url = session.pop('next_url', url_for('index'))
            print(f"login: admin login successful, redirecting to {next_url}")
            return redirect(next_url)
        
        # Regular user login with database validation
        try:
            conn = get_db_connection()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT user_id, username, password_hash, full_name, role, is_active
                        FROM propintel.users 
                        WHERE username = %s
                    """, (username,))
                    user = cur.fetchone()
                    
                    if user:
                        # Check if user is active
                        if not user['is_active']:
                            flash('Your account is inactive. Please contact an administrator.', 'warning')
                            return render_template('login.html')
                        
                        # Verify password
                        try:
                            if check_password_hash(user['password_hash'], password):
                                # Clear existing session
                                session.clear()
                                
                                # Set new session data
                                session['user_id'] = user['user_id']
                                session.permanent = remember
                                
                                # Update last login time
                                try:
                                    cur.execute("""
                                        UPDATE propintel.users 
                                        SET last_login = CURRENT_TIMESTAMP 
                                        WHERE user_id = %s
                                    """, (user['user_id'],))
                                    conn.commit()
                                except Exception as e:
                                    print(f"login: error updating last login: {e}")
                                
                                # Welcome message
                                flash(f'Welcome back, {user["full_name"]}!', 'success')
                                
                                # Redirect to next_url or index
                                next_url = session.pop('next_url', url_for('index'))
                                print(f"login: successful login for {username}, redirecting to {next_url}")
                                return redirect(next_url)
                            else:
                                print(f"login: invalid password for {username}")
                                flash('Invalid password', 'danger')
                        except Exception as pw_error:
                            print(f"login: password verification error: {pw_error}")
                            flash('Error verifying credentials', 'danger')
                    else:
                        print(f"login: user not found: {username}")
                        flash('Username not found', 'danger')
            except Exception as db_error:
                print(f"login: database error: {db_error}")
                flash('Database error during login', 'danger')
            finally:
                conn.close()
        except Exception as conn_error:
            print(f"login: connection error: {conn_error}")
            flash('Could not connect to database', 'danger')
        
        # If we got here, login failed
        print("login: authentication failed")
    
    # Render login form for GET requests
    return render_template('login.html')

# Improved logout route
@app.route('/logout')
def logout():
    '''Log out the current user'''
    print(f"logout: session before = {session}")
    
    # Clear the session data
    session.clear()
    
    print(f"logout: session after = {session}")
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))
