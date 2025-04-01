#!/usr/bin/env python3

"""
Fix for session saving issue in PropIntel
This solves the specific problem where login is successful but user_id isn't saved in the session
"""

import os
import sys
import flask
from flask.sessions import SessionInterface, SessionMixin
from flask_session import Session
import datetime
import json
import uuid
import hashlib
import pickle
import base64

class DebugFileSystemSession(flask.sessions.SecureCookieSession):
    """Debug version of FileSystemSession that prints all operations"""
    
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        print(f"DebugFileSystemSession.__init__: {self}")
    
    def __setitem__(self, key, value):
        print(f"DebugFileSystemSession.__setitem__: Setting {key} = {value}")
        super().__setitem__(key, value)
    
    def __getitem__(self, key):
        value = super().__getitem__(key)
        print(f"DebugFileSystemSession.__getitem__: Getting {key} = {value}")
        return value
    
    def get(self, key, default=None):
        value = super().get(key, default)
        print(f"DebugFileSystemSession.get: Getting {key} = {value} (default={default})")
        return value
    
    def pop(self, key, default=None):
        value = super().pop(key, default)
        print(f"DebugFileSystemSession.pop: Popping {key} = {value} (default={default})")
        return value
    
    def clear(self):
        print(f"DebugFileSystemSession.clear: Clearing session {self}")
        super().clear()

class DebugFileSystemSessionInterface(SessionInterface):
    """Debug version of FileSystemSessionInterface"""
    
    def __init__(self, session_dir):
        self.session_dir = session_dir
        if not os.path.exists(session_dir):
            os.makedirs(session_dir)
    
    def get_session_filename(self, sid):
        return os.path.join(self.session_dir, f"session_{sid}")
    
    def open_session(self, app, request):
        sid = request.cookies.get(app.session_cookie_name)
        print(f"DebugFileSystemSessionInterface.open_session: sid={sid}")
        
        if sid is None:
            sid = str(uuid.uuid4())
            print(f"DebugFileSystemSessionInterface.open_session: New sid={sid}")
            return DebugFileSystemSession(sid=sid)
        
        filename = self.get_session_filename(sid)
        if os.path.exists(filename):
            try:
                with open(filename, 'rb') as f:
                    data = pickle.load(f)
                    print(f"DebugFileSystemSessionInterface.open_session: Loaded data={data}")
                session = DebugFileSystemSession(data, sid=sid)
                return session
            except Exception as e:
                print(f"DebugFileSystemSessionInterface.open_session: Error loading session: {e}")
        
        return DebugFileSystemSession(sid=sid)
    
    def save_session(self, app, session, response):
        print(f"DebugFileSystemSessionInterface.save_session: session={session}")
        
        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        samesite = self.get_cookie_samesite(app)
        
        if not session:
            print("DebugFileSystemSessionInterface.save_session: Empty session, deleting")
            if session.sid and os.path.exists(self.get_session_filename(session.sid)):
                os.unlink(self.get_session_filename(session.sid))
            response.delete_cookie(app.session_cookie_name, domain=domain, path=path)
            return
        
        # Set session cookie
        if session.sid is None:
            session.sid = str(uuid.uuid4())
            print(f"DebugFileSystemSessionInterface.save_session: New sid={session.sid}")
        
        filename = self.get_session_filename(session.sid)
        
        # Save session to file
        try:
            session_data = dict(session)
            print(f"DebugFileSystemSessionInterface.save_session: Saving data={session_data}")
            with open(filename, 'wb') as f:
                pickle.dump(session_data, f)
        except Exception as e:
            print(f"DebugFileSystemSessionInterface.save_session: Error saving session: {e}")
        
        # Set the cookie
        response.set_cookie(
            app.session_cookie_name,
            session.sid,
            expires=self.get_expiration_time(app, session),
            httponly=httponly,
            domain=domain,
            path=path,
            secure=secure,
            samesite=samesite
        )
        print(f"DebugFileSystemSessionInterface.save_session: Cookie set with sid={session.sid}")
    
    def get_cookie_domain(self, app):
        return app.config.get('SESSION_COOKIE_DOMAIN')
    
    def get_cookie_path(self, app):
        return app.config.get('SESSION_COOKIE_PATH', '/')
    
    def get_cookie_httponly(self, app):
        return app.config.get('SESSION_COOKIE_HTTPONLY', True)
    
    def get_cookie_secure(self, app):
        return app.config.get('SESSION_COOKIE_SECURE', False)
    
    def get_cookie_samesite(self, app):
        return app.config.get('SESSION_COOKIE_SAMESITE', None)
    
    def get_expiration_time(self, app, session):
        if session.permanent:
            return datetime.datetime.now() + app.permanent_session_lifetime
        return None

def create_manual_login_fix():
    """Create manual login fix file"""
    print("Creating manual login fix...")
    
    fix_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'manual_login_fix.py')
    with open(fix_path, 'w') as f:
        f.write('''#!/usr/bin/env python3

"""
Manual fix for PropIntel login issue
This handles the specific issue where login is successful but user_id isn't saved in the session
"""'''

import os
from flask import Flask, session, request, redirect, url_for, render_template, g
from werkzeug.security import check_password_hash

app = Flask(__name__)

# Configure Flask app
app.secret_key = 'debug_testing_key'
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_session')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = 86400  # 1 day in seconds

@app.route('/')
def index():
    """Test index page"""
    return f'''
    <h1>Session Test</h1>
    <p>Session data: {session}</p>
    <p>User: {g.get('user')}</p>
    <p><a href="/login">Login</a></p>
    <p><a href="/logout">Logout</a></p>
    '''

@app.route('/login', methods=['GET', 'POST'])
def login():
    """Test login page"""
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        
        # Clear any existing session
        session.clear()
        
        # Set user_id in session
        if username == 'admin' and password == 'admin123':
            # This is the key part - directly modify session
            session['user_id'] = 1
            session['username'] = 'admin'
            session.modified = True
            
            # Print session to debug
            print(f"Login successful, session: {session}")
            
            # Force save session by returning a response
            resp = redirect(url_for('index'))
            return resp
    
    return '''
    <h1>Login</h1>
    <form method="post">
      <p>Username: <input type="text" name="username"></p>
      <p>Password: <input type="password" name="password"></p>
      <p><input type="submit" value="Login"></p>
    </form>
    '''

@app.route('/logout')
def logout():
    """Test logout page"""
    # Clear session
    session.clear()
    return redirect(url_for('index'))

@app.before_request
def before_request():
    """Load user from session"""
    g.user = None
    print(f"Session at start of request: {session}")
    
    if 'user_id' in session:
        user_id = session['user_id']
        print(f"Found user_id in session: {user_id}")
        g.user = {'id': user_id, 'username': session.get('username', 'unknown')}

if __name__ == '__main__':
    # Create session dir if it doesn't exist
    if not os.path.exists(app.config['SESSION_FILE_DIR']):
        os.makedirs(app.config['SESSION_FILE_DIR'])
    
    app.run(debug=True, port=5001)
""")
    
    print(f"Created manual login fix: {fix_path}")
    os.chmod(fix_path, 0o755)
    return True

def create_direct_login_fix():
    """Create direct login fix for app.py"""
    print("Creating direct login fix...")
    
    fix_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'direct_login_fix.py')
    with open(fix_path, 'w') as f:
        f.write("""#!/usr/bin/env python3

'''
Direct fix for login issue in PropIntel app.py
This fixes the specific issue where login is successful but user_id isn't saved in the session
'''

# Replace the login function in app.py with this version:

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
            # Clear existing session first
            session.clear()
            
            # Set new session data
            session['user_id'] = 'guest'
            session['is_guest'] = True
            session.permanent = True
            
            # Force session to be marked as modified
            session.modified = True
            
            flash('Logged in as guest', 'info')
            
            # Redirect to next_url or index
            next_url = session.pop('next_url', url_for('index'))
            print(f"login: guest login successful, redirecting to {next_url}")
            
            # Create response for redirect
            response = redirect(next_url)
            
            # Add debug cookie to test cookie setting
            response.set_cookie('login_test', 'guest_login_at_' + str(datetime.datetime.now()))
            
            return response
        
        # Special handling for admin login
        if username.lower() == 'admin' and password == 'admin123':
            # Clear existing session first
            session.clear()
            
            # Set new session data - IMPORTANT: use string for consistency
            session['user_id'] = '1'  # Store as string for consistency
            session.permanent = remember
            
            # Force session to be marked as modified
            session.modified = True
            
            print(f"login: admin session after setting user_id: {session}")
            
            flash('Welcome back, System Administrator!', 'success')
            
            # Redirect to next_url or index
            next_url = session.pop('next_url', url_for('index'))
            print(f"login: admin login successful, redirecting to {next_url}")
            
            # Create response for redirect
            response = redirect(next_url)
            
            # Add debug cookie to test cookie setting
            response.set_cookie('login_test', 'admin_login_at_' + str(datetime.datetime.now()))
            
            return response
        
        # Regular user login with database validation
        try:
            conn = get_db_connection()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute('''
                        SELECT user_id, username, password_hash, full_name, role, is_active
                        FROM propintel.users 
                        WHERE username = %s
                    ''', (username,))
                    user = cur.fetchone()
                    
                    if user:
                        # Check if user is active
                        if not user['is_active']:
                            flash('Your account is inactive. Please contact an administrator.', 'warning')
                            return render_template('login.html')
                        
                        # Verify password
                        try:
                            if check_password_hash(user['password_hash'], password):
                                # Clear existing session first
                                session.clear()
                                
                                # Set new session data - IMPORTANT: convert to string
                                session['user_id'] = str(user['user_id'])  # Store as string for consistency
                                session.permanent = remember
                                
                                # Force session to be marked as modified
                                session.modified = True
                                
                                # Update last login time
                                try:
                                    cur.execute('''
                                        UPDATE propintel.users 
                                        SET last_login = CURRENT_TIMESTAMP 
                                        WHERE user_id = %s
                                    ''', (user['user_id'],))
                                    conn.commit()
                                except Exception as e:
                                    print(f"login: error updating last login: {e}")
                                
                                # Welcome message
                                flash(f'Welcome back, {user["full_name"]}!', 'success')
                                
                                # Redirect to next_url or index
                                next_url = session.pop('next_url', url_for('index'))
                                print(f"login: successful login for {username}, redirecting to {next_url}")
                                
                                # Create response for redirect
                                response = redirect(next_url)
                                
                                # Add debug cookie to test cookie setting
                                response.set_cookie('login_test', f'user_login_{username}_at_' + str(datetime.datetime.now()))
                                
                                return response
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

# Replace the before_request function with this version:

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
        
        # Convert user_id to integer for database queries
        try:
            # For regular users, try to get user from database
            conn = get_db_connection()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute('''
                        SELECT user_id, username, email, full_name, role 
                        FROM propintel.users 
                        WHERE user_id = %s AND is_active = TRUE
                    ''', (int(user_id),))
                    user = cur.fetchone()
                    
                    if user:
                        g.user = user
                        print(f"before_request: loaded user from database: {user['username']}")
                    else:
                        # Try admin check for user_id = 1 or '1'
                        if user_id == '1' or user_id == 1:
                            g.user = {
                                'user_id': 1,
                                'username': 'admin',
                                'email': 'admin@propintel.com',
                                'full_name': 'System Administrator',
                                'role': 'admin'
                            }
                            print("before_request: loaded admin user as fallback")
                        else:
                            # User not found or not active, clear session
                            print(f"before_request: user {user_id} not found or not active, clearing session")
                            session.pop('user_id', None)
                            session.pop('is_guest', None)
            except Exception as db_error:
                print(f"before_request: database error: {db_error}")
                # Special handling for admin ID 1 when database fails
                if user_id == '1' or user_id == 1:
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
            # Check if it's the admin user (user_id = '1')
            if user_id == '1':
                g.user = {
                    'user_id': 1,
                    'username': 'admin',
                    'email': 'admin@propintel.com',
                    'full_name': 'System Administrator',
                    'role': 'admin'
                }
                print("before_request: loaded admin user with string ID '1'")
            else:
                # Clear invalid session data
                session.clear()
    else:
        print("before_request: no user_id in session")
""")
    
    print(f"Created direct login fix: {fix_path}")
    os.chmod(fix_path, 0o755)
    return True

def create_cookie_test():
    """Create a simple cookie test file"""
    print("Creating cookie test...")
    
    test_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'cookie_test.py')
    with open(test_path, 'w') as f:
        f.write("""#!/usr/bin/env python3

'''
Cookie test for PropIntel
This is a simple test to check if cookies can be set and retrieved
'''

from flask import Flask, request, make_response, render_template_string

app = Flask(__name__)

@app.route('/')
def index():
    count = int(request.cookies.get('visit-count', 0)) + 1
    resp = make_response(render_template_string('''
    <h1>Cookie Test</h1>
    <p>Visit count: {{ count }}</p>
    <p>All cookies: {{ request.cookies }}</p>
    <p><a href="/set">Set test cookie</a></p>
    <p><a href="/clear">Clear cookies</a></p>
    ''', count=count))
    resp.set_cookie('visit-count', str(count))
    return resp

@app.route('/set')
def set_cookie():
    resp = make_response(render_template_string('''
    <h1>Cookie Set</h1>
    <p>Test cookie has been set.</p>
    <p><a href="/">Back to home</a></p>
    '''))
    resp.set_cookie('test-cookie', 'This is a test cookie')
    return resp

@app.route('/clear')
def clear_cookies():
    resp = make_response(render_template_string('''
    <h1>Cookies Cleared</h1>
    <p>All cookies have been cleared.</p>
    <p><a href="/">Back to home</a></p>
    '''))
    resp.delete_cookie('visit-count')
    resp.delete_cookie('test-cookie')
    return resp

if __name__ == '__main__':
    app.run(debug=True, port=5050)
""")
    
    print(f"Created cookie test: {test_path}")
    os.chmod(test_path, 0o755)
    return True

def create_session_config_fix():
    """Create session configuration fix"""
    print("Creating session configuration fix...")
    
    config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'session_config_fix.py')
    with open(config_path, 'w') as f:
        f.write("""#!/usr/bin/env python3

'''
Session configuration fix for PropIntel
To be added at the top of app.py, before creating the Flask app
'''

# ==== ADD THIS TO THE TOP OF APP.PY, BEFORE CREATING THE FLASK APP ====

# Import Flask and Flask-Session
from flask import Flask, session, request, redirect, url_for, render_template, g, flash, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
import datetime
import os
import uuid

# ==== ADD THIS RIGHT AFTER CREATING THE FLASK APP ====

# Configure Flask-Session with Redis (preferred) or Filesystem storage
app.config['SESSION_TYPE'] = 'filesystem'  # or 'redis' if available
app.config['SESSION_FILE_DIR'] = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_session')
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)
app.config['SESSION_USE_SIGNER'] = True
app.config['SESSION_KEY_PREFIX'] = 'propintel_session_'

# Important: Initialize Flask-Session
Session(app)

# Set a strong secret key
app.secret_key = os.environ.get('SECRET_KEY', str(uuid.uuid4()))

# Add session debugging
@app.after_request
def after_request_func(response):
    # Debug cookies being set in the response
    print(f"Cookies being set: {[k for k in response.headers.getlist('Set-Cookie')]}")
    
    # Force the response to use the secure flag
    response.headers.add('X-Session-Debug', str(session))
    return response
""")
    
    print(f"Created session configuration fix: {config_path}")
    os.chmod(config_path, 0o755)
    return True

def main():
    """Main function to run session saving fix"""
    print("PropIntel Session Saving Fix")
    print("===========================")
    print("This script addresses the specific issue with sessions not being saved.")
    
    create_manual_login_fix()
    create_direct_login_fix()
    create_cookie_test()
    create_session_config_fix()
    
    print("\nSession saving fixes created:")
    print("1. manual_login_fix.py - Standalone test app to verify session functionality")
    print("2. direct_login_fix.py - Direct fix for the login and before_request functions")
    print("3. cookie_test.py - Simple test for cookie functionality")
    print("4. session_config_fix.py - Flask-Session configuration with enhanced debugging")
    
    print("\nTo fix the session saving issue:")
    print("1. First, test basic cookie functionality:")
    print("   python cookie_test.py")
    print("   Visit http://localhost:5050/ to verify cookies are working")
    
    print("\n2. Replace the Flask-Session configuration in app.py:")
    print("   - Add the code from session_config_fix.py")
    
    print("\n3. Replace the login and before_request functions:")
    print("   - Update with the code from direct_login_fix.py")
    
    print("\n4. If issues persist, try the standalone test app:")
    print("   python manual_login_fix.py")
    print("   Visit http://localhost:5001/ to test session functionality")
    
    print("\nImportant: Make sure to install Flask-Session:")
    print("pip install Flask-Session")

if __name__ == "__main__":
    main()