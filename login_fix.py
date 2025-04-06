"""
Fix for admin login issues in PropIntel app.

This file contains corrections for the admin login functionality.
Replace the corresponding sections in your app.py file.
"""

from flask import session, g, flash, redirect, url_for, make_response, request
from functools import wraps
from psycopg2.extras import RealDictCursor
import os

# Fix for before_request function to handle admin user correctly
@app.before_request
def before_request():
    """Load user before each request"""
    # Initialize g.user
    g.user = None
    
    # Skip session check for static files
    if request.path.startswith("/static/"):
        return
    
    # If user_id is in session, try to load user
    if "user_id" in session:
        user_id = session["user_id"]
        
        # Handle special case for guest user
        if user_id == "guest":
            g.user = {
                "user_id": "guest",
                "username": "guest",
                "email": "guest@example.com",
                "full_name": "Guest User",
                "role": "guest"
            }
            return
        
        # Handle special case for admin user - make sure user_id is compared correctly
        if user_id == "1":
            g.user = {
                "user_id": "1",  # Keep as string for consistent comparison
                "username": "admin",
                "email": "admin@propintel.com",
                "full_name": "System Administrator",
                "role": "admin"
            }
            return
        
        # For regular users, try to get user from database
        try:
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
                        # Convert user_id to string for consistent comparison
                        user['user_id'] = str(user['user_id'])
                        g.user = user
                    else:
                        # User not found or not active, clear session
                        session.pop('user_id', None)
            except Exception as db_error:
                # Special handling for admin ID 1 when database fails
                if user_id == '1':
                    g.user = {
                        'user_id': '1',  # Keep as string for consistent comparison
                        'username': 'admin',
                        'email': 'admin@propintel.com',
                        'full_name': 'System Administrator',
                        'role': 'admin'
                    }
            finally:
                conn.close()
        except (ValueError, TypeError):
            # Clear invalid session data
            session.clear()

# Fix for login function
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page with improved admin login handling"""
    # If already logged in, redirect to index
    if g.user:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember = 'remember' in request.form
        
        # Guest login
        if username.lower() == 'guest':
            # Clear existing session
            session.clear()
            
            # Set guest user data
            session['user_id'] = 'guest'
            session.permanent = True
            
            # Create response with redirect
            resp = make_response(redirect(url_for('index')))
            flash('Logged in as guest', 'info')
            return resp
        
        # Admin login - store user_id as string and double check credentials
        if username.lower() == 'admin':
            # First check database for admin user
            conn = None
            try:
                conn = get_db_connection()
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT user_id, password_hash FROM propintel.users 
                        WHERE username = 'admin' AND is_active = TRUE
                    """)
                    admin_user = cur.fetchone()
                    
                    if admin_user:
                        # Verify password using bcrypt
                        import bcrypt
                        password_match = bcrypt.checkpw(
                            password.encode('utf-8'), 
                            admin_user['password_hash'].encode('utf-8')
                        )
                        
                        if password_match:
                            # Clear existing session
                            session.clear()
                            # Store user_id as string
                            session['user_id'] = str(admin_user['user_id'])
                            session.permanent = remember
                            flash('Welcome back, System Administrator!', 'success')
                            return redirect(url_for('index'))
            except Exception:
                # Database check failed, fall back to hardcoded credentials
                pass
            finally:
                if conn:
                    conn.close()
            
            # Fallback to hardcoded admin credentials
            if password == 'admin123':
                # Clear existing session
                session.clear()
                # Store user_id as string
                session['user_id'] = '1'
                session.permanent = remember
                flash('Welcome back, System Administrator!', 'success')
                return redirect(url_for('index'))
        
        # Regular login (for database users)
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT user_id, username, email, full_name, role, password_hash, is_active
                    FROM propintel.users
                    WHERE username = %s
                """, (username,))
                
                user = cur.fetchone()
                
                if user and user['is_active']:
                    # Verify password using bcrypt
                    import bcrypt
                    password_match = bcrypt.checkpw(
                        password.encode('utf-8'), 
                        user['password_hash'].encode('utf-8')
                    )
                    
                    if password_match:
                        # Clear existing session
                        session.clear()
                        # Store user_id as string
                        session['user_id'] = str(user['user_id'])
                        session.permanent = remember
                        
                        # Update last login timestamp
                        cur.execute("""
                            UPDATE propintel.users
                            SET last_login = CURRENT_TIMESTAMP
                            WHERE user_id = %s
                        """, (user['user_id'],))
                        conn.commit()
                        
                        # Success message
                        flash(f"Welcome back, {user['full_name']}!", 'success')
                        
                        # Redirect to next_url if it exists
                        next_url = session.pop('next_url', None)
                        if next_url:
                            return redirect(next_url)
                        return redirect(url_for('index'))
        except Exception as e:
            flash(f"Login error: {str(e)}", 'danger')
        finally:
            if conn:
                conn.close()
        
        # Login failed
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

# Improved admin_required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Ensure g.user exists and is properly loaded
        if g.user is None:
            # Store the URL for redirect after login
            session['next_url'] = request.url
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
            
        # Verify role is admin (case-insensitive)
        if g.user.get('role', '').lower() != 'admin':
            flash('Administrator access required', 'danger')
            return redirect(url_for('index'))
            
        return f(*args, **kwargs)
    return decorated_function