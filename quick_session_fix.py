#!/usr/bin/env python3

"""
Quick session fix for PropIntel
Copy these functions into your app.py to replace the existing ones
"""

# Fix for before_request function - replace in app.py
@app.before_request
def before_request():
    """Load logged in user before each request"""
    g.user = None
    
    if 'user_id' in session:
        # Special handling for guest user
        if session['user_id'] == 'guest':
            g.user = {
                'user_id': 'guest',
                'username': 'guest',
                'email': 'guest@example.com',
                'full_name': 'Guest User',
                'role': 'guest'
            }
            return
        
        # Handle admin special case
        if session['user_id'] == 'admin' or session['user_id'] == 1:
            # Hardcoded admin object as fallback
            g.user = {
                'user_id': 1,
                'username': 'admin',
                'email': 'admin@propintel.com',
                'full_name': 'System Administrator',
                'role': 'admin'
            }
            return
            
        # Fetch user from database for regular users
        try:
            # Convert user_id to integer for regular users
            user_id = int(session['user_id'])
            conn = get_db_connection()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT user_id, username, email, full_name, role 
                        FROM propintel.users 
                        WHERE user_id = %s AND is_active = TRUE
                    """, (user_id,))
                    user = cur.fetchone()
                    
                    if user:
                        g.user = user
                    else:
                        # Clear invalid session
                        session.pop('user_id', None)
                        session.pop('is_guest', None)
            except Exception as db_error:
                print(f"Database error in before_request: {db_error}")
            finally:
                conn.close()
        except (ValueError, TypeError) as e:
            print(f"Error converting user_id: {e}")
            # Invalid user_id format, clear the session
            session.pop('user_id', None)
            session.pop('is_guest', None)
        except Exception as conn_error:
            print(f"Connection error in before_request: {conn_error}")

# Fix for login route - replace in app.py
@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
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
            
        # Guest login (no password needed)
        if username.lower() == 'guest':
            # Set session
            session.clear()
            session['user_id'] = 'guest'
            session['is_guest'] = True
            session.permanent = True  # Make session last longer
            
            flash('Logged in as guest', 'info')
            next_page = request.args.get('next') or url_for('index')
            print(f"Guest login success, redirecting to: {next_page}")
            return redirect(next_page)
            
        # Admin hardcoded login for testing
        if username.lower() == 'admin' and password == 'admin123':
            # Set session
            session.clear()
            session['user_id'] = 'admin'  # Store as string to avoid integer conversion issues
            session.permanent = remember
            
            flash('Welcome back, System Administrator!', 'success')
            next_page = request.args.get('next') or url_for('index')
            print(f"Admin login success, redirecting to: {next_page}")
            return redirect(next_page)
        
        # Regular login
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
                        try:
                            # Check password
                            if check_password_hash(user['password_hash'], password):
                                if not user['is_active']:
                                    flash('Your account is inactive. Please contact an administrator.', 'warning')
                                    return render_template('login.html')
                                    
                                # Set session
                                session.clear()
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
                                    print(f"Error updating last login: {e}")
                                
                                flash(f'Welcome back, {user["full_name"]}!', 'success')
                                next_page = request.args.get('next') or url_for('index')
                                print(f"Regular login success for {username}, redirecting to: {next_page}")
                                return redirect(next_page)
                            else:
                                flash('Invalid password', 'danger')
                        except Exception as pw_error:
                            print(f"Password verification error: {pw_error}")
                            flash('Error verifying credentials', 'danger')
                    else:
                        flash('Username not found', 'danger')
            except Exception as db_error:
                print(f"Database error in login: {db_error}")
                flash('Database error during login', 'danger')
            finally:
                conn.close()
        except Exception as conn_error:
            print(f"Connection error in login: {conn_error}")
            flash('Could not connect to database', 'danger')
    
    return render_template('login.html')

# Add this to app.py if not already present
@app.before_first_request
def configure_app():
    # Set permanent session lifetime to 30 days
    from datetime import timedelta
    app.permanent_session_lifetime = timedelta(days=30)
    
    # Ensure secret key is set
    if not app.secret_key or app.secret_key == 'dev':
        secret_key_path = "secret_key.txt"
        if os.path.exists(secret_key_path):
            with open(secret_key_path, "r") as f:
                app.secret_key = f.read().strip()
        else:
            import hashlib
            app.secret_key = hashlib.sha256(os.urandom(32)).hexdigest()
            with open(secret_key_path, "w") as f:
                f.write(app.secret_key)