"""
Patch for the before_request function in app.py
Copy this code and replace the existing before_request function in app.py
"""

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
        
        # Special handling for admin user if we can't connect to database
        if session['user_id'] == 1:
            try:
                # Try database first
                conn = get_db_connection()
                try:
                    with conn.cursor(cursor_factory=RealDictCursor) as cur:
                        cur.execute("""
                            SELECT user_id, username, email, full_name, role 
                            FROM propintel.users 
                            WHERE user_id = 1
                        """)
                        admin_user = cur.fetchone()
                        
                        if admin_user:
                            g.user = admin_user
                            return
                except Exception as db_error:
                    print(f"Database error in before_request: {db_error}")
                finally:
                    conn.close()
            except Exception as conn_error:
                print(f"Connection error in before_request: {conn_error}")
            
            # Fallback if database query fails for admin
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
            conn = get_db_connection()
            try:
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute("""
                        SELECT user_id, username, email, full_name, role 
                        FROM propintel.users 
                        WHERE user_id = %s AND is_active = TRUE
                    """, (session['user_id'],))
                    user = cur.fetchone()
                    
                    if user:
                        g.user = user
                    else:
                        # Clear invalid session
                        session.pop('user_id', None)
                        session.pop('is_guest', None)
            except Exception as db_error:
                print(f"Database error in before_request: {db_error}")
                # Clear invalid session
                session.pop('user_id', None)
                session.pop('is_guest', None)
            finally:
                conn.close()
        except Exception as conn_error:
            print(f"Connection error in before_request: {conn_error}")
            # Clear invalid session
            session.pop('user_id', None)
            session.pop('is_guest', None)