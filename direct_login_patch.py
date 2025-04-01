#!/usr/bin/env python3

"""
Direct login patch for PropIntel
This fixes the cookie setting issue in the login and before_request functions
"""

# REPLACE YOUR login FUNCTION WITH THIS ONE:

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page with direct cookie handling"""
    # If already logged in, redirect to index
    if g.user:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '')
        password = request.form.get('password', '')
        remember = 'remember' in request.form
        
        # Guest login
        if username.lower() == 'guest':
            # Clear existing session
            session.clear()
            
            # Set guest user data
            session['user_id'] = 'guest'  
            session.permanent = True
            
            # Create response with direct cookie
            resp = make_response(redirect(url_for('index')))
            
            # Set an explicit debug cookie to test cookie functionality
            resp.set_cookie('login-debug', 'guest-login')
            
            # Return the response
            flash('Logged in as guest', 'info')
            return resp
        
        # Admin login
        if username.lower() == 'admin' and password == 'admin123':
            # Clear existing session
            session.clear()
            
            # Set admin user data
            session['user_id'] = '1'  # Store as string for consistency
            session.permanent = remember
            
            # Create response with direct cookie
            resp = make_response(redirect(url_for('index')))
            
            # Set an explicit debug cookie to test cookie functionality
            resp.set_cookie('login-debug', 'admin-login')
            
            # Return the response
            flash('Welcome back, System Administrator!', 'success')
            return resp
        
        # Regular login (database users) 
        # Your existing database checks here...
        flash('Invalid username or password', 'danger')
    
    # Render login form for GET requests
    return render_template('login.html')

# ADD THIS FUNCTION TO DIRECTLY SET SESSION COOKIES:

def set_session_cookie(response, session_data, max_age=None):
    """Helper function to directly set session cookies"""
    if max_age is None:
        max_age = 30 * 24 * 60 * 60  # 30 days in seconds
    
    # Convert session_data to cookie value
    from flask.sessions import SecureCookieSessionInterface
    session_serializer = SecureCookieSessionInterface().get_signing_serializer(app)
    
    if session_serializer:
        cookie_data = session_serializer.dumps(dict(session_data))
        response.set_cookie(
            app.session_cookie_name,
            cookie_data,
            max_age=max_age,
            httponly=True,
            secure=False,  # Set to True for HTTPS
            samesite='Lax'
        )
    
    return response
