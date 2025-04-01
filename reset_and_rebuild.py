#!/usr/bin/env python3

"""
Complete reset and rebuild script for PropIntel
This script:
1. Deletes the entire propintel schema
2. Creates a new schema from scratch
3. Rebuilds all tables with proper structure
4. Creates an admin user
5. Fixes all application issues
"""

import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor
import configparser
import hashlib
import datetime
import shutil
from werkzeug.security import generate_password_hash

def get_db_config():
    """Get database configuration from config file or environment variables"""
    # Check for DATABASE_URL environment variable
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Parse DATABASE_URL (for Heroku)
        from urllib.parse import urlparse
        
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
        result = urlparse(database_url)
        
        return {
            "user": result.username,
            "password": result.password,
            "host": result.hostname,
            "port": result.port or 5432,
            "database": result.path[1:],
        }
    else:
        # Default connection parameters with the provided password
        default_params = {
            "user": "postgres",
            "password": "1234",
            "host": "localhost",
            "port": 5432,
            "database": "postgres",
        }
        
        # Try to read from config file
        if os.path.exists('db_config.ini'):
            try:
                config = configparser.ConfigParser()
                config.read('db_config.ini')
                if 'database' in config:
                    return {
                        "user": config['database'].get('user', default_params['user']),
                        "password": config['database'].get('password', default_params['password']),
                        "host": config['database'].get('host', default_params['host']),
                        "port": int(config['database'].get('port', default_params['port'])),
                        "database": config['database'].get('database', default_params['database']),
                    }
            except Exception as e:
                print(f"Error reading config file: {e}. Using default parameters.")
        
        # If db_config.ini doesn't exist or has an error, update it with the correct password
        update_db_config(default_params)
        
        return default_params

def update_db_config(params):
    """Update or create db_config.ini with the correct parameters"""
    config = configparser.ConfigParser()
    config['database'] = {
        'user': params['user'],
        'password': params['password'],
        'host': params['host'],
        'port': str(params['port']),
        'database': params['database']
    }
    
    with open('db_config.ini', 'w') as f:
        config.write(f)
    
    print("Updated db_config.ini with correct database parameters")

def check_install_requirements():
    """Check and install required packages"""
    try:
        import werkzeug
        import flask
        import psycopg2
        import flask_session
        print("Required packages are already installed.")
    except ImportError as e:
        print(f"Missing package: {e}")
        print("Installing required packages...")
        os.system("pip install flask werkzeug psycopg2-binary flask-session")
        print("Packages installed. Please restart this script.")
        sys.exit(0)

def reset_database():
    """Delete and recreate the propintel schema"""
    print("Completely resetting the database...")
    
    try:
        # Connect to database
        params = get_db_config()
        print(f"Connecting to database: {params['host']}:{params['port']}/{params['database']} as {params['user']}")
        conn = psycopg2.connect(**params)
        conn.autocommit = True
        
        with conn.cursor() as cur:
            # Drop the entire schema if it exists
            print("Dropping propintel schema if it exists...")
            cur.execute("DROP SCHEMA IF EXISTS propintel CASCADE")
            
            # Create the schema fresh
            print("Creating new propintel schema...")
            cur.execute("CREATE SCHEMA propintel")
            
            print("Schema reset successfully.")
        
        conn.close()
        return True
    except Exception as e:
        print(f"Error resetting database: {e}")
        return False

def rebuild_database():
    """Rebuild all database tables from scratch"""
    print("Rebuilding database tables...")
    
    try:
        # Connect to database
        conn = psycopg2.connect(**get_db_config())
        conn.autocommit = True
        
        with conn.cursor() as cur:
            # Create sessions table for server-side session storage
            print("Creating sessions table...")
            cur.execute("""
                CREATE TABLE propintel.sessions (
                    id VARCHAR(255) PRIMARY KEY,
                    data BYTEA NOT NULL,
                    expiry TIMESTAMP NOT NULL
                )
            """)
            
            # Create users table
            print("Creating users table...")
            cur.execute("""
                CREATE TABLE propintel.users (
                    user_id SERIAL PRIMARY KEY,
                    username VARCHAR(50) UNIQUE NOT NULL,
                    password_hash VARCHAR(255) NOT NULL,
                    email VARCHAR(100) UNIQUE NOT NULL,
                    full_name VARCHAR(100) NOT NULL,
                    role VARCHAR(20) NOT NULL DEFAULT 'user',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_login TIMESTAMP,
                    is_active BOOLEAN DEFAULT TRUE
                )
            """)
            
            # Create admin user
            print("Creating admin user...")
            admin_password_hash = generate_password_hash('admin123')
            cur.execute("""
                INSERT INTO propintel.users (
                    username, password_hash, email, full_name, role
                ) VALUES (
                    'admin', %s, 'admin@propintel.com', 'System Administrator', 'admin'
                )
            """, (admin_password_hash,))
            
            # Create properties table
            print("Creating properties table...")
            cur.execute("""
                CREATE TABLE propintel.properties (
                    property_id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES propintel.users(user_id),
                    property_name VARCHAR(255) NOT NULL,
                    project_name VARCHAR(255),
                    status VARCHAR(50) DEFAULT 'Active',
                    address TEXT NOT NULL,
                    location VARCHAR(255),
                    project_type VARCHAR(100),
                    project_manager VARCHAR(100),
                    due_date DATE,
                    latitude NUMERIC(10, 6),
                    longitude NUMERIC(10, 6),
                    purchase_date DATE,
                    purchase_price NUMERIC(12, 2),
                    current_value NUMERIC(12, 2),
                    total_income NUMERIC(12, 2) DEFAULT 0,
                    total_expenses NUMERIC(12, 2) DEFAULT 0,
                    profit NUMERIC(12, 2) DEFAULT 0,
                    notes TEXT,
                    is_hidden BOOLEAN DEFAULT FALSE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create work table
            print("Creating work table...")
            cur.execute("""
                CREATE TABLE propintel.work (
                    work_id SERIAL PRIMARY KEY,
                    property_id INTEGER REFERENCES propintel.properties(property_id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES propintel.users(user_id),
                    work_description TEXT NOT NULL,
                    work_date DATE NOT NULL,
                    work_cost NUMERIC(10, 2),
                    payment_method VARCHAR(50),
                    status VARCHAR(50) DEFAULT 'Pending',
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create money_in table
            print("Creating money_in table...")
            cur.execute("""
                CREATE TABLE propintel.money_in (
                    money_in_id SERIAL PRIMARY KEY,
                    property_id INTEGER REFERENCES propintel.properties(property_id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES propintel.users(user_id),
                    income_details TEXT,
                    income_date DATE NOT NULL,
                    income_amount NUMERIC(10, 2) NOT NULL,
                    payment_method VARCHAR(50),
                    income_category VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create money_out table
            print("Creating money_out table...")
            cur.execute("""
                CREATE TABLE propintel.money_out (
                    money_out_id SERIAL PRIMARY KEY,
                    property_id INTEGER REFERENCES propintel.properties(property_id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES propintel.users(user_id),
                    expense_details TEXT,
                    expense_date DATE NOT NULL,
                    expense_amount NUMERIC(10, 2) NOT NULL,
                    payment_method VARCHAR(50),
                    expense_category VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create property_images table
            print("Creating property_images table...")
            cur.execute("""
                CREATE TABLE propintel.property_images (
                    image_id SERIAL PRIMARY KEY,
                    property_id INTEGER REFERENCES propintel.properties(property_id) ON DELETE CASCADE,
                    user_id INTEGER REFERENCES propintel.users(user_id),
                    work_id INTEGER REFERENCES propintel.work(work_id) ON DELETE SET NULL,
                    image_path VARCHAR(255) NOT NULL,
                    image_type VARCHAR(50) DEFAULT 'property',
                    description TEXT,
                    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create user_settings table
            print("Creating user_settings table...")
            cur.execute("""
                CREATE TABLE propintel.user_settings (
                    setting_id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES propintel.users(user_id) ON DELETE CASCADE,
                    map_theme VARCHAR(20) DEFAULT 'light',
                    default_view VARCHAR(20) DEFAULT 'card',
                    notifications_enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create audit_log table
            print("Creating audit_log table...")
            cur.execute("""
                CREATE TABLE propintel.audit_log (
                    log_id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES propintel.users(user_id) ON DELETE SET NULL,
                    action_type VARCHAR(50) NOT NULL,
                    table_name VARCHAR(50),
                    record_id INTEGER,
                    details TEXT,
                    ip_address VARCHAR(45),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            # Create settings for admin user
            print("Creating admin user settings...")
            cur.execute("""
                INSERT INTO propintel.user_settings (
                    user_id, map_theme, default_view, notifications_enabled
                ) VALUES (
                    1, 'light', 'card', TRUE
                )
            """)
            
            print("Database tables rebuilt successfully.")
        
        conn.close()
        return True
    except Exception as e:
        print(f"Error rebuilding database: {e}")
        return False

def create_flask_session_fix():
    """Create Flask session fix files"""
    print("\nCreating Flask session fix...")
    
    # Create flask_session directory if it doesn't exist
    flask_session_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'flask_session')
    if not os.path.exists(flask_session_dir):
        os.makedirs(flask_session_dir)
        print(f"Created flask_session directory: {flask_session_dir}")
    
    # Create .gitignore file for flask_session
    gitignore_path = os.path.join(flask_session_dir, '.gitignore')
    with open(gitignore_path, 'w') as f:
        f.write("*\n!.gitignore\n")
    print(f"Created .gitignore file in flask_session directory")
    
    # Create session fix file
    session_fix_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'session_fix.py')
    print(f"Creating session fix file: {session_fix_path}")
    
    with open(session_fix_path, 'w') as f:
        f.write("""#!/usr/bin/env python3

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
""")
    
    # Create secret key
    secret_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secret_key.txt')
    if not os.path.exists(secret_key_path):
        with open(secret_key_path, 'w') as f:
            f.write(hashlib.sha256(os.urandom(32)).hexdigest())
        print(f"Created new secret key file: {secret_key_path}")
    else:
        print(f"Secret key file already exists: {secret_key_path}")
    
    return True

def add_template_filters():
    """Create currency and date filters file"""
    print("\nCreating template filters...")
    
    filters_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'template_filters.py')
    print(f"Creating template filters file: {filters_path}")
    
    with open(filters_path, 'w') as f:
        f.write("""#!/usr/bin/env python3

'''
Template filters for PropIntel
Add these to your app.py file after creating the Flask app
'''

import datetime
import locale

# Set locale for currency formatting
try:
    locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
except:
    try:
        locale.setlocale(locale.LC_ALL, 'en_US')
    except:
        # Fallback if locale not available
        pass

# Format currency filter
@app.template_filter('format_currency')
def format_currency_filter(value):
    '''Format a number as currency ($X,XXX.XX)'''
    if value is None:
        return "$0.00"
    try:
        value = float(value)
        return "${:,.2f}".format(value)
    except (ValueError, TypeError):
        return "$0.00"

# Format date filter
@app.template_filter('format_date')
def format_date_filter(value):
    '''Format a date as Month DD, YYYY'''
    if not value:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            try:
                value = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return value
    
    if isinstance(value, datetime.datetime):
        return value.strftime('%b %d, %Y')
    return str(value)

# Format percent filter
@app.template_filter('format_percent')
def format_percent_filter(value):
    '''Format a number as percentage (X.XX%)'''
    if value is None:
        return "0.00%"
    try:
        value = float(value) * 100  # Convert decimal to percentage
        return "{:.2f}%".format(value)
    except (ValueError, TypeError):
        return "0.00%"

# Safe division filter (avoid divide by zero)
@app.template_filter('safe_divide')
def safe_divide_filter(numerator, denominator):
    '''Safely divide two numbers, avoiding divide by zero'''
    try:
        if denominator == 0:
            return 0
        return numerator / denominator
    except (ValueError, TypeError):
        return 0
""")
    
    return True

def fix_directories():
    """Create necessary directories and files"""
    print("\nCreating required directories and files...")
    
    # Create uploads directory
    uploads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    if not os.path.exists(uploads_dir):
        os.makedirs(uploads_dir)
        print(f"Created uploads directory: {uploads_dir}")
    
    # Create .gitignore file for uploads
    gitignore_path = os.path.join(uploads_dir, '.gitignore')
    with open(gitignore_path, 'w') as f:
        f.write("*\n!.gitignore\n")
    print(f"Created .gitignore file in uploads directory")
    
    # Create static directory
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    if not os.path.exists(static_dir):
        os.makedirs(static_dir)
        print(f"Created static directory: {static_dir}")
    
    # Create images directory
    images_dir = os.path.join(static_dir, 'images')
    if not os.path.exists(images_dir):
        os.makedirs(images_dir)
        print(f"Created images directory: {images_dir}")
    
    # Create placeholder for logo.png
    logo_path = os.path.join(static_dir, 'logo.png')
    if not os.path.exists(logo_path):
        with open(logo_path, 'w') as f:
            f.write('Placeholder for logo.png')
        print(f"Created placeholder for logo.png")
    
    # Create placeholder for property-placeholder.jpg
    placeholder_path = os.path.join(images_dir, 'property-placeholder.jpg')
    if not os.path.exists(placeholder_path):
        with open(placeholder_path, 'w') as f:
            f.write('Placeholder for property-placeholder.jpg')
        print(f"Created placeholder for property-placeholder.jpg")
    
    return True

def create_improved_login_functions():
    """Create improved login and session handling functions"""
    print("\nCreating improved login and session management functions...")
    
    login_fix_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'login_session_fix.py')
    print(f"Creating login and session fix file: {login_fix_path}")
    
    with open(login_fix_path, 'w') as f:
        f.write("""#!/usr/bin/env python3

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
                    cur.execute(\"\"\"
                        SELECT user_id, username, email, full_name, role 
                        FROM propintel.users 
                        WHERE user_id = %s AND is_active = TRUE
                    \"\"\", (int(user_id),))
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
                    cur.execute(\"\"\"
                        SELECT user_id, username, password_hash, full_name, role, is_active
                        FROM propintel.users 
                        WHERE username = %s
                    \"\"\", (username,))
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
                                    cur.execute(\"\"\"
                                        UPDATE propintel.users 
                                        SET last_login = CURRENT_TIMESTAMP 
                                        WHERE user_id = %s
                                    \"\"\", (user['user_id'],))
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
""")
    
    return True

def create_app_patching_instructions():
    """Create instructions for patching app.py"""
    print("\nCreating app patching instructions...")
    
    instructions_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'APP_PATCHING_INSTRUCTIONS.md')
    with open(instructions_path, 'w') as f:
        f.write("""# App Patching Instructions

Follow these steps to patch your app.py file with all the fixes:

## 1. Add Flask-Session Import

Add this import at the top of your app.py file:

```python
from flask_session import Session
```

## 2. Add Flask-Session Configuration

Add this code after creating the Flask app (`app = Flask(__name__)`):

```python
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
```

## 3. Add Template Filters

Add these filter functions after the Flask-Session configuration:

```python
# Template filters
@app.template_filter('format_currency')
def format_currency_filter(value):
    '''Format a number as currency ($X,XXX.XX)'''
    if value is None:
        return "$0.00"
    try:
        value = float(value)
        return "${:,.2f}".format(value)
    except (ValueError, TypeError):
        return "$0.00"

@app.template_filter('format_date')
def format_date_filter(value):
    '''Format a date as Month DD, YYYY'''
    if not value:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.datetime.strptime(value, '%Y-%m-%d')
        except ValueError:
            try:
                value = datetime.datetime.strptime(value, '%Y-%m-%d %H:%M:%S')
            except ValueError:
                return value
    
    if isinstance(value, datetime.datetime):
        return value.strftime('%b %d, %Y')
    return str(value)

@app.template_filter('format_percent')
def format_percent_filter(value):
    '''Format a number as percentage (X.XX%)'''
    if value is None:
        return "0.00%"
    try:
        value = float(value) * 100  # Convert decimal to percentage
        return "{:.2f}%".format(value)
    except (ValueError, TypeError):
        return "0.00%"

@app.template_filter('safe_divide')
def safe_divide_filter(numerator, denominator):
    '''Safely divide two numbers, avoiding divide by zero'''
    try:
        if denominator == 0:
            return 0
        return numerator / denominator
    except (ValueError, TypeError):
        return 0
```

## 4. Replace login_required Decorator

Replace the existing login_required decorator with this improved version:

```python
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
```

## 5. Replace before_request Function

Replace the existing before_request function with this improved version:

```python
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
                    cur.execute(\"\"\"
                        SELECT user_id, username, email, full_name, role 
                        FROM propintel.users 
                        WHERE user_id = %s AND is_active = TRUE
                    \"\"\", (int(user_id),))
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
```

## 6. Replace login Route

Replace the existing login route with this improved version:

```python
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
                    cur.execute(\"\"\"
                        SELECT user_id, username, password_hash, full_name, role, is_active
                        FROM propintel.users 
                        WHERE username = %s
                    \"\"\", (username,))
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
                                    cur.execute(\"\"\"
                                        UPDATE propintel.users 
                                        SET last_login = CURRENT_TIMESTAMP 
                                        WHERE user_id = %s
                                    \"\"\", (user['user_id'],))
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
```

## 7. Replace logout Route

Replace the existing logout route with this improved version:

```python
@app.route('/logout')
def logout():
    '''Log out the current user'''
    print(f"logout: session before = {session}")
    
    # Clear the session data
    session.clear()
    
    print(f"logout: session after = {session}")
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))
```

## 8. Install Required Packages

Make sure to install the required packages:

```bash
pip install flask-session
```

## 9. Clear Browser Cookies and Restart Flask

After making all these changes:

1. Clear your browser cookies for the application
2. Restart the Flask application
3. Try logging in with admin/admin123

## 10. Additional Troubleshooting

If you still encounter issues:

1. Check the Flask console output for errors
2. Make sure all the required directories exist
3. Verify that Flask-Session is installed
4. Ensure the database connection is working properly""")
    
    print(f"Created app patching instructions: {instructions_path}")
    return True

def update_requirements_file():
    """Update requirements.txt file"""
    print("\nUpdating requirements.txt file...")
    
    requirements_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'requirements.txt')
    
    # Make backup of existing requirements.txt
    if os.path.exists(requirements_path):
        backup_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'requirements.txt.bak')
        shutil.copy2(requirements_path, backup_path)
        print(f"Backed up existing requirements.txt to {backup_path}")
    
    with open(requirements_path, 'w') as f:
        f.write("""Flask==2.3.3
Werkzeug==2.3.7
Jinja2==3.1.2
itsdangerous==2.1.2
click==8.1.7
MarkupSafe==2.1.3
psycopg2-binary==2.9.9
Flask-Session==0.5.0
pandas==2.1.1
openpyxl==3.1.2
xlrd==2.0.1
numpy==1.26.0
geopy==2.4.0
python-dateutil==2.8.2
configparser==6.0.0
gunicorn==21.2.0
python-dotenv==1.0.0
Pillow==10.0.0
pytz==2023.3
email-validator==2.0.0
""")
    
    print(f"Updated requirements.txt file")
    return True

def main():
    """Main function to run all fixes"""
    print("PropIntel Complete Reset and Rebuild")
    print("===================================")
    print("This script will completely reset and rebuild the PropIntel application.")
    print("WARNING: This will DELETE ALL DATA in the propintel schema!")
    
    # Ask for confirmation
    confirm = input("Are you sure you want to proceed? (y/n): ")
    if confirm.lower() != 'y':
        print("Operation cancelled.")
        return
    
    # Check and install required packages
    check_install_requirements()
    
    # Reset database
    if not reset_database():
        print("Failed to reset database. Exiting.")
        return
    
    # Rebuild database
    if not rebuild_database():
        print("Failed to rebuild database. Exiting.")
        return
    
    # Create Flask session fix
    create_flask_session_fix()
    
    # Add template filters
    add_template_filters()
    
    # Fix directories
    fix_directories()
    
    # Create improved login functions
    create_improved_login_functions()
    
    # Create app patching instructions
    create_app_patching_instructions()
    
    # Update requirements.txt
    update_requirements_file()
    
    print("\nAll fixes completed successfully!")
    print("\nNext steps:")
    print("1. Install required packages:")
    print("   pip install -r requirements.txt")
    print("2. Follow the instructions in APP_PATCHING_INSTRUCTIONS.md to update your app.py file")
    print("3. Restart your Flask application:")
    print("   python app.py")
    print("\nDefault login credentials:")
    print("  Username: admin")
    print("  Password: admin123")

if __name__ == "__main__":
    main()