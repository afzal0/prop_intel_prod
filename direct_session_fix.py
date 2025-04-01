#!/usr/bin/env python3

"""
Direct session fix for PropIntel - replaces Flask's session with a more reliable
implementation using server-side sessions stored in the database
"""

import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor
import json
import uuid
import hashlib
import datetime
import configparser
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
        # Try to read from config file
        config = configparser.ConfigParser()
        
        # Default connection parameters
        default_params = {
            "user": "postgres",
            "password": "1234",
            "host": "localhost",
            "port": 5432,
            "database": "postgres",
        }
        
        if os.path.exists('db_config.ini'):
            try:
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
        
        return default_params

def apply_direct_session_fix():
    """Apply direct session fix for PropIntel"""
    print("PropIntel Direct Session Fix")
    print("============================")
    
    # Get database connection parameters
    try:
        params = get_db_config()
        print(f"Using database: {params['host']}:{params['port']}/{params['database']}")
    except Exception as e:
        print(f"Error loading database configuration: {e}")
        return False

    try:
        # Connect to database
        print("\nConnecting to database...")
        conn = psycopg2.connect(**params)
        conn.autocommit = True
        
        with conn.cursor() as cur:
            # Create schema
            print("Creating schema if it doesn't exist...")
            cur.execute("CREATE SCHEMA IF NOT EXISTS propintel")
            
            # Create sessions table for server-side sessions
            print("Creating sessions table...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS propintel.sessions (
                    session_id VARCHAR(255) PRIMARY KEY,
                    user_id VARCHAR(255) NOT NULL,
                    data JSONB,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    expires_at TIMESTAMP DEFAULT (NOW() + INTERVAL '30 days')
                )
            """)
            
            # Check if users table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables 
                    WHERE table_schema = 'propintel' AND table_name = 'users'
                )
            """)
            
            if not cur.fetchone()[0]:
                # Create users table
                print("Creating users table...")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS propintel.users (
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
                    ) ON CONFLICT (username) DO NOTHING
                """, (admin_password_hash,))
            
        conn.close()
        
        # Create uploads directory
        uploads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
        if not os.path.exists(uploads_dir):
            print(f"Creating uploads directory: {uploads_dir}")
            os.makedirs(uploads_dir)
        
        # Create secret key
        secret_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secret_key.txt')
        if not os.path.exists(secret_key_path):
            print("Generating new secret key...")
            secret_key = hashlib.sha256(os.urandom(32)).hexdigest()
            with open(secret_key_path, "w") as f:
                f.write(secret_key)
        
        # Create session manager
        session_manager_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'session_manager.py')
        print(f"Creating session manager: {session_manager_path}")
        
        with open(session_manager_path, 'w') as f:
            f.write("""#!/usr/bin/env python3

'''
Server-side session manager for PropIntel
This is an alternative to Flask's cookie-based sessions, which can be unreliable
'''

import os
import json
import uuid
import datetime
import psycopg2
from psycopg2.extras import RealDictCursor

class DatabaseSessionManager:
    def __init__(self, app=None):
        self.app = app
        if app is not None:
            self.init_app(app)
    
    def init_app(self, app):
        self.app = app
        
        # Override Flask's session interface
        app.session_interface = DatabaseSessionInterface()
        
        # Cleanup expired sessions periodically
        @app.before_first_request
        def cleanup_sessions():
            try:
                conn = self.get_db_connection()
                with conn.cursor() as cur:
                    cur.execute('''
                        DELETE FROM propintel.sessions 
                        WHERE expires_at < NOW()
                    ''')
                conn.commit()
                conn.close()
            except Exception as e:
                app.logger.error(f"Error cleaning up sessions: {e}")
    
    def get_db_connection(self):
        '''Get a connection to the PostgreSQL database'''
        from db_connect import get_db_config
        
        # Get database connection parameters
        params = get_db_config()
        conn = psycopg2.connect(**params)
        return conn

class ServerSideSession(dict):
    '''Server-side session stored in the database'''
    def __init__(self, session_id=None, user_id=None):
        super().__init__()
        self.session_id = session_id or str(uuid.uuid4())
        self.user_id = user_id
        self.modified = False
        
    def __setitem__(self, key, value):
        self.modified = True
        super().__setitem__(key, value)
    
    def __delitem__(self, key):
        self.modified = True
        super().__delitem__(key)
    
    def clear(self):
        self.modified = True
        super().clear()

class DatabaseSessionInterface:
    '''Session interface that stores sessions in the database'''
    def open_session(self, app, request):
        # Get session ID from cookie
        session_id = request.cookies.get(app.session_cookie_name)
        
        if session_id:
            # Try to load session from database
            try:
                conn = self.get_db_connection()
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    cur.execute('''
                        SELECT session_id, user_id, data 
                        FROM propintel.sessions 
                        WHERE session_id = %s AND expires_at > NOW()
                    ''', (session_id,))
                    
                    session_data = cur.fetchone()
                    
                    if session_data:
                        # Load session from database
                        session = ServerSideSession(
                            session_id=session_data['session_id'],
                            user_id=session_data['user_id']
                        )
                        
                        # Load data from JSON
                        if session_data['data']:
                            session.update(session_data['data'])
                        
                        # Update last access time
                        cur.execute('''
                            UPDATE propintel.sessions
                            SET updated_at = NOW(),
                                expires_at = NOW() + INTERVAL '30 days'
                            WHERE session_id = %s
                        ''', (session_id,))
                        
                        conn.commit()
                        conn.close()
                        return session
            except Exception as e:
                app.logger.error(f"Error loading session: {e}")
            
        # Create new session if none exists or loading failed
        return ServerSideSession()
    
    def save_session(self, app, session, response):
        domain = self.get_cookie_domain(app)
        
        # Delete session if empty
        if not session:
            try:
                conn = self.get_db_connection()
                with conn.cursor() as cur:
                    cur.execute('''
                        DELETE FROM propintel.sessions 
                        WHERE session_id = %s
                    ''', (session.session_id,))
                conn.commit()
                conn.close()
            except Exception as e:
                app.logger.error(f"Error deleting session: {e}")
            
            if session.session_id and app.session_cookie_name in request.cookies:
                response.delete_cookie(app.session_cookie_name, domain=domain)
            
            return
        
        # Don't save if not modified and already exists
        if not session.modified:
            return
        
        # Save session to database
        try:
            conn = self.get_db_connection()
            with conn.cursor() as cur:
                # Convert session to JSON
                session_data = dict(session)
                
                # Make sure user_id is set
                if 'user_id' in session:
                    session.user_id = session['user_id']
                
                # Use UPSERT to create or update session
                cur.execute('''
                    INSERT INTO propintel.sessions 
                    (session_id, user_id, data, updated_at, expires_at)
                    VALUES (%s, %s, %s, NOW(), NOW() + INTERVAL '30 days')
                    ON CONFLICT (session_id) 
                    DO UPDATE SET
                        user_id = EXCLUDED.user_id,
                        data = EXCLUDED.data,
                        updated_at = EXCLUDED.updated_at,
                        expires_at = EXCLUDED.expires_at
                ''', (
                    session.session_id,
                    session.user_id or 'guest',
                    json.dumps(session_data)
                ))
                
            conn.commit()
            conn.close()
        except Exception as e:
            app.logger.error(f"Error saving session: {e}")
        
        # Set session cookie
        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        expires = self.get_expiration_time(app, session)
        
        response.set_cookie(
            app.session_cookie_name,
            session.session_id,
            expires=expires,
            httponly=httponly,
            domain=domain,
            secure=secure
        )
    
    def get_cookie_domain(self, app):
        return app.config.get('SESSION_COOKIE_DOMAIN')
    
    def get_cookie_httponly(self, app):
        return app.config.get('SESSION_COOKIE_HTTPONLY', True)
    
    def get_cookie_secure(self, app):
        return app.config.get('SESSION_COOKIE_SECURE', False)
    
    def get_expiration_time(self, app, session):
        # 30 days expiration
        return datetime.datetime.now() + datetime.timedelta(days=30)
    
    def get_db_connection(self):
        '''Get a connection to the PostgreSQL database'''
        from db_connect import get_db_config
        
        # Get database connection parameters
        params = get_db_config()
        conn = psycopg2.connect(**params)
        return conn

# Create an instance of the session manager
session_manager = DatabaseSessionManager()
""")
        
        # Create app initialization
        app_init_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'app_init.py')
        print(f"Creating app init file: {app_init_path}")
        
        with open(app_init_path, 'w') as f:
            f.write("""#!/usr/bin/env python3

'''
App initialization file for PropIntel with server-side sessions
Add this code to the top of app.py after importing Flask
'''

# Initialize server-side sessions
from session_manager import session_manager
session_manager.init_app(app)

# Create uploads directory
import os
uploads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
if not os.path.exists(uploads_dir):
    os.makedirs(uploads_dir)
app.config['UPLOAD_FOLDER'] = uploads_dir

# Set a strong secret key
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
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=30)
""")
        
        # Create simplified login_required decorator
        decorator_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'login_decorator.py')
        print(f"Creating login decorator: {decorator_path}")
        
        with open(decorator_path, 'w') as f:
            f.write("""#!/usr/bin/env python3

'''
Simple login_required decorator for PropIntel
'''

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            session['next_url'] = request.url
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Simple access control decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not g.user or g.user.get('role') != 'admin':
            flash('You do not have permission to access this page', 'danger')
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function
""")
        
        print("\nDirect session fix applied successfully!")
        print("\nTo fix the session issues:")
        print("1. Install the server-side session manager:")
        print("   - Add 'from session_manager import session_manager' to the top of app.py")
        print("   - Initialize it with 'session_manager.init_app(app)' after creating the Flask app")
        print("2. Replace the login_required decorator with the one from login_decorator.py")
        print("3. Make sure uploads directory exists and is properly configured")
        
        print("\nAfter these changes, the upload section should work without redirecting to login.")
        return True
    except Exception as e:
        print(f"Error applying direct session fix: {e}")
        return False

if __name__ == "__main__":
    apply_direct_session_fix()