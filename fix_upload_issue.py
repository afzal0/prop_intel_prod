#!/usr/bin/env python3
"""
Fix for PropIntel upload section issues
"""
import os
import psycopg2
from psycopg2.extras import RealDictCursor
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

def fix_upload_issues():
    """Fix upload section issues in PropIntel"""
    print("PropIntel Upload Section Fix")
    print("============================")
    # Create uploads directory if it doesn't exist
    uploads_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'uploads')
    if not os.path.exists(uploads_dir):
        print(f"Creating uploads directory: {uploads_dir}")
        os.makedirs(uploads_dir)
    else:
        print(f"Uploads directory already exists: {uploads_dir}")
    
    # Create static directory for sample file
    static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
    if not os.path.exists(static_dir):
        print(f"Creating static directory: {static_dir}")
        os.makedirs(static_dir)
    
    # Create sample Excel template
    sample_template_path = os.path.join(static_dir, 'sample_template.xlsx')
    if not os.path.exists(sample_template_path):
        print(f"Creating placeholder for sample template: {sample_template_path}")
        with open(sample_template_path, 'w') as f:
            f.write('Placeholder for Excel template')
    
    # Create secret key file
    secret_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secret_key.txt')
    if not os.path.exists(secret_key_path):
        print("Generating new secret key...")
        import hashlib
        secret_key = hashlib.sha256(os.urandom(32)).hexdigest()
        with open(secret_key_path, "w") as f:
            f.write(secret_key)
        print(f"Secret key stored in {secret_key_path}")
    else:
        print(f"Using existing secret key from {secret_key_path}")
    
    # Create login_required fix file
    login_required_fix_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'login_required_fix.py')
    with open(login_required_fix_path, 'w') as f:
        f.write('''#!/usr/bin/env python3
"""
Fixed login_required decorator and upload route for PropIntel
Copy these into your app.py file to replace the existing ones
"""

# Fixed login_required decorator - prevents redirect loops
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Debug current session
        print(f"Session in login_required: {session}")
        print(f"g.user in login_required: {g.user}")
        if g.user is None:
            # Store the original URL to return to after login
            session['next_url'] = request.url
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Fixed upload_file route with better debug and error handling
@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """Page for uploading Excel files to process"""
    # Debug access to this page
    print(f"Upload page accessed by user: {g.user}")
    if session.get('is_guest'):
        flash('Guest users cannot upload files', 'warning')
        return redirect(url_for('index'))
    
    # Create upload folder if it doesn't exist
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    
    if request.method == 'POST':
        # Debug request files
        print(f"Request files: {request.files}")
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        # If user does not select file, browser also
        # submits an empty part without filename
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Process the file
            try:
                print(f"Processing file: {file_path}")
                # Check if extractor is properly initialized
                if not hasattr(app, 'extractor') or app.extractor is None:
                    # Import the extractor module if needed
                    import property_data_extractor as extractor
                    app.extractor = extractor
                app.extractor.extract_data_from_excel(file_path)
                flash(f'Successfully processed {filename}', 'success')
            except Exception as e:
                print(f"Error processing file: {e}")
                flash(f'Error processing file: {e}', 'danger')
            
            return redirect(url_for('index'))
    
    return render_template('upload.html')

# Fixed route for the sample template download
@app.route('/download_template')
def download_template():
    """Download a sample Excel template"""
    template_path = os.path.join(app.static_folder, 'sample_template.xlsx')
    
    # Create a basic template if it doesn't exist
    if not os.path.exists(template_path):
        try:
            import pandas as pd
            import numpy as np
            
            # Create Excel writer
            writer = pd.ExcelWriter(template_path, engine='xlsxwriter')
            
            # Properties sheet
            properties_df = pd.DataFrame({
                'property_name': ['123 Smith St', '45 Jones Ave'],
                'address': ['123 Smith Street, Melbourne VIC 3000', '45 Jones Avenue, Richmond VIC 3121'],
                'purchase_date': ['2020-01-15', '2019-08-20'],
                'purchase_price': [750000, 650000],
                'current_value': [850000, 720000],
                'notes': ['3 bedroom townhouse', '2 bedroom apartment']
            })
            properties_df.to_excel(writer, sheet_name='Properties', index=False)
            
            # Work sheet
            work_df = pd.DataFrame({
                'property_name': ['123 Smith St', '45 Jones Ave'],
                'work_description': ['Kitchen renovation', 'Bathroom repairs'],
                'work_date': ['2023-02-15', '2023-03-10'],
                'work_cost': [25000, 3500],
                'payment_method': ['Bank Transfer', 'Credit Card']
            })
            work_df.to_excel(writer, sheet_name='Work', index=False)
            
            # Income sheet
            income_df = pd.DataFrame({
                'property_name': ['123 Smith St', '45 Jones Ave'],
                'income_details': ['Rent payment - January', 'Rent payment - January'],
                'income_date': ['2023-01-05', '2023-01-03'],
                'income_amount': [2800, 2200],
                'payment_method': ['Bank Transfer', 'Direct Deposit']
            })
            income_df.to_excel(writer, sheet_name='Income', index=False)
            
            # Expenses sheet
            expenses_df = pd.DataFrame({
                'property_name': ['123 Smith St', '45 Jones Ave'],
                'expense_details': ['Council rates', 'Water bill'],
                'expense_date': ['2023-01-20', '2023-01-15'],
                'expense_amount': [850, 120],
                'payment_method': ['Bank Transfer', 'Direct Debit']
            })
            expenses_df.to_excel(writer, sheet_name='Expenses', index=False)
            
            # Save the Excel file
            writer.save()
        except Exception as e:
            print(f"Error creating template: {e}")
            # Create a placeholder file
            with open(template_path, 'w') as f:
                f.write('Placeholder for Excel template')
    
    return send_file(template_path, as_attachment=True,
                    download_name='property_import_template.xlsx',
                    mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

# Improved before_request function with better debugging
@app.before_request
def before_request():
    """Load logged in user before each request"""
    g.user = None
    # Debug session
    print(f"Session before loading user: {session}")
    
    if 'user_id' in session:
        user_id = session['user_id']
        # Debug user_id
        print(f"Loading user_id: {user_id}, type: {type(user_id)}")
        
        # Special handling for guest user
        if user_id == 'guest':
            g.user = {
                'user_id': 'guest',
                'username': 'guest',
                'email': 'guest@example.com',
                'full_name': 'Guest User',
                'role': 'guest'
            }
            print("Loaded guest user")
            return
        
        # Handle admin special case (either string 'admin' or integer 1)
        if user_id == 'admin' or user_id == 1:
            g.user = {
                'user_id': 1,
                'username': 'admin',
                'email': 'admin@propintel.com',
                'full_name': 'System Administrator',
                'role': 'admin'
            }
            print("Loaded admin user")
            return
        
        # Fetch user from database for regular users
        try:
            # Convert user_id to integer for regular users
            if isinstance(user_id, str) and user_id.isdigit():
                user_id = int(user_id)
                
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
                        print(f"Loaded user: {user['username']}")
                    else:
                        # Clear invalid session
                        print(f"User not found for ID: {user_id}, clearing session")
                        session.pop('user_id', None)
                        session.pop('is_guest', None)
            except Exception as db_error:
                print(f"Database error in before_request: {db_error}")
                # Don't clear session on database error
            finally:
                conn.close()
        except (ValueError, TypeError) as e:
            print(f"Error converting user_id: {e}")
            # Invalid user_id format, clear the session
            session.pop('user_id', None)
            session.pop('is_guest', None)
        except Exception as conn_error:
            print(f"Connection error in before_request: {conn_error}")
            # Don't clear session on connection error
''')
    
    # Create a sample properties table to fix upload functionality
    try:
        print("\nCreating/checking database tables for upload functionality...")
        conn = psycopg2.connect(**get_db_config())
        conn.autocommit = True
        with conn.cursor() as cur:
            # Create schema
            cur.execute("CREATE SCHEMA IF NOT EXISTS propintel")
            
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
                        username, password_hash, email, full_name, role, created_at
                    ) VALUES (
                        'admin', %s, 'admin@propintel.com', 'System Administrator', 'admin', CURRENT_TIMESTAMP
                    ) ON CONFLICT (username) DO NOTHING
                """, (admin_password_hash,))
            
            # Check if properties table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'propintel' AND table_name = 'properties'
                )
            """)
            if not cur.fetchone()[0]:
                # Create properties table
                print("Creating properties table...")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS propintel.properties (
                        property_id SERIAL PRIMARY KEY,
                        user_id INTEGER,
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
            
            # Check if money_in table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'propintel' AND table_name = 'money_in'
                )
            """)
            if not cur.fetchone()[0]:
                # Create money_in table
                print("Creating money_in table...")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS propintel.money_in (
                        money_in_id SERIAL PRIMARY KEY,
                        property_id INTEGER,
                        user_id INTEGER,
                        income_details TEXT,
                        income_date DATE NOT NULL,
                        income_amount NUMERIC(10, 2) NOT NULL,
                        payment_method VARCHAR(50),
                        income_category VARCHAR(100),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            
            # Check if money_out table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'propintel' AND table_name = 'money_out'
                )
            """)
            if not cur.fetchone()[0]:
                # Create money_out table
                print("Creating money_out table...")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS propintel.money_out (
                        money_out_id SERIAL PRIMARY KEY,
                        property_id INTEGER,
                        user_id INTEGER,
                        expense_details TEXT,
                        expense_date DATE NOT NULL,
                        expense_amount NUMERIC(10, 2) NOT NULL,
                        payment_method VARCHAR(50),
                        expense_category VARCHAR(100),
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
            
            # Check if work table exists
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.tables
                    WHERE table_schema = 'propintel' AND table_name = 'work'
                )
            """)
            if not cur.fetchone()[0]:
                # Create work table
                print("Creating work table...")
                cur.execute("""
                    CREATE TABLE IF NOT EXISTS propintel.work (
                        work_id SERIAL PRIMARY KEY,
                        property_id INTEGER,
                        user_id INTEGER,
                        work_description TEXT NOT NULL,
                        work_date DATE NOT NULL,
                        work_cost NUMERIC(10, 2),
                        payment_method VARCHAR(50),
                        status VARCHAR(50) DEFAULT 'Pending',
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)
        
        conn.close()
        print("Database tables created/checked successfully.")
    except Exception as e:
        print(f"Error checking/creating database tables: {e}")
    
    print("\nUpload fix completed successfully!")
    print("\nTo fix the upload issues:")
    print("1. Copy the functions from login_required_fix.py into app.py")
    print("2. Make sure you have the proper imports at the top of app.py:")
    print("   - from functools import wraps")
    print("   - from flask import send_file")
    print("\nThen restart your application and try accessing the upload page.")
    return True

if __name__ == "__main__":
    fix_upload_issues()