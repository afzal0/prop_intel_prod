from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g, abort, send_file
import os
import psycopg2
from werkzeug.security import check_password_hash
from psycopg2.extras import RealDictCursor, DictCursor
import configparser
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import tempfile
from datetime import datetime, timedelta
import json
import uuid
import hashlib
from functools import wraps
import pytz
import re
from PIL import Image
import io
import secrets
import string
import ipaddress
from flask import make_response
from analytics_dashboard import analytics_dashboard

# Import our data extraction script
import property_data_extractor as extractor
import json as standard_json
import decimal

# Save reference to the original dumps
_original_dumps = standard_json.dumps

class DecimalJSONEncoder(standard_json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, decimal.Decimal):
            return float(obj)
        return super().default(obj)

def decimal_safe_dumps(obj, *args, **kwargs):
    # Force use of DecimalJSONEncoder unless already set
    kwargs['cls'] = kwargs.get('cls', DecimalJSONEncoder)
    return _original_dumps(obj, *args, **kwargs)

# Now patch it
standard_json.dumps = decimal_safe_dumps

# Set the custom JSON encoder for the app
app = Flask(__name__)
app.json_encoder = DecimalJSONEncoder
app.secret_key = os.environ.get('SECRET_KEY', 'propintel_secret_key')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROPERTY_IMAGES'] = 'static/images/properties'
app.config['WORK_IMAGES'] = 'static/images/work'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
app.config['ALLOWED_DOCUMENT_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt'}
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') != 'development'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_KEY_PREFIX'] = 'propintel_session_'  # Prefix for session keys
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flask_session")
app.config["PERMANENT_SESSION_LIFETIME"] = timedelta(days=31)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/images')
DOCUMENTS_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/documents')
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size

# Add this to top of app.py
from flask_session import Session 
Session(app)
# Create necessary folders
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROPERTY_IMAGES'], exist_ok=True)
os.makedirs(app.config['WORK_IMAGES'], exist_ok=True)
os.makedirs('static', exist_ok=True)

# Default center of Melbourne
MELBOURNE_CENTER = [-37.8136, 144.9631]

# Check if a file has an allowed extension
def allowed_file(filename, allowed_extensions=None):
    if allowed_extensions is None:
        allowed_extensions = app.config['ALLOWED_EXTENSIONS']
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in allowed_extensions


secret_key_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'secret_key.txt')
if os.path.exists(secret_key_path):
    with open(secret_key_path, 'r') as f:
        app.secret_key = f.read().strip()
else:
    app.secret_key = str(uuid.uuid4())
    with open(secret_key_path, 'w') as f:
        f.write(app.secret_key)

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Debug session
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

# Generate a secure random filename
def secure_random_filename(filename):
    # Get the file extension
    ext = filename.rsplit('.', 1)[1].lower() if '.' in filename else ''
    # Generate a random string
    random_str = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(16))
    # Generate a timestamp
    timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    # Return the new filename
    return f"{timestamp}_{random_str}.{ext}"

# Resize and optimize images
def optimize_image(image_data, max_size=(1200, 1200), quality=85):
    try:
        img = Image.open(io.BytesIO(image_data))
        img.thumbnail(max_size, Image.LANCZOS)
        output = io.BytesIO()
        
        # Preserve EXIF data for JPEGs
        if img.format == 'JPEG':
            img.save(output, format='JPEG', quality=quality, optimize=True)
        elif img.format == 'PNG':
            img.save(output, format='PNG', optimize=True)
        elif img.format == 'GIF':
            img.save(output, format='GIF')
        else:
            img.save(output, format='JPEG', quality=quality, optimize=True)
            
        output.seek(0)
        return output.getvalue()
    except Exception as e:
        print(f"Error optimizing image: {e}")
        return image_data




@app.before_request
def before_request():
    """Load user before each request and set common app variables"""
    # Initialize g.user
    g.user = None
    
    # Check if the logo file exists to avoid 404 requests
    import os
    logo_path = os.path.join(app.static_folder, 'logo.png')
    g.has_logo = os.path.exists(logo_path)
    
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
                        # Verify password using Werkzeug's password hash checker first, then fallback methods
                        try:
                            # First try with Werkzeug's check_password_hash
                            password_match = check_password_hash(admin_user['password_hash'], password)
                            
                            # If that fails and it looks like a legacy format, try alternative methods
                            if not password_match:
                                import bcrypt
                                # Check if it's a bcrypt hash
                                if admin_user['password_hash'].startswith('$2'):
                                    try:
                                        # This is already a bcrypt hash
                                        password_match = bcrypt.checkpw(
                                            password.encode('utf-8'), 
                                            admin_user['password_hash'].encode('utf-8')
                                        )
                                    except Exception:
                                        # If bcrypt check fails, continue with other methods
                                        pass
                                
                                # Last resort - try direct comparison for plain text passwords (legacy)
                                if not password_match and not admin_user['password_hash'].startswith('pbkdf2:') and not admin_user['password_hash'].startswith('$2'):
                                    password_match = (password == admin_user['password_hash'])
                                
                                # If match with any legacy format, upgrade to Werkzeug hash format
                                if password_match:
                                    new_hash = generate_password_hash(password)
                                    cur.execute("""
                                        UPDATE propintel.users
                                        SET password_hash = %s
                                        WHERE user_id = %s
                                    """, (new_hash, admin_user['user_id']))
                                    conn.commit()
                            
                            if password_match:
                                # Clear existing session
                                session.clear()
                                # Store user_id as string
                                session['user_id'] = str(admin_user['user_id'])
                                session.permanent = remember
                                flash('Welcome back, System Administrator!', 'success')
                                return redirect(url_for('index'))
                        except Exception as e:
                            # Log error but show a generic message
                            print(f"Admin password verification error: {str(e)}")
                            # Continue to fallback authentication
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
                    # Verify password using Werkzeug's password hash checker first, then fallback methods
                    try:
                        # First try with Werkzeug's check_password_hash
                        password_match = check_password_hash(user['password_hash'], password)
                        
                        # If that fails and it looks like a legacy format, try alternative methods
                        if not password_match:
                            import bcrypt
                            # Check if it's a bcrypt hash
                            if user['password_hash'].startswith('$2'):
                                try:
                                    # This is already a bcrypt hash
                                    password_match = bcrypt.checkpw(
                                        password.encode('utf-8'), 
                                        user['password_hash'].encode('utf-8')
                                    )
                                except Exception:
                                    # If bcrypt check fails, continue with other methods
                                    pass
                            
                            # Last resort - try direct comparison for plain text passwords (legacy)
                            if not password_match and not user['password_hash'].startswith('pbkdf2:') and not user['password_hash'].startswith('$2'):
                                password_match = (password == user['password_hash'])
                            
                            # If match with any legacy format, upgrade to Werkzeug hash format
                            if password_match:
                                new_hash = generate_password_hash(password)
                                cur.execute("""
                                    UPDATE propintel.users
                                    SET password_hash = %s
                                    WHERE user_id = %s
                                """, (new_hash, user['user_id']))
                                conn.commit()
                        
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
                        # Log the actual error but show a generic message to the user
                        print(f"Password verification error: {str(e)}")
                        flash("Login error: Please try again", 'danger')
        except Exception as e:
            flash(f"Login error: {str(e)}", 'danger')
        finally:
            if conn:
                conn.close()
        
        # Login failed
        flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

# Login required decorator

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            # Store the original URL in session to return after login
            next_url = request.url
            session['next_url'] = next_url
            
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

# Admin required decorator
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

# Admin required decorator
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None or g.user['role'] != 'admin':
            flash('Administrator access required', 'danger')
            # Store the URL for redirect after login if not logged in
            if g.user is None:
                session['next_url'] = request.url
                return redirect(url_for('login'))
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Function to log user actions
def log_action(action_type, table_name=None, record_id=None, details=None):
    if g.user:
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                # Get client IP address
                ip = request.remote_addr
                
                cur.execute("""
                    INSERT INTO propintel.audit_log 
                    (user_id, action_type, table_name, record_id, details, ip_address)
                    VALUES (%s, %s, %s, %s, %s, %s)
                """, (g.user['user_id'], action_type, table_name, record_id, details, ip))
                conn.commit()
        except Exception as e:
            print(f"Error logging action: {e}")
        finally:
            conn.close()

# Database connection
def get_db_connection():
    """Get a connection to the PostgreSQL database"""
    # Check for DATABASE_URL environment variable (for Heroku)
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Use environment variable if available
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        
        conn = psycopg2.connect(database_url)
        return conn
    else:
        # Fall back to the extractor's db config
        params = extractor.get_db_config()
        conn = psycopg2.connect(**params)
        return conn



@app.route('/')
def index():
    """Home page with property search"""
    # Use the same code as the property_search route
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property count for statistics
            cur.execute("SELECT COUNT(*) FROM propintel.properties")
            property_count = cur.fetchone()['count']
            
            # Get income/expense totals for statistics
            cur.execute("""
                SELECT SUM(income_amount) as total_income
                FROM propintel.money_in
            """)
            income_result = cur.fetchone()
            total_income = income_result['total_income'] if income_result and income_result['total_income'] else 0
            
            cur.execute("""
                SELECT SUM(expense_amount) as total_expense
                FROM propintel.money_out
            """)
            expense_result = cur.fetchone()
            total_expense = expense_result['total_expense'] if expense_result and expense_result['total_expense'] else 0
            
            # Get all property locations for the map with counts (including those without coordinates)
            cur.execute("""
                SELECT p.property_id, p.property_name, p.address, 
                       COALESCE(p.latitude, -37.8136) as latitude, 
                       COALESCE(p.longitude, 144.9631) as longitude,
                       COUNT(DISTINCT w.work_id) AS work_count,
                       COUNT(DISTINCT mi.money_in_id) AS income_count,
                       COUNT(DISTINCT mo.money_out_id) AS expense_count
                FROM propintel.properties p
                LEFT JOIN propintel.work w ON p.property_id = w.property_id
                LEFT JOIN propintel.money_in mi ON p.property_id = mi.property_id
                LEFT JOIN propintel.money_out mo ON p.property_id = mo.property_id
                WHERE (p.is_hidden IS NULL OR p.is_hidden = false)
                GROUP BY p.property_id
            """)
            properties = cur.fetchall()
            
            # Convert to GeoJSON format
            features = []
            for prop in properties:
                features.append({
                    'type': 'Feature',
                    'geometry': {
                        'type': 'Point',
                        'coordinates': [prop['longitude'], prop['latitude']]
                    },
                    'properties': {
                        'id': prop['property_id'],
                        'name': prop['property_name'],
                        'address': prop['address'],
                        'url': url_for('property_detail', property_id=prop['property_id']),
                        'work_count': prop['work_count'],
                        'income_count': prop['income_count'],
                        'expense_count': prop['expense_count']
                    }
                })
            
            geojson = {
                'type': 'FeatureCollection',
                'features': features
            }
            
    except Exception as e:
        flash(f"Error loading dashboard: {e}", "danger")
        property_count = 0
        total_income = 0
        total_expense = 0
        geojson = {"type": "FeatureCollection", "features": []}
    finally:
        conn.close()
    
    # Calculate ROI if we have income and expense data
    roi = 0
    if total_income > 0 and total_expense > 0:
        roi = ((total_income - total_expense) / total_expense) * 100
    
    return render_template('property_search.html', 
                          property_count=property_count,
                          total_income=total_income,
                          total_expense=total_expense,
                          roi=roi,
                          geojson=json.dumps(geojson),
                          center_lat=MELBOURNE_CENTER[0],
                          center_lng=MELBOURNE_CENTER[1])

@app.route('/property_map')
def property_map():
    """Advanced property search view with map"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property count for statistics
            cur.execute("SELECT COUNT(*) FROM propintel.properties")
            property_count = cur.fetchone()['count']
            
            # Get income/expense totals for statistics
            cur.execute("""
                SELECT SUM(income_amount) as total_income
                FROM propintel.money_in
            """)
            income_result = cur.fetchone()
            total_income = income_result['total_income'] if income_result and income_result['total_income'] else 0
            
            cur.execute("""
                SELECT SUM(expense_amount) as total_expense
                FROM propintel.money_out
            """)
            expense_result = cur.fetchone()
            total_expense = expense_result['total_expense'] if expense_result and expense_result['total_expense'] else 0
            
            # Get all property locations for the map with counts (including those without coordinates)
            cur.execute("""
                SELECT p.property_id, p.property_name, p.address, 
                       COALESCE(p.latitude, -37.8136) as latitude, 
                       COALESCE(p.longitude, 144.9631) as longitude,
                       COUNT(DISTINCT w.work_id) AS work_count,
                       COUNT(DISTINCT mi.money_in_id) AS income_count,
                       COUNT(DISTINCT mo.money_out_id) AS expense_count
                FROM propintel.properties p
                LEFT JOIN propintel.work w ON p.property_id = w.property_id
                LEFT JOIN propintel.money_in mi ON p.property_id = mi.property_id
                LEFT JOIN propintel.money_out mo ON p.property_id = mo.property_id
                WHERE (p.is_hidden IS NULL OR p.is_hidden = false)
                GROUP BY p.property_id
            """)
            properties = cur.fetchall()
            
            # Convert to GeoJSON format
            features = []
            for prop in properties:
                features.append({
                    'type': 'Feature',
                    'geometry': {
                        'type': 'Point',
                        'coordinates': [prop['longitude'], prop['latitude']]
                    },
                    'properties': {
                        'id': prop['property_id'],
                        'name': prop['property_name'],
                        'address': prop['address'],
                        'url': url_for('property_detail', property_id=prop['property_id']),
                        'work_count': prop['work_count'],
                        'income_count': prop['income_count'],
                        'expense_count': prop['expense_count']
                    }
                })
            
            geojson = {
                'type': 'FeatureCollection',
                'features': features
            }
    except Exception as e:
        flash(f"Error loading property map: {e}", "danger")
        property_count = 0
        total_income = 0
        total_expense = 0
        geojson = {"type": "FeatureCollection", "features": []}
    finally:
        conn.close()
    
    # Calculate ROI if we have income and expense data
    roi = 0
    if total_income > 0 and total_expense > 0:
        roi = ((total_income - total_expense) / total_expense) * 100
    
    return render_template('property_search.html', 
                          property_count=property_count,
                          total_income=total_income,
                          total_expense=total_expense,
                          roi=roi,
                          geojson=json.dumps(geojson),
                          center_lat=MELBOURNE_CENTER[0],
                          center_lng=MELBOURNE_CENTER[1])

@app.route('/property/<int:property_id>/enhanced')
def property_detail_enhanced(property_id):
    """Enhanced view for property details with visualizations"""
    # Reuse the same data fetching logic from the original property_detail view
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property details
            cur.execute("""
                SELECT * FROM propintel.properties WHERE property_id = %s
            """, (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                flash('Property not found', 'danger')
                return redirect(url_for('properties'))
            
            # Get work records
            cur.execute("""
                SELECT * FROM propintel.work 
                WHERE property_id = %s
                ORDER BY work_date DESC
            """, (property_id,))
            work_records = cur.fetchall()
            
            # Get income records
            cur.execute("""
                SELECT * FROM propintel.money_in 
                WHERE property_id = %s
                ORDER BY income_date DESC
            """, (property_id,))
            income_records = cur.fetchall()
            
            # Get expense records
            cur.execute("""
                SELECT * FROM propintel.money_out 
                WHERE property_id = %s
                ORDER BY expense_date DESC
            """, (property_id,))
            expense_records = cur.fetchall()
            
            # Get monthly trend data for charts
            cur.execute("""
                SELECT 
                    TO_CHAR(income_date, 'YYYY-MM') as month,
                    SUM(income_amount) as total
                FROM propintel.money_in
                WHERE property_id = %s
                GROUP BY TO_CHAR(income_date, 'YYYY-MM')
                ORDER BY month
            """, (property_id,))
            income_trends = cur.fetchall()
            
            cur.execute("""
                SELECT 
                    TO_CHAR(expense_date, 'YYYY-MM') as month,
                    SUM(expense_amount) as total
                FROM propintel.money_out
                WHERE property_id = %s
                GROUP BY TO_CHAR(expense_date, 'YYYY-MM')
                ORDER BY month
            """, (property_id,))
            expense_trends = cur.fetchall()
            
            # Calculate totals
            work_total = sum(float(record['work_cost'] or 0) for record in work_records)
            income_total = sum(float(record['income_amount'] or 0) for record in income_records)
            expense_total = sum(float(record['expense_amount'] or 0) for record in expense_records)
            net_total = income_total - expense_total - work_total
    except Exception as e:
        flash(f"Error loading property details: {e}", "danger")
        return redirect(url_for('properties'))
    finally:
        conn.close()
    
    # Use property coords if available, otherwise default to Melbourne
    map_lat = property_data['latitude'] if property_data['latitude'] else MELBOURNE_CENTER[0]
    map_lng = property_data['longitude'] if property_data['longitude'] else MELBOURNE_CENTER[1]
    
    # Prepare trend data for charts
    trend_labels = []
    income_data = []
    expense_data = []
    
    # Combine all months from both income and expense records
    all_months = set()
    for record in income_trends:
        all_months.add(record['month'])
    for record in expense_trends:
        all_months.add(record['month'])
    
    # Sort months chronologically
    all_months = sorted(list(all_months))
    
    # Create datasets with 0 for missing months
    income_by_month = {record['month']: float(record['total']) for record in income_trends}
    expense_by_month = {record['month']: float(record['total']) for record in expense_trends}
    
    for month in all_months:
        trend_labels.append(month)
        income_data.append(income_by_month.get(month, 0))
        expense_data.append(expense_by_month.get(month, 0))
    
    # Prepare work timeline data
    timeline_data = []
    for record in work_records:
        if record['work_date']:
            timeline_data.append({
                'id': record['work_id'],
                'description': record['work_description'],
                'date': record['work_date'].strftime('%Y-%m-%d'),
                'cost': float(record['work_cost'] or 0)
            })
    
    return render_template('property_detail_enhanced.html', 
                          property=property_data,
                          work_records=work_records,
                          income_records=income_records,
                          expense_records=expense_records,
                          work_total=work_total,
                          income_total=income_total,
                          expense_total=expense_total,
                          net_total=net_total,
                          map_lat=map_lat,
                          map_lng=map_lng,
                          trend_labels=json.dumps(trend_labels),
                          income_data=json.dumps(income_data),
                          expense_data=json.dumps(expense_data),
                          timeline_data=json.dumps(timeline_data))

@app.route('/property/toggle_visibility/<int:property_id>', methods=['POST'])
@login_required
def toggle_property_visibility(property_id):
    """API endpoint to toggle a property's visibility (admin only)"""
    # Check if user is admin
    if not g.user or g.user.get('role') != 'admin':
        return jsonify({"error": "Unauthorized"}), 403
        
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Check if property exists
            cur.execute("SELECT property_id, is_hidden FROM propintel.properties WHERE property_id = %s", (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                return jsonify({"error": "Property not found"}), 404
                
            # Toggle is_hidden status (add the column if it doesn't exist)
            try:
                cur.execute("SELECT column_name FROM information_schema.columns WHERE table_schema = 'propintel' AND table_name = 'properties' AND column_name = 'is_hidden'")
                if not cur.fetchone():
                    cur.execute("ALTER TABLE propintel.properties ADD COLUMN is_hidden BOOLEAN DEFAULT false")
                    conn.commit()
            except Exception as e:
                conn.rollback()
                return jsonify({"error": f"Failed to check/create is_hidden column: {str(e)}"}), 500
                
            # Toggle the value
            current_status = property_data[1] if len(property_data) > 1 and property_data[1] is not None else False
            new_status = not current_status
            
            cur.execute("UPDATE propintel.properties SET is_hidden = %s WHERE property_id = %s", (new_status, property_id))
            conn.commit()
            
            return jsonify({
                "success": True,
                "property_id": property_id,
                "is_hidden": new_status
            })
            
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()


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



# DUPLICATE ROUTE: # REMOVED DUPLICATE LOGIN FUNCTION

#     """User login page with direct cookie handling"""
#     # If already logged in, redirect to index
#     if g.user:
#         return redirect(url_for('index'))
        
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

@app.route('/logout')
def logout():
    '''Log out the current user'''
    print(f"logout: session before = {session}")
    
    # Clear the session data
    session.clear()
    
    print(f"logout: session after = {session}")
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    """User registration page"""
    # Redirect if already logged in
    if g.user:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name', '').strip()
        
        # Validate inputs
        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters long')
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append('Username can only contain letters, numbers, and underscores')
        if not email or not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            errors.append('Please enter a valid email address')
        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters long')
        if password != confirm_password:
            errors.append('Passwords do not match')
        if not full_name or len(full_name) < 2:
            errors.append('Please enter your full name')
            
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('register.html', 
                                 username=username, 
                                 email=email, 
                                 full_name=full_name)
        
        # Hash password
        password_hash = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                # Check if username or email already exists
                cur.execute("""
                    SELECT username, email FROM propintel.users 
                    WHERE username = %s OR email = %s
                """, (username, email))
                existing_user = cur.fetchone()
                
                if existing_user:
                    if existing_user[0] == username:
                        flash('Username already taken', 'danger')
                    else:
                        flash('Email already registered', 'danger')
                    return render_template('register.html', 
                                         username=username, 
                                         email=email, 
                                         full_name=full_name)
                
                # Insert new user
                cur.execute("""
                    INSERT INTO propintel.users 
                    (username, email, password_hash, full_name, role, created_at)
                    VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    RETURNING user_id
                """, (username, email, password_hash, full_name, 'user'))
                
                user_id = cur.fetchone()[0]
                
                # Create user settings
                cur.execute("""
                    INSERT INTO propintel.user_settings
                    (user_id, created_at)
                    VALUES (%s, CURRENT_TIMESTAMP)
                """, (user_id,))
                
                conn.commit()
                
                flash('Registration successful! You can now log in.', 'success')
                return redirect(url_for('login'))
        except Exception as e:
            conn.rollback()
            flash(f"Error during registration: {str(e)}", 'danger')
        finally:
            conn.close()
    
    return render_template('register.html')

@app.route('/user/profile', methods=['GET', 'POST'])
@login_required
def user_profile():
    """User profile page"""
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        full_name = request.form.get('full_name', '').strip()
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Validate inputs
        errors = []
        if not email or not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            errors.append('Please enter a valid email address')
        if not full_name or len(full_name) < 2:
            errors.append('Please enter your full name')
            
        # Password change validation (optional)
        if current_password:
            if not new_password or len(new_password) < 8:
                errors.append('New password must be at least 8 characters long')
            if new_password != confirm_password:
                errors.append('New passwords do not match')
                
        if errors:
            for error in errors:
                flash(error, 'danger')
            return redirect(url_for('user_profile'))
        
        conn = get_db_connection()
        try:
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Check if email is already taken by another user
                cur.execute("""
                    SELECT user_id FROM propintel.users 
                    WHERE email = %s AND user_id != %s
                """, (email, g.user['user_id']))
                if cur.fetchone():
                    flash('Email already registered to another user', 'danger')
                    return redirect(url_for('user_profile'))
                
                # If user wants to change password
                if current_password:
                    # Verify current password
                    cur.execute("""
                        SELECT password_hash FROM propintel.users 
                        WHERE user_id = %s
                    """, (g.user['user_id'],))
                    user_data = cur.fetchone()
                    
                    if not check_password_hash(user_data['password_hash'], current_password):
                        flash('Current password is incorrect', 'danger')
                        return redirect(url_for('user_profile'))
                    
                    # Update profile with new password
                    cur.execute("""
                        UPDATE propintel.users 
                        SET email = %s, full_name = %s, password_hash = %s 
                        WHERE user_id = %s
                    """, (email, full_name, generate_password_hash(new_password), g.user['user_id']))
                    
                    flash('Profile and password updated successfully', 'success')
                else:
                    # Update profile without changing password
                    cur.execute("""
                        UPDATE propintel.users 
                        SET email = %s, full_name = %s 
                        WHERE user_id = %s
                    """, (email, full_name, g.user['user_id']))
                    
                    flash('Profile updated successfully', 'success')
                
                conn.commit()
                log_action('update', 'users', g.user['user_id'], 'Profile updated')
                
        except Exception as e:
            conn.rollback()
            flash(f"Error updating profile: {str(e)}", 'danger')
        finally:
            conn.close()
            
        return redirect(url_for('user_profile'))
    
    # GET request - show profile
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get user data
            cur.execute("""
                SELECT username, email, full_name, role, created_at, last_login
                FROM propintel.users 
                WHERE user_id = %s
            """, (g.user['user_id'],))
            user_data = cur.fetchone()
            
            # Get user settings
            cur.execute("""
                SELECT * FROM propintel.user_settings
                WHERE user_id = %s
            """, (g.user['user_id'],))
            user_settings = cur.fetchone()
            
            if not user_settings:
                # Create default settings if not exist
                cur.execute("""
                    INSERT INTO propintel.user_settings (user_id)
                    VALUES (%s)
                    RETURNING *
                """, (g.user['user_id'],))
                user_settings = cur.fetchone()
                conn.commit()
            
            # Get user stats
            cur.execute("""
                SELECT COUNT(*) as property_count
                FROM propintel.properties
                WHERE user_id = %s
            """, (g.user['user_id'],))
            property_count = cur.fetchone()['property_count']
            
            cur.execute("""
                SELECT COUNT(*) as work_count
                FROM propintel.work
                WHERE user_id = %s
            """, (g.user['user_id'],))
            work_count = cur.fetchone()['work_count']
            
            # Get recent activities from audit log
            cur.execute("""
                SELECT action_type, table_name, details, created_at
                FROM propintel.audit_log
                WHERE user_id = %s
                ORDER BY created_at DESC
                LIMIT 10
            """, (g.user['user_id'],))
            recent_activities = cur.fetchall()
            
    except Exception as e:
        flash(f"Error loading profile: {str(e)}", 'danger')
        user_data = {}
        user_settings = {}
        property_count = 0
        work_count = 0
        recent_activities = []
    finally:
        conn.close()
    
    return render_template('user/profile.html', 
                          user=user_data,
                          settings=user_settings,
                          property_count=property_count,
                          work_count=work_count,
                          recent_activities=recent_activities)

@app.route('/user/settings', methods=['POST'])
@login_required
def update_user_settings():
    """Update user settings"""
    map_theme = request.form.get('map_theme', 'light')
    default_view = request.form.get('default_view', 'card')
    notifications_enabled = 'notifications_enabled' in request.form
    
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("""
                UPDATE propintel.user_settings
                SET map_theme = %s, default_view = %s, notifications_enabled = %s
                WHERE user_id = %s
            """, (map_theme, default_view, notifications_enabled, g.user['user_id']))
            conn.commit()
            
            flash('Settings updated successfully', 'success')
            log_action('update', 'user_settings', g.user['user_id'], 'Settings updated')
    except Exception as e:
        conn.rollback()
        flash(f"Error updating settings: {str(e)}", 'danger')
    finally:
        conn.close()
        
    return redirect(url_for('user_profile'))

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin user management page"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT user_id, username, email, full_name, role, created_at, last_login, is_active
                FROM propintel.users
                ORDER BY username
            """)
            users = cur.fetchall()
    except Exception as e:
        flash(f"Error loading users: {str(e)}", 'danger')
        users = []
    finally:
        conn.close()
        
    return render_template('admin/users.html', users=users)

@app.route('/admin/user/create', methods=['GET', 'POST'])
@admin_required
def admin_create_user():
    """Admin create new user"""
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        full_name = request.form.get('full_name', '').strip()
        role = request.form.get('role', 'user')
        
        # Validate inputs
        errors = []
        if not username or len(username) < 3:
            errors.append('Username must be at least 3 characters long')
        if not re.match(r'^[a-zA-Z0-9_]+$', username):
            errors.append('Username can only contain letters, numbers, and underscores')
        if not email or not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            errors.append('Please enter a valid email address')
        if not password or len(password) < 8:
            errors.append('Password must be at least 8 characters long')
        if password != confirm_password:
            errors.append('Passwords do not match')
        if not full_name or len(full_name) < 2:
            errors.append('Please enter the full name')
        if role not in ['admin', 'user', 'manager']:
            errors.append('Invalid role selected')
            
        if errors:
            for error in errors:
                flash(error, 'danger')
            return render_template('admin/create_user.html', 
                                 username=username, 
                                 email=email, 
                                 full_name=full_name,
                                 role=role)
        
        # Hash password
        password_hash = generate_password_hash(password)
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                # Check if username or email already exists
                cur.execute("""
                    SELECT username, email FROM propintel.users 
                    WHERE username = %s OR email = %s
                """, (username, email))
                existing_user = cur.fetchone()
                
                if existing_user:
                    if existing_user[0] == username:
                        flash('Username already taken', 'danger')
                    else:
                        flash('Email already registered', 'danger')
                    return render_template('admin/create_user.html', 
                                         username=username, 
                                         email=email, 
                                         full_name=full_name,
                                         role=role)
                
                # Insert new user
                cur.execute("""
                    INSERT INTO propintel.users 
                    (username, email, password_hash, full_name, role, created_at)
                    VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                    RETURNING user_id
                """, (username, email, password_hash, full_name, role))
                
                user_id = cur.fetchone()[0]
                
                # Create user settings
                cur.execute("""
                    INSERT INTO propintel.user_settings
                    (user_id, created_at)
                    VALUES (%s, CURRENT_TIMESTAMP)
                """, (user_id,))
                
                conn.commit()
                log_action('create', 'users', user_id, f'Created user: {username}')
                
                flash(f'User {username} created successfully', 'success')
                return redirect(url_for('admin_users'))
        except Exception as e:
            conn.rollback()
            flash(f"Error creating user: {str(e)}", 'danger')
        finally:
            conn.close()
    
    return render_template('admin/create_user.html')

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@admin_required
def admin_edit_user(user_id):
    """Admin edit user"""
    # Don't allow editing yourself through this route
    if g.user['user_id'] == user_id:
        flash('Please use the profile page to edit your own account', 'warning')
        return redirect(url_for('user_profile'))
        
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get user data
            cur.execute("""
                SELECT user_id, username, email, full_name, role, is_active
                FROM propintel.users 
                WHERE user_id = %s
            """, (user_id,))
            user_data = cur.fetchone()
            
            if not user_data:
                flash('User not found', 'danger')
                return redirect(url_for('admin_users'))
                
            if request.method == 'POST':
                email = request.form.get('email', '').strip()
                full_name = request.form.get('full_name', '').strip()
                role = request.form.get('role', 'user')
                is_active = 'is_active' in request.form
                new_password = request.form.get('new_password')
                
                # Validate inputs
                errors = []
                if not email or not re.match(r'[^@]+@[^@]+\.[^@]+', email):
                    errors.append('Please enter a valid email address')
                if not full_name or len(full_name) < 2:
                    errors.append('Please enter the full name')
                if role not in ['admin', 'user', 'manager']:
                    errors.append('Invalid role selected')
                    
                if new_password and len(new_password) < 8:
                    errors.append('New password must be at least 8 characters long')
                    
                if errors:
                    for error in errors:
                        flash(error, 'danger')
                    return render_template('admin/edit_user.html', user=user_data)
                
                # Check if email is already taken by another user
                cur.execute("""
                    SELECT user_id FROM propintel.users 
                    WHERE email = %s AND user_id != %s
                """, (email, user_id))
                if cur.fetchone():
                    flash('Email already registered to another user', 'danger')
                    return render_template('admin/edit_user.html', user=user_data)
                
                # Prepare update based on whether password is being changed
                if new_password:
                    cur.execute("""
                        UPDATE propintel.users 
                        SET email = %s, full_name = %s, role = %s, is_active = %s, password_hash = %s 
                        WHERE user_id = %s
                    """, (email, full_name, role, is_active, generate_password_hash(new_password), user_id))
                    
                    update_msg = 'User profile and password updated'
                else:
                    cur.execute("""
                        UPDATE propintel.users 
                        SET email = %s, full_name = %s, role = %s, is_active = %s 
                        WHERE user_id = %s
                    """, (email, full_name, role, is_active, user_id))
                    
                    update_msg = 'User profile updated'
                
                conn.commit()
                log_action('update', 'users', user_id, update_msg)
                
                flash(f'User {user_data["username"]} updated successfully', 'success')
                return redirect(url_for('admin_users'))
    except Exception as e:
        conn.rollback()
        flash(f"Error updating user: {str(e)}", 'danger')
        return redirect(url_for('admin_users'))
    finally:
        conn.close()
    
    return render_template('admin/edit_user.html', user=user_data)

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    """Toggle user active status"""
    # Don't allow deactivating yourself
    if g.user['user_id'] == user_id:
        return jsonify({"error": "You cannot deactivate your own account"}), 403
        
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get current status
            cur.execute("""
                SELECT username, is_active
                FROM propintel.users 
                WHERE user_id = %s
            """, (user_id,))
            user_data = cur.fetchone()
            
            if not user_data:
                return jsonify({"error": "User not found"}), 404
                
            # Toggle status
            new_status = not user_data['is_active']
            cur.execute("""
                UPDATE propintel.users 
                SET is_active = %s 
                WHERE user_id = %s
            """, (new_status, user_id))
            
            action = 'activated' if new_status else 'deactivated'
            log_action('update', 'users', user_id, f'User {action}: {user_data["username"]}')
            
            conn.commit()
            return jsonify({
                "success": True,
                "user_id": user_id,
                "is_active": new_status,
                "message": f"User {action} successfully"
            })
    except Exception as e:
        conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """Page for uploading Excel files to process"""
    if g.user['user_id'] == 'guest':
        flash('Guest users cannot upload files', 'warning')
        return redirect(url_for('index'))
        
    if request.method == 'POST':
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
                extractor.extract_data_from_excel(file_path)
                flash(f'Successfully processed {filename}', 'success')
            except Exception as e:
                flash(f'Error processing file: {e}', 'danger')
            
            return redirect(url_for('index'))
    
    return render_template('upload.html')

@app.route('/properties')
def properties():
    """List all properties"""
    # Get search and filter parameters
    search = request.args.get('search', '')
    status_filter = request.args.get('status', '')
    project_type = request.args.get('project_type', '')
    project_manager = request.args.get('project_manager', '')
    sort_by = request.args.get('sort', 'property_id')
    sort_dir = request.args.get('dir', 'asc')
    export_excel = request.args.get('export', '')
    
    # Validate sort parameters to prevent SQL injection
    valid_sort_fields = ['property_id', 'property_name', 'project_name', 'status', 'due_date', 
                         'project_manager', 'total_income', 'total_expenses', 'profit']
    if sort_by not in valid_sort_fields:
        sort_by = 'property_id'
        
    if sort_dir not in ['asc', 'desc']:
        sort_dir = 'asc'
    
    # Build query filters
    filters = []
    params = []
    
    # For non-admin users, only show their own properties
    if g.user and g.user['role'] != 'admin' and g.user['user_id'] != 'guest':
        filters.append("p.user_id = %s")
        params.append(g.user['user_id'])
    
    # Add search filter
    if search:
        filters.append("(p.property_name ILIKE %s OR p.address ILIKE %s OR p.project_name ILIKE %s)")
        params.extend([f'%{search}%', f'%{search}%', f'%{search}%'])
    
    # Add status filter
    if status_filter:
        filters.append("p.status = %s")
        params.append(status_filter)
        
    # Add project type filter
    if project_type:
        filters.append("p.project_type = %s")
        params.append(project_type)
        
    # Add project manager filter
    if project_manager:
        filters.append("p.project_manager ILIKE %s")
        params.append(f'%{project_manager}%')
    
    # Include the is_hidden filter for all users except admins
    if not g.user or g.user['role'] != 'admin':
        filters.append("(p.is_hidden IS NULL OR p.is_hidden = false)")
    
    # Construct the WHERE clause
    where_clause = " AND ".join(filters) if filters else "1=1"
    
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get distinct project types and project managers for filters
            cur.execute("SELECT DISTINCT project_type FROM propintel.properties WHERE project_type IS NOT NULL ORDER BY project_type")
            project_types = [row['project_type'] for row in cur.fetchall()]
            
            cur.execute("SELECT DISTINCT project_manager FROM propintel.properties WHERE project_manager IS NOT NULL ORDER BY project_manager")
            project_managers = [row['project_manager'] for row in cur.fetchall()]
            
            # Get distinct statuses
            cur.execute("SELECT DISTINCT status FROM propintel.properties WHERE status IS NOT NULL ORDER BY status")
            statuses = [row['status'] for row in cur.fetchall()]
            
            # Main query with filters and sorting
            query = f"""
                SELECT p.*, 
                       u.username as owner_username,
                       COUNT(DISTINCT w.work_id) AS work_count,
                       COUNT(DISTINCT mi.money_in_id) AS income_count,
                       COUNT(DISTINCT mo.money_out_id) AS expense_count,
                       COALESCE(p.total_income, 0) as total_income,
                       COALESCE(p.total_expenses, 0) as total_expenses,
                       COALESCE(p.profit, 0) as profit
                FROM propintel.properties p
                LEFT JOIN propintel.users u ON p.user_id = u.user_id
                LEFT JOIN propintel.work w ON p.property_id = w.property_id
                LEFT JOIN propintel.money_in mi ON p.property_id = mi.property_id
                LEFT JOIN propintel.money_out mo ON p.property_id = mo.property_id
                WHERE {where_clause}
                GROUP BY p.property_id, u.username
                ORDER BY {sort_by} {sort_dir}
            """
            
            cur.execute(query, params)
            properties = cur.fetchall()
            
            # Get property images
            if properties:
                property_ids = [p['property_id'] for p in properties]
                placeholders = ','.join(['%s'] * len(property_ids))
                
                cur.execute(f"""
                    SELECT property_id, image_path 
                    FROM propintel.property_images 
                    WHERE property_id IN ({placeholders})
                    AND image_type = 'property'
                    ORDER BY upload_date DESC
                """, property_ids)
                
                # Organize images by property
                property_images = {}
                for row in cur.fetchall():
                    if row['property_id'] not in property_images:
                        property_images[row['property_id']] = []
                    property_images[row['property_id']].append(row['image_path'])
                
                # Add image to property data
                for prop in properties:
                    prop_id = prop['property_id']
                    if prop_id in property_images:
                        prop['image'] = property_images[prop_id][0]  # Primary image
                        prop['images'] = property_images[prop_id]  # All images
                    else:
                        prop['image'] = None
                        prop['images'] = []
                
    except Exception as e:
        flash(f"Error loading properties: {e}", "danger")
        properties = []
        project_types = []
        project_managers = []
        statuses = []
    finally:
        conn.close()
    
    # Handle Excel export request
    if export_excel:
        import pandas as pd
        from io import BytesIO
        from flask import send_file
        
        # Create a Pandas dataframe from properties
        df_data = [{
            'Property Name': p['property_name'],
            'Address': p['address'],
            'Location': p['location'] or '',
            'Status': p['status'] or '',
            'Project Type': p['project_type'] or '',
            'Project Manager': p['project_manager'] or '',
            'Total Income': float(p['total_income']) if p['total_income'] else 0,
            'Total Expenses': float(p['total_expenses']) if p['total_expenses'] else 0,
            'Profit': float(p['profit']) if p['profit'] else 0,
            'Number of Work Items': p['work_count'],
            'Number of Income Records': p['income_count'],
            'Number of Expense Records': p['expense_count']
        } for p in properties]
        
        df = pd.DataFrame(df_data)
        
        # Create an Excel file in memory
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Properties', index=False)
            
            # Auto-adjust columns width
            worksheet = writer.sheets['Properties']
            for idx, col in enumerate(df.columns):
                max_len = max(df[col].astype(str).map(len).max(), len(col) + 2)
                worksheet.column_dimensions[worksheet.cell(1, idx + 1).column_letter].width = max_len
        
        output.seek(0)
        
        # Set filename based on filters
        filename = 'PropIntel_Properties'
        if search:
            filename += f'_search_{search}'
        if status_filter:
            filename += f'_status_{status_filter}'
        if project_type:
            filename += f'_type_{project_type}'
        filename += '.xlsx'
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            download_name=filename,
            as_attachment=True
        )
    
    return render_template('properties.html', 
                          properties=properties, 
                          search=search,
                          status_filter=status_filter,
                          project_type=project_type,
                          project_manager=project_manager,
                          sort_by=sort_by,
                          sort_dir=sort_dir,
                          project_types=project_types,
                          project_managers=project_managers,
                          statuses=statuses)
@app.route('/analytics')
@login_required
def analytics():
    return analytics_dashboard()

@app.route('/analytics/data')
@login_required
def analytics_data():
    """API endpoint to fetch analytics dashboard data based on filters"""
    from analytics_dashboard import update_dashboard_data
    return update_dashboard_data()

@app.route('/budget-planner')
@login_required
def budget_planner():
    """Budget planning page with real data from the database"""
    # Get filter parameters
    property_id = request.args.get('property_id', 'all')
    year = request.args.get('year', str(datetime.datetime.now().year))
    status = request.args.get('status', 'all')
    conn = None
    properties = []
    budget_data = {
        'expense_data': {},
        'income_data': {},
        'active_budgets': [],
        'upcoming_expenses': [],
        'allocation_data': {
            'wage': 0,
            'project_manager': 0,
            'material': 0,
            'miscellaneous': 0
        },
        'total_expenses': 0,
        'monthly_overview': []
    }
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get properties for dropdown
            cur.execute("""
                SELECT property_id, property_name, address, location
                FROM propintel.properties 
                WHERE is_hidden IS NOT TRUE
                ORDER BY property_name
            """)
            properties = cur.fetchall()
            
            if not properties:
                # If no properties are found, show a message but don't crash
                flash("No properties found. Add properties to use the budget planner.", "warning")
                return render_template('budget_planner.html', properties=[], budget_data=budget_data)
            
            # Build property filter condition for SQL queries
            property_filter = ""
            if property_id and property_id != 'all':
                property_filter = f"AND mo.property_id = '{property_id}'"  # Using table alias for money_out table
                
            # Get year start and end dates for filtering
            year_start = f"{year}-01-01"
            year_end = f"{year}-12-31"
                
            # Get monthly expense data filtered by year and property
            cur.execute(f"""
                SELECT 
                    mo.property_id,
                    date_trunc('month', mo.expense_date) AS month,
                    mo.expense_category,
                    SUM(mo.expense_amount) AS total_amount
                FROM propintel.money_out mo
                WHERE 
                    mo.expense_date >= %s 
                    AND mo.expense_date <= %s
                    {property_filter}
                GROUP BY mo.property_id, date_trunc('month', mo.expense_date), mo.expense_category
                ORDER BY mo.property_id, month
            """, (year_start, year_end))
            monthly_expenses = cur.fetchall()
            
            # Define month labels for consistency
            months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
            
            # Initialize expense data for all properties and months
            expense_data = {}
            for prop in properties:
                prop_id = prop['property_id']
                expense_data[prop_id] = {}
                for month in months:
                    expense_data[prop_id][month] = {
                        'wage': 0,
                        'project_manager': 0,
                        'material': 0,
                        'miscellaneous': 0,
                        'total': 0
                    }
            
            # Populate expense data with actual values
            for expense in monthly_expenses:
                if not expense['property_id'] or not expense['month']:
                    continue  # Skip invalid entries
                    
                prop_id = expense['property_id']
                month = expense['month'].strftime('%b')
                category = expense['expense_category'] or 'miscellaneous'
                amount = float(expense['total_amount']) if expense['total_amount'] else 0
                
                if prop_id not in expense_data:
                    expense_data[prop_id] = {}
                    
                if month not in expense_data[prop_id]:
                    expense_data[prop_id][month] = {
                        'wage': 0,
                        'project_manager': 0,
                        'material': 0,
                        'miscellaneous': 0,
                        'total': 0
                    }
                
                # Standardize category names
                if category.lower() in ['wage', 'wages', 'labor', 'labour', 'salary', 'salaries']:
                    expense_data[prop_id][month]['wage'] += amount
                elif category.lower() in ['project_manager', 'project manager', 'manager', 'management']:
                    expense_data[prop_id][month]['project_manager'] += amount
                elif category.lower() in ['material', 'materials', 'supplies', 'supply', 'equipment']:
                    expense_data[prop_id][month]['material'] += amount
                else:
                    expense_data[prop_id][month]['miscellaneous'] += amount
                    
                # Update total for this property/month
                expense_data[prop_id][month]['total'] += amount
            
            # Get monthly income data filtered by year and property
            cur.execute(f"""
                SELECT 
                    mi.property_id,
                    date_trunc('month', mi.income_date) AS month,
                    SUM(mi.income_amount) AS total_amount
                FROM propintel.money_in mi
                WHERE 
                    mi.income_date >= %s 
                    AND mi.income_date <= %s
                    {property_filter.replace('mo.', 'mi.')}
                GROUP BY mi.property_id, date_trunc('month', mi.income_date)
                ORDER BY mi.property_id, month
            """, (year_start, year_end))
            monthly_income = cur.fetchall()
            
            # Initialize income data for all properties
            income_data = {}
            for prop in properties:
                prop_id = prop['property_id']
                income_data[prop_id] = {}
                for month in months:
                    income_data[prop_id][month] = 0
            
            # Populate income data with actual values
            for income in monthly_income:
                if not income['property_id'] or not income['month']:
                    continue  # Skip invalid entries
                    
                prop_id = income['property_id']
                month = income['month'].strftime('%b')
                amount = float(income['total_amount']) if income['total_amount'] else 0
                
                if prop_id not in income_data:
                    income_data[prop_id] = {}
                    for m in months:
                        income_data[prop_id][m] = 0
                    
                income_data[prop_id][month] = amount
            
            # Build status filter condition
            status_filter = ""
            if status and status != 'all':
                status_filter = f"AND w.status = '{status}'"
            else:
                status_filter = "AND w.status = 'Pending'"
                
            # Get active budgets from work table (filtered by status and property)
            cur.execute(f"""
                SELECT 
                    w.property_id,
                    p.property_name,
                    w.work_id,
                    w.work_description,
                    w.work_date,
                    w.work_cost,
                    w.status
                FROM propintel.work w
                JOIN propintel.properties p ON w.property_id = p.property_id
                WHERE w.work_date >= %s
                    AND w.work_date <= %s
                    {property_filter.replace('mo.', 'w.')}
                    {status_filter}
                ORDER BY w.work_date ASC
                LIMIT 10
            """, (year_start, year_end))
            active_budgets_raw = cur.fetchall()
            
            # Process active budgets
            active_budgets = []
            for budget in active_budgets_raw:
                # Get expenses for this work/property to calculate spent amount
                cur.execute("""
                    SELECT COALESCE(SUM(expense_amount), 0) AS spent_amount
                    FROM propintel.money_out
                    WHERE property_id = %s
                      AND expense_date >= %s - interval '30 days'
                      AND expense_date <= CURRENT_DATE
                """, (budget['property_id'], budget['work_date']))
                
                spent_result = cur.fetchone()
                spent_amount = float(spent_result['spent_amount']) if spent_result and spent_result['spent_amount'] else 0
                budget_amount = float(budget['work_cost']) if budget['work_cost'] else 0
                
                # Calculate percentage
                percentage = 0
                if budget_amount > 0:
                    percentage = min(100, (spent_amount / budget_amount) * 100)
                
                # Add to processed active budgets
                active_budgets.append({
                    'id': budget['work_id'],
                    'property_id': budget['property_id'], 
                    'property_name': budget['property_name'],
                    'description': budget['work_description'],
                    'date': budget['work_date'],
                    'budget_amount': budget_amount,
                    'spent_amount': spent_amount,
                    'percentage': percentage
                })
            
            # Get upcoming planned expenses (with filters)
            cur.execute(f"""
                SELECT 
                    w.property_id,
                    p.property_name,
                    w.work_description,
                    w.work_date,
                    w.work_cost,
                    w.status
                FROM propintel.work w
                JOIN propintel.properties p ON w.property_id = p.property_id
                WHERE 
                    w.work_date > CURRENT_DATE
                    AND w.work_date <= %s
                    {property_filter.replace('mo.', 'w.')}
                    {status_filter}
                ORDER BY w.work_date ASC
                LIMIT 10
            """, (year_end,))
            upcoming_expenses = cur.fetchall()
            
            # Process upcoming expenses for display
            formatted_upcoming = []
            for expense in upcoming_expenses:
                # Format for display
                formatted_upcoming.append({
                    'description': expense['work_description'],
                    'property': expense['property_name'],
                    'date': expense['work_date'],
                    'amount': float(expense['work_cost']) if expense['work_cost'] else 0,
                    'category': 'material'  # Default category, could be improved with actual data
                })
            
            # Get expense categories allocation with filters
            cur.execute(f"""
                SELECT 
                    mo.expense_category,
                    SUM(mo.expense_amount) AS total_amount
                FROM propintel.money_out mo
                WHERE mo.expense_date >= %s
                  AND mo.expense_date <= %s
                  {property_filter}
                GROUP BY mo.expense_category
            """, (year_start, year_end))
            category_totals = cur.fetchall()
            
            # Process category allocation data
            allocation_data = {
                'wage': 0,
                'project_manager': 0,
                'material': 0,
                'miscellaneous': 0
            }
            
            total_expenses = 0
            for item in category_totals:
                if not item['expense_category'] and not item['total_amount']:
                    continue  # Skip empty entries
                    
                category = item['expense_category'] or 'miscellaneous'
                amount = float(item['total_amount']) if item['total_amount'] else 0
                total_expenses += amount
                
                # Standardize category names
                if category.lower() in ['wage', 'wages', 'labor', 'labour', 'salary', 'salaries']:
                    allocation_data['wage'] += amount
                elif category.lower() in ['project_manager', 'project manager', 'manager', 'management']:
                    allocation_data['project_manager'] += amount
                elif category.lower() in ['material', 'materials', 'supplies', 'supply', 'equipment']:
                    allocation_data['material'] += amount
                else:
                    allocation_data['miscellaneous'] += amount
            
            # Calculate monthly overview data (totals across all properties)
            monthly_budget_data = []
            monthly_spent_data = []
            
            for i, month in enumerate(months):
                # Calculate budget amount - for simplicity, we're using income as the budget
                # In a real app, you'd have a separate budget table
                month_budget = 0
                month_spent = 0
                
                for prop_id in income_data:
                    month_budget += income_data[prop_id].get(month, 0)
                
                for prop_id in expense_data:
                    month_spent += expense_data[prop_id].get(month, {}).get('total', 0)
                
                monthly_budget_data.append(month_budget)
                monthly_spent_data.append(month_spent)
            
            # Assemble the budget data to pass to the template
            budget_data = {
                'expense_data': expense_data,
                'income_data': income_data,
                'active_budgets': active_budgets,
                'upcoming_expenses': formatted_upcoming,
                'allocation_data': allocation_data,
                'total_expenses': total_expenses,
                'monthly_budget': monthly_budget_data,
                'monthly_spent': monthly_spent_data,
                'months': months
            }
            
    except Exception as e:
        # Log the error but don't redirect
        print(f"Error loading budget data: {e}")
        # Provide some dummy properties as fallback
        properties = [
            {'property_id': '1', 'property_name': 'Property A'},
            {'property_id': '2', 'property_name': 'Property B'},
            {'property_id': '3', 'property_name': 'Property C'},
            {'property_id': '4', 'property_name': 'Property D'}
        ]
        flash(f"Error loading budget data: {str(e)}", "danger")
    finally:
        if conn:
            conn.close()
    
    return render_template('budget_planner.html', properties=properties, budget_data=budget_data)
@app.route('/property/<int:property_id>')
def property_detail(property_id):
    """Detailed view of a property"""
    export_excel = request.args.get('export', '')
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property details
            cur.execute("""
                SELECT * FROM propintel.properties WHERE property_id = %s
            """, (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                flash('Property not found', 'danger')
                return redirect(url_for('properties'))
            
            # Initialize variables with defaults
            property_images = []
            work_records = []
            work_images = []
            income_records = []
            expense_records = []
            income_total = 0
            expense_total = 0
            work_total = 0
            net_total = 0
            trend_labels = []
            income_data = []
            expense_data = []
            
            # Safe default for expense categories
            expense_categories = {
                'wage_total': 0,
                'pm_total': 0,
                'material_total': 0,
                'misc_total': 0
            }
            
            # Get property images if the table exists
            try:
                cur.execute("""
                    SELECT * FROM propintel.property_images 
                    WHERE property_id = %s AND image_type = 'property'
                    ORDER BY upload_date DESC
                """, (property_id,))
                property_images = cur.fetchall() or []
            except (psycopg2.Error, Exception):
                # Table might not exist, continue without images
                pass
            
            # Get work records
            try:
                cur.execute("""
                    SELECT * FROM propintel.work 
                    WHERE property_id = %s
                    ORDER BY work_date DESC
                """, (property_id,))
                work_records = cur.fetchall() or []
                
                # Try to add image paths to work records
                try:
                    for idx, record in enumerate(work_records):
                        work_desc = record.get('work_description', '')
                        if work_desc:
                            cur.execute("""
                                SELECT image_path FROM propintel.property_images 
                                WHERE property_id = %s AND image_type = 'work' 
                                    AND description LIKE %s
                                LIMIT 1
                            """, (property_id, f"%{work_desc}%"))
                            image_result = cur.fetchone()
                            if image_result:
                                work_records[idx]['image_path'] = image_result['image_path']
                except Exception:
                    # Ignore errors adding image paths
                    pass
            except Exception:
                # Continue without work records if there's an error
                pass
            
            # Get work images if possible
            try:
                cur.execute("""
                    SELECT * FROM propintel.property_images 
                    WHERE property_id = %s AND image_type = 'work'
                    ORDER BY upload_date DESC
                """, (property_id,))
                work_images = cur.fetchall() or []
            except Exception:
                # Continue without work images
                pass
            
            # Get income records
            try:
                cur.execute("""
                    SELECT * FROM propintel.money_in 
                    WHERE property_id = %s
                    ORDER BY income_date DESC
                """, (property_id,))
                income_records = cur.fetchall() or []
                
                # Calculate income total
                income_total = sum(record.get('income_amount', 0) or 0 for record in income_records)
            except Exception:
                # Continue without income records
                pass
            
            # Get expense records
            try:
                cur.execute("""
                    SELECT * FROM propintel.money_out 
                    WHERE property_id = %s
                    ORDER BY expense_date DESC
                """, (property_id,))
                expense_records = cur.fetchall() or []
                
                # Calculate expense total
                expense_total = sum(record.get('expense_amount', 0) or 0 for record in expense_records)
                
                # Try to add receipt images to expense records
                try:
                    for idx, record in enumerate(expense_records):
                        expense_details = record.get('expense_details', '')
                        if expense_details:
                            cur.execute("""
                                SELECT image_path FROM propintel.property_images 
                                WHERE property_id = %s AND image_type = 'receipt' 
                                    AND description LIKE %s
                                LIMIT 1
                            """, (property_id, f"%{expense_details}%"))
                            image_result = cur.fetchone()
                            if image_result:
                                expense_records[idx]['image_path'] = image_result['image_path']
                except Exception:
                    # Ignore errors adding image paths
                    pass
            except Exception:
                # Continue without expense records
                pass
            
            # Calculate work total
            try:
                work_total = sum(record.get('work_cost', 0) or 0 for record in work_records)
            except Exception:
                # Continue without work total
                work_total = 0
            
            # Calculate net total
            net_total = income_total - expense_total
            
            # Try to categorize expenses
            try:
                # First try SQL categorization
                try:
                    cur.execute("""
                        SELECT
                            COALESCE(SUM(CASE WHEN expense_category = 'wage' OR 
                                                expense_details ILIKE '%wage%' OR 
                                                expense_details ILIKE '%salary%' 
                                        THEN expense_amount ELSE 0 END), 0) as wage_total,
                            COALESCE(SUM(CASE WHEN expense_category = 'project_manager' OR 
                                                expense_details ILIKE '%project manager%' OR 
                                                expense_details ILIKE '%pm %' 
                                        THEN expense_amount ELSE 0 END), 0) as pm_total,
                            COALESCE(SUM(CASE WHEN expense_category = 'material' OR 
                                                expense_details ILIKE '%material%' OR 
                                                expense_details ILIKE '%supplies%' 
                                        THEN expense_amount ELSE 0 END), 0) as material_total,
                            COALESCE(SUM(CASE WHEN (expense_category IS NULL OR expense_category = 'miscellaneous') AND 
                                                expense_details NOT ILIKE '%wage%' AND 
                                                expense_details NOT ILIKE '%salary%' AND
                                                expense_details NOT ILIKE '%project manager%' AND
                                                expense_details NOT ILIKE '%pm %' AND
                                                expense_details NOT ILIKE '%material%' AND
                                                expense_details NOT ILIKE '%supplies%'
                                        THEN expense_amount ELSE 0 END), 0) as misc_total
                        FROM propintel.money_out
                        WHERE property_id = %s
                    """, (property_id,))
                    
                    category_result = cur.fetchone()
                    if category_result:
                        # Make sure all keys exist
                        if all(k in category_result for k in ['wage_total', 'pm_total', 'material_total', 'misc_total']):
                            expense_categories = category_result
                except Exception:
                    # SQL categorization failed, try manual categorization
                    pass
                
                # Fall back to manual categorization if SQL version failed
                if not all(k in expense_categories for k in ['wage_total', 'pm_total', 'material_total', 'misc_total']):
                    expense_categories = {
                        'wage_total': 0,
                        'pm_total': 0,
                        'material_total': 0,
                        'misc_total': 0
                    }
                    
                    for record in expense_records:
                        try:
                            amount = record.get('expense_amount', 0) or 0
                            details = (record.get('expense_details', '') or '').lower()
                            
                            if 'wage' in details or 'salary' in details:
                                expense_categories['wage_total'] += amount
                            elif 'project manager' in details or 'pm ' in details:
                                expense_categories['pm_total'] += amount
                            elif 'material' in details or 'supplies' in details:
                                expense_categories['material_total'] += amount
                            else:
                                expense_categories['misc_total'] += amount
                        except Exception:
                            # Skip this record on error
                            continue
            except Exception:
                # If all categorization fails, use empty categories
                expense_categories = {
                    'wage_total': 0,
                    'pm_total': 0,
                    'material_total': 0,
                    'misc_total': 0
                }
            
            # Get monthly trend data for charts
            try:
                trend_months = {}
                for record in income_records:
                    try:
                        month_key = record['income_date'].strftime('%Y-%m')
                        if month_key not in trend_months:
                            trend_months[month_key] = {'income': 0, 'expense': 0}
                        trend_months[month_key]['income'] += record.get('income_amount', 0) or 0
                    except Exception:
                        # Skip this record on error
                        continue
                
                for record in expense_records:
                    try:
                        month_key = record['expense_date'].strftime('%Y-%m')
                        if month_key not in trend_months:
                            trend_months[month_key] = {'income': 0, 'expense': 0}
                        trend_months[month_key]['expense'] += record.get('expense_amount', 0) or 0
                    except Exception:
                        # Skip this record on error
                        continue
                
                # Sort months for chart display
                sorted_months = sorted(trend_months.keys())
                trend_labels = [month for month in sorted_months]
                income_data = [trend_months[month]['income'] for month in sorted_months]
                expense_data = [trend_months[month]['expense'] for month in sorted_months]
            except Exception:
                # If trend data fails, use empty lists
                trend_labels = []
                income_data = []
                expense_data = []
            
            # Default map coordinates if property doesn't have lat/long
            try:
                map_lat = property_data.get('latitude') if property_data.get('latitude') else 40.7128
                map_lng = property_data.get('longitude') if property_data.get('longitude') else -74.0060
            except Exception:
                map_lat = 40.7128
                map_lng = -74.0060
            
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('properties'))
    finally:
        if conn:
            conn.close()
    
    # Ensure all variables exist before rendering
    wage_expense_total = expense_categories.get('wage_total', 0) or 0
    pm_expense_total = expense_categories.get('pm_total', 0) or 0
    material_expense_total = expense_categories.get('material_total', 0) or 0
    misc_expense_total = expense_categories.get('misc_total', 0) or 0
    
    # Handle Excel export request
    if export_excel:
        import pandas as pd
        from io import BytesIO
        from flask import send_file
        
        # Create Excel workbook with multiple sheets
        output = BytesIO()
        with pd.ExcelWriter(output, engine='openpyxl') as writer:
            # Property Details Sheet
            property_df = pd.DataFrame([{
                'Property Name': property_data.get('property_name', ''),
                'Address': property_data.get('address', ''),
                'Location': property_data.get('location', ''),
                'Status': property_data.get('status', ''),
                'Project Type': property_data.get('project_type', ''),
                'Project Manager': property_data.get('project_manager', ''),
                'Total Income': float(income_total),
                'Total Expenses': float(expense_total),
                'Work Costs': float(work_total),
                'Net Profit': float(net_total)
            }])
            property_df.to_excel(writer, sheet_name='Property Details', index=False)
            
            # Income Records Sheet
            if income_records:
                income_df = pd.DataFrame([{
                    'Date': record.get('income_date'),
                    'Amount': float(record.get('income_amount', 0)) if record.get('income_amount') else 0,
                    'Source': record.get('income_source', ''),
                    'Details': record.get('income_details', '')
                } for record in income_records])
                income_df.to_excel(writer, sheet_name='Income Records', index=False)
            
            # Expense Records Sheet
            if expense_records:
                expense_df = pd.DataFrame([{
                    'Date': record.get('expense_date'),
                    'Amount': float(record.get('expense_amount', 0)) if record.get('expense_amount') else 0,
                    'Category': record.get('expense_category', ''),
                    'Details': record.get('expense_details', '')
                } for record in expense_records])
                expense_df.to_excel(writer, sheet_name='Expense Records', index=False)
            
            # Work Records Sheet
            if work_records:
                work_df = pd.DataFrame([{
                    'Date': record.get('work_date'),
                    'Cost': float(record.get('work_cost', 0)) if record.get('work_cost') else 0,
                    'Description': record.get('work_description', ''),
                    'Worker': record.get('worker_name', '')
                } for record in work_records])
                work_df.to_excel(writer, sheet_name='Work Records', index=False)
            
            # Auto-adjust columns width
            for sheet_name in writer.sheets:
                worksheet = writer.sheets[sheet_name]
                for idx, col in enumerate(worksheet.columns):
                    max_length = 0
                    for cell in col:
                        if cell.value:
                            try:
                                if len(str(cell.value)) > max_length:
                                    max_length = len(str(cell.value))
                            except:
                                pass
                    adjusted_width = (max_length + 2)
                    worksheet.column_dimensions[worksheet.cell(1, idx + 1).column_letter].width = adjusted_width
        
        output.seek(0)
        
        filename = f"PropIntel_Property_{property_data.get('property_name', property_id)}.xlsx"
        filename = filename.replace(' ', '_').replace('/', '_')
        
        return send_file(
            output,
            mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            download_name=filename,
            as_attachment=True
        )
    
    # Pass all data to template
    return render_template(
        'property_detail.html', 
        property=property_data,
        property_images=property_images,
        work_records=work_records,
        work_images=work_images,
        income_records=income_records, 
        expense_records=expense_records,
        income_total=income_total,
        expense_total=expense_total,
        work_total=work_total,
        net_total=net_total,
        trend_labels=trend_labels,
        income_data=income_data,
        expense_data=expense_data,
        map_lat=map_lat,
        map_lng=map_lng,
        wage_expense_total=wage_expense_total,
        pm_expense_total=pm_expense_total,
        material_expense_total=material_expense_total,
        misc_expense_total=misc_expense_total
    )


@app.route('/map')
def map_view():
    """View all properties on a map with simple implementation"""
    # Create some hardcoded sample properties for demonstration
    # This ensures the map always has something to show
    sample_properties = [
        {"id": 1, "name": "Downtown Apartment", "address": "123 Main St", "lat": -37.8136, "lng": 144.9631, "budget_status": "under"},
        {"id": 2, "name": "Suburban House", "address": "456 Oak Ave", "lat": -37.8236, "lng": 144.9731, "budget_status": "over"},
        {"id": 3, "name": "Beach Cottage", "address": "789 Shore Dr", "lat": -37.8036, "lng": 144.9831, "budget_status": "under"},
        {"id": 4, "name": "Mountain Retreat", "address": "101 Summit Way", "lat": -37.7936, "lng": 144.9531, "budget_status": "over"},
        {"id": 5, "name": "City Loft", "address": "202 Urban Blvd", "lat": -37.8336, "lng": 144.9431, "budget_status": "under"}
    ]
    
    # Convert to GeoJSON format
    features = []
    for prop in sample_properties:
        features.append({
            'type': 'Feature',
            'geometry': {
                'type': 'Point',
                'coordinates': [prop['lng'], prop['lat']]  # GeoJSON uses [longitude, latitude]
            },
            'properties': {
                'id': prop['id'],
                'name': prop['name'],
                'address': prop['address'],
                'url': url_for('index'),  # Just go to dashboard for demo
                'is_over_budget': prop['budget_status'] == 'over',
                'work_count': 3,  # Demo values
                'income_count': 5,
                'expense_count': 8,
                'income': 15000,
                'expenses': 10000,
                'work_cost': 3000
            }
        })
    
    geojson = {
        'type': 'FeatureCollection',
        'features': features
    }
    
    # Also try to get real properties from the database as a fallback
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Check if any properties have coordinates
            cur.execute("""
                SELECT property_id, property_name, address, latitude, longitude 
                FROM propintel.properties 
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL
            """)
            db_properties = cur.fetchall()
            
            # If we found properties in the DB, use those instead
            if db_properties and len(db_properties) > 0:
                print(f"Found {len(db_properties)} real properties with coordinates")
                
                # Convert DB properties to GeoJSON
                db_features = []
                for prop in db_properties:
                    db_features.append({
                        'type': 'Feature',
                        'geometry': {
                            'type': 'Point',
                            'coordinates': [float(prop['longitude']), float(prop['latitude'])]
                        },
                        'properties': {
                            'id': prop['property_id'],
                            'name': prop['property_name'],
                            'address': prop['address'] or "No address",
                            'url': url_for('property_detail', property_id=prop['property_id']),
                            'is_over_budget': False,  # Default values
                            'work_count': 0,
                            'income_count': 0,
                            'expense_count': 0,
                            'income': 0,
                            'expenses': 0,
                            'work_cost': 0
                        }
                    })
                
                # Use real properties if we found them
                if db_features:
                    geojson['features'] = db_features
    except Exception as e:
        import traceback
        print(f"Error loading DB properties: {e}")
        print(traceback.format_exc())
        # Continue with sample properties if DB fails
    finally:
        if 'conn' in locals() and conn:
            conn.close()
    
    return render_template('map.html', 
                          geojson=json.dumps(geojson),
                          center_lat=-37.8136,  # Melbourne, Australia
                          center_lng=144.9631)

@app.route('/api/property-locations')
def property_locations_api():
    """API endpoint for property locations"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT property_id, property_name, address, latitude, longitude
                FROM propintel.properties
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL
            """)
            properties = cur.fetchall()
            
            # Convert to GeoJSON format
            features = []
            for prop in properties:
                features.append({
                    'type': 'Feature',
                    'geometry': {
                        'type': 'Point',
                        'coordinates': [prop['longitude'], prop['latitude']]
                    },
                    'properties': {
                        'id': prop['property_id'],
                        'name': prop['property_name'],
                        'address': prop['address'],
                        'url': url_for('property_detail', property_id=prop['property_id'])
                    }
                })
            
            geojson = {
                'type': 'FeatureCollection',
                'features': features
            }
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()
    
    return jsonify(geojson)

# Import shapefile utilities
from shapefile_utils import get_lga_list, get_lga_documents, get_document_statistics, generate_lga_geojson, import_vic_lgas, get_work_heatmap_data, generate_work_heatmap

# Builders Hub routes
@app.route('/builders-hub')
@login_required
def builders_hub():
    """Builders Hub page showing LGA map and documents"""
    
    # Check if we should return only the GeoJSON data
    if request.args.get('lga_geojson'):
        try:
            from shapefile_utils import generate_lga_geojson
            lga_geojson = generate_lga_geojson()
            return jsonify(lga_geojson)
        except Exception as e:
            app.logger.error(f"Error generating GeoJSON for API: {e}")
            return jsonify({"type": "FeatureCollection", "features": []})
    
    # Get all LGAs
    try:
        lgas = get_lga_list()
    except Exception as e:
        app.logger.error(f"Error retrieving LGA list: {e}")
        lgas = []
    
    # Get all documents for LGAs
    try:
        documents = get_lga_documents()
    except Exception as e:
        app.logger.error(f"Error retrieving LGA documents: {e}")
        documents = []
    
    # Get document statistics
    try:
        stats = get_document_statistics()
    except Exception as e:
        app.logger.error(f"Error retrieving document statistics: {e}")
        stats = {
            'permit_count': 0,
            'regulation_count': 0,
            'form_count': 0,
            'other_count': 0
        }
    
    # Get GeoJSON data for LGA map directly from shapefile
    try:
        import json
        import geopandas as gpd
        import shapely.geometry
        from shapely.validation import make_valid
        
        # Read directly from shapefile
        shp_file = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'spatial', 'Vic_LGA.shp')
        
        # Default empty GeoJSON collection
        lga_geojson = {
            "type": "FeatureCollection",
            "features": []
        }
        features = []
        
        if os.path.exists(shp_file):
            app.logger.info(f"Reading shapefile from {shp_file}")
            try:
                gdf = gpd.read_file(shp_file)
                app.logger.info(f"Shapefile read successfully with {len(gdf)} features")
                
                # Convert to WGS84 for web mapping
                if gdf.crs and gdf.crs != "EPSG:4326":
                    app.logger.info(f"Converting from {gdf.crs} to EPSG:4326")
                    gdf = gdf.to_crs("EPSG:4326")
                
                # Get document counts from database
                doc_counts = {}
                try:
                    conn = get_db_connection()
                    with conn.cursor() as cur:
                        cur.execute("""
                        SELECT lga_code, COUNT(document_id) as doc_count
                        FROM propintel.lgas
                        LEFT JOIN propintel.documents ON propintel.lgas.lga_id = propintel.documents.lga_id
                        GROUP BY lga_code
                        """)
                        for row in cur.fetchall():
                            doc_counts[row[0]] = row[1]
                except Exception as db_err:
                    app.logger.error(f"Error retrieving document counts: {db_err}")
                finally:
                    if conn:
                        conn.close()
                
                # Process each feature
                for idx, row in gdf.iterrows():
                    # Skip rows with None geometry
                    if row.geometry is None:
                        app.logger.warning(f"Skipping row {idx} with None geometry")
                        continue
                        
                    try:
                        # Ensure geometry is valid
                        if not row.geometry.is_valid:
                            app.logger.warning(f"Invalid geometry at row {idx}, attempting to repair")
                            try:
                                row.geometry = make_valid(row.geometry)
                            except Exception as validity_error:
                                app.logger.error(f"Failed to repair geometry: {validity_error}")
                                continue
                                
                        # Get document count for this LGA
                        lga_code = f"LGA{row['LGA_CODE24']}" if 'LGA_CODE24' in row and row['LGA_CODE24'] else ""
                        doc_count = doc_counts.get(lga_code, 0)
                        
                        # Build properties with safety checks
                        properties = {
                            "lga_id": idx,
                            "lga_code": lga_code,
                            "lga_name": row['LGA_NAME24'] if 'LGA_NAME24' in row else f"LGA {idx}",
                            "state_code": row['STE_CODE21'] if 'STE_CODE21' in row else "VIC",
                            "state_name": row['STE_NAME21'] if 'STE_NAME21' in row else "Victoria",
                            "area_sqkm": float(row['AREASQKM']) if 'AREASQKM' in row and row['AREASQKM'] is not None else 0,
                            "document_count": doc_count
                        }
                        
                        # Simplify geometry for better performance
                        try:
                            # Use a small simplification tolerance to preserve shape
                            simplified = row.geometry.simplify(0.001)
                            if simplified is not None and simplified.is_valid:
                                geometry = shapely.geometry.mapping(simplified)
                                
                                # Create feature
                                feature = {
                                    "type": "Feature",
                                    "properties": properties,
                                    "geometry": geometry
                                }
                                features.append(feature)
                            else:
                                app.logger.warning(f"Simplified geometry is invalid for row {idx}")
                        except Exception as geom_error:
                            app.logger.error(f"Error simplifying geometry for row {idx}: {geom_error}")
                    except Exception as e:
                        app.logger.error(f"Error processing LGA geometry for row {idx}: {e}")
                
                # Create full GeoJSON structure
                if len(features) > 0:
                    app.logger.info(f"Generated {len(features)} valid GeoJSON features")
                    lga_geojson["features"] = features
                else:
                    app.logger.warning("No valid GeoJSON features generated from shapefile")
                    # Add a single fallback feature for Victoria if no features could be generated
                    fallback_feature = {
                        "type": "Feature",
                        "properties": {
                            "lga_id": 1,
                            "lga_code": "LGA20000",
                            "lga_name": "Victoria",
                            "state_code": "VIC",
                            "state_name": "Victoria",
                            "area_sqkm": 227444,
                            "document_count": 0
                        },
                        "geometry": {
                            "type": "MultiPolygon",
                            "coordinates": [[[
                                [144.9, -37.8], [145.0, -37.8], [145.0, -37.9], [144.9, -37.9], [144.9, -37.8]
                            ]]]
                        }
                    }
                    lga_geojson["features"] = [fallback_feature]
            except Exception as gdf_error:
                app.logger.error(f"Error reading shapefile: {gdf_error}")
                # Create fallback Victoria outline geometry
                fallback_feature = {
                    "type": "Feature",
                    "properties": {
                        "lga_id": 1,
                        "lga_code": "LGA20000",
                        "lga_name": "Victoria",
                        "state_code": "VIC",
                        "state_name": "Victoria",
                        "area_sqkm": 227444,
                        "document_count": 0
                    },
                    "geometry": {
                        "type": "MultiPolygon",
                        "coordinates": [[[
                            [144.9, -37.8], [145.0, -37.8], [145.0, -37.9], [144.9, -37.9], [144.9, -37.8]
                        ]]]
                    }
                }
                lga_geojson["features"] = [fallback_feature]
        else:
            app.logger.error(f"Shapefile not found at {shp_file}")
            # Create fallback Victoria outline geometry
            fallback_feature = {
                "type": "Feature",
                "properties": {
                    "lga_id": 1,
                    "lga_code": "LGA20000",
                    "lga_name": "Victoria",
                    "state_code": "VIC",
                    "state_name": "Victoria",
                    "area_sqkm": 227444,
                    "document_count": 0
                },
                "geometry": {
                    "type": "MultiPolygon",
                    "coordinates": [[[
                        [144.9, -37.8], [145.0, -37.8], [145.0, -37.9], [144.9, -37.9], [144.9, -37.8]
                    ]]]
                }
            }
            lga_geojson["features"] = [fallback_feature]
            
        # Serialize to JSON string
        try:
            lga_geojson_str = json.dumps(lga_geojson)
            app.logger.info(f"GeoJSON serialized with {len(lga_geojson['features'])} features")
        except Exception as json_error:
            app.logger.error(f"Error serializing GeoJSON: {json_error}")
            lga_geojson_str = '{"type":"FeatureCollection","features":[]}'
    except Exception as e:
        app.logger.error(f"Error generating LGA GeoJSON: {e}")
        lga_geojson_str = '{"type":"FeatureCollection","features":[]}'
    
    # Center the map on Melbourne by default
    center_lat = -37.8136
    center_lng = 144.9631
    
    return render_template('builders_hub.html',
                          lgas=lgas,
                          documents=documents,
                          stats=stats,
                          lga_geojson=lga_geojson_str)
                          
@app.route('/document-upload', methods=['GET', 'POST'])
@login_required
def document_upload():
    """Upload document page and handler"""
    # No role check here - all users can upload documents
    # Documents uploaded by regular users will be set as private by default
    
    # Initialize error dictionary for form validation
    errors = {}
    
    # Create documents directory if it doesn't exist
    documents_dir = DOCUMENTS_FOLDER
    try:
        os.makedirs(documents_dir, exist_ok=True)
        app.logger.info(f"Created or verified documents directory: {documents_dir}")
    except Exception as e:
        app.logger.error(f"Error creating documents directory: {e}")
    
    # Get all LGAs for the form
    try:
        lgas = get_lga_list()
    except Exception as e:
        app.logger.error(f"Error retrieving LGA list: {e}")
        lgas = []
    
    # Handle form submission
    if request.method == 'POST':
        document_name = request.form.get('document_name')
        document_type = request.form.get('document_type')
        lga_id = request.form.get('lga_id')
        description = request.form.get('description', '')
        is_public = 'is_public' in request.form
        
        # Check if file is in request
        if 'document_file' not in request.files:
            errors['document_file'] = 'No file selected'
            flash('No file selected', 'danger')
            return render_template('upload_document.html', lgas=lgas, errors=errors)
        
        document_file = request.files['document_file']
        
        # Validate file
        if document_file.filename == '':
            errors['document_file'] = 'No file selected'
            flash('No file selected', 'danger')
            return render_template('upload_document.html', lgas=lgas, errors=errors)
        
        # Check file type
        if not allowed_file(document_file.filename, app.config['ALLOWED_DOCUMENT_EXTENSIONS']):
            errors['document_file'] = f"File type not allowed. Allowed types: {', '.join(app.config['ALLOWED_DOCUMENT_EXTENSIONS'])}"
            flash('File type not allowed. Please upload PDF, DOC, DOCX, XLS, XLSX, or TXT file.', 'danger')
            return render_template('upload_document.html', lgas=lgas, errors=errors)
        
        # Save file
        try:
            # Use the documents directory
            upload_dir = DOCUMENTS_FOLDER
            
            # Generate a safe filename
            filename = secure_filename(document_file.filename)
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            new_filename = f"{timestamp}_{filename}"
            file_path = os.path.join(upload_dir, new_filename)
            
            # Save the file
            document_file.save(file_path)
            file_size = os.path.getsize(file_path)
            
            # Only store the filename in database, not the full path
            file_path_val = new_filename
            
            # Save to database
            conn = get_db_connection()
            cursor = conn.cursor()
            
            # Get location data from form
            address = request.form.get('address', '')
            latitude = request.form.get('latitude')
            longitude = request.form.get('longitude')
            
            # Convert to float if provided
            try:
                latitude = float(latitude) if latitude else None
                longitude = float(longitude) if longitude else None
            except ValueError:
                latitude = None
                longitude = None
            
            # Geocode address if provided but no coordinates
            if address and not (latitude and longitude):
                try:
                    # Simple geocoding with Nominatim (OpenStreetMap)
                    import requests
                    geocode_url = f"https://nominatim.openstreetmap.org/search?format=json&q={address}"
                    response = requests.get(geocode_url, headers={'User-Agent': 'PropIntel/1.0'})
                    
                    if response.status_code == 200:
                        results = response.json()
                        if results and len(results) > 0:
                            latitude = float(results[0]['lat'])
                            longitude = float(results[0]['lon'])
                except Exception as geocode_error:
                    app.logger.error(f"Error geocoding address: {geocode_error}")
            
            cursor.execute("""
            INSERT INTO propintel.documents (
                lga_id, user_id, document_name, document_type, description, 
                file_path, file_size, is_public, upload_date, address, latitude, longitude
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """, (
                lga_id, g.user['user_id'], document_name, document_type, description,
                new_filename, file_size, is_public, datetime.now().isoformat(), address, latitude, longitude
            ))
            
            conn.commit()
            cursor.close()
            conn.close()
            
            flash('Document uploaded successfully', 'success')
            return redirect(url_for('builders_hub'))
            
        except Exception as e:
            import traceback
            app.logger.error(f"Error uploading document: {e}")
            app.logger.error(traceback.format_exc())
            flash(f'Error uploading document: {str(e)}', 'danger')
    
    return render_template('upload_document.html', lgas=lgas)

@app.route('/download-document/<int:document_id>')
@login_required
def download_document(document_id):
    """Handle document downloads"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        # Get document info
        cursor.execute("""
        SELECT 
            document_name, file_path, is_public 
        FROM 
            propintel.documents 
        WHERE 
            document_id = %s
        """, (document_id,))
        
        document = cursor.fetchone()
        
        if not document:
            flash('Document not found', 'danger')
            return redirect(url_for('builders_hub'))
        
        # Check if document is public or user is admin
        if not document['is_public'] and g.user['role'] != 'admin':
            flash('You do not have permission to access this document', 'danger')
            return redirect(url_for('builders_hub'))
        
        # Update download count
        cursor.execute("""
        UPDATE propintel.documents 
        SET download_count = download_count + 1 
        WHERE document_id = %s
        """, (document_id,))
        
        conn.commit()
        cursor.close()
        conn.close()
        
        # Prepare file for download
        file_path = os.path.join(DOCUMENTS_FOLDER, document['file_path'])
        
        if not os.path.exists(file_path):
            flash('Document file not found', 'danger')
            return redirect(url_for('builders_hub'))
        
        return send_file(file_path, as_attachment=True, download_name=document['document_name'])
        
    except Exception as e:
        app.logger.error(f"Error downloading document: {e}")
        flash('Error downloading document', 'danger')
        return redirect(url_for('builders_hub'))

@app.route('/api/lgas')
@login_required
def get_lgas_api():
    """API endpoint to get all LGAs"""
    lgas = get_lga_list()
    return jsonify(lgas)

@app.route('/api/lga-documents/<int:lga_id>')
@login_required
def get_lga_documents_api(lga_id):
    """API endpoint to get documents for a specific LGA"""
    documents = get_lga_documents(lga_id)
    return jsonify(documents)
    
@app.route('/api/document-locations')
@login_required
def get_document_locations():
    """API endpoint to get document locations for map markers"""
    lga_id = request.args.get('lga_id')
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=DictCursor) as cur:
            query = """
            SELECT 
                d.document_id, 
                d.document_name, 
                d.document_type, 
                COALESCE(d.description, '') as address,
                d.latitude, 
                d.longitude
            FROM 
                propintel.documents d
            WHERE 
                d.latitude IS NOT NULL 
                AND d.longitude IS NOT NULL
            """
            
            if lga_id:
                query += " AND d.lga_id = %s"
                cur.execute(query, (lga_id,))
            else:
                cur.execute(query)
                
            documents = cur.fetchall()
            
            # Convert to dict for JSON serialization
            result = []
            for doc in documents:
                result.append({
                    'document_id': doc['document_id'],
                    'document_name': doc['document_name'],
                    'document_type': doc['document_type'],
                    'address': doc['address'],
                    'latitude': float(doc['latitude']) if doc['latitude'] else None,
                    'longitude': float(doc['longitude']) if doc['longitude'] else None
                })
                
            return jsonify(result)
            
    except Exception as e:
        app.logger.error(f"Error retrieving document locations: {e}")
        return jsonify([]), 500
    finally:
        if conn:
            conn.close()

@app.route('/import-lga-data')
@login_required
def import_lga_data():
    """Import LGA data from shapefile"""
    # Check if user is admin
    if g.user['role'] != 'admin':
        flash('You need admin privileges to import LGA data', 'danger')
        return redirect(url_for('builders_hub'))
    
    try:
        success = import_vic_lgas()
        
        if success:
            flash('LGA data imported successfully', 'success')
        else:
            flash('Error importing LGA data', 'danger')
            
    except Exception as e:
        app.logger.error(f"Error importing LGA data: {e}")
        flash(f'Error importing LGA data: {str(e)}', 'danger')
    
    return redirect(url_for('builders_hub'))

@app.route('/map')
@login_required
def map():
    """Property map page"""
    # Initialize heatmap data
    try:
        # Generate/update work heatmap data
        generate_work_heatmap()
        
        # Get heatmap data
        heatmap_data = get_work_heatmap_data()
    except Exception as e:
        app.logger.error(f"Error generating work heatmap: {e}")
        heatmap_data = []
    
    # Get all properties with their coordinates
    conn = get_db_connection()
    try:
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        # Get all properties with financial data
        cursor.execute("""
        SELECT 
            p.property_id, 
            p.property_name, 
            p.address, 
            p.location,
            p.latitude, 
            p.longitude,
            p.total_income,
            p.total_expenses,
            COUNT(w.work_id) as work_count,
            SUM(w.work_cost) as work_cost,
            COALESCE(SUM(mi.income_amount), 0) as income,
            COUNT(mi.money_in_id) as income_count,
            COALESCE(SUM(mo.expense_amount), 0) as expenses,
            COUNT(mo.money_out_id) as expense_count,
            CASE WHEN (COALESCE(SUM(mo.expense_amount), 0) + COALESCE(SUM(w.work_cost), 0)) > COALESCE(SUM(mi.income_amount), 0) 
                THEN true ELSE false END as is_over_budget
        FROM 
            propintel.properties p
        LEFT JOIN
            propintel.work w ON p.property_id = w.property_id
        LEFT JOIN
            propintel.money_in mi ON p.property_id = mi.property_id
        LEFT JOIN
            propintel.money_out mo ON p.property_id = mo.property_id
        WHERE 
            p.is_hidden IS NOT TRUE
        GROUP BY 
            p.property_id
        """)
        
        properties = cursor.fetchall()
        
        # Get center point (average of all property coordinates)
        if properties:
            valid_coords = [(float(p['latitude']), float(p['longitude'])) 
                          for p in properties 
                          if p['latitude'] is not None and p['longitude'] is not None]
            
            if valid_coords:
                center_lat = sum(lat for lat, _ in valid_coords) / len(valid_coords)
                center_lng = sum(lng for _, lng in valid_coords) / len(valid_coords)
            else:
                # Default to Melbourne if no valid coordinates
                center_lat = -37.8136
                center_lng = 144.9631
        else:
            center_lat = -37.8136
            center_lng = 144.9631
        
        # Process properties for GeoJSON
        geojson = {
            "type": "FeatureCollection",
            "features": []
        }
        
        for prop in properties:
            if prop['latitude'] and prop['longitude']:
                feature = {
                    "type": "Feature",
                    "properties": {
                        "id": prop['property_id'],
                        "name": prop['property_name'],
                        "address": prop['address'],
                        "url": f"/property/{prop['property_id']}",
                        "income": float(prop['income']) if prop['income'] else 0,
                        "expenses": float(prop['expenses']) if prop['expenses'] else 0,
                        "work_cost": float(prop['work_cost']) if prop['work_cost'] else 0,
                        "income_count": prop['income_count'],
                        "expense_count": prop['expense_count'],
                        "work_count": prop['work_count'],
                        "is_over_budget": prop['is_over_budget']
                    },
                    "geometry": {
                        "type": "Point",
                        "coordinates": [float(prop['longitude']), float(prop['latitude'])]
                    }
                }
                geojson['features'].append(feature)
        
        cursor.close()
        
        # Convert to JSON string for template
        import json
        geojson_str = json.dumps(geojson)
        
        return render_template('map.html', 
                              geojson=geojson_str,
                              center_lat=center_lat,
                              center_lng=center_lng)
    
    except Exception as e:
        app.logger.error(f"Error loading map data: {e}")
        return render_template('map.html', 
                              geojson='{"type":"FeatureCollection","features":[]}',
                              center_lat=-37.8136,
                              center_lng=144.9631)
    
    finally:
        if conn:
            conn.close()

@app.route('/get-lga-data')
def get_lga_data():
    """API endpoint to get LGA geojson data"""
    from shapefile_utils import generate_lga_geojson
    
    # Get GeoJSON for the map
    lga_geojson = generate_lga_geojson()
    
    return jsonify(lga_geojson)

@app.route('/get-lga-documents')
def get_lga_documents_endpoint():
    """API endpoint to get documents for an LGA"""
    from shapefile_utils import get_lga_documents
    
    # Get LGA ID from request parameters
    lga_id = request.args.get('lga_id')
    
    # Convert to int if provided
    if lga_id:
        try:
            lga_id = int(lga_id)
        except ValueError:
            return jsonify({"error": "Invalid LGA ID"}), 400
    
    # Get documents for the specified LGA or all if not specified
    documents = get_lga_documents(lga_id)
    
    return jsonify(documents)

@app.route('/upload-document', methods=['GET', 'POST'])
@login_required
def upload_document():
    """For admins to upload documents to an LGA"""
    from shapefile_utils import get_lga_list
    
    # Check if user is admin - remove this restriction to allow all users access
    # if g.user['role'] != 'admin':
    #     flash('You do not have permission to access this page', 'danger')
    #     return redirect(url_for('builders_hub'))
    
    if request.method == 'POST':
        # Get form data
        document_name = request.form.get('document_name', '').strip()
        document_type = request.form.get('document_type', '').strip()
        lga_id = request.form.get('lga_id')
        description = request.form.get('description', '')
        address = request.form.get('address', '')
        
        # Regular users can only upload private documents (admin can see them)
        # Only admin can make documents public
        is_public = g.user['role'] == 'admin' and 'is_public' in request.form
        
        # Get coordinates if provided
        try:
            latitude = float(request.form.get('latitude')) if request.form.get('latitude') else None
            longitude = float(request.form.get('longitude')) if request.form.get('longitude') else None
        except (ValueError, TypeError):
            latitude = None
            longitude = None
        
        # Validate required fields
        if not document_name or not document_type or not lga_id:
            flash('Document name, type, and LGA are required', 'danger')
            return redirect(url_for('upload_document'))
        
        # Check if a file was uploaded
        if 'document_file' not in request.files:
            flash('No file selected', 'danger')
            return redirect(url_for('upload_document'))
            
        document_file = request.files['document_file']
        
        # Check if file was actually selected
        if document_file.filename == '':
            flash('No file selected', 'danger')
            return redirect(url_for('upload_document'))
        
        # Check if the file is allowed
        if not allowed_file(document_file.filename, app.config['ALLOWED_DOCUMENT_EXTENSIONS']):
            flash(f'File type not allowed. Allowed types: {", ".join(app.config["ALLOWED_DOCUMENT_EXTENSIONS"])}', 'danger')
            return redirect(url_for('upload_document'))
        
        try:
            # Generate secure filename
            filename = secure_filename(document_file.filename)
            timestamp = datetime.now().strftime("%Y%m%d%H%M%S")
            secure_filename_val = f"{timestamp}_{filename}"
            
            # Create documents directory if it doesn't exist
            documents_dir = os.path.join('static', 'documents')
            os.makedirs(documents_dir, exist_ok=True)
            
            # Save the file
            file_path = os.path.join(documents_dir, secure_filename_val)
            document_file.save(file_path)
            
            # Get file size
            file_size = os.path.getsize(file_path)
            
            # Only store the filename in database, not the full path
            file_path_val = secure_filename_val
            
            # Connect to database
            conn = get_db_connection()
            
            try:
                with conn.cursor() as cur:
                    # Insert document record
                    cur.execute("""
                        INSERT INTO propintel.documents 
                        (lga_id, user_id, document_name, document_type, description, 
                         file_path, file_size, is_public, upload_date, address, latitude, longitude)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        lga_id, 
                        g.user['user_id'], 
                        document_name,
                        document_type,
                        description,
                        file_path_val,
                        file_size,
                        is_public,
                        datetime.now().isoformat(),  # Use ISO format to avoid timezone issues
                        address,
                        latitude,
                        longitude
                    ))
                    
                    # Log the action
                    log_action('create', 'documents', cur.lastrowid, f"Uploaded document '{document_name}'")
                    
                conn.commit()
                flash('Document uploaded successfully', 'success')
                return redirect(url_for('builders_hub'))
                
            except Exception as e:
                conn.rollback()
                flash(f'Database error: {str(e)}', 'danger')
                
            finally:
                conn.close()
                
        except Exception as e:
            errors['general'] = f'Error uploading document: {str(e)}'
            flash(f'Error uploading document: {str(e)}', 'danger')
            
            # Return to form with errors instead of redirecting
            return render_template('upload_document.html', lgas=lgas, errors=errors)
    
    # GET method - show upload form
    lgas = get_lga_list()
    return render_template('upload_document.html', lgas=lgas, errors={})

@app.route('/batch-upload-documents', methods=['GET', 'POST'])
@login_required
def batch_upload_documents():
    """Handle batch upload of multiple documents"""
    # Only admin can use batch upload
    if g.user['role'] != 'admin':
        flash('You need admin privileges to use batch upload', 'danger')
        return redirect(url_for('builders_hub'))
        
    # Create documents directory if needed
    try:
        os.makedirs(DOCUMENTS_FOLDER, exist_ok=True)
        app.logger.info(f"Created or verified documents directory: {DOCUMENTS_FOLDER}")
    except Exception as e:
        app.logger.error(f"Error creating documents directory: {e}")
        
    if request.method == 'GET':
        # Get LGAs for the dropdown
        from shapefile_utils import get_lga_list
        lgas = get_lga_list()
        return render_template('batch_upload_documents.html', lgas=lgas)
    
    # Handle POST request (form submission)
    if request.method == 'POST':
        # Get common data
        lga_id = request.form.get('lga_id')
        global_is_public = 'is_public' in request.form
        document_count = int(request.form.get('document_count', 1))
        
        upload_results = []
        conn = get_db_connection()
        
        try:
            for i in range(document_count):
                # Skip if this index was removed by the user
                if f'document_name_{i}' not in request.form or f'document_file_{i}' not in request.files:
                    continue
                
                document_name = request.form.get(f'document_name_{i}')
                document_type = request.form.get(f'document_type_{i}')
                description = request.form.get(f'description_{i}', '')
                address = request.form.get(f'address_{i}', '')
                
                # Handle override of public setting if needed
                is_public = global_is_public
                if f'override_public_{i}' in request.form:
                    is_public = f'is_public_{i}' in request.form
                
                # Get coordinates if provided
                try:
                    latitude = float(request.form.get(f'latitude_{i}')) if request.form.get(f'latitude_{i}') else None
                    longitude = float(request.form.get(f'longitude_{i}')) if request.form.get(f'longitude_{i}') else None
                except (ValueError, TypeError):
                    latitude = None
                    longitude = None
                
                # Handle file upload
                document_file = request.files[f'document_file_{i}']
                if document_file and allowed_file(document_file.filename, app.config['ALLOWED_DOCUMENT_EXTENSIONS']):
                    # Generate a secure filename with timestamp to avoid collisions
                    timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                    original_filename = secure_filename(document_file.filename)
                    filename = f"{timestamp}_{original_filename}"
                    
                    # Ensure documents directory exists
                    os.makedirs(DOCUMENTS_FOLDER, exist_ok=True)
                    
                    # Save file
                    file_path = os.path.join(DOCUMENTS_FOLDER, filename)
                    document_file.save(file_path)
                    
                    # Get file size
                    file_size = os.path.getsize(file_path)
                    
                    # Only store filename in database, not full path
                    file_path_val = filename
                    
                    # Insert into database
                    cursor = conn.cursor()
                    cursor.execute("""
                        INSERT INTO propintel.documents 
                        (lga_id, user_id, document_name, document_type, description, 
                         file_path, file_size, is_public, upload_date, address, latitude, longitude)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    """, (
                        lga_id, 
                        g.user['user_id'], 
                        document_name,
                        document_type,
                        description,
                        file_path_val,
                        file_size,
                        is_public,
                        datetime.now().isoformat(),  # Use ISO format to avoid timezone issues
                        address,
                        latitude,
                        longitude
                    ))
                    
                    upload_results.append({
                        'name': document_name,
                        'success': True,
                        'message': 'Document uploaded successfully'
                    })
                else:
                    app.logger.error(f"Document {i} ('{document_name}') has invalid type. Filename: {document_file.filename}")
                    upload_results.append({
                        'name': document_name,
                        'success': False,
                        'message': f'Invalid file type. Allowed types: {", ".join(app.config["ALLOWED_DOCUMENT_EXTENSIONS"])}'
                    })
            
            conn.commit()
            
        except Exception as e:
            conn.rollback()
            import traceback
            app.logger.error(f"Error in batch upload: {str(e)}")
            app.logger.error(traceback.format_exc())
            upload_results.append({
                'name': f'Document {i+1}',
                'success': False,
                'message': f'Error: {str(e)}'
            })
        
        finally:
            conn.close()
        
        # Check results
        success_count = sum(1 for result in upload_results if result['success'])
        total_count = len(upload_results)
        
        if total_count == 0:
            flash('No documents were uploaded. Please try again.', 'danger')
        elif success_count == 0:
            flash('All document uploads failed. Please check the files and try again.', 'danger')
        elif success_count < total_count:
            flash(f'{success_count} out of {total_count} documents were uploaded successfully.', 'warning')
        else:
            flash(f'All {success_count} documents were uploaded successfully!', 'success')
        
        return redirect(url_for('builders_hub'))

@app.route('/toggle-document-public')
@login_required
def toggle_document_public():
    """Toggle a document's public status (admin only)"""
    document_id = request.args.get('id')
    
    # Admin access check
    if not g.user or g.user['role'] != 'admin':
        flash('You do not have permission to perform this action', 'danger')
        return redirect(url_for('builders_hub'))
        
    if not document_id:
        flash('No document specified', 'danger')
        return redirect(url_for('builders_hub'))
    
    try:
        document_id = int(document_id)
    except ValueError:
        flash('Invalid document ID', 'danger')
        return redirect(url_for('builders_hub'))
    
    try:
        # Connect to database
        conn = get_db_connection()
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get current status
            cur.execute("""
                SELECT is_public, document_name FROM propintel.documents
                WHERE document_id = %s
            """, (document_id,))
            
            document = cur.fetchone()
            
            if not document:
                flash('Document not found', 'danger')
                return redirect(url_for('builders_hub'))
            
            # Toggle the public status
            cur.execute("""
                UPDATE propintel.documents
                SET is_public = NOT is_public
                WHERE document_id = %s
                RETURNING is_public
            """, (document_id,))
            
            result = cur.fetchone()
            new_status = result['is_public']
            
            conn.commit()
            
            if new_status:
                flash(f'Document "{document["document_name"]}" is now public', 'success')
            else:
                flash(f'Document "{document["document_name"]}" is now private', 'info')
                
    except Exception as e:
        flash(f'Error: {str(e)}', 'danger')
    finally:
        if conn:
            conn.close()
    
    return redirect(url_for('builders_hub'))

@app.route('/download-document-file')
def download_document_file():
    """To download a document"""
    document_id = request.args.get('id')
    
    if not document_id:
        flash('No document specified', 'danger')
        return redirect(url_for('builders_hub'))
    
    try:
        document_id = int(document_id)
    except ValueError:
        flash('Invalid document ID', 'danger')
        return redirect(url_for('builders_hub'))
    
    try:
        # Connect to database
        conn = get_db_connection()
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get document record
            cur.execute("""
                SELECT document_id, document_name, file_path, is_public, download_count, user_id
                FROM propintel.documents
                WHERE document_id = %s
            """, (document_id,))
            
            document = cur.fetchone()
            
            if not document:
                flash('Document not found', 'danger')
                return redirect(url_for('builders_hub'))
            
            # Check permissions: allow if document is public, or if user is admin,
            # or if user is the document owner
            is_document_owner = g.user and str(g.user['user_id']) == str(document['user_id'])
            is_admin = g.user and g.user['role'] == 'admin'
            
            if not document['is_public'] and not is_admin and not is_document_owner:
                flash('You do not have permission to download this document', 'danger')
                return redirect(url_for('builders_hub'))
            
            # Update download count
            cur.execute("""
                UPDATE propintel.documents
                SET download_count = download_count + 1
                WHERE document_id = %s
            """, (document_id,))
            
            conn.commit()
            
            # Determine file type for MIME type
            stored_file_path = document['file_path']
            file_ext = stored_file_path.rsplit('.', 1)[1].lower() if '.' in stored_file_path else ''
            
            mime_types = {
                'pdf': 'application/pdf',
                'doc': 'application/msword',
                'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                'xls': 'application/vnd.ms-excel',
                'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                'txt': 'text/plain'
            }
            
            mime_type = mime_types.get(file_ext, 'application/octet-stream')
            
            # Log the download action
            log_action('download', 'documents', document_id, f"Downloaded document '{document['document_name']}'")
            
            # Construct full file path - stored_file_path is just the filename, need to add the directory
            app.logger.info(f"Constructing full path for: {stored_file_path}")
            full_file_path = os.path.join(DOCUMENTS_FOLDER, stored_file_path)
            
            if not os.path.exists(full_file_path):
                flash('Document file not found on server', 'danger')
                return redirect(url_for('builders_hub'))
                
            app.logger.info(f"Serving document: {full_file_path}")
            
            # Return the file
            return send_file(
                full_file_path,
                mimetype=mime_type,
                as_attachment=True,
                download_name=f"{document['document_name']}.{file_ext}"
            )
            
    except Exception as e:
        import traceback
        app.logger.error(f"Error downloading document: {str(e)}")
        app.logger.error(traceback.format_exc())
        flash(f'Error downloading document: {str(e)}', 'danger')
        return redirect(url_for('builders_hub'))
    
    finally:
        if conn:
            conn.close()

@app.route('/import-lga-shapefile')
@login_required
def import_lga_shapefile():
    """Import LGA data from shapefile"""
    # Check if user is admin
    if g.user['role'] != 'admin':
        flash('You need admin privileges to import LGA data', 'danger')
        return redirect(url_for('builders_hub'))
        
    try:
        from shapefile_utils import import_vic_lgas
        
        # Import shapefile data
        success = import_vic_lgas()
        
        if success:
            flash(f'Successfully imported/updated LGA records', 'success')
        else:
            flash('No LGA records were imported or updated', 'warning')
            
    except Exception as e:
        flash(f'Error importing LGA data: {str(e)}', 'danger')
        
    return redirect(url_for('builders_hub'))

@app.route('/property/new', methods=['GET', 'POST'])
@login_required
def new_property():
    """Add a new property with image upload"""
    if g.user['user_id'] == 'guest':
        flash('Guest users cannot add properties', 'warning')
        return redirect(url_for('properties'))
        
    if request.method == 'POST':
        # Basic details
        property_name = request.form.get('property_name', '').strip()
        address = request.form.get('address', '').strip()
        project_manager = request.form.get('property_manager', '').strip()
        
        # Project details
        purchase_date_str = request.form.get('purchase_date', '')
        notes = request.form.get('notes', '')
        
        # Validate required fields
        if not property_name or not address:
            flash('Property name and address are required', 'danger')
            return redirect(url_for('new_property'))
        
        # Parse dates
        purchase_date = None
        if purchase_date_str:
            try:
                purchase_date = datetime.datetime.strptime(purchase_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid purchase date format', 'warning')
        
        # Handle property image upload
        property_image_path = None
        if 'property_image' in request.files:
            property_image = request.files['property_image']
            if property_image and property_image.filename != '' and allowed_file(property_image.filename):
                # Create a secure filename
                filename = secure_filename(property_image.filename)
                # Add timestamp to avoid name collisions
                timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                new_filename = f"{timestamp}_{filename}"
                # Save the image
                property_dir = os.path.join(UPLOAD_FOLDER, 'properties')
                os.makedirs(property_dir, exist_ok=True)
                file_path = os.path.join(property_dir, new_filename)
                property_image.save(file_path)
                # Store the relative path for database
                property_image_path = f"images/properties/{new_filename}"
        
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Insert new property
                cur.execute("""
                    INSERT INTO propintel.properties 
                    (user_id, property_name, address, project_manager, purchase_date, notes)
                    VALUES (%s, %s, %s, %s, %s, %s)
                    RETURNING property_id
                """, (
                    g.user['user_id'], property_name, address, project_manager, 
                    purchase_date, notes
                ))
                
                new_property_id = cur.fetchone()['property_id']
                
                # If we have an image, save it to the property_images table
                if property_image_path:
                    cur.execute("""
                        INSERT INTO propintel.property_images
                        (property_id, user_id, image_path, image_type, description)
                        VALUES (%s, %s, %s, %s, %s)
                    """, (
                        new_property_id, g.user['user_id'], property_image_path, 
                        'property', f"Main image for {property_name}"
                    ))
                
                conn.commit()
                flash(f"Property '{property_name}' added successfully", 'success')
                return redirect(url_for('property_detail', property_id=new_property_id))
        except Exception as e:
            conn.rollback()
            flash(f"Error: {e}", "danger")
            return redirect(url_for('new_property'))
        finally:
            if conn:
                conn.close()
                
    return render_template('property_form.html')


@app.route('/property/<int:property_id>/work/<int:work_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_work(property_id, work_id):
    """Edit an existing work record"""
    if g.user['user_id'] == 'guest':
        flash('Guest users cannot edit work records', 'warning')
        return redirect(url_for('property_detail', property_id=property_id))
        
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property name
            cur.execute("""
                SELECT property_name FROM propintel.properties WHERE property_id = %s
            """, (property_id,))
            property_data = cur.fetchone()
            
            # Get work record to edit
            cur.execute("""
                SELECT * FROM propintel.work WHERE work_id = %s AND property_id = %s
            """, (work_id, property_id))
            work = cur.fetchone()
            
            if not work:
                flash('Work record not found', 'danger')
                return redirect(url_for('property_detail', property_id=property_id))
            
            # Get current image if any
            try:
                cur.execute("""
                    SELECT image_path FROM propintel.property_images 
                    WHERE property_id = %s AND image_type = 'work' 
                        AND description LIKE %s
                    LIMIT 1
                """, (property_id, f"%{work.get('work_description', '')}%"))
                image_result = cur.fetchone()
                if image_result:
                    work['image_path'] = image_result['image_path']
            except Exception:
                # Ignore errors getting image path
                pass
            
            if request.method == 'POST':
                work_description = request.form.get('work_description')
                work_date = request.form.get('work_date')
                work_cost = request.form.get('work_cost')
                expense_type = request.form.get('expense_type')
                payment_method = request.form.get('payment_method')
                
                # Update work record
                cur.execute("""
                    UPDATE propintel.work
                    SET work_description = %s, work_date = %s,
                        work_cost = %s, payment_method = %s,
                        updated_at = NOW()
                    WHERE work_id = %s AND property_id = %s
                """, (
                    work_description, work_date, work_cost,
                    payment_method, work_id, property_id
                ))
                
                # Handle image upload
                if 'work_image' in request.files and request.files['work_image'].filename:
                    image_file = request.files['work_image']
                    
                    if image_file and allowed_file(image_file.filename):
                        # Create unique filename
                        filename = secure_filename(image_file.filename)
                        unique_filename = f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                        filepath = os.path.join(app.config['WORK_IMAGES'], unique_filename)
                        
                        image_file.save(filepath)
                        
                        # Store image data in database
                        try:
                            cur.execute("""
                                INSERT INTO propintel.property_images
                                (property_id, image_path, description, image_type, upload_date)
                                VALUES (%s, %s, %s, 'work', NOW())
                            """, (property_id, filepath, work_description))
                        except Exception as e:
                            # If image table doesn't exist, continue without storing image path
                            print(f"Error storing image reference: {e}")
                
                conn.commit()
                flash('Work record updated successfully', 'success')
                return redirect(url_for('property_detail', property_id=property_id))
    
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('property_detail', property_id=property_id))
    finally:
        if conn:
            conn.close()
    
    # Default: show edit form
    return render_template('edit_work.html', 
                          property_id=property_id,
                          property_name=property_data.get('property_name', 'Property'),
                          work=work)

@app.route('/property/<int:property_id>/expense/<int:expense_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_expense(property_id, expense_id):
    """Edit an existing expense record"""
    if g.user['user_id'] == 'guest':
        flash('Guest users cannot edit expense records', 'warning')
        return redirect(url_for('property_detail', property_id=property_id))
        
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property name
            cur.execute("""
                SELECT property_name FROM propintel.properties WHERE property_id = %s
            """, (property_id,))
            property_data = cur.fetchone()
            
            # Get expense record to edit
            cur.execute("""
                SELECT * FROM propintel.money_out WHERE money_out_id = %s AND property_id = %s
            """, (expense_id, property_id))
            expense = cur.fetchone()
            
            if not expense:
                flash('Expense record not found', 'danger')
                return redirect(url_for('property_detail', property_id=property_id))
            
            # Get current image if any
            try:
                cur.execute("""
                    SELECT image_path FROM propintel.property_images 
                    WHERE property_id = %s AND image_type = 'receipt' 
                        AND description LIKE %s
                    LIMIT 1
                """, (property_id, f"%{expense.get('expense_details', '')}%"))
                image_result = cur.fetchone()
                if image_result:
                    expense['image_path'] = image_result['image_path']
            except Exception:
                # Ignore errors getting image path
                pass
            
            if request.method == 'POST':
                expense_details = request.form.get('expense_details')
                expense_date = request.form.get('expense_date')
                expense_amount = request.form.get('expense_amount')
                expense_category = request.form.get('expense_category')
                payment_method = request.form.get('payment_method')
                
                # Update expense record
                cur.execute("""
                    UPDATE propintel.money_out
                    SET expense_details = %s, expense_date = %s,
                        expense_amount = %s, expense_category = %s,
                        payment_method = %s, updated_at = NOW()
                    WHERE money_out_id = %s AND property_id = %s
                """, (
                    expense_details, expense_date, expense_amount,
                    expense_category, payment_method,
                    expense_id, property_id
                ))
                
                # Handle image upload
                if 'expense_image' in request.files and request.files['expense_image'].filename:
                    image_file = request.files['expense_image']
                    
                    if image_file and allowed_file(image_file.filename):
                        # Create unique filename
                        filename = secure_filename(image_file.filename)
                        unique_filename = f"{datetime.datetime.now().strftime('%Y%m%d%H%M%S')}_{filename}"
                        filepath = os.path.join(app.config['PROPERTY_IMAGES'], unique_filename)
                        
                        image_file.save(filepath)
                        
                        # Store image data in database
                        try:
                            cur.execute("""
                                INSERT INTO propintel.property_images
                                (property_id, image_path, description, image_type, upload_date)
                                VALUES (%s, %s, %s, 'receipt', NOW())
                            """, (property_id, filepath, expense_details))
                        except Exception as e:
                            # If image table doesn't exist, continue without storing image path
                            print(f"Error storing image reference: {e}")
                
                conn.commit()
                flash('Expense record updated successfully', 'success')
                return redirect(url_for('property_detail', property_id=property_id))
    
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('property_detail', property_id=property_id))
    finally:
        if conn:
            conn.close()
    
    # Default: show edit form
    return render_template('edit_expense.html', 
                          property_id=property_id,
                          property_name=property_data.get('property_name', 'Property'),
                          expense=expense)

@app.route('/property/<int:property_id>/income/<int:income_id>/edit', methods=['GET', 'POST'])
@login_required
def edit_income(property_id, income_id):
    """Edit an existing income record"""
    if g.user['user_id'] == 'guest':
        flash('Guest users cannot edit income records', 'warning')
        return redirect(url_for('property_detail', property_id=property_id))
        
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property name
            cur.execute("""
                SELECT property_name FROM propintel.properties WHERE property_id = %s
            """, (property_id,))
            property_data = cur.fetchone()
            
            # Get income record to edit
            cur.execute("""
                SELECT * FROM propintel.money_in WHERE money_in_id = %s AND property_id = %s
            """, (income_id, property_id))
            income = cur.fetchone()
            
            if not income:
                flash('Income record not found', 'danger')
                return redirect(url_for('property_detail', property_id=property_id))
            
            if request.method == 'POST':
                income_details = request.form.get('income_details')
                income_date = request.form.get('income_date')
                income_amount = request.form.get('income_amount')
                payment_method = request.form.get('payment_method')
                
                # Update income record
                cur.execute("""
                    UPDATE propintel.money_in
                    SET income_details = %s, income_date = %s,
                        income_amount = %s, payment_method = %s,
                        updated_at = NOW()
                    WHERE money_in_id = %s AND property_id = %s
                """, (
                    income_details, income_date, income_amount,
                    payment_method, income_id, property_id
                ))
                
                conn.commit()
                flash('Income record updated successfully', 'success')
                return redirect(url_for('property_detail', property_id=property_id))
    
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('property_detail', property_id=property_id))
    finally:
        if conn:
            conn.close()
    
    # Default: show edit form
    return render_template('edit_income.html', 
                          property_id=property_id,
                          property_name=property_data.get('property_name', 'Property'),
                          income=income)

@app.route('/property/<int:property_id>/work/new', methods=['GET', 'POST'])
@login_required
def new_work(property_id):
    """Add a new work record with image upload"""
    if g.user['user_id'] == 'guest':
        flash('Guest users cannot add work records', 'warning')
        return redirect(url_for('property_detail', property_id=property_id))
        
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property with owner info
            cur.execute("""
                SELECT p.property_id, p.property_name, p.user_id
                FROM propintel.properties p
                WHERE p.property_id = %s
            """, (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                flash('Property not found', 'danger')
                return redirect(url_for('properties'))
            
            # Check if user has permission to add work to this property
            if g.user['role'] != 'admin' and g.user['user_id'] != property_data['user_id']:
                flash('You do not have permission to add work to this property', 'danger')
                return redirect(url_for('property_detail', property_id=property_id))
            
            property_name = property_data['property_name']
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('property_detail', property_id=property_id))
    finally:
        if conn:
            conn.close()
    
    if request.method == 'POST':
        work_description = request.form.get('work_description', '').strip()
        work_date = request.form.get('work_date')
        work_cost = request.form.get('work_cost')
        payment_method = request.form.get('payment_method', '').strip()
        status = request.form.get('status', 'Pending')
        expense_type = request.form.get('expense_type', 'miscellaneous')
        
        if not work_description or not work_date:
            flash('Work description and date are required', 'danger')
            return redirect(url_for('new_work', property_id=property_id))
        
        try:
            work_date = datetime.datetime.strptime(work_date, '%Y-%m-%d').date()
            work_cost = float(work_cost) if work_cost else 0
        except ValueError:
            flash('Invalid date or cost format', 'danger')
            return redirect(url_for('new_work', property_id=property_id))
        
        # Handle work image upload
        work_image_path = None
        if 'work_image' in request.files:
            work_image = request.files['work_image']
            if work_image and work_image.filename != '' and allowed_file(work_image.filename):
                # Create a secure filename
                filename = secure_filename(work_image.filename)
                # Add timestamp to avoid name collisions
                timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                new_filename = f"{timestamp}_{filename}"
                # Save the image
                work_dir = os.path.join(UPLOAD_FOLDER, 'work')
                os.makedirs(work_dir, exist_ok=True)
                file_path = os.path.join(work_dir, new_filename)
                work_image.save(file_path)
                # Store the relative path for database
                work_image_path = f"images/work/{new_filename}"
        
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Check if expense_type column exists
                try:
                    # Insert work record
                    cur.execute("""
                        INSERT INTO propintel.work 
                        (property_id, user_id, work_description, work_date, work_cost, 
                         payment_method, status, expense_type)
                        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                        RETURNING work_id
                    """, (
                        property_id, g.user['user_id'], work_description, work_date, 
                        work_cost, payment_method, status, expense_type
                    ))
                except psycopg2.Error:
                    # If expense_type column doesn't exist, insert without it
                    cur.execute("""
                        INSERT INTO propintel.work 
                        (property_id, user_id, work_description, work_date, work_cost, 
                         payment_method, status)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        RETURNING work_id
                    """, (
                        property_id, g.user['user_id'], work_description, work_date, 
                        work_cost, payment_method, status
                    ))
                
                work_id = cur.fetchone()['work_id']
                
                # If we have an image, save it to the property_images table
                if work_image_path:
                    # Check if property_images table exists
                    try:
                        cur.execute("""
                            INSERT INTO propintel.property_images
                            (property_id, user_id, image_path, image_type, description)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (
                            property_id, g.user['user_id'], work_image_path, 
                            'work', f"Image for work: {work_description}"
                        ))
                    except psycopg2.Error:
                        # If table doesn't exist, log it but continue
                        print("Warning: Could not save work image - property_images table may not exist")
                
                # Also create an expense record based on the work
                try:
                    cur.execute("""
                        INSERT INTO propintel.money_out
                        (property_id, user_id, expense_details, expense_date, expense_amount, 
                         payment_method, expense_category)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                    """, (
                        property_id, g.user['user_id'], work_description, work_date,
                        work_cost, payment_method, expense_type
                    ))
                except psycopg2.Error:
                    # If expense_category column doesn't exist, insert without it
                    cur.execute("""
                        INSERT INTO propintel.money_out
                        (property_id, user_id, expense_details, expense_date, expense_amount, 
                         payment_method)
                        VALUES (%s, %s, %s, %s, %s, %s)
                    """, (
                        property_id, g.user['user_id'], work_description, work_date,
                        work_cost, payment_method
                    ))
                
                conn.commit()
                flash('Work record added successfully', 'success')
                return redirect(url_for('property_detail', property_id=property_id))
        except Exception as e:
            conn.rollback()
            flash(f"Error: {e}", "danger")
            return redirect(url_for('new_work', property_id=property_id))
        finally:
            if conn:
                conn.close()
    
    return render_template('work_form.html', property_id=property_id, property_name=property_name)

@app.route('/property/<int:property_id>/income/new', methods=['GET', 'POST'])
@login_required
def new_income(property_id):
    """Add a new income record to a property"""
    if session.get('is_guest'):
        flash('Guest users cannot add income records', 'warning')
        return redirect(url_for('property_detail', property_id=property_id))
        
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property with owner info
            cur.execute("""
                SELECT p.property_id, p.property_name, p.user_id
                FROM propintel.properties p
                WHERE p.property_id = %s
            """, (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                flash('Property not found', 'danger')
                return redirect(url_for('properties'))
            
            # Check if user has permission to add income to this property
            if g.user['role'] != 'admin' and g.user['user_id'] != property_data['user_id']:
                flash('You do not have permission to add income to this property', 'danger')
                return redirect(url_for('property_detail', property_id=property_id))
            
            property_name = property_data['property_name']
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('property_detail', property_id=property_id))
    finally:
        conn.close()
    
    if request.method == 'POST':
        income_details = request.form.get('income_details', '').strip()
        income_date = request.form.get('income_date')
        income_amount = request.form.get('income_amount')
        payment_method = request.form.get('payment_method', '').strip()
        income_category = request.form.get('income_category', '').strip()
        
        if not income_date or not income_amount:
            flash('Date and amount are required', 'danger')
            return redirect(url_for('new_income', property_id=property_id))
        
        try:
            income_date = datetime.datetime.strptime(income_date, '%Y-%m-%d').date()
            income_amount = float(income_amount)
        except ValueError:
            flash('Invalid date or amount format', 'danger')
            return redirect(url_for('new_income', property_id=property_id))
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO propintel.money_in 
                    (property_id, user_id, income_details, income_date, income_amount, payment_method, income_category)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING money_in_id
                """, (property_id, g.user['user_id'], income_details, income_date, income_amount, payment_method, income_category))
                
                income_id = cur.fetchone()[0]
                conn.commit()
                
                log_action('create', 'money_in', income_id, f"Added income record to property {property_id}")
                flash("Income record added successfully", "success")
                return redirect(url_for('property_detail', property_id=property_id))
        except Exception as e:
            conn.rollback()
            flash(f"Error adding income record: {e}", "danger")
        finally:
            conn.close()
    
    # Get income categories for dropdown
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT DISTINCT income_category FROM propintel.money_in WHERE income_category IS NOT NULL ORDER BY income_category")
            categories = [row['income_category'] for row in cur.fetchall()]
    except Exception as e:
        categories = []
    finally:
        conn.close()
    
    return render_template('income_form.html', 
                          property_id=property_id, 
                          property_name=property_name,
                          categories=categories)

@app.route('/property/<int:property_id>/expense/new', methods=['GET', 'POST'])
@login_required
def new_expense(property_id):
    """Add a new expense record with receipt image"""
    if g.user['user_id'] == 'guest':
        flash('Guest users cannot add expense records', 'warning')
        return redirect(url_for('property_detail', property_id=property_id))
        
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property with owner info
            cur.execute("""
                SELECT p.property_id, p.property_name, p.user_id
                FROM propintel.properties p
                WHERE p.property_id = %s
            """, (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                flash('Property not found', 'danger')
                return redirect(url_for('properties'))
            
            # Check if user has permission to add expense to this property
            if g.user['role'] != 'admin' and g.user['user_id'] != property_data['user_id']:
                flash('You do not have permission to add expenses to this property', 'danger')
                return redirect(url_for('property_detail', property_id=property_id))
            
            property_name = property_data['property_name']
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('property_detail', property_id=property_id))
    finally:
        if conn:
            conn.close()
    
    if request.method == 'POST':
        expense_details = request.form.get('expense_details', '').strip()
        expense_date = request.form.get('expense_date')
        expense_amount = request.form.get('expense_amount')
        payment_method = request.form.get('payment_method', '').strip()
        expense_category = request.form.get('expense_category', 'miscellaneous')
        
        if not expense_date or not expense_amount:
            flash('Expense date and amount are required', 'danger')
            return redirect(url_for('new_expense', property_id=property_id))
        
        try:
            expense_date = datetime.datetime.strptime(expense_date, '%Y-%m-%d').date()
            expense_amount = float(expense_amount)
        except ValueError:
            flash('Invalid date or amount format', 'danger')
            return redirect(url_for('new_expense', property_id=property_id))
        
        # Handle expense receipt image upload
        expense_image_path = None
        if 'expense_image' in request.files:
            expense_image = request.files['expense_image']
            if expense_image and expense_image.filename != '' and allowed_file(expense_image.filename):
                # Create a secure filename
                filename = secure_filename(expense_image.filename)
                # Add timestamp to avoid name collisions
                timestamp = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
                new_filename = f"{timestamp}_{filename}"
                # Save the image
                receipts_dir = os.path.join(UPLOAD_FOLDER, 'receipts')
                os.makedirs(receipts_dir, exist_ok=True)
                file_path = os.path.join(receipts_dir, new_filename)
                expense_image.save(file_path)
                # Store the relative path for database
                expense_image_path = f"images/receipts/{new_filename}"
        
        # Auto-categorize the expense if not specified
        if not expense_category:
            lower_details = expense_details.lower()
            if 'wage' in lower_details or 'salary' in lower_details or 'payment' in lower_details:
                expense_category = 'wage'
            elif 'project manager' in lower_details or 'pm ' in lower_details:
                expense_category = 'project_manager'
            elif 'material' in lower_details or 'supplies' in lower_details:
                expense_category = 'material'
            else:
                expense_category = 'miscellaneous'
        
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                # Insert expense record
                try:
                    cur.execute("""
                        INSERT INTO propintel.money_out 
                        (property_id, user_id, expense_details, expense_date, expense_amount, 
                         payment_method, expense_category)
                        VALUES (%s, %s, %s, %s, %s, %s, %s)
                        RETURNING money_out_id
                    """, (
                        property_id, g.user['user_id'], expense_details, expense_date, 
                        expense_amount, payment_method, expense_category
                    ))
                except psycopg2.Error:
                    # If expense_category column doesn't exist, insert without it
                    cur.execute("""
                        INSERT INTO propintel.money_out 
                        (property_id, user_id, expense_details, expense_date, expense_amount, 
                         payment_method)
                        VALUES (%s, %s, %s, %s, %s, %s)
                        RETURNING money_out_id
                    """, (
                        property_id, g.user['user_id'], expense_details, expense_date, 
                        expense_amount, payment_method
                    ))
                
                expense_id = cur.fetchone()['money_out_id']
                
                # If we have an image, save it to the property_images table
                if expense_image_path:
                    try:
                        cur.execute("""
                            INSERT INTO propintel.property_images
                            (property_id, user_id, image_path, image_type, description)
                            VALUES (%s, %s, %s, %s, %s)
                        """, (
                            property_id, g.user['user_id'], expense_image_path, 
                            'receipt', f"Receipt for expense: {expense_details}"
                        ))
                    except psycopg2.Error:
                        # If table doesn't exist, log it but continue
                        print("Warning: Could not save expense image - property_images table may not exist")
                
                conn.commit()
                flash('Expense record added successfully', 'success')
                return redirect(url_for('property_detail', property_id=property_id))
        except Exception as e:
            conn.rollback()
            flash(f"Error: {e}", "danger")
            return redirect(url_for('new_expense', property_id=property_id))
        finally:
            if conn:
                conn.close()
    
    return render_template('expense_form.html', property_id=property_id, property_name=property_name)

@app.route('/search')
def search():
    """Search for properties"""
    query = request.args.get('q', '')
    
    if not query:
        return redirect(url_for('properties'))
    
    # Get search filters
    status_filter = request.args.get('status', '')
    project_type = request.args.get('project_type', '')
    project_manager = request.args.get('project_manager', '')
    sort_by = request.args.get('sort', 'property_id')
    sort_dir = request.args.get('dir', 'asc')
    
    # Validate sort parameters
    valid_sort_fields = ['property_id', 'property_name', 'project_name', 'status', 'due_date', 
                         'project_manager', 'total_income', 'total_expenses', 'profit']
    if sort_by not in valid_sort_fields:
        sort_by = 'property_id'
        
    if sort_dir not in ['asc', 'desc']:
        sort_dir = 'asc'
    
    # Build query filters
    filters = []
    params = []
    
    # For non-admin users, only show their own properties
    if g.user and g.user['role'] != 'admin' and g.user['user_id'] != 'guest':
        filters.append("p.user_id = %s")
        params.append(g.user['user_id'])
    
    # Add search filter
    if query:
        filters.append("""
            (p.property_name ILIKE %s OR 
            p.address ILIKE %s OR 
            p.project_name ILIKE %s OR 
            p.project_manager ILIKE %s OR
            p.project_type ILIKE %s OR
            p.location ILIKE %s)
        """)
        search_param = f'%{query}%'
        params.extend([search_param, search_param, search_param, search_param, search_param, search_param])
    
    # Add status filter
    if status_filter:
        filters.append("p.status = %s")
        params.append(status_filter)
        
    # Add project type filter
    if project_type:
        filters.append("p.project_type = %s")
        params.append(project_type)
        
    # Add project manager filter
    if project_manager:
        filters.append("p.project_manager ILIKE %s")
        params.append(f'%{project_manager}%')
    
    # Include the is_hidden filter for all users except admins
    if not g.user or g.user['role'] != 'admin':
        filters.append("(p.is_hidden IS NULL OR p.is_hidden = false)")
    
    # Construct the WHERE clause
    where_clause = " AND ".join(filters) if filters else "1=1"
    
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Main query with filters and sorting
            query_sql = f"""
                SELECT p.*, 
                       u.username as owner_username,
                       COUNT(DISTINCT w.work_id) AS work_count,
                       COUNT(DISTINCT mi.money_in_id) AS income_count,
                       COUNT(DISTINCT mo.money_out_id) AS expense_count,
                       COALESCE(p.total_income, 0) as total_income,
                       COALESCE(p.total_expenses, 0) as total_expenses,
                       COALESCE(p.profit, 0) as profit
                FROM propintel.properties p
                LEFT JOIN propintel.users u ON p.user_id = u.user_id
                LEFT JOIN propintel.work w ON p.property_id = w.property_id
                LEFT JOIN propintel.money_in mi ON p.property_id = mi.property_id
                LEFT JOIN propintel.money_out mo ON p.property_id = mo.property_id
                WHERE {where_clause}
                GROUP BY p.property_id, u.username
                ORDER BY {sort_by} {sort_dir}
            """
            
            cur.execute(query_sql, params)
            properties = cur.fetchall()
            
            # Get property images
            if properties:
                property_ids = [p['property_id'] for p in properties]
                placeholders = ','.join(['%s'] * len(property_ids))
                
                cur.execute(f"""
                    SELECT property_id, image_path 
                    FROM propintel.property_images 
                    WHERE property_id IN ({placeholders})
                    AND image_type = 'property'
                    ORDER BY upload_date DESC
                """, property_ids)
                
                # Organize images by property
                property_images = {}
                for row in cur.fetchall():
                    if row['property_id'] not in property_images:
                        property_images[row['property_id']] = []
                    property_images[row['property_id']].append(row['image_path'])
                
                # Add image to property data
                for prop in properties:
                    prop_id = prop['property_id']
                    if prop_id in property_images:
                        prop['image'] = property_images[prop_id][0]  # Primary image
                        prop['images'] = property_images[prop_id]  # All images
                    else:
                        prop['image'] = None
                        prop['images'] = []
            
            # Get distinct project types and project managers for filters
            cur.execute("SELECT DISTINCT project_type FROM propintel.properties WHERE project_type IS NOT NULL ORDER BY project_type")
            project_types = [row['project_type'] for row in cur.fetchall()]
            
            cur.execute("SELECT DISTINCT project_manager FROM propintel.properties WHERE project_manager IS NOT NULL ORDER BY project_manager")
            project_managers = [row['project_manager'] for row in cur.fetchall()]
            
            # Get distinct statuses
            cur.execute("SELECT DISTINCT status FROM propintel.properties WHERE status IS NOT NULL ORDER BY status")
            statuses = [row['status'] for row in cur.fetchall()]
            
            # Get user settings for map theme
            map_theme = 'light'  # Default
            if g.user and g.user['user_id'] != 'guest':
                cur.execute("""
                    SELECT map_theme FROM propintel.user_settings
                    WHERE user_id = %s
                """, (g.user['user_id'],))
                settings = cur.fetchone()
                if settings and settings['map_theme']:
                    map_theme = settings['map_theme']
            
            # If properties were found, handle display format
            if 'format' in request.args and request.args.get('format') == 'map':
                # Convert to GeoJSON format for map view
                features = []
                for prop in properties:
                    if prop['latitude'] and prop['longitude']:
                        features.append({
                            'type': 'Feature',
                            'geometry': {
                                'type': 'Point',
                                'coordinates': [prop['longitude'], prop['latitude']]
                            },
                            'properties': {
                                'id': prop['property_id'],
                                'name': prop['property_name'],
                                'project_name': prop['project_name'],
                                'address': prop['address'],
                                'status': prop['status'],
                                'project_manager': prop['project_manager'],
                                'income': float(prop['total_income'] or 0),
                                'expenses': float(prop['total_expenses'] or 0),
                                'profit': float(prop['profit'] or 0),
                                'url': url_for('property_detail', property_id=prop['property_id']),
                                'work_count': prop['work_count'],
                                'income_count': prop['income_count'],
                                'expense_count': prop['expense_count'],
                                'image': prop.get('image')
                            }
                        })
                
                geojson = {
                    'type': 'FeatureCollection',
                    'features': features
                }
                
                return render_template('property_search.html', 
                                    geojson=json.dumps(geojson),
                                    center_lat=MELBOURNE_CENTER[0],
                                    center_lng=MELBOURNE_CENTER[1],
                                    property_count=len(properties),
                                    search=query,
                                    map_theme=map_theme)
            else:
                # Return standard property listing with search results
                return render_template('properties.html', 
                                    properties=properties, 
                                    search=query,
                                    status_filter=status_filter,
                                    project_type=project_type,
                                    project_manager=project_manager,
                                    sort_by=sort_by,
                                    sort_dir=sort_dir,
                                    project_types=project_types,
                                    project_managers=project_managers,
                                    statuses=statuses)
    except Exception as e:
        flash(f"Error searching properties: {e}", "danger")
    finally:
        conn.close()
    
    # Default fallback to properties with search parameter
    return redirect(url_for('properties', search=query))

@app.route('/about')
def about():
    """About page with application information"""
    # Get stats
    property_count = 0
    user_count = 0
    total_income = 0
    total_expenses = 0
    
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get counts
            cur.execute("SELECT COUNT(*) as count FROM propintel.properties")
            property_count = cur.fetchone()['count']
            
            cur.execute("SELECT COUNT(*) as count FROM propintel.users WHERE is_active = TRUE")
            user_count = cur.fetchone()['count']
            
            # Get financial totals
            cur.execute("SELECT SUM(total_income) as income, SUM(total_expenses) as expenses FROM propintel.properties")
            result = cur.fetchone()
            total_income = float(result['income'] or 0)
            total_expenses = float(result['expenses'] or 0)
            
            # Get project type distribution
            cur.execute("""
                SELECT project_type, COUNT(*) as count 
                FROM propintel.properties 
                WHERE project_type IS NOT NULL 
                GROUP BY project_type 
                ORDER BY count DESC
            """)
            project_types = cur.fetchall()
            
            # Get status distribution
            cur.execute("""
                SELECT status, COUNT(*) as count 
                FROM propintel.properties 
                WHERE status IS NOT NULL 
                GROUP BY status 
                ORDER BY count DESC
            """)
            statuses = cur.fetchall()
            
    except Exception as e:
        flash(f"Error loading about page: {e}", "danger")
        project_types = []
        statuses = []
    finally:
        conn.close()
    
    # Format data for charts
    project_type_labels = [pt['project_type'] for pt in project_types]
    project_type_data = [pt['count'] for pt in project_types]
    
    status_labels = [s['status'] for s in statuses]
    status_data = [s['count'] for s in statuses]
    
    # Check if the logo file exists to avoid 404 requests
    import os
    logo_path = os.path.join(app.static_folder, 'logo.png')
    has_logo = os.path.exists(logo_path)
    
    return render_template('about.html',
                         property_count=property_count,
                         user_count=user_count,
                         total_income=total_income,
                         total_expenses=total_expenses,
                         profit=total_income - total_expenses,
                         project_type_labels=json.dumps(project_type_labels),
                         project_type_data=json.dumps(project_type_data),
                         status_labels=json.dumps(status_labels),
                         status_data=json.dumps(status_data),
                         has_logo=has_logo)

@app.template_filter('format_date')
def format_date(value):
    """Format dates for display"""
    if value is None:
        return ""
    if isinstance(value, str):
        try:
            value = datetime.datetime.strptime(value, '%Y-%m-%d')
        except:
            return value
    return value.strftime('%d/%m/%Y')

@app.template_filter('format_currency')
def format_currency(value):
    """Format currency values for display"""
    if value is None:
        return "$0.00"
    return f"${float(value):,.2f}"

@app.route('/api/properties')
def api_properties():
    """API endpoint to get all properties as JSON (for debugging)"""
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get all properties
            cur.execute("""
                SELECT p.*, 
                       COUNT(DISTINCT w.work_id) AS work_count,
                       COUNT(DISTINCT mi.money_in_id) AS income_count,
                       COUNT(DISTINCT mo.money_out_id) AS expense_count
                FROM propintel.properties p
                LEFT JOIN propintel.work w ON p.property_id = w.property_id
                LEFT JOIN propintel.money_in mi ON p.property_id = mi.property_id
                LEFT JOIN propintel.money_out mo ON p.property_id = mo.property_id
                GROUP BY p.property_id
                ORDER BY p.property_id
            """)
            properties = cur.fetchall()
            
            # Convert to JSON-compatible format
            result = []
            for prop in properties:
                prop_dict = dict(prop)
                # Convert any Decimal objects to float
                for key, value in prop_dict.items():
                    if isinstance(value, decimal.Decimal):
                        prop_dict[key] = float(value)
                result.append(prop_dict)
            
            return jsonify({
                "count": len(result),
                "properties": result
            })
    except Exception as e:
        return jsonify({"error": str(e)}), 500
    finally:
        conn.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5002)) 
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='127.0.0.1', port=port, debug=debug)