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
import logging
import traceback

# Configure application logging
logging.basicConfig(
    filename='app.log',
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger(__name__)
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

# Import our blueprint
from app_routes import extra_bp

# Set the custom JSON encoder for the app
app = Flask(__name__)
app.json_encoder = DecimalJSONEncoder
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROPERTY_IMAGES'] = 'static/images/properties'
app.config['WORK_IMAGES'] = 'static/images/work'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif', 'pdf'}
app.config['ALLOWED_DOCUMENT_EXTENSIONS'] = {'pdf', 'doc', 'docx', 'xls', 'xlsx', 'txt'}
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') != 'development'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['PREFERRED_URL_SCHEME'] = 'https'

# Register our blueprint
app.register_blueprint(extra_bp)

# Security headers
@app.after_request
def add_security_headers(response):
    """Add security headers to each response"""
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://unpkg.com https://cdnjs.cloudflare.com https://fonts.googleapis.com; img-src 'self' data: https://*.tile.openstreetmap.org https://server.arcgisonline.com https://stamen-tiles-*.a.ssl.fastly.net; font-src 'self' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com https://fonts.gstatic.com; connect-src 'self' https://*.tile.openstreetmap.org https://server.arcgisonline.com https://stamen-tiles-*.a.ssl.fastly.net;"
    return response

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    """Handle 404 errors"""
    return render_template('error.html', error_code=404, 
                         error_message="Page not found. The requested page does not exist."), 404

@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors"""
    # Log the error
    logger.error(f"Internal server error: {error}", exc_info=True)
    return render_template('error.html', error_code=500, 
                         error_message="Internal server error. Our team has been notified."), 500
                         
@app.errorhandler(403)
def forbidden_error(error):
    """Handle 403 errors"""
    return render_template('error.html', error_code=403, 
                         error_message="Forbidden. You don't have permission to access this resource."), 403

# Register template filters
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
    """Format value as currency."""
    if value is None:
        return "$0.00"
    
    try:
        value = float(value)
        return "${:,.2f}".format(value)
    except (ValueError, TypeError):
        return "$0.00"

@app.template_filter('format_date')
def format_date_filter(value):
    """Format date to DD/MM/YYYY format."""
    if not value:
        return ""
    
    try:
        if isinstance(value, str):
            from datetime import datetime
            value = datetime.strptime(value, "%Y-%m-%d")
        return value.strftime("%d/%m/%Y")
    except Exception:
        return str(value)

@app.template_filter('format_percent')
def format_percent_filter(value):
    """Format value as percentage."""
    if value is None:
        return "0%"
    
    try:
        value = float(value) * 100
        return "{:.1f}%".format(value)
    except (ValueError, TypeError):
        return "0%"

@app.template_filter('safe_divide')
def safe_divide_filter(numerator, denominator):
    """Safely divide two numbers, returning 0 if denominator is 0."""
    try:
        numerator = float(numerator)
        denominator = float(denominator)
        if denominator == 0:
            return 0
        return numerator / denominator
    except (ValueError, TypeError):
        return 0

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
    """Format value as currency."""
    if value is None:
        return "$0.00"
    
    try:
        value = float(value)
        return "${:,.2f}".format(value)
    except (ValueError, TypeError):
        return "$0.00"

@app.template_filter('format_date')
def format_date_filter(value):
    """Format date to DD/MM/YYYY format."""
    if not value:
        return ""
    
    try:
        if isinstance(value, str):
            from datetime import datetime
            value = datetime.strptime(value, "%Y-%m-%d")
        return value.strftime("%d/%m/%Y")
    except Exception:
        return str(value)

@app.template_filter('format_percent')
def format_percent_filter(value):
    """Format value as percentage."""
    if value is None:
        return "0%"
    
    try:
        value = float(value) * 100
        return "{:.1f}%".format(value)
    except (ValueError, TypeError):
        return "0%"

@app.template_filter('safe_divide')
def safe_divide_filter(numerator, denominator):
    """Safely divide two numbers, returning 0 if denominator is 0."""
    try:
        numerator = float(numerator)
        denominator = float(denominator)
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
    
    # Initialize variables with default values in case of database errors
    properties = []
    project_types = []
    project_managers = []
    statuses = []
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            try:
                # Get distinct project types and project managers for filters
                cur.execute("SELECT DISTINCT project_type FROM propintel.properties WHERE project_type IS NOT NULL ORDER BY project_type")
                project_types = [row['project_type'] for row in cur.fetchall()]
            except Exception as e:
                logger.error(f"Error fetching project types: {e}", exc_info=True)
            
            try:
                cur.execute("SELECT DISTINCT project_manager FROM propintel.properties WHERE project_manager IS NOT NULL ORDER BY project_manager")
                project_managers = [row['project_manager'] for row in cur.fetchall()]
            except Exception as e:
                logger.error(f"Error fetching project managers: {e}", exc_info=True)
            
            try:
                # Get distinct statuses
                cur.execute("SELECT DISTINCT status FROM propintel.properties WHERE status IS NOT NULL ORDER BY status")
                statuses = [row['status'] for row in cur.fetchall()]
            except Exception as e:
                logger.error(f"Error fetching statuses: {e}", exc_info=True)
            
            # Main query with filters and sorting
            try:
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
                
                # Add default values for properties to ensure we don't have None values
                for prop in properties:
                    prop['work_count'] = prop.get('work_count', 0) or 0
                    prop['income_count'] = prop.get('income_count', 0) or 0
                    prop['expense_count'] = prop.get('expense_count', 0) or 0
                    prop['property_name'] = prop.get('property_name', 'Unnamed Property') or 'Unnamed Property'
                    prop['address'] = prop.get('address', 'No address') or 'No address'
            except Exception as e:
                logger.error(f"Error fetching properties: {e}", exc_info=True)
                flash(f"Error loading properties: {str(e)}", "danger")
                properties = []
                
            # Get property images
            if properties:
                try:
                    property_ids = [p['property_id'] for p in properties]
                    placeholders = ','.join(['%s'] * len(property_ids))
                    
                    try:
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
                        logger.error(f"Error fetching property images: {e}", exc_info=True)
                        # Set default image values for all properties
                        for prop in properties:
                            prop['image'] = None
                            prop['images'] = []
                except Exception as e:
                    logger.error(f"Error processing property IDs for images: {e}", exc_info=True)
                    # Set default image values for all properties
                    for prop in properties:
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
        try:
            import pandas as pd
            from io import BytesIO
            from flask import send_file
            
            # Create a Pandas dataframe from properties
            df_data = []
            for p in properties:
                try:
                    prop_data = {
                        'Property Name': p.get('property_name', 'Unnamed Property'),
                        'Address': p.get('address', 'No address'),
                        'Location': p.get('location', '') or '',
                        'Status': p.get('status', '') or '',
                        'Project Type': p.get('project_type', '') or '',
                        'Project Manager': p.get('project_manager', '') or '',
                        'Number of Work Items': p.get('work_count', 0),
                        'Number of Income Records': p.get('income_count', 0),
                        'Number of Expense Records': p.get('expense_count', 0)
                    }
                    
                    # Safely handle numeric values which could be None or non-numeric
                    try:
                        prop_data['Total Income'] = float(p.get('total_income', 0) or 0)
                    except (ValueError, TypeError):
                        prop_data['Total Income'] = 0
                        
                    try:
                        prop_data['Total Expenses'] = float(p.get('total_expenses', 0) or 0)
                    except (ValueError, TypeError):
                        prop_data['Total Expenses'] = 0
                        
                    try:
                        prop_data['Profit'] = float(p.get('profit', 0) or 0)
                    except (ValueError, TypeError):
                        prop_data['Profit'] = 0
                        
                    df_data.append(prop_data)
                except Exception as e:
                    logger.error(f"Error processing property for Excel: {e}", exc_info=True)
                    continue
            
            df = pd.DataFrame(df_data)
            
            # Create an Excel file in memory
            output = BytesIO()
            with pd.ExcelWriter(output, engine='openpyxl') as writer:
                df.to_excel(writer, sheet_name='Properties', index=False)
                
                # Auto-adjust columns width
                try:
                    worksheet = writer.sheets['Properties']
                    for idx, col in enumerate(df.columns):
                        # Apply safe column width with error handling
                        try:
                            if len(df) > 0:  # Only if we have data
                                max_len = max(df[col].astype(str).map(len).max(), len(col) + 2)
                            else:
                                max_len = len(col) + 5  # Default width if no data
                            worksheet.column_dimensions[worksheet.cell(1, idx + 1).column_letter].width = max_len
                        except Exception as e:
                            logger.error(f"Error setting Excel column width: {e}", exc_info=True)
                            # Use default width as fallback
                            worksheet.column_dimensions[worksheet.cell(1, idx + 1).column_letter].width = 15
                except Exception as e:
                    logger.error(f"Error adjusting Excel column widths: {e}", exc_info=True)
            
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
        except Exception as e:
            logger.error(f"Error generating Excel export: {e}", exc_info=True)
            flash(f"Error generating Excel export: {str(e)}", "danger")
            # Continue to render the properties page as fallback
    
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
    try:
        # Get filter parameters
        property_id = request.args.get('property_id', 'all')
        year = request.args.get('year', str(datetime.now().year))
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
                
                # Get active budgets from the budget table
                budget_property_filter = ""
                if property_id and property_id != 'all':
                    budget_property_filter = f"AND b.property_id = '{property_id}'"
                
                status_filter = ""
                if status and status != 'all':
                    status_filter = f"AND LOWER(b.status) = LOWER('{status}')"
                
                cur.execute(f"""
                    SELECT 
                        b.budget_id, 
                        b.budget_name, 
                        b.budget_description, 
                        b.budget_amount, 
                        b.start_date, 
                        b.end_date,
                        b.wage_allocation,
                        b.pm_allocation,
                        b.material_allocation,
                        b.misc_allocation,
                        b.status,
                        p.property_name,
                        p.property_id
                    FROM 
                        propintel.budgets b
                    JOIN 
                        propintel.properties p ON b.property_id = p.property_id
                    WHERE 
                        1=1
                        {budget_property_filter}
                        {status_filter}
                    ORDER BY 
                        b.created_at DESC
                    LIMIT 5
                """)
                active_budgets = cur.fetchall()
                
                # Process active budgets for display
                for budget in active_budgets:
                    # Calculate spent amount (sample calculation, replace with actual logic)
                    # This would typically involve summing expenses from the money_out table
                    spent_amount = 0
                    try:
                        cur.execute("""
                            SELECT COALESCE(SUM(expense_amount), 0) as total_spent
                            FROM propintel.money_out
                            WHERE property_id = %s
                            AND expense_date BETWEEN %s AND %s
                        """, (
                            budget['property_id'],
                            budget['start_date'],
                            budget['end_date']
                        ))
                        spent_result = cur.fetchone()
                        if spent_result:
                            spent_amount = float(spent_result['total_spent'])
                    except Exception as e:
                        app.logger.error(f"Error calculating spent amount: {e}")
                    
                    # Calculate percentage spent
                    budget_amount = float(budget['budget_amount']) if budget['budget_amount'] else 0
                    percentage = (spent_amount / budget_amount * 100) if budget_amount > 0 else 0
                    
                    # Format the budget for display
                    budget_data['active_budgets'].append({
                        'budget_id': budget['budget_id'],
                        'property_name': budget['property_name'],
                        'description': budget['budget_name'],
                        'date': budget['end_date'],
                        'budget_amount': budget_amount,
                        'spent_amount': spent_amount,
                        'percentage': percentage,
                        'status': budget['status']
                    })
                
                # Calculate budget allocation totals (by category)
                allocation_query = """
                    SELECT 
                        COALESCE(SUM(wage_allocation), 0) as wage,
                        COALESCE(SUM(pm_allocation), 0) as project_manager,
                        COALESCE(SUM(material_allocation), 0) as material,
                        COALESCE(SUM(misc_allocation), 0) as miscellaneous
                    FROM propintel.budgets
                    WHERE 1=1
                """
                if property_id and property_id != 'all':
                    allocation_query += f" AND property_id = '{property_id}'"
                    
                cur.execute(allocation_query)
                allocation_result = cur.fetchone()
                
                if allocation_result:
                    budget_data['allocation_data'] = {
                        'wage': float(allocation_result['wage']),
                        'project_manager': float(allocation_result['project_manager']),
                        'material': float(allocation_result['material']),
                        'miscellaneous': float(allocation_result['miscellaneous'])
                    }
                
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
                
                # Get upcoming expenses (placeholder)
                upcoming_expenses = []
                try:
                    cur.execute(f"""
                        SELECT 
                            mo.expense_id,
                            mo.expense_description,
                            mo.expense_date,
                            mo.expense_amount,
                            mo.expense_category,
                            p.property_name
                        FROM propintel.money_out mo
                        JOIN propintel.properties p ON mo.property_id = p.property_id
                        WHERE 
                            mo.expense_date > CURRENT_DATE
                            AND mo.expense_date <= (CURRENT_DATE + INTERVAL '30 days')
                            {property_filter}
                        ORDER BY mo.expense_date ASC
                        LIMIT 5
                    """)
                    expense_records = cur.fetchall()
                    
                    for expense in expense_records:
                        upcoming_expenses.append({
                            'description': expense['expense_description'],
                            'date': expense['expense_date'],
                            'amount': float(expense['expense_amount']),
                            'category': expense['expense_category'].lower().replace(' ', '_'),
                            'property': expense['property_name']
                        })
                except Exception as e:
                    app.logger.error(f"Error getting upcoming expenses: {e}")
                
                # Create monthly budget data for the chart
                monthly_budget = [0] * 12
                monthly_spent = [0] * 12
                
                # Get monthly budget data from budgets table
                try:
                    cur.execute(f"""
                        SELECT 
                            EXTRACT(MONTH FROM start_date) as month,
                            COALESCE(SUM(budget_amount / 
                                GREATEST(1, EXTRACT(MONTH FROM end_date) - EXTRACT(MONTH FROM start_date) + 1)), 0) as amount
                        FROM propintel.budgets
                        WHERE 
                            EXTRACT(YEAR FROM start_date) = %s OR EXTRACT(YEAR FROM end_date) = %s
                            {budget_property_filter}
                        GROUP BY EXTRACT(MONTH FROM start_date)
                        ORDER BY month
                    """, (year, year))
                    
                    budget_months = cur.fetchall()
                    for bm in budget_months:
                        if 1 <= int(bm['month']) <= 12:
                            monthly_budget[int(bm['month'])-1] = float(bm['amount'])
                except Exception as e:
                    app.logger.error(f"Error getting monthly budget data: {e}")
                
                # Complete the budget_data dictionary with processed values
                budget_data = {
                    'expense_data': expense_data,
                    'income_data': {},  # Process income data similarly
                    'active_budgets': budget_data['active_budgets'],
                    'upcoming_expenses': upcoming_expenses,
                    'allocation_data': budget_data['allocation_data'],
                    'total_expenses': sum(monthly_spent),
                    'monthly_budget': monthly_budget,
                    'monthly_spent': monthly_spent,
                    'months': months
                }
                
                return render_template('budget_planner.html', 
                                    properties=properties, 
                                    budget_data=budget_data,
                                    selected_property=property_id,
                                    selected_year=year,
                                    selected_status=status,
                                    available_years=list(range(datetime.now().year - 5, datetime.now().year + 2))
                                    )
        except Exception as e:
            app.logger.error(f"Database error in budget planner: {str(e)}")
            if conn:
                conn.close()
            flash(f"Error loading budget data: {str(e)}", "danger")
            return render_template('budget_planner.html', 
                                properties=properties, 
                                budget_data=budget_data,
                                error=str(e))
    except Exception as e:
        app.logger.error(f"Unexpected error in budget planner: {str(e)}")
        flash(f"An unexpected error occurred: {str(e)}", "danger")
        return render_template('budget_planner.html', 
                            properties=[], 
                            budget_data={},
                            error=str(e))

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
    """Property map page with document overlay capabilities"""
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
        
        # Get LGA list and document statistics for additional functionality
        lgas = get_lga_list()
        doc_stats = get_document_statistics()
        
        return render_template('map.html', 
                            geojson=geojson_str,
                            center_lat=center_lat,
                            center_lng=center_lng,
                            lgas=lgas,
                            doc_stats=doc_stats)
    
    except Exception as e:
        app.logger.error(f"Error loading map data: {e}")
        return render_template('map.html', 
                            geojson='{"type":"FeatureCollection","features":[]}',
                            center_lat=-37.8136,
                            center_lng=144.9631,
                            lgas=[],
                            doc_stats={})
    
    finally:
        if conn:
            conn.close()

# Add alias route for map_view that redirects to map
@app.route('/map_view')
@login_required
def map_view():
    """Alias for the map route to maintain backward compatibility"""
    return redirect(url_for('map'))

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

@app.route('/delete-document', methods=['POST'])
@login_required
def delete_document():
    """Delete a document (admin only)"""
    document_id = request.args.get('id')
    
    # Admin access check
    if not g.user or g.user['role'] != 'admin':
        return jsonify({'success': False, 'message': 'You do not have permission to perform this action'}), 403
        
    if not document_id:
        return jsonify({'success': False, 'message': 'No document specified'}), 400
    
    try:
        document_id = int(document_id)
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid document ID'}), 400
    
    try:
        # Connect to database
        conn = get_db_connection()
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get document record to get the file path
            cur.execute("""
                SELECT document_id, document_name, file_path 
                FROM propintel.documents
                WHERE document_id = %s
            """, (document_id,))
            
            document = cur.fetchone()
            
            if not document:
                return jsonify({'success': False, 'message': 'Document not found'}), 404
            
            # Delete the file from the filesystem if it exists
            if document['file_path']:
                full_file_path = os.path.join(DOCUMENTS_FOLDER, document['file_path'])
                if os.path.exists(full_file_path):
                    try:
                        os.remove(full_file_path)
                        app.logger.info(f"Deleted file: {full_file_path}")
                    except Exception as e:
                        app.logger.error(f"Error deleting file {full_file_path}: {str(e)}")
                        # Continue anyway, as we want to remove the database record
            
            # Delete the document record
            cur.execute("""
                DELETE FROM propintel.documents
                WHERE document_id = %s
            """, (document_id,))
            
            conn.commit()
            
            # Log the action
            log_action('delete', 'documents', document_id, f"Deleted document '{document['document_name']}'")
            
            return jsonify({'success': True, 'message': 'Document deleted successfully'})
            
    except Exception as e:
        app.logger.error(f"Error deleting document: {str(e)}")
        return jsonify({'success': False, 'message': str(e)}), 500
    
    finally:
        if conn:
            conn.close()

@app.route('/api/save-budget', methods=['POST'])
@login_required
def save_budget():
    """Save budget data to database"""
    try:
        if g.user['user_id'] == 'guest':
            return jsonify({'status': 'error', 'message': 'Guest users cannot save budgets'}), 403
            
        data = request.json
        property_id = data.get('property_id')
        budget_amount = data.get('budget_amount')
        budget_name = data.get('budget_name')
        budget_description = data.get('budget_description')
        start_date = data.get('start_date')
        end_date = data.get('end_date')
        
        # Budget allocations
        wage_amount = data.get('wage_amount', 0)
        pm_amount = data.get('pm_amount', 0)
        material_amount = data.get('material_amount', 0)
        misc_amount = data.get('misc_amount', 0)
        
        # Validate required fields
        if not property_id or not budget_amount or not budget_name:
            return jsonify({'status': 'error', 'message': 'Missing required fields'}), 400
            
        # Validate property exists
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("SELECT property_id FROM propintel.properties WHERE property_id = %s", (property_id,))
                if not cur.fetchone():
                    return jsonify({'status': 'error', 'message': 'Property not found'}), 404
                
                # Insert budget record
                cur.execute("""
                    INSERT INTO propintel.budgets 
                    (property_id, user_id, budget_name, budget_description, budget_amount, 
                     start_date, end_date, wage_allocation, pm_allocation, material_allocation, misc_allocation)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING budget_id
                """, (
                    property_id, g.user['user_id'], budget_name, budget_description, budget_amount,
                    start_date, end_date, wage_amount, pm_amount, material_amount, misc_amount
                ))
                budget_id = cur.fetchone()[0]
                conn.commit()
                
                return jsonify({
                    'status': 'success', 
                    'message': 'Budget saved successfully',
                    'budget_id': budget_id
                })
                
        except Exception as e:
            conn.rollback()
            app.logger.error(f"Database error saving budget: {str(e)}")
            return jsonify({'status': 'error', 'message': f'Error saving budget: {str(e)}'}), 500
        finally:
            conn.close()
            
    except Exception as e:
        app.logger.error(f"Unexpected error saving budget: {str(e)}")
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {str(e)}'}), 500

@app.route('/download-document/<int:document_id>')
@login_required
def download_document(document_id):
    """Download a document file"""
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cursor:
            cursor.execute("""
            SELECT * FROM propintel.documents WHERE document_id = %s
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


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5002)) 
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='127.0.0.1', port=port, debug=debug)