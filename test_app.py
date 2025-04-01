from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g, abort
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import configparser
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import tempfile
import datetime
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
import time
import pickle
from datetime import timedelta

# Import our data extraction script
import property_data_extractor as extractor
import json as standard_json
import decimal

# Install flask-session
try:
    from flask_session import Session
    print("Using Flask-Session for server-side sessions")
except ImportError:
    print("WARNING: Flask-Session not installed, using default client-side sessions")
    print("Run: pip install flask-session")

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

# Generate a stronger secret key if not provided
if not os.environ.get('SECRET_KEY'):
    app.secret_key = secrets.token_hex(24)  # 48 characters
else:
    app.secret_key = os.environ.get('SECRET_KEY')

# Session configuration - critical to fix login issues
app.config['SESSION_TYPE'] = 'filesystem'
app.config['SESSION_FILE_DIR'] = os.path.join(os.getcwd(), 'flask_session')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=7)
app.config['SESSION_COOKIE_SECURE'] = False  # Set to True in production with HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_USE_SIGNER'] = True  # Sign the session cookie

# Ensure session directory exists
os.makedirs(app.config['SESSION_FILE_DIR'], exist_ok=True)

# Initialize server-side session
if 'Session' in locals():
    Session(app)

# Regular application configuration
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['PROPERTY_IMAGES'] = 'static/images/properties'
app.config['WORK_IMAGES'] = 'static/images/work'
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif'}
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

# Create necessary folders
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['PROPERTY_IMAGES'], exist_ok=True)
os.makedirs(app.config['WORK_IMAGES'], exist_ok=True)
os.makedirs('static', exist_ok=True)

# Default center of Melbourne
MELBOURNE_CENTER = [-37.8136, 144.9631]

# Setup logging (simplified)
import logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("app.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('propintel')

# Check if a file has an allowed extension
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

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
        logger.error(f"Error optimizing image: {e}")
        return image_data

# Session management
@app.before_request
def before_request():
    """Process session and user before each request"""
    # Initialize g.user as None
    g.user = None
    
    # Skip for static files to improve performance
    if request.path.startswith('/static/'):
        return
    
    # Debug logging
    logger.debug(f"Request path: {request.path}")
    logger.debug(f"Session data: {dict(session)}")
    
    # Check for user_id in session
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
        
        # Fetch user from database for regular users
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                user_id = session['user_id']
                # Convert to integer if it's not 'guest' and is a numeric string
                if user_id != 'guest' and user_id.isdigit():
                    user_id = int(user_id)
    
                    cur.execute("""
                        SELECT user_id, username, email, full_name, role 
                        FROM propintel.users 
                        WHERE user_id = %s AND is_active = TRUE
                    """, (user_id,))
                
                if user_id:
                    g.user_id = user_id
                    logger.debug(f"User in g.user: {g.user['username']}")
                else:
                    logger.debug(f"User not found in database or not active: {session['user_id']}")
                    # Clear invalid session
                    session.pop('user_id', None)
                    if 'is_guest' in session:
                        session.pop('is_guest', None)
        except Exception as e:
            logger.error(f"Error in before_request: {e}")
        finally:
            if conn:
                conn.close()
    else:
        logger.debug("No user_id in session")

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Debug info
        logger.debug(f"login_required checking access to: {request.path}")
        logger.debug(f"g.user: {g.user}")
        
        if g.user is None:
            flash('Please log in to access this page', 'warning')
            
            # Store the next URL in session
            session['next_url'] = request.url
            session.modified = True
            
            logger.debug(f"Redirecting to login, stored next_url: {request.url}")
            return redirect(url_for('login'))
            
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
                session.modified = True
                return redirect(url_for('login'))
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

# Function to log user actions
def log_action(action_type, table_name=None, record_id=None, details=None):
    if g.user:
        conn = None
        try:
            conn = get_db_connection()
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
            logger.error(f"Error logging action: {e}")
        finally:
            if conn:
                conn.close()

# Database connection
def get_db_connection():
    """Get a connection to the PostgreSQL database with retry logic"""
    max_retries = 3
    retry_count = 0
    
    while retry_count < max_retries:
        try:
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
        except Exception as e:
            retry_count += 1
            if retry_count >= max_retries:
                raise
            logger.error(f"Database connection error (attempt {retry_count}): {e}")
            time.sleep(1)  # Wait before retrying

@app.route('/')
def index():
    """Home page with property search"""
    # Use the same code as the property_search route
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
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
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
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
        if conn:
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
        
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
            conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    # Debug
    logger.debug("\n===== LOGIN ROUTE =====")
    logger.debug(f"Session at login start: {dict(session)}")
    
    # Redirect if already logged in
    if g.user:
        next_url = session.pop('next_url', None) or url_for('index')
        logger.debug(f"Already logged in, redirecting to: {next_url}")
        return redirect(next_url)
        
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = 'remember' in request.form
        
        logger.debug(f"Login attempt for: {username}")
        
        # Validate inputs
        if not username or not password:
            flash('Username and password are required', 'danger')
            return render_template('login.html')
            
        # Check for guest login
        if username == 'guest':
            logger.debug("Setting up guest session")
            session.clear()
            session['user_id'] = 'guest'
            session['is_guest'] = True
            session.permanent = True
            session.modified = True
            
            logger.debug(f"Session after guest login: {dict(session)}")
            flash('Logged in as guest', 'info')
            
            next_url = session.pop('next_url', None) or url_for('index')
            return redirect(next_url)
            
        # TEMPORARY: Admin hardcoded login for testing until database is properly set up
        if username == 'admin' and password == 'admin123':
            logger.debug("Admin login successful")
            session.clear()
            session['user_id'] = '1'  # Admin user ID should be 1
            session.permanent = remember
            session.modified = True
            
            logger.debug(f"Session after admin login: {dict(session)}")
            flash('Welcome back, System Administrator!', 'success')
            
            next_url = session.pop('next_url', None) or url_for('index')
            return redirect(next_url)
        
        # Regular login
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor(cursor_factory=RealDictCursor) as cur:
                cur.execute("""
                    SELECT user_id, username, password_hash, full_name, role, is_active
                    FROM propintel.users 
                    WHERE username = %s
                """, (username,))
                user = cur.fetchone()
                
                if user:
                    # Check if password hash starts with $2b$ (bcrypt format)
                    if user['password_hash'].startswith('$2b$') and check_password_hash(user['password_hash'], password):
                        if not user['is_active']:
                            flash('Your account is inactive. Please contact an administrator.', 'warning')
                            return render_template('login.html')
                            
                        # Set session
                        logger.debug(f"Valid login for: {username}")
                        session.clear()
                        session['user_id'] = user['user_id']
                        session.permanent = remember
                        session.modified = True
                        
                        logger.debug(f"Session after login: {dict(session)}")
                        
                        # Update last login time
                        try:
                            cur.execute("""
                                UPDATE propintel.users 
                                SET last_login = CURRENT_TIMESTAMP 
                                WHERE user_id = %s
                            """, (user['user_id'],))
                            conn.commit()
                        except Exception as e:
                            logger.error(f"Error updating last login: {e}")
                        
                        # Log action
                        try:
                            log_action('login')
                        except Exception as e:
                            logger.error(f"Error logging action: {e}")
                        
                        flash(f'Welcome back, {user["full_name"]}!', 'success')
                        next_url = session.pop('next_url', None) or url_for('index')
                        logger.debug(f"Redirecting after login to: {next_url}")
                        return redirect(next_url)
                
                # Incorrect login
                logger.debug(f"Invalid login for: {username}")
                flash('Invalid username or password', 'danger')
        except Exception as e:
            logger.error(f"Login error: {e}")
            flash(f"Error during login: {str(e)}", 'danger')
        finally:
            if conn:
                conn.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    logger.debug("===== LOGOUT ROUTE =====")
    logger.debug(f"Session before logout: {dict(session)}")
    
    if g.user and 'user_id' in session and session['user_id'] != 'guest':
        logger.debug(f"Logging out user: {g.user.get('username')}")
        log_action('logout')
    
    session.clear()
    logger.debug(f"Session after clear: {dict(session)}")
    
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
        
        conn = None
        try:
            conn = get_db_connection()
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
            if conn:
                conn.rollback()
            flash(f"Error during registration: {str(e)}", 'danger')
        finally:
            if conn:
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
        
        conn = None
        try:
            conn = get_db_connection()
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
            if conn:
                conn.rollback()
            flash(f"Error updating profile: {str(e)}", 'danger')
        finally:
            if conn:
                conn.close()
            
        return redirect(url_for('user_profile'))
    
    # GET request - show profile
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
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
    
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
            conn.rollback()
        flash(f"Error updating settings: {str(e)}", 'danger')
    finally:
        if conn:
            conn.close()
        
    return redirect(url_for('user_profile'))

@app.route('/admin/users')
@admin_required
def admin_users():
    """Admin user management page"""
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
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
        
        conn = None
        try:
            conn = get_db_connection()
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
            if conn:
                conn.rollback()
            flash(f"Error creating user: {str(e)}", 'danger')
        finally:
            if conn:
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
        
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
            conn.rollback()
        flash(f"Error updating user: {str(e)}", 'danger')
        return redirect(url_for('admin_users'))
    finally:
        if conn:
            conn.close()
    
    return render_template('admin/edit_user.html', user=user_data)

@app.route('/admin/user/<int:user_id>/toggle', methods=['POST'])
@admin_required
def admin_toggle_user(user_id):
    """Toggle user active status"""
    # Don't allow deactivating yourself
    if g.user['user_id'] == user_id:
        return jsonify({"error": "You cannot deactivate your own account"}), 403
        
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
            conn.rollback()
        return jsonify({"error": str(e)}), 500
    finally:
        if conn:
            conn.close()

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """Page for uploading Excel files to process"""
    logger.debug(f"\n===== UPLOAD FILE ROUTE =====")
    logger.debug(f"g.user: {g.user}")
    
    # Check for guest users
    if g.user.get('user_id') == 'guest':
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
    
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
            conn.close()
    
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

@app.route('/property/<int:property_id>')
def property_detail(property_id):
    """View details for a specific property"""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property details with owner info
            cur.execute("""
                SELECT p.*, u.username as owner_username, u.full_name as owner_name
                FROM propintel.properties p
                LEFT JOIN propintel.users u ON p.user_id = u.user_id
                WHERE p.property_id = %s
            """, (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                flash('Property not found', 'danger')
                return redirect(url_for('properties'))
            
            # Check access control - only owner and admin can view hidden properties
            if property_data['is_hidden'] and (not g.user or 
                                              (g.user['role'] != 'admin' and 
                                               g.user['user_id'] != property_data['user_id'])):
                flash('This property is not available', 'warning')
                return redirect(url_for('properties'))
            
            # Check user permission - regular users can only view their own properties
            if g.user and g.user['role'] != 'admin' and g.user['user_id'] != 'guest':
                if g.user['user_id'] != property_data['user_id']:
                    flash('You do not have permission to view this property', 'danger')
                    return redirect(url_for('properties'))
            
            # Get property images
            cur.execute("""
                SELECT image_id, image_path, description, upload_date
                FROM propintel.property_images
                WHERE property_id = %s
                ORDER BY upload_date DESC
            """, (property_id,))
            property_images = cur.fetchall()
            
            # Get work records
            cur.execute("""
                SELECT w.*, u.username as created_by
                FROM propintel.work w
                LEFT JOIN propintel.users u ON w.user_id = u.user_id
                WHERE w.property_id = %s
                ORDER BY w.work_date DESC
            """, (property_id,))
            work_records = cur.fetchall()
            
            # Get work images
            if work_records:
                work_ids = [w['work_id'] for w in work_records]
                placeholders = ','.join(['%s'] * len(work_ids))
                
                cur.execute(f"""
                    SELECT image_id, work_id, image_path, description, upload_date
                    FROM propintel.property_images
                    WHERE property_id = %s AND image_type = 'work' 
                    AND work_id IN ({placeholders})
                    ORDER BY upload_date DESC
                """, [property_id] + work_ids)
                
                # Group images by work_id
                work_images = {}
                for img in cur.fetchall():
                    work_id = img['work_id']
                    if work_id not in work_images:
                        work_images[work_id] = []
                    work_images[work_id].append(img)
                
                # Add images to work records
                for work in work_records:
                    work_id = work['work_id']
                    if work_id in work_images:
                        work['images'] = work_images[work_id]
                    else:
                        work['images'] = []
            
            # Get income records
            cur.execute("""
                SELECT mi.*, u.username as created_by
                FROM propintel.money_in mi
                LEFT JOIN propintel.users u ON mi.user_id = u.user_id
                WHERE mi.property_id = %s
                ORDER BY mi.income_date DESC
            """, (property_id,))
            income_records = cur.fetchall()
            
            # Get expense records
            cur.execute("""
                SELECT mo.*, u.username as created_by
                FROM propintel.money_out mo
                LEFT JOIN propintel.users u ON mo.user_id = u.user_id
                WHERE mo.property_id = %s
                ORDER BY mo.expense_date DESC
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
            
            # Calculate totals - use stored values if available
            if property_data['total_income'] is not None and property_data['total_expenses'] is not None:
                income_total = float(property_data['total_income'])
                expense_total = float(property_data['total_expenses'])
            else:
                income_total = sum(float(record['income_amount'] or 0) for record in income_records)
                expense_total = sum(float(record['expense_amount'] or 0) for record in expense_records)
                
            work_total = sum(float(record['work_cost'] or 0) for record in work_records)
            net_total = income_total - expense_total - work_total
            
            # Check if user can edit this property
            can_edit = False
            if g.user:
                if g.user['role'] == 'admin' or g.user['user_id'] == property_data['user_id']:
                    can_edit = True
    except Exception as e:
        flash(f"Error loading property details: {e}", "danger")
        return redirect(url_for('properties'))
    finally:
        if conn:
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
                'cost': float(record['work_cost'] or 0),
                'status': record['status']
            })
    
    return render_template('property_detail.html', 
                          property=property_data,
                          work_records=work_records,
                          income_records=income_records,
                          expense_records=expense_records,
                          property_images=property_images,
                          work_total=work_total,
                          income_total=income_total,
                          expense_total=expense_total,
                          net_total=net_total,
                          map_lat=map_lat,
                          map_lng=map_lng,
                          map_theme=map_theme,
                          trend_labels=json.dumps(trend_labels),
                          income_data=json.dumps(income_data),
                          expense_data=json.dumps(expense_data),
                          timeline_data=json.dumps(timeline_data),
                          can_edit=can_edit)



@app.route('/map')
def map_view():
    """View all properties on a map"""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT property_id, property_name, address, latitude, longitude
                FROM propintel.properties
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL
                AND (is_hidden IS NULL OR is_hidden = false)
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
        flash(f"Error loading map: {e}", "danger")
        geojson = {"type": "FeatureCollection", "features": []}
    finally:
        if conn:
            conn.close()
    
    return render_template('map.html', 
                          geojson=json.dumps(geojson),
                          center_lat=MELBOURNE_CENTER[0],
                          center_lng=MELBOURNE_CENTER[1])

@app.route('/api/property-locations')
def property_locations_api():
    """API endpoint for property locations"""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT property_id, property_name, address, latitude, longitude
                FROM propintel.properties
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL
                AND (is_hidden IS NULL OR is_hidden = false)
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
        if conn:
            conn.close()
    
    return jsonify(geojson)

@app.route('/property/new', methods=['GET', 'POST'])
@login_required
def new_property():
    """Add a new property"""
    logger.debug(f"\n===== NEW PROPERTY ROUTE =====")
    logger.debug(f"g.user: {g.user}")
    
    if g.user['user_id'] == 'guest':
        flash('Guest users cannot add properties', 'warning')
        return redirect(url_for('properties'))
        
    if request.method == 'POST':
        # Basic details
        property_name = request.form.get('property_name', '').strip()
        project_name = request.form.get('project_name', '').strip()
        address = request.form.get('address', '').strip()
        location = request.form.get('location', '').strip()
        
        # Project details
        status = request.form.get('status', 'Active')
        project_type = request.form.get('project_type', '').strip()
        project_manager = request.form.get('project_manager', '').strip()
        due_date_str = request.form.get('due_date', '')
        
        # Financial details (optional)
        purchase_date_str = request.form.get('purchase_date', '')
        purchase_price = request.form.get('purchase_price', '')
        current_value = request.form.get('current_value', '')
        notes = request.form.get('notes', '')
        
        # Validate required fields
        if not property_name or not address:
            flash('Property name and address are required', 'danger')
            return redirect(url_for('new_property'))
        
        # Parse dates
        due_date = None
        if due_date_str:
            try:
                due_date = datetime.datetime.strptime(due_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid due date format', 'warning')
        
        purchase_date = None
        if purchase_date_str:
            try:
                purchase_date = datetime.datetime.strptime(purchase_date_str, '%Y-%m-%d').date()
            except ValueError:
                flash('Invalid purchase date format', 'warning')
        
        # Parse numeric values
        try:
            purchase_price = float(purchase_price) if purchase_price else None
            current_value = float(current_value) if current_value else None
        except ValueError:
            flash('Invalid numeric value format', 'warning')
            purchase_price = None
            current_value = None
        
        conn = None
        try:
            # Use geopy to get coordinates if not provided
            latitude = None
            longitude = None
            
            from geopy.geocoders import Nominatim
            geolocator = Nominatim(user_agent="propintel-app")
            
            try:
                location_obj = geolocator.geocode(address)
                if location_obj:
                    latitude = location_obj.latitude
                    longitude = location_obj.longitude
            except Exception as e:
                flash(f"Error geocoding address: {e}", "warning")
            
            # Get user ID from session
            user_id = g.user['user_id'] if g.user and g.user['user_id'] != 'guest' else None
            
            conn = get_db_connection()
            with conn.cursor() as cur:
                # Insert property record
                cur.execute("""
                    INSERT INTO propintel.properties 
                    (user_id, property_name, project_name, status, address, location,
                     project_type, project_manager, due_date, latitude, longitude,
                     purchase_date, purchase_price, current_value, notes)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    RETURNING property_id
                """, (user_id, property_name, project_name, status, address, location,
                      project_type, project_manager, due_date, latitude, longitude,
                      purchase_date, purchase_price, current_value, notes))
                
                property_id = cur.fetchone()[0]
                
                # Process uploaded images
                if 'property_images' in request.files:
                    images = request.files.getlist('property_images')
                    
                    for image in images:
                        if image and image.filename and allowed_file(image.filename):
                            # Create secure filename
                            filename = secure_random_filename(image.filename)
                            file_path = os.path.join(app.config['PROPERTY_IMAGES'], filename)
                            
                            # Read, optimize and save the image
                            image_data = image.read()
                            optimized_data = optimize_image(image_data)
                            
                            with open(file_path, 'wb') as f:
                                f.write(optimized_data)
                            
                            # Save image record in database
                            relative_path = os.path.join('images/properties', filename)
                            cur.execute("""
                                INSERT INTO propintel.property_images
                                (property_id, user_id, image_path, image_type, description, upload_date)
                                VALUES (%s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                            """, (property_id, user_id, relative_path, 'property', f"Image for {property_name}"))
                
                conn.commit()
                log_action('create', 'properties', property_id, f"Created property: {property_name}")
                
                flash(f"Property '{property_name}' created successfully", "success")
                return redirect(url_for('property_detail', property_id=property_id))
        except Exception as e:
            if conn:
                conn.rollback()
            flash(f"Error creating property: {e}", "danger")
        finally:
            if conn:
                conn.close()
    
    # Get project types and project managers for dropdown options
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT DISTINCT project_type FROM propintel.properties WHERE project_type IS NOT NULL ORDER BY project_type")
            project_types = [row['project_type'] for row in cur.fetchall()]
            
            cur.execute("SELECT DISTINCT project_manager FROM propintel.properties WHERE project_manager IS NOT NULL ORDER BY project_manager")
            project_managers = [row['project_manager'] for row in cur.fetchall()]
            
            cur.execute("SELECT DISTINCT status FROM propintel.properties WHERE status IS NOT NULL ORDER BY status")
            statuses = [row['status'] for row in cur.fetchall()]
            
    except Exception as e:
        project_types = []
        project_managers = []
        statuses = ['Active', 'Completed', 'On Hold', 'Cancelled']
    finally:
        if conn:
            conn.close()
    
    return render_template('property_form.html', 
                          project_types=project_types, 
                          project_managers=project_managers,
                          statuses=statuses)

@app.route('/property/<int:property_id>/work/new', methods=['GET', 'POST'])
@login_required
def new_work(property_id):
    """Add a new work record to a property"""
    logger.debug(f"\n===== NEW WORK ROUTE =====")
    logger.debug(f"g.user: {g.user}")
    
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
        
        if not work_description or not work_date:
            flash('Work description and date are required', 'danger')
            return redirect(url_for('new_work', property_id=property_id))
        
        try:
            work_date = datetime.datetime.strptime(work_date, '%Y-%m-%d').date()
            work_cost = float(work_cost) if work_cost else 0
        except ValueError:
            flash('Invalid date or cost format', 'danger')
            return redirect(url_for('new_work', property_id=property_id))
        
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as cur:
                # Insert work record with user ID
                cur.execute("""
                    INSERT INTO propintel.work 
                    (property_id, user_id, work_description, work_date, work_cost, payment_method, status)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING work_id
                """, (property_id, g.user['user_id'], work_description, work_date, work_cost, payment_method, status))
                
                work_id = cur.fetchone()[0]
                
                # Process uploaded images
                if 'work_images' in request.files:
                    images = request.files.getlist('work_images')
                    
                    for image in images:
                        if image and image.filename and allowed_file(image.filename):
                            # Create secure filename
                            filename = secure_random_filename(image.filename)
                            file_path = os.path.join(app.config['WORK_IMAGES'], filename)
                            
                            # Read, optimize and save the image
                            image_data = image.read()
                            optimized_data = optimize_image(image_data)
                            
                            with open(file_path, 'wb') as f:
                                f.write(optimized_data)
                            
                            # Save image record in database
                            relative_path = os.path.join('images/work', filename)
                            cur.execute("""
                                INSERT INTO propintel.property_images
                                (property_id, user_id, work_id, image_path, image_type, description, upload_date)
                                VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
                            """, (property_id, g.user['user_id'], work_id, relative_path, 'work', f"Image for work {work_id}"))
                
                conn.commit()
                log_action('create', 'work', work_id, f"Added work record to property {property_id}")
                
                flash("Work record added successfully", "success")
                return redirect(url_for('property_detail', property_id=property_id))
        except Exception as e:
            if conn:
                conn.rollback()
            flash(f"Error adding work record: {e}", "danger")
        finally:
            if conn:
                conn.close()
    
    # Get status options
    statuses = ['Pending', 'In Progress', 'Completed', 'Cancelled']
    
    return render_template('work_form.html', 
                          property_id=property_id, 
                          property_name=property_name,
                          statuses=statuses)

@app.route('/property/<int:property_id>/income/new', methods=['GET', 'POST'])
@login_required
def new_income(property_id):
    """Add a new income record to a property"""
    logger.debug(f"\n===== NEW INCOME ROUTE =====")
    logger.debug(f"g.user: {g.user}")
    
    if g.user['user_id'] == 'guest':
        flash('Guest users cannot add income records', 'warning')
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
            
            # Check if user has permission to add income to this property
            if g.user['role'] != 'admin' and g.user['user_id'] != property_data['user_id']:
                flash('You do not have permission to add income to this property', 'danger')
                return redirect(url_for('property_detail', property_id=property_id))
            
            property_name = property_data['property_name']
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('property_detail', property_id=property_id))
    finally:
        if conn:
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
        
        conn = None
        try:
            conn = get_db_connection()
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
            if conn:
                conn.rollback()
            flash(f"Error adding income record: {e}", "danger")
        finally:
            if conn:
                conn.close()
    
    # Get income categories for dropdown
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT DISTINCT income_category FROM propintel.money_in WHERE income_category IS NOT NULL ORDER BY income_category")
            categories = [row['income_category'] for row in cur.fetchall()]
    except Exception as e:
        categories = []
    finally:
        if conn:
            conn.close()
    
    return render_template('income_form.html', 
                          property_id=property_id, 
                          property_name=property_name,
                          categories=categories)

@app.route('/property/<int:property_id>/expense/new', methods=['GET', 'POST'])
@login_required
def new_expense(property_id):
    """Add a new expense record to a property"""
    logger.debug(f"\n===== NEW EXPENSE ROUTE =====")
    logger.debug(f"g.user: {g.user}")
    
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
            
            # Check if user has permission to add expenses to this property
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
        expense_category = request.form.get('expense_category', '').strip()
        
        if not expense_date or not expense_amount:
            flash('Date and amount are required', 'danger')
            return redirect(url_for('new_expense', property_id=property_id))
        
        try:
            expense_date = datetime.datetime.strptime(expense_date, '%Y-%m-%d').date()
            expense_amount = float(expense_amount)
        except ValueError:
            flash('Invalid date or amount format', 'danger')
            return redirect(url_for('new_expense', property_id=property_id))
        
        conn = None
        try:
            conn = get_db_connection()
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO propintel.money_out 
                    (property_id, user_id, expense_details, expense_date, expense_amount, payment_method, expense_category)
                    VALUES (%s, %s, %s, %s, %s, %s, %s)
                    RETURNING money_out_id
                """, (property_id, g.user['user_id'], expense_details, expense_date, expense_amount, payment_method, expense_category))
                
                expense_id = cur.fetchone()[0]
                conn.commit()
                
                log_action('create', 'money_out', expense_id, f"Added expense record to property {property_id}")
                flash("Expense record added successfully", "success")
                return redirect(url_for('property_detail', property_id=property_id))
        except Exception as e:
            if conn:
                conn.rollback()
            flash(f"Error adding expense record: {e}", "danger")
        finally:
            if conn:
                conn.close()
    
    # Get expense categories for dropdown
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("SELECT DISTINCT expense_category FROM propintel.money_out WHERE expense_category IS NOT NULL ORDER BY expense_category")
            categories = [row['expense_category'] for row in cur.fetchall()]
    except Exception as e:
        categories = []
    finally:
        if conn:
            conn.close()
    
    return render_template('expense_form.html', 
                          property_id=property_id, 
                          property_name=property_name,
                          categories=categories)

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
    
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
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
    
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
            conn.close()
    
    # Format data for charts
    project_type_labels = [pt['project_type'] for pt in project_types]
    project_type_data = [pt['count'] for pt in project_types]
    
    status_labels = [s['status'] for s in statuses]
    status_data = [s['count'] for s in statuses]
    
    return render_template('about.html',
                         property_count=property_count,
                         user_count=user_count,
                         total_income=total_income,
                         total_expenses=total_expenses,
                         profit=total_income - total_expenses,
                         project_type_labels=json.dumps(project_type_labels),
                         project_type_data=json.dumps(project_type_data),
                         status_labels=json.dumps(status_labels),
                         status_data=json.dumps(status_data))

@app.route('/debug/session')
def debug_session_route():
    """Diagnostic route to view session state"""
    return jsonify({
        'session': dict(session),
        'g_user': g.user,
        'request_path': request.path,
        'cookies': dict(request.cookies)
    })

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
    conn = None
    try:
        conn = get_db_connection()
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
        if conn:
            conn.close()

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') == 'development'
    
    # Print session configuration info
    print("\nSession configuration:")
    print(f"- Secret key length: {len(app.secret_key)} bytes")
    print(f"- Session type: {app.config.get('SESSION_TYPE', 'client-side')}")
    print(f"- Session lifetime: {app.config.get('PERMANENT_SESSION_LIFETIME')}")
    print(f"- Session file dir: {app.config.get('SESSION_FILE_DIR', 'Not set')}")
    print(f"- Cookie secure: {app.config.get('SESSION_COOKIE_SECURE')}")
    print(f"- Cookie httponly: {app.config.get('SESSION_COOKIE_HTTPONLY')}")
    print(f"- Cookie samesite: {app.config.get('SESSION_COOKIE_SAMESITE', 'Not set')}")
    
    app.run(host='127.0.0.1', port=port, debug=debug)
                          