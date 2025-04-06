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
app.config['ALLOWED_EXTENSIONS'] = {'png', 'jpg', 'jpeg', 'gif','pdf'}
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit
app.config['SESSION_COOKIE_SECURE'] = os.environ.get('FLASK_ENV') != 'development'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_KEY_PREFIX'] = 'propintel_session_'  # Prefix for session keys
app.config["SESSION_PERMANENT"] = True
app.config["SESSION_TYPE"] = "filesystem"
app.config["SESSION_FILE_DIR"] = os.path.join(os.path.dirname(os.path.abspath(__file__)), "flask_session")
app.config["PERMANENT_SESSION_LIFETIME"] = datetime.timedelta(days=31)
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/images')
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
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']


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
    """Budget planning page"""
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get list of properties
            cur.execute("""
                SELECT property_id, property_name 
                FROM propintel.properties
                WHERE is_hidden IS NOT TRUE
                ORDER BY property_name
            """)
            properties = cur.fetchall()
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('index'))
    finally:
        if conn:
            conn.close()
            
    return render_template('budget_planner.html', properties=properties)
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
    """View all properties on a map with building polygons from OpenStreetMap"""
    from analytics_dashboard import prepare_property_geojson
    
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property data with financial information for budget analysis
            cur.execute("""
                SELECT p.property_id, p.property_name, p.address, p.location, p.latitude, p.longitude,
                       COALESCE(SUM(mi.income_amount), 0) as total_income,
                       COALESCE(SUM(mo.expense_amount), 0) as total_expenses,
                       COALESCE(SUM(w.work_cost), 0) as work_cost,
                       COUNT(w.work_id) as work_count,
                       COUNT(mi.money_in_id) as income_count,
                       COUNT(mo.money_out_id) as expense_count
                FROM propintel.properties p
                LEFT JOIN propintel.money_in mi ON p.property_id = mi.property_id
                LEFT JOIN propintel.money_out mo ON p.property_id = mo.property_id
                LEFT JOIN propintel.work w ON p.property_id = w.property_id
                WHERE p.latitude IS NOT NULL AND p.longitude IS NOT NULL
                GROUP BY p.property_id, p.property_name, p.address, p.location, p.latitude, p.longitude
            """)
            properties = cur.fetchall()
            
            # Use the prepare_property_geojson function with polygon fetching enabled
            geojson = prepare_property_geojson(properties, fetch_polygons=True)
            
    except Exception as e:
        flash(f"Error loading map: {e}", "danger")
        geojson = {"type": "FeatureCollection", "features": []}
    finally:
        conn.close()
    
    return render_template('map.html', 
                          geojson=standard_json.dumps(geojson, cls=DecimalJSONEncoder),
                          center_lat=MELBOURNE_CENTER[0],
                          center_lng=MELBOURNE_CENTER[1])

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
    port = int(os.environ.get('PORT', 5001))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='127.0.0.1', port=port, debug=debug)