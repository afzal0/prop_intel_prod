from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, g
import os
import psycopg2
from psycopg2.extras import RealDictCursor
import configparser
from werkzeug.utils import secure_filename
import tempfile
import datetime
import json
import uuid
import hashlib
from functools import wraps

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
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

# Create necessary folders
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs('static', exist_ok=True)

# Default center of Melbourne
MELBOURNE_CENTER = [-37.8136, 144.9631]

# Dummy users database (in production, use a real database)
USERS = {
    'admin': {
        'username': 'admin',
        'password': hashlib.sha256('admin123'.encode()).hexdigest(),
        'name': 'Administrator',
        'role': 'admin'
    }
}

# Session management
@app.before_request
def before_request():
    g.user = None
    if 'user_id' in session:
        user = USERS.get(session['user_id'])
        if user:
            g.user = user

# Login required decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if g.user is None:
            flash('Please log in to access this page', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

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
            
            # Get all property locations for the map
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
        flash(f"Error loading dashboard: {e}", "danger")
        property_count = 0
        geojson = {"type": "FeatureCollection", "features": []}
    finally:
        conn.close()
    
    return render_template('property_search.html', 
                          property_count=property_count,
                          geojson=json.dumps(geojson),
                          center_lat=MELBOURNE_CENTER[0],
                          center_lng=MELBOURNE_CENTER[1])

@app.route('/search')
def property_search():
    """Advanced property search view with map"""
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
        flash(f"Error loading property map: {e}", "danger")
        geojson = {"type": "FeatureCollection", "features": []}
    finally:
        conn.close()
    
    return render_template('property_search.html', 
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

@app.route('/login', methods=['GET', 'POST'])
def login():
    """User login page"""
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        # Check for guest login
        if username == 'guest':
            session['user_id'] = 'guest'
            session['is_guest'] = True
            flash('Logged in as guest', 'info')
            return redirect(request.args.get('next') or url_for('index'))
        
        # Regular login
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        user = USERS.get(username)
        
        if user and user['password'] == password_hash:
            session['user_id'] = username
            session['is_guest'] = False
            flash(f'Welcome back, {user["name"]}!', 'success')
            return redirect(request.args.get('next') or url_for('index'))
        else:
            flash('Invalid username or password', 'danger')
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    """User logout"""
    session.pop('user_id', None)
    session.pop('is_guest', None)
    flash('You have been logged out', 'info')
    return redirect(url_for('index'))

@app.route('/upload', methods=['GET', 'POST'])
@login_required
def upload_file():
    """Page for uploading Excel files to process"""
    if session.get('is_guest'):
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
    # Get search parameters
    search = request.args.get('search', '')
    
    conn = get_db_connection()
    try:
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            if search:
                # Search by name or address
                cur.execute("""
                    SELECT p.*, 
                           COUNT(DISTINCT w.work_id) AS work_count,
                           COUNT(DISTINCT mi.money_in_id) AS income_count,
                           COUNT(DISTINCT mo.money_out_id) AS expense_count
                    FROM propintel.properties p
                    LEFT JOIN propintel.work w ON p.property_id = w.property_id
                    LEFT JOIN propintel.money_in mi ON p.property_id = mi.property_id
                    LEFT JOIN propintel.money_out mo ON p.property_id = mo.property_id
                    WHERE p.property_name ILIKE %s OR p.address ILIKE %s
                    GROUP BY p.property_id
                    ORDER BY p.property_id
                """, (f'%{search}%', f'%{search}%'))
            else:
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
    except Exception as e:
        flash(f"Error loading properties: {e}", "danger")
        properties = []
    finally:
        conn.close()
    
    return render_template('properties.html', properties=properties, search=search)

@app.route('/property/<int:property_id>')
def property_detail(property_id):
    """View details for a specific property"""
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
    
    return render_template('property_detail.html', 
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

@app.route('/map')
def map_view():
    """View all properties on a map"""
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
        flash(f"Error loading map: {e}", "danger")
        geojson = {"type": "FeatureCollection", "features": []}
    finally:
        conn.close()
    
    return render_template('map.html', 
                          geojson=json.dumps(geojson),
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
    """Add a new property"""
    if session.get('is_guest'):
        flash('Guest users cannot add properties', 'warning')
        return redirect(url_for('properties'))
        
    if request.method == 'POST':
        property_name = request.form.get('property_name')
        address = request.form.get('address')
        
        if not property_name or not address:
            flash('Property name and address are required', 'danger')
            return redirect(url_for('new_property'))
        
        conn = get_db_connection()
        try:
            # Use geopy to get coordinates
            from geopy.geocoders import Nominatim
            geolocator = Nominatim(user_agent="propintel-app")
            
            location = None
            try:
                location = geolocator.geocode(address)
            except Exception as e:
                flash(f"Error geocoding address: {e}", "warning")
            
            latitude = location.latitude if location else None
            longitude = location.longitude if location else None
            
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO propintel.properties (property_name, address, latitude, longitude)
                    VALUES (%s, %s, %s, %s)
                    RETURNING property_id
                """, (property_name, address, latitude, longitude))
                
                property_id = cur.fetchone()[0]
                conn.commit()
                
                flash(f"Property '{property_name}' created successfully", "success")
                return redirect(url_for('property_detail', property_id=property_id))
        except Exception as e:
            conn.rollback()
            flash(f"Error creating property: {e}", "danger")
        finally:
            conn.close()
    
    return render_template('property_form.html')

@app.route('/property/<int:property_id>/work/new', methods=['GET', 'POST'])
@login_required
def new_work(property_id):
    """Add a new work record to a property"""
    if session.get('is_guest'):
        flash('Guest users cannot add work records', 'warning')
        return redirect(url_for('property_detail', property_id=property_id))
        
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT property_id, property_name FROM propintel.properties WHERE property_id = %s", (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                flash('Property not found', 'danger')
                return redirect(url_for('properties'))
            
            property_name = property_data[1]
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('property_detail', property_id=property_id))
    finally:
        conn.close()
    
    if request.method == 'POST':
        work_description = request.form.get('work_description')
        work_date = request.form.get('work_date')
        work_cost = request.form.get('work_cost')
        payment_method = request.form.get('payment_method')
        
        if not work_description or not work_date:
            flash('Work description and date are required', 'danger')
            return redirect(url_for('new_work', property_id=property_id))
        
        try:
            work_date = datetime.datetime.strptime(work_date, '%Y-%m-%d').date()
            work_cost = float(work_cost) if work_cost else 0
        except ValueError:
            flash('Invalid date or cost format', 'danger')
            return redirect(url_for('new_work', property_id=property_id))
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO propintel.work (property_id, work_description, work_date, work_cost, payment_method)
                    VALUES (%s, %s, %s, %s, %s)
                """, (property_id, work_description, work_date, work_cost, payment_method))
                conn.commit()
                
                flash("Work record added successfully", "success")
                return redirect(url_for('property_detail', property_id=property_id))
        except Exception as e:
            conn.rollback()
            flash(f"Error adding work record: {e}", "danger")
        finally:
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
        with conn.cursor() as cur:
            cur.execute("SELECT property_id, property_name FROM propintel.properties WHERE property_id = %s", (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                flash('Property not found', 'danger')
                return redirect(url_for('properties'))
            
            property_name = property_data[1]
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('property_detail', property_id=property_id))
    finally:
        conn.close()
    
    if request.method == 'POST':
        income_details = request.form.get('income_details')
        income_date = request.form.get('income_date')
        income_amount = request.form.get('income_amount')
        payment_method = request.form.get('payment_method')
        
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
                    INSERT INTO propintel.money_in (property_id, income_details, income_date, income_amount, payment_method)
                    VALUES (%s, %s, %s, %s, %s)
                """, (property_id, income_details, income_date, income_amount, payment_method))
                conn.commit()
                
                flash("Income record added successfully", "success")
                return redirect(url_for('property_detail', property_id=property_id))
        except Exception as e:
            conn.rollback()
            flash(f"Error adding income record: {e}", "danger")
        finally:
            conn.close()
    
    return render_template('income_form.html', property_id=property_id, property_name=property_name)

@app.route('/property/<int:property_id>/expense/new', methods=['GET', 'POST'])
@login_required
def new_expense(property_id):
    """Add a new expense record to a property"""
    if session.get('is_guest'):
        flash('Guest users cannot add expense records', 'warning')
        return redirect(url_for('property_detail', property_id=property_id))
        
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT property_id, property_name FROM propintel.properties WHERE property_id = %s", (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                flash('Property not found', 'danger')
                return redirect(url_for('properties'))
            
            property_name = property_data[1]
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('property_detail', property_id=property_id))
    finally:
        conn.close()
    
    if request.method == 'POST':
        expense_details = request.form.get('expense_details')
        expense_date = request.form.get('expense_date')
        expense_amount = request.form.get('expense_amount')
        payment_method = request.form.get('payment_method')
        
        if not expense_date or not expense_amount:
            flash('Date and amount are required', 'danger')
            return redirect(url_for('new_expense', property_id=property_id))
        
        try:
            expense_date = datetime.datetime.strptime(expense_date, '%Y-%m-%d').date()
            expense_amount = float(expense_amount)
        except ValueError:
            flash('Invalid date or amount format', 'danger')
            return redirect(url_for('new_expense', property_id=property_id))
        
        conn = get_db_connection()
        try:
            with conn.cursor() as cur:
                cur.execute("""
                    INSERT INTO propintel.money_out (property_id, expense_details, expense_date, expense_amount, payment_method)
                    VALUES (%s, %s, %s, %s, %s)
                """, (property_id, expense_details, expense_date, expense_amount, payment_method))
                conn.commit()
                
                flash("Expense record added successfully", "success")
                return redirect(url_for('property_detail', property_id=property_id))
        except Exception as e:
            conn.rollback()
            flash(f"Error adding expense record: {e}", "danger")
        finally:
            conn.close()
    
    return render_template('expense_form.html', property_id=property_id, property_name=property_name)

@app.route('/search')
def search():
    """Search for properties"""
    query = request.args.get('q', '')
    
    if not query:
        return redirect(url_for('properties'))
    
    return redirect(url_for('properties', search=query))

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

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV') == 'development'
    app.run(host='127.0.0.1', port=port, debug=debug)