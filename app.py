import os
import sys
import logging
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import psycopg2
from psycopg2.extras import RealDictCursor
import configparser
from werkzeug.utils import secure_filename
import tempfile
import datetime
import json
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger()

# Create Flask app
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', '70d0bad2f44c1fbd0c9e1765837225677012174de7bc02e698a1319f24b49302d6348f39c225f35e56dc350473ff47ab9895e7c1abb24a7ed80647eb483bb5319d7ab0ea52884d329b27d32ab112da0a')
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB limit

# Create upload folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Default center of Melbourne
MELBOURNE_CENTER = [-37.8136, 144.9631]

def get_db_config():
    """
    Get database configuration from environment variable (for Heroku)
    or from config file (for local development)
    """
    # Check for DATABASE_URL environment variable (set by Heroku)
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Parse Heroku DATABASE_URL
        # Note: Heroku uses 'postgres://' but psycopg2 needs 'postgresql://'
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
        # Parse the URL
        result = urlparse(database_url)
        
        # Build connection parameters
        return {
            "user": result.username,
            "password": result.password,
            "host": result.hostname,
            "port": result.port or 5432,
            "database": result.path[1:],  # Remove leading slash
        }
    else:
        # Fallback to config file for local development
        config = configparser.ConfigParser()
        
        # Default connection parameters
        default_params = {
            "user": "prop_intel",
            "password": "nyrty7-cytrit-qePkyf",
            "host": "propintel.postgres.database.azure.com",
            "port": 5432,
            "database": "postgres",
        }
        
        # Try to read from config file
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

def get_db_connection():
    """Get a connection to the PostgreSQL database"""
    conn_params = get_db_config()
    logger.info(f"Connecting to database at {conn_params['host']}:{conn_params['port']}/{conn_params['database']}")
    conn = psycopg2.connect(**conn_params)
    return conn

@app.route('/')
def index():
    """Home page with dashboard overview"""
    # Get property count
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Get property count
            cur.execute("SELECT COUNT(*) FROM propintel.properties")
            property_count = cur.fetchone()[0]
            
            # Get work record count and total cost
            cur.execute("""
                SELECT COUNT(*), SUM(work_cost) 
                FROM propintel.work
            """)
            work_data = cur.fetchone()
            work_count = work_data[0]
            work_total = work_data[1] if work_data[1] else 0
            
            # Get money in count and total
            cur.execute("""
                SELECT COUNT(*), SUM(income_amount) 
                FROM propintel.money_in
            """)
            income_data = cur.fetchone()
            income_count = income_data[0]
            income_total = income_data[1] if income_data[1] else 0
            
            # Get money out count and total
            cur.execute("""
                SELECT COUNT(*), SUM(expense_amount) 
                FROM propintel.money_out
            """)
            expense_data = cur.fetchone()
            expense_count = expense_data[0]
            expense_total = expense_data[1] if expense_data[1] else 0
            
            # Get recent properties
            cur.execute("""
                SELECT property_id, property_name, address 
                FROM propintel.properties 
                ORDER BY property_id DESC LIMIT 5
            """)
            recent_properties = cur.fetchall()
    except Exception as e:
        logger.error(f"Database error: {e}")
        flash(f"Database error: {e}", "danger")
        return render_template('error.html', error=str(e))
    finally:
        conn.close()
    
    return render_template('index.html', 
                          property_count=property_count,
                          work_count=work_count,
                          work_total=work_total,
                          income_count=income_count,
                          income_total=income_total,
                          expense_count=expense_count,
                          expense_total=expense_total,
                          recent_properties=recent_properties)

@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    """Page for uploading Excel files to process"""
    if request.method == 'POST':
        # Check if the post request has the file part
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        
        file = request.files['file']
        
        # If user does not select file, browser also
        # submits an empty part without filename
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            # Process the file
            try:
                # Import the extractor here to avoid circular imports
                import property_data_extractor as extractor
                extractor.extract_data_from_excel(file_path)
                flash(f'Successfully processed {filename}')
            except Exception as e:
                flash(f'Error processing file: {e}')
            
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
        logger.error(f"Database error: {e}")
        flash(f"Database error: {e}", "danger")
        return render_template('error.html', error=str(e))
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
                flash('Property not found')
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
            
            # Calculate totals
            work_total = sum(float(record['work_cost'] or 0) for record in work_records)
            income_total = sum(float(record['income_amount'] or 0) for record in income_records)
            expense_total = sum(float(record['expense_amount'] or 0) for record in expense_records)
            net_total = income_total - expense_total - work_total
    except Exception as e:
        logger.error(f"Database error: {e}")
        flash(f"Database error: {e}", "danger")
        return render_template('error.html', error=str(e))
    finally:
        conn.close()
    
    # Use property coords if available, otherwise default to Melbourne
    map_lat = property_data['latitude'] if property_data['latitude'] else MELBOURNE_CENTER[0]
    map_lng = property_data['longitude'] if property_data['longitude'] else MELBOURNE_CENTER[1]
    
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
                          map_lng=map_lng)

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
        logger.error(f"Database error: {e}")
        flash(f"Database error: {e}", "danger")
        return render_template('error.html', error=str(e))
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
        logger.error(f"API error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
    
    return jsonify(geojson)

@app.route('/api/property-count')
def property_count_api():
    """API endpoint for property count"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT COUNT(*) FROM propintel.properties")
            count = cur.fetchone()[0]
    except Exception as e:
        logger.error(f"API error: {e}")
        return jsonify({'error': str(e)}), 500
    finally:
        conn.close()
    
    return jsonify({'count': count})

@app.route('/debug')
def debug_info():
    """Debug endpoint to help diagnose issues"""
    import sys
    import platform
    
    # Basic information
    debug_data = {
        'python_version': sys.version,
        'platform': platform.platform(),
        'working_directory': os.getcwd(),
        'environment': os.environ.get('FLASK_ENV', 'not set'),
    }
    
    # Check for essential directories
    directories = ['templates', 'static', 'uploads']
    dir_status = {}
    for dir_name in directories:
        dir_path = os.path.join(os.getcwd(), dir_name)
        dir_status[dir_name] = {
            'exists': os.path.exists(dir_path),
            'is_dir': os.path.isdir(dir_path) if os.path.exists(dir_path) else False
        }
        if dir_status[dir_name]['exists'] and dir_status[dir_name]['is_dir']:
            try:
                dir_status[dir_name]['contents'] = os.listdir(dir_path)[:10]  # First 10 files
            except:
                dir_status[dir_name]['contents'] = 'Error listing contents'
    
    debug_data['directories'] = dir_status
    
    # Test database connection
    db_status = 'Not tested'
    try:
        conn_params = get_db_config()
        # Mask password
        masked_params = conn_params.copy()
        if 'password' in masked_params:
            masked_params['password'] = '*****'
        debug_data['db_connection_params'] = masked_params
        
        # Try to connect
        conn = psycopg2.connect(**conn_params)
        with conn.cursor() as cur:
            cur.execute('SELECT version();')
            db_version = cur.fetchone()[0]
        conn.close()
        db_status = f'Connected: {db_version}'
    except Exception as e:
        db_status = f'Error: {str(e)}'
    
    debug_data['database_status'] = db_status
    
    return jsonify(debug_data)

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

@app.errorhandler(404)
def page_not_found(e):
    return render_template('error.html', error='Page not found'), 404

@app.errorhandler(500)
def server_error(e):
    return render_template('error.html', error='Server error occurred'), 500

# Create an error.html template for error handling
if not os.path.exists('templates/error.html'):
    os.makedirs('templates', exist_ok=True)
    with open('templates/error.html', 'w') as f:
        f.write('''
        {% extends "base.html" %}
        {% block title %}Error{% endblock %}
        {% block content %}
        <div class="container">
            <div class="row justify-content-center">
                <div class="col-lg-8">
                    <div class="card shadow mb-4">
                        <div class="card-header py-3">
                            <h6 class="m-0 font-weight-bold text-danger">Error</h6>
                        </div>
                        <div class="card-body">
                            <div class="text-center mb-4">
                                <i class="fas fa-exclamation-triangle fa-3x text-warning mb-3"></i>
                                <h4 class="text-gray-900">Something went wrong!</h4>
                                <p class="text-gray-600">{{ error }}</p>
                            </div>
                            <div class="text-center">
                                <a href="{{ url_for('index') }}" class="btn btn-primary">
                                    <i class="fas fa-home me-2"></i>Return to Dashboard
                                </a>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
        {% endblock %}
        ''')

if __name__ == '__main__':
    # Use the PORT environment variable provided by Heroku, or default to 5000
    port = int(os.environ.get('PORT', 5000))
    
    # In production, we're using Gunicorn so this won't be called
    app.run(host='0.0.0.0', port=port)