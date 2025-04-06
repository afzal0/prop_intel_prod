import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor
from flask import Flask, flash, redirect, url_for, render_template, g, session

# Create a simple test Flask app
app = Flask(__name__)
app.secret_key = 'testing_secret_key'

# Database configuration
DB_CONFIG = {
    'user': 'postgres',
    'password': '1234',
    'host': 'localhost',
    'port': '5432',
    'database': 'postgres'
}

# Custom template filters
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
    '''Format a date as DD/MM/YYYY'''
    if value is None:
        return ""
    try:
        return value.strftime('%d/%m/%Y')
    except AttributeError:
        return value

def get_db_connection():
    """Get a database connection using the provided configuration"""
    conn = psycopg2.connect(
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        host=DB_CONFIG['host'],
        port=DB_CONFIG['port'],
        dbname=DB_CONFIG['database']
    )
    conn.autocommit = False
    return conn

@app.before_request
def load_logged_in_user():
    """Load user information before each request"""
    g.user = {'user_id': session.get('user_id', 'guest'), 'role': 'user'}

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/properties')
def properties():
    return redirect(url_for('index'))

def property_detail(property_id):
    """Detailed view of a property"""
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
                # Manual categorization since it's the most reliable
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
                # If all categorization fails, use empty categories (already initialized)
                pass
            
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
    
    # Serialize chart data for JavaScript
    import json
    trend_labels_json = json.dumps(trend_labels)
    income_data_json = json.dumps(income_data)
    expense_data_json = json.dumps(expense_data)
    
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
        trend_labels=trend_labels_json,
        income_data=income_data_json,
        expense_data=expense_data_json,
        map_lat=map_lat,
        map_lng=map_lng,
        wage_expense_total=wage_expense_total,
        pm_expense_total=pm_expense_total,
        material_expense_total=material_expense_total,
        misc_expense_total=misc_expense_total
    )

# Add the route for property_detail
app.route('/property/<int:property_id>')(property_detail)

if __name__ == '__main__':
    app.run(debug=True, port=5001)