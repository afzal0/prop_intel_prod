import os
import datetime
from werkzeug.utils import secure_filename
from flask import g, redirect, url_for, flash, request, abort, render_template
import psycopg2
from psycopg2.extras import RealDictCursor

# Database configuration
DB_CONFIG = {
    'user': 'postgres',
    'password': '1234',
    'host': 'localhost',
    'port': '5432',
    'database': 'postgres'
}

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

# File upload configuration
UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static/images')
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max upload size

# Helper function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# Updated route to handle new property with image upload
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

# Updated route to handle work record with image upload and expense categorization
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

# Updated route to handle expense records with image upload and categorization
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

# Modified property_detail route to include expense categorization and images
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
            
            # Initialize empty lists for records that might not exist
            property_images = []
            work_images = []
            
            # Get property images
            try:
                cur.execute("""
                    SELECT * FROM propintel.property_images 
                    WHERE property_id = %s AND image_type = 'property'
                    ORDER BY upload_date DESC
                """, (property_id,))
                property_images = cur.fetchall() or []
            except psycopg2.Error:
                # Table might not exist, continue without images
                pass
            
            # Get work records
            cur.execute("""
                SELECT * FROM propintel.work 
                WHERE property_id = %s
                ORDER BY work_date DESC
            """, (property_id,))
            work_records = cur.fetchall()
            
            # Add image_path to work records if possible
            try:
                for idx, record in enumerate(work_records):
                    cur.execute("""
                        SELECT image_path FROM propintel.property_images 
                        WHERE property_id = %s AND image_type = 'work' 
                            AND description LIKE %s
                        LIMIT 1
                    """, (property_id, f"%{record['work_description']}%"))
                    image_result = cur.fetchone()
                    if image_result:
                        work_records[idx]['image_path'] = image_result['image_path']
            except psycopg2.Error:
                # Table might not exist, continue without images
                pass
            
            # Get work images
            try:
                cur.execute("""
                    SELECT * FROM propintel.property_images 
                    WHERE property_id = %s AND image_type = 'work'
                    ORDER BY upload_date DESC
                """, (property_id,))
                work_images = cur.fetchall() or []
            except psycopg2.Error:
                # Table might not exist, continue without images
                pass
            
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
            
            # Add image_path to expense records if possible
            try:
                for idx, record in enumerate(expense_records):
                    cur.execute("""
                        SELECT image_path FROM propintel.property_images 
                        WHERE property_id = %s AND image_type = 'receipt' 
                            AND description LIKE %s
                        LIMIT 1
                    """, (property_id, f"%{record['expense_details']}%"))
                    image_result = cur.fetchone()
                    if image_result:
                        expense_records[idx]['image_path'] = image_result['image_path']
            except psycopg2.Error:
                # Table might not exist, continue without images
                pass
            
            # Initialize expense category totals
            expense_categories = {
                'wage_total': 0,
                'pm_total': 0,
                'material_total': 0,
                'misc_total': 0
            }
            
            # Calculate expense totals by category if the column exists
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
                    expense_categories = category_result
            except psycopg2.Error:
                # If expense_category column doesn't exist, categorize manually
                for record in expense_records:
                    amount = record['expense_amount'] or 0
                    details = (record.get('expense_details', '') or '').lower()
                    
                    if 'wage' in details or 'salary' in details:
                        expense_categories['wage_total'] += amount
                    elif 'project manager' in details or 'pm ' in details:
                        expense_categories['pm_total'] += amount
                    elif 'material' in details or 'supplies' in details:
                        expense_categories['material_total'] += amount
                    else:
                        expense_categories['misc_total'] += amount
            
            # Calculate totals
            income_total = sum(record['income_amount'] for record in income_records)
            expense_total = sum(record['expense_amount'] for record in expense_records)
            work_total = sum(record['work_cost'] for record in work_records if record['work_cost'])
            net_total = income_total - expense_total
            
            # Get monthly trend data for charts
            trend_months = {}
            for record in income_records:
                month_key = record['income_date'].strftime('%Y-%m')
                if month_key not in trend_months:
                    trend_months[month_key] = {'income': 0, 'expense': 0}
                trend_months[month_key]['income'] += record['income_amount']
            
            for record in expense_records:
                month_key = record['expense_date'].strftime('%Y-%m')
                if month_key not in trend_months:
                    trend_months[month_key] = {'income': 0, 'expense': 0}
                trend_months[month_key]['expense'] += record['expense_amount']
            
            # Sort months for chart display
            sorted_months = sorted(trend_months.keys())
            trend_labels = [month for month in sorted_months]
            income_data = [trend_months[month]['income'] for month in sorted_months]
            expense_data = [trend_months[month]['expense'] for month in sorted_months]
            
            # Default map coordinates if property doesn't have lat/long
            map_lat = property_data.get('latitude', 40.7128) or 40.7128
            map_lng = property_data.get('longitude', -74.0060) or -74.0060
            
    except Exception as e:
        flash(f"Error: {e}", "danger")
        return redirect(url_for('properties'))
    finally:
        if conn:
            conn.close()
    
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
        wage_expense_total=expense_categories['wage_total'],
        pm_expense_total=expense_categories['pm_total'],
        material_expense_total=expense_categories['material_total'],
        misc_expense_total=expense_categories['misc_total']
    )