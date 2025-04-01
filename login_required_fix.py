#!/usr/bin/env python3
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
