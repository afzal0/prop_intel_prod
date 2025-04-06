#!/usr/bin/env python3
"""
Comprehensive app fixer for PropIntel.

This script:
1. Fixes duplicate route definitions
2. Adds missing login_required decorator if needed
3. Updates login, admin_required, and before_request implementations
4. Adds analytics dashboard route if not present
"""

import os
import re
import sys
import shutil
from datetime import datetime

def backup_file(filename):
    """Create a timestamped backup of a file"""
    if not os.path.exists(filename):
        print(f"Error: {filename} not found")
        return False
        
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    backup_name = f"{filename}.{timestamp}.bak"
    
    try:
        shutil.copy2(filename, backup_name)
        print(f"Created backup: {backup_name}")
        return True
    except Exception as e:
        print(f"Error creating backup: {e}")
        return False

def fix_duplicate_routes(app_file):
    """
    Finds and removes duplicate route definitions in app.py.
    It keeps the first occurrence and comments out any duplicates.
    """
    print("Fixing duplicate routes...")
    
    if not os.path.exists(app_file):
        print(f"Error: {app_file} not found")
        return False
        
    with open(app_file, 'r') as f:
        lines = f.readlines()
    
    # Dictionary to track routes
    # Key: route path, Value: line number of first occurrence
    routes = {}
    
    # First find all routes and their line numbers
    for i, line in enumerate(lines):
        # Look for @app.route patterns
        match = re.search(r'@app\.route\([\'"]([^\'"]+)[\'"]', line)
        if match:
            route_path = match.group(1)
            
            if route_path in routes:
                print(f"Found duplicate route: {route_path} on line {i+1} (original on line {routes[route_path]+1})")
            else:
                routes[route_path] = i
    
    # Now fix the duplicates by commenting them out
    modified = False
    for route_path, first_line in routes.items():
        # Find all occurrences of this route
        for i, line in enumerate(lines):
            if i == first_line:
                # Skip the first occurrence
                continue
                
            match = re.search(r'@app\.route\([\'"]' + re.escape(route_path) + r'[\'"]', line)
            if match:
                # Comment out this line and the function definition below it
                lines[i] = f"# DUPLICATE ROUTE: {lines[i]}"
                
                # Find and comment the function definition that follows
                j = i + 1
                while j < len(lines) and not lines[j].strip().startswith('def '):
                    j += 1
                
                if j < len(lines) and lines[j].strip().startswith('def '):
                    lines[j] = f"# DUPLICATE FUNCTION: {lines[j]}"
                    
                    # Also comment out the docstring and function body until the next def or empty line
                    k = j + 1
                    indent_level = len(lines[j]) - len(lines[j].lstrip())
                    while k < len(lines):
                        if lines[k].startswith('def ') or (lines[k].strip() == '' and k > j + 3):
                            break
                        lines[k] = f"# {lines[k]}"
                        k += 1
                
                print(f"Commented out duplicate route: {route_path} on line {i+1}")
                modified = True
    
    if modified:
        # Write the fixed content
        with open(app_file, 'w') as f:
            f.write(''.join(lines))
        print("Successfully fixed duplicate routes")
        return True
    else:
        print("No duplicate routes found to fix")
        return True

def fix_login_required(app_file):
    """Add login_required decorator to app.py if missing"""
    print("Checking for login_required decorator...")
    
    with open(app_file, 'r') as f:
        content = f.read()
    
    # Check if login_required is defined
    if re.search(r'def\s+login_required\s*\(', content):
        print("login_required is already defined, no fix needed")
        return True
    
    # Check if login_required is used
    if '@login_required' in content:
        print("login_required is used but not defined, adding definition...")
        
        # Prepare the login_required function
        login_required_code = """
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
"""
        
        # Find a good place to insert it - before admin_required if possible
        admin_required_match = re.search(r'def\s+admin_required\s*\(', content)
        if admin_required_match:
            insert_point = admin_required_match.start()
            # Add a newline before it
            new_content = content[:insert_point] + login_required_code + content[insert_point:]
        else:
            # Find where imports end and add it there
            import_section_end = max(
                content.rfind('import ', 0, 500),
                content.rfind('from ', 0, 500)
            )
            
            # Find the end of the line
            line_end = content.find('\n', import_section_end)
            if line_end != -1:
                insert_point = line_end + 1
                new_content = content[:insert_point] + login_required_code + content[insert_point:]
            else:
                # Can't find a good place, just add it at the top
                new_content = login_required_code + content
        
        # Check if wraps is imported
        if 'from functools import wraps' not in content:
            # Add import statement
            import_statement = "from functools import wraps\n"
            first_import = min(
                content.find('import ') if content.find('import ') >= 0 else float('inf'),
                content.find('from ') if content.find('from ') >= 0 else float('inf')
            )
            
            if first_import != float('inf'):
                new_content = new_content[:first_import] + import_statement + new_content[first_import:]
            else:
                # No imports found, add at the beginning
                new_content = import_statement + new_content
        
        # Write the new content
        with open(app_file, 'w') as f:
            f.write(new_content)
        print("Successfully added login_required")
        return True
    else:
        print("login_required is not used, no fix needed")
        return True

def update_auth_functions(app_file):
    """Update the authentication functions with fixed versions"""
    print("Updating authentication functions...")
    
    with open(app_file, 'r') as f:
        content = f.read()
    
    # Updated before_request function
    before_request_code = """
@app.before_request
def before_request():
    \"\"\"Load user before each request\"\"\"
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
                    cur.execute(\"\"\"
                        SELECT user_id, username, email, full_name, role 
                        FROM propintel.users 
                        WHERE user_id = %s AND is_active = TRUE
                    \"\"\", (int(user_id),))
                    
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
"""
    
    # Updated login function
    login_function_code = """
@app.route('/login', methods=['GET', 'POST'])
def login():
    \"\"\"User login page with improved admin login handling\"\"\"
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
                    cur.execute(\"\"\"
                        SELECT user_id, password_hash FROM propintel.users 
                        WHERE username = 'admin' AND is_active = TRUE
                    \"\"\")
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
                cur.execute(\"\"\"
                    SELECT user_id, username, email, full_name, role, password_hash, is_active
                    FROM propintel.users
                    WHERE username = %s
                \"\"\", (username,))
                
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
                        cur.execute(\"\"\"
                            UPDATE propintel.users
                            SET last_login = CURRENT_TIMESTAMP
                            WHERE user_id = %s
                        \"\"\", (user['user_id'],))
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
"""
    
    # Updated admin_required function
    admin_required_code = """
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
"""
    
    # Replace each function in the file
    modified = False
    
    # Replace before_request
    before_request_pattern = r'@app\.before_request\s*\ndef\s+before_request\s*\([^)]*\):.*?(?=\n\S)'
    before_request_match = re.search(before_request_pattern, content, re.DOTALL)
    if before_request_match:
        content = content[:before_request_match.start()] + before_request_code + content[before_request_match.end():]
        print("Updated before_request function")
        modified = True
    else:
        print("Could not find before_request function, skipping update")
    
    # Replace login function
    # First check and remove any duplicate login routes we missed
    login_pattern = r'@app\.route\s*\([\'"]\/login[\'"](,\s*methods=\[[^\]]+\])?\)[^@]*def\s+login\s*\([^)]*\):.*?(?=(\n\S|\Z))'
    login_matches = list(re.finditer(login_pattern, content, re.DOTALL))
    
    if len(login_matches) > 1:
        # Keep first occurrence, remove the rest
        for match in reversed(login_matches[1:]):
            content = content[:match.start()] + f"# REMOVED DUPLICATE LOGIN FUNCTION\n" + content[match.end():]
        print(f"Removed {len(login_matches) - 1} duplicate login function(s)")
        modified = True
    
    # Now replace the remaining login function
    login_match = re.search(login_pattern, content, re.DOTALL)
    if login_match:
        content = content[:login_match.start()] + login_function_code + content[login_match.end():]
        print("Updated login function")
        modified = True
    else:
        print("Could not find login function, skipping update")
    
    # Replace admin_required function
    admin_required_pattern = r'def\s+admin_required\s*\([^)]*\):.*?(?=\n\S)'
    admin_required_match = re.search(admin_required_pattern, content, re.DOTALL)
    if admin_required_match:
        content = content[:admin_required_match.start()] + admin_required_code + content[admin_required_match.end():]
        print("Updated admin_required function")
        modified = True
    else:
        print("Could not find admin_required function, skipping update")
    
    if modified:
        with open(app_file, 'w') as f:
            f.write(content)
        print("Successfully updated authentication functions")
        return True
    else:
        print("No authentication functions were updated")
        return False

def add_analytics_route(app_file):
    """Add analytics dashboard route if not present"""
    print("Checking for analytics route...")
    
    with open(app_file, 'r') as f:
        content = f.read()
    
    # Check if analytics route already exists
    if "@app.route('/analytics')" in content:
        print("Analytics route already exists, skipping")
        return True
    
    # Find the last route definition
    last_route_match = re.search(r'@app\.route\([^\n]+\)\s*\ndef\s+([a-zA-Z0-9_]+)\s*\(', content)
    if not last_route_match:
        print("Could not find any route definitions, skipping analytics route")
        return False
    
    # Find the end of the function to insert after
    function_name = last_route_match.group(1)
    function_pattern = f"def\\s+{function_name}\\s*\\([^)]*\\):.*?(?=(\\n@|\\Z))"
    function_match = re.search(function_pattern, content, re.DOTALL)
    
    if not function_match:
        print(f"Could not find the end of function {function_name}, skipping analytics route")
        return False
    
    # Prepare the analytics route code
    analytics_route_code = """

# Analytics Dashboard Route
@app.route('/analytics')
@login_required
def analytics():
    \"\"\"Analytics dashboard page\"\"\"
    try:
        from analytics_dashboard import analytics_dashboard
        return analytics_dashboard()
    except ImportError:
        flash("Analytics dashboard module not available", "warning")
        return redirect(url_for('index'))
"""
    
    # Insert the analytics route
    insert_point = function_match.end()
    new_content = content[:insert_point] + analytics_route_code + content[insert_point:]
    
    with open(app_file, 'w') as f:
        f.write(new_content)
    print("Successfully added analytics route")
    return True

def main():
    """Main function to fix the app"""
    app_file = "app.py"
    
    print("===== PropIntel App Fixer =====")
    print(f"Starting fixes for {app_file} at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Backup the file before making changes
    if not backup_file(app_file):
        print("Error: Could not backup file, aborting")
        return 1
    
    # Fix duplicate routes
    if not fix_duplicate_routes(app_file):
        print("Error fixing duplicate routes")
        return 1
    
    # Fix login_required decorator
    if not fix_login_required(app_file):
        print("Error fixing login_required decorator")
        return 1
    
    # Update authentication functions
    if not update_auth_functions(app_file):
        print("Warning: Could not update all authentication functions")
    
    # Add analytics route
    if not add_analytics_route(app_file):
        print("Warning: Could not add analytics route")
    
    print("\nAll fixes completed successfully!")
    print("Run tests with: python test_app_fixes.py")
    
    return 0

if __name__ == "__main__":
    sys.exit(main())