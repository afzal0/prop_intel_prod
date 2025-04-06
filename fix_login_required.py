#!/usr/bin/env python3
"""
This script scans app.py for login_required usage and adds the definition if missing.
"""

import os
import re
import sys

def fix_login_required():
    """Add login_required decorator to app.py if missing"""
    app_file = "app.py"
    
    if not os.path.exists(app_file):
        print(f"Error: {app_file} not found")
        return False
    
    with open(app_file, 'r') as f:
        content = f.read()
    
    # Check if login_required is defined
    if re.search(r'def\s+login_required\s*\(', content):
        print("login_required is already defined in app.py")
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
        
        # Backup the original file
        backup_file = f"{app_file}.bak"
        try:
            with open(backup_file, 'w') as f:
                f.write(content)
            print(f"Backed up original {app_file} to {backup_file}")
            
            # Write the new content
            with open(app_file, 'w') as f:
                f.write(new_content)
            print(f"Successfully added login_required to {app_file}")
            return True
        except Exception as e:
            print(f"Error updating {app_file}: {e}")
            return False
    else:
        print("login_required is not used in app.py, no fix needed")
        return True

if __name__ == "__main__":
    success = fix_login_required()
    sys.exit(0 if success else 1)