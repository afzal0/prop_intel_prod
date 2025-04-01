#!/usr/bin/env python3

"""
Patch for adding the missing format_currency and format_date filters to app.py
Just run this file to patch your main app.py file, or copy the filter functions manually
"""

import os
import re
import shutil
import datetime

def patch_app_py():
    """Patch app.py with the missing filters"""
    app_py_path = '/Users/afzalkhan/prop_intel_prod back/app.py'
    backup_path = '/Users/afzalkhan/prop_intel_prod back/app.py.bak'
    
    # Make a backup of the original app.py
    if os.path.exists(app_py_path):
        shutil.copy2(app_py_path, backup_path)
        print(f"Backup created at {backup_path}")
    else:
        print(f"Error: {app_py_path} not found")
        return False
    
    try:
        # Read the original app.py
        with open(app_py_path, 'r') as f:
            content = f.read()
        
        # Check if import datetime is already present
        if 'import datetime' not in content:
            # Add import datetime
            import_match = re.search(r'import\s+([^\n]+)', content)
            if import_match:
                # Insert after the first import statement
                insert_pos = import_match.end()
                content = content[:insert_pos] + '\nimport datetime' + content[insert_pos:]
            else:
                # Prepend to the file
                content = 'import datetime\n' + content
        
        # Check if the filters are already present
        if 'format_currency_filter' not in content:
            # Find a good spot to insert the filters (after creating the Flask app)
            app_creation_match = re.search(r'app\s*=\s*Flask\([^)]*\)', content)
            
            if app_creation_match:
                insert_pos = app_creation_match.end() + 1
                
                # Filter code to insert
                filter_code = """

# Format currency filter
@app.template_filter('format_currency')
def format_currency_filter(value):
    if value is None:
        return "$0.00"
    try:
        value = float(value)
        return "${:,.2f}".format(value)
    except (ValueError, TypeError):
        return "$0.00"

# Format date filter
@app.template_filter('format_date')
def format_date_filter(value):
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
"""
                # Insert the filter code
                content = content[:insert_pos] + filter_code + content[insert_pos:]
            else:
                print("Warning: Could not find Flask app creation in app.py.")
                print("Please add the filter code manually.")
                return False
        else:
            print("Filters already present in app.py.")
            return True
        
        # Write the modified content back to app.py
        with open(app_py_path, 'w') as f:
            f.write(content)
        
        print(f"Successfully patched {app_py_path} with format_currency and format_date filters.")
        return True
    
    except Exception as e:
        print(f"Error patching app.py: {e}")
        
        # Restore from backup if there was an error
        if os.path.exists(backup_path):
            shutil.copy2(backup_path, app_py_path)
            print(f"Restored {app_py_path} from backup due to error.")
        
        return False

if __name__ == "__main__":
    print("PropIntel Template Filter Patch")
    print("===============================")
    
    # Patch app.py
    if patch_app_py():
        print("\nFilter patch applied successfully!")
        print("\nThe following filters have been added to app.py:")
        print("1. format_currency - Formats numbers as currency (e.g., $1,234.56)")
        print("2. format_date - Formats dates as 'Mon DD, YYYY'")
        print("\nYou can now use these filters in your templates like this:")
        print("{{ value|format_currency }}")
        print("{{ date|format_date }}")
        print("\nRestart your Flask application for the changes to take effect.")
    else:
        print("\nCould not automatically patch app.py.")
        print("\nPlease add these filters manually to app.py:")
        print("""
# Format currency filter
@app.template_filter('format_currency')
def format_currency_filter(value):
    if value is None:
        return "$0.00"
    try:
        value = float(value)
        return "${:,.2f}".format(value)
    except (ValueError, TypeError):
        return "$0.00"

# Format date filter
@app.template_filter('format_date')
def format_date_filter(value):
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
""")