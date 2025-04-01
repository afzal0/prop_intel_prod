#!/usr/bin/env python3

"""
Fix for the missing format_currency filter in PropIntel
Add this code to app.py to define the missing filter
"""

import os
import locale
import datetime
from flask import Flask

def add_currency_filter(app):
    """
    Add the format_currency filter to the Flask app
    """
    print("Adding currency and date formatting filters to Flask application...")
    
    # Set locale for currency formatting
    try:
        locale.setlocale(locale.LC_ALL, 'en_US.UTF-8')
    except:
        try:
            locale.setlocale(locale.LC_ALL, 'en_US')
        except:
            print("Warning: Could not set locale to en_US. Currency formatting may not work correctly.")
    
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
    
    print("Filters added successfully.")
    return app

# Add this code to update the app_simple_fix.py with the filter
def update_simple_app():
    """
    Update the app_simple_fix.py file with currency filter
    """
    simple_app_path = '/Users/afzalkhan/prop_intel_prod back/app_simple_fix.py'
    
    if os.path.exists(simple_app_path):
        with open(simple_app_path, 'r') as f:
            content = f.read()
        
        # Add the format_currency filter after app creation
        if 'app = Flask(__name__)' in content and 'format_currency_filter' not in content:
            insert_index = content.find('app = Flask(__name__)') + len('app = Flask(__name__)')
            
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
            new_content = content[:insert_index] + filter_code + content[insert_index:]
            
            with open(simple_app_path, 'w') as f:
                f.write(new_content)
            
            print(f"Updated {simple_app_path} with currency filter.")
        else:
            print(f"Filter already exists or app creation line not found in {simple_app_path}.")
    else:
        print(f"File {simple_app_path} not found.")

if __name__ == "__main__":
    print("PropIntel Currency Filter Fix")
    print("============================")
    
    # Update the simplified app
    update_simple_app()
    
    print("\nTo fix the missing format_currency filter, add this code to your app.py:")
    print("------------------------------------------------------------------")
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
    print("\nMake sure to add this code after creating the Flask app (app = Flask(__name__)).")
    print("\nAnd ensure you have imported datetime at the top of app.py:")
    print("import datetime")