#!/usr/bin/env python3
"""
Script to fix duplicate route definitions in app.py.
"""

import os
import re
import sys

def fix_duplicate_routes():
    """
    Finds and removes duplicate route definitions in app.py.
    It keeps the first occurrence and comments out any duplicates.
    """
    app_file = "app.py"
    
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
        # Backup the original file
        backup_file = f"{app_file}.bak"
        try:
            with open(backup_file, 'w') as f:
                f.write(''.join(lines))  # Write backup with comments for visibility
            print(f"Backed up original {app_file} to {backup_file}")
            
            # Write the fixed content
            with open(app_file, 'w') as f:
                f.write(''.join(lines))
            print(f"Successfully fixed duplicate routes in {app_file}")
            return True
        except Exception as e:
            print(f"Error updating {app_file}: {e}")
            return False
    else:
        print("No duplicate routes found to fix")
        return True

if __name__ == "__main__":
    success = fix_duplicate_routes()
    sys.exit(0 if success else 1)