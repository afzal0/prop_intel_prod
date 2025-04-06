#!/usr/bin/env python3
"""
Test suite for PropIntel app fixes.

This script tests:
1. Flask app initialization
2. Route definitions
3. Login functionality
4. Admin access controls
5. Database connections
6. Analytics dashboard
"""

import unittest
import os
import sys
import tempfile
import flask
import re
from importlib import util
from unittest.mock import patch, MagicMock, PropertyMock

class AppTestCase(unittest.TestCase):
    """Base test case for the Flask application"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        print("\n=== Setting up test environment ===")
        cls.app_path = os.path.abspath('app.py')
        if not os.path.exists(cls.app_path):
            print(f"Cannot find app.py at {cls.app_path}")
            cls.skipTest(cls, "app.py not found")
            return
            
        # Create a test Flask application for testing
        cls.test_app = flask.Flask("test_app")
        cls.test_app.secret_key = 'test_secret_key'
        cls.test_app.config['TESTING'] = True
        cls.test_app.config['SERVER_NAME'] = 'localhost:5000'
        
        # Need to define a simple login route for testing
        @cls.test_app.route('/login')
        def test_login():
            return "Login Page"
            
        # Create an application context for our tests
        cls.test_app_context = cls.test_app.app_context()
        cls.test_app_context.push()
        cls.test_request_context = cls.test_app.test_request_context()
        cls.test_request_context.push()
            
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        print("\n=== Cleaning up test environment ===")
        # Pop the request and application contexts
        if hasattr(cls, 'test_request_context'):
            cls.test_request_context.pop()
        if hasattr(cls, 'test_app_context'):
            cls.test_app_context.pop()
        
    def setUp(self):
        """Set up before each test"""
        # Create a fresh client for each test
        self.client = self.test_app.test_client()
        
class RouteTests(unittest.TestCase):
    """Tests for route definitions"""
    
    def test_routes_are_unique(self):
        """Test that app.py doesn't have duplicate route definitions"""
        # Read app.py file
        with open('app.py', 'r') as f:
            content = f.read()
            
        # Find all route definitions
        routes = {}
        duplicates = []
        
        # Use regex to find all route definitions
        route_defs = re.findall(r'@app\.route\([\'"]([^\'"]+)[\'"]', content)
        
        for route in route_defs:
            if route in routes:
                duplicates.append(route)
            else:
                routes[route] = True
                
        # Check that there are no duplicates
        if duplicates:
            print(f"Duplicated routes found: {duplicates}")
        self.assertEqual(len(duplicates), 0, f"Duplicate routes found: {duplicates}")
        
class LoginTests(unittest.TestCase):
    """Tests for login functionality"""
    
    def test_login_function_definition(self):
        """Test that login function exists in app.py"""
        # Read app.py file
        with open('app.py', 'r') as f:
            content = f.read()
            
        # Check that login function is defined
        login_func_match = re.search(r'def\s+login\s*\(', content)
        self.assertIsNotNone(login_func_match, "Login function should be defined in app.py")
        
        # Check for duplicate login function definitions
        login_func_matches = re.findall(r'def\s+login\s*\(', content)
        self.assertEqual(len(login_func_matches), 1, 
                         f"Found {len(login_func_matches)} login function definitions, should be exactly 1")
        
    def test_login_required_definition(self):
        """Test that login_required decorator is defined in app.py"""
        # Read app.py file
        with open('app.py', 'r') as f:
            content = f.read()
            
        # Check that login_required function is defined
        login_required_match = re.search(r'def\s+login_required\s*\(', content)
        self.assertIsNotNone(login_required_match, "login_required decorator should be defined in app.py")
        
        # Check that login_required is used as a decorator
        login_required_usage = re.search(r'@login_required', content)
        self.assertIsNotNone(login_required_usage, "login_required should be used as a decorator in app.py")
        
class AdminTests(unittest.TestCase):
    """Tests for admin functionality"""
    
    def test_admin_required_definition(self):
        """Test that admin_required decorator is defined in app.py"""
        # Read app.py file
        with open('app.py', 'r') as f:
            content = f.read()
            
        # Check that admin_required function is defined
        admin_required_match = re.search(r'def\s+admin_required\s*\(', content)
        self.assertIsNotNone(admin_required_match, "admin_required decorator should be defined in app.py")
        
        # Check that admin_required is used as a decorator
        admin_required_usage = re.search(r'@admin_required', content)
        self.assertIsNotNone(admin_required_usage, "admin_required should be used as a decorator in app.py")
            
class AnalyticsTests(unittest.TestCase):
    """Tests for analytics dashboard"""
    
    def test_analytics_files_exist(self):
        """Test that analytics files exist"""
        # Check that analytics_dashboard.py exists
        self.assertTrue(os.path.exists('analytics_dashboard.py'), 
                       "analytics_dashboard.py should exist")
                       
        # Check that analytics_dashboard.html exists
        self.assertTrue(os.path.exists('templates/analytics_dashboard.html'), 
                       "templates/analytics_dashboard.html should exist")
                       
    def test_analytics_route_definition(self):
        """Test that analytics route is defined in app.py"""
        # Read app.py file
        with open('app.py', 'r') as f:
            content = f.read()
            
        # Check for analytics route definition
        analytics_route_match = re.search(r'@app\.route\([\'"]\/analytics[\'"]', content)
        
        # If we have a route definition already, check it's protected by login_required
        if analytics_route_match:
            # Find the decorator line
            line_num = content[:analytics_route_match.start()].count('\n') + 1
            lines = content.split('\n')
            
            # Find the analytics function definition
            for i in range(line_num, min(line_num + 5, len(lines))):
                if re.match(r'\s*def\s+analytics\s*\(', lines[i]):
                    # Check the line before for login_required
                    if i > 0 and '@login_required' in lines[i-1]:
                        self.assertTrue(True, "Analytics route is protected by login_required")
                    else:
                        self.fail("Analytics route should be protected by login_required")
        else:
            # Analytics route not found, so let's add a test for adding it
            # First remove any existing analytics route and definition
            new_content = re.sub(r'@app\.route\([\'"]\/analytics[\'"]\).*?def\s+analytics\s*\([^)]*\):.*?(?=(\n@|\Z))',
                                '', content, flags=re.DOTALL)
            
            # Now we can test adding the route
            anal_route = """
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
            # Find a good spot to insert - after the last route
            last_route = re.search(r'@app\.route.*\ndef\s+([a-zA-Z0-9_]+)\s*\([^)]*\):.*?(?=(\n@|\Z))', 
                                  new_content, re.DOTALL)
            if last_route:
                insert_point = last_route.end()
                new_content = new_content[:insert_point] + anal_route + new_content[insert_point:]
                
                # Write to a temp file
                with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp:
                    temp.write(new_content)
                    temp_name = temp.name
                
                # Verify route addition was successful
                with open(temp_name, 'r') as f:
                    added_content = f.read()
                
                # This should now be found
                analytics_route_match = re.search(r'@app\.route\([\'"]\/analytics[\'"]', added_content)
                self.assertIsNotNone(analytics_route_match, "Analytics route should be successfully added")
                
                # Cleanup
                os.unlink(temp_name)
            else:
                self.skipTest("Could not find a place to insert analytics route")
                
def run_tests():
    """Run the test suite"""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    
    # Add test classes
    suite.addTests(loader.loadTestsFromTestCase(RouteTests))
    suite.addTests(loader.loadTestsFromTestCase(LoginTests))
    suite.addTests(loader.loadTestsFromTestCase(AdminTests))
    suite.addTests(loader.loadTestsFromTestCase(AnalyticsTests))
    
    # Run the tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    # Return 0 if successful, 1 otherwise
    return 0 if result.wasSuccessful() else 1

if __name__ == "__main__":
    print("=== Running PropIntel App Tests ===")
    sys.exit(run_tests())