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
from unittest.mock import patch, MagicMock

class AppTestCase(unittest.TestCase):
    """Base test case for the Flask application"""
    
    @classmethod
    def setUpClass(cls):
        """Set up test environment"""
        print("\n=== Setting up test environment ===")
        cls.app_path = os.path.abspath('app.py')
        if not os.path.exists(cls.app_path):
            raise FileNotFoundError(f"Cannot find app.py at {cls.app_path}")
            
        # Import the app.py file dynamically
        cls.app_module_name = "app_under_test"
        spec = util.spec_from_file_location(cls.app_module_name, cls.app_path)
        cls.app_module = util.module_from_spec(spec)
        
        # Create a mock connection function to avoid actual DB access
        cls.db_connection_mock = MagicMock()
        # The mock cursor should return an empty list for any query
        cursor_mock = MagicMock()
        cursor_mock.__enter__ = MagicMock(return_value=cursor_mock)
        cursor_mock.fetchone = MagicMock(return_value={})
        cursor_mock.fetchall = MagicMock(return_value=[])
        cls.db_connection_mock.__enter__ = MagicMock(return_value=cls.db_connection_mock)
        cls.db_connection_mock.cursor = MagicMock(return_value=cursor_mock)
        
        # Patch the DB connection function
        with patch('psycopg2.connect', return_value=cls.db_connection_mock):
            # Load the app module
            try:
                spec.loader.exec_module(cls.app_module)
                print("App module loaded successfully")
            except Exception as e:
                print(f"Error loading app module: {e}")
                raise

        # Access the Flask app instance
        try:
            cls.app = cls.app_module.app
            print(f"Found Flask app: {cls.app.name}")
        except AttributeError:
            print("Could not find 'app' in the app module")
            raise
            
        # Prepare the Flask app for testing
        cls.app.config['TESTING'] = True
        cls.app.config['SERVER_NAME'] = 'localhost'
        cls.app.config['SECRET_KEY'] = 'test_secret_key'
        cls.client = cls.app.test_client()
        
        # Create an application context
        cls.app_context = cls.app.app_context()
        cls.app_context.push()
        
    @classmethod
    def tearDownClass(cls):
        """Clean up test environment"""
        print("\n=== Cleaning up test environment ===")
        # Pop the application context
        cls.app_context.pop()
        
    def setUp(self):
        """Set up before each test"""
        # Create a fresh client for each test
        self.client = self.app.test_client()
        
class RouteTests(AppTestCase):
    """Tests for route definitions"""
    
    def test_routes_are_unique(self):
        """Test that each route is defined only once"""
        routes = {}
        duplicate_routes = []
        
        for rule in self.app.url_map.iter_rules():
            endpoint = rule.endpoint
            
            # Skip static and other built-in routes
            if endpoint == 'static':
                continue
                
            # Check if we have multiple routes with the same URL rule
            url = str(rule)
            if url in routes:
                duplicate_routes.append(url)
            else:
                routes[url] = endpoint
                
        # Assert that there are no duplicate route URLs
        self.assertEqual(duplicate_routes, [], f"Found duplicate routes: {duplicate_routes}")
        
    def test_essential_routes_exist(self):
        """Test that essential routes exist"""
        # List of essential route endpoints
        essential_endpoints = [
            'index',
            'login',
            'logout',
            'properties',
            'property_detail'
        ]
        
        existing_endpoints = [rule.endpoint for rule in self.app.url_map.iter_rules()]
        
        for endpoint in essential_endpoints:
            self.assertIn(endpoint, existing_endpoints, f"Essential endpoint '{endpoint}' is missing")
            
class LoginTests(AppTestCase):
    """Tests for login functionality"""
    
    def test_login_route_accessible(self):
        """Test that login page is accessible"""
        response = self.client.get('/login')
        self.assertEqual(response.status_code, 200, "Login page should return 200 OK")
        
    def test_login_has_required_fields(self):
        """Test that login page has required form fields"""
        response = self.client.get('/login')
        html = response.data.decode('utf-8')
        
        # Check for username field
        self.assertIn('name="username"', html, "Login form should have username field")
        
        # Check for password field
        self.assertIn('name="password"', html, "Login form should have password field")
        
        # Check for submit button
        self.assertIn('<button type="submit"', html, "Login form should have submit button")
        
    @patch('flask.session', {})
    def test_admin_login(self):
        """Test admin login logic"""
        # Mock before_request to avoid actual session checks
        with patch.object(self.app_module, 'before_request', return_value=None):
            # Mock the login function to avoid database calls
            with patch.object(flask.session, 'clear'):
                with patch.object(flask.session, '__setitem__'):
                    with patch.object(flask, 'redirect') as mock_redirect:
                        # Test hardcoded admin login
                        self.app_module.login()
                        
                        # Check if login would redirect to index
                        mock_redirect.assert_called()
        
    @patch('flask.g', MagicMock())
    def test_login_required_decorator(self):
        """Test that login_required decorator exists and works"""
        # Check that login_required decorator is defined
        self.assertTrue(hasattr(self.app_module, 'login_required'), 
                        "login_required decorator should be defined")
        
        # Create a test function with the decorator
        @self.app_module.login_required
        def test_func():
            return "Test function"
        
        # Set g.user to None to simulate no login
        flask.g.user = None
        
        # Call the decorated function and verify it tries to redirect
        with patch.object(flask, 'redirect') as mock_redirect:
            test_func()
            mock_redirect.assert_called()
            
        # Set g.user to a value to simulate logged in
        flask.g.user = {"user_id": "1", "role": "admin"}
        
        # Now it should return the function's result, not redirect
        with patch.object(flask, 'redirect') as mock_redirect:
            result = test_func()
            mock_redirect.assert_not_called()
            self.assertEqual(result, "Test function")
            
class AdminTests(AppTestCase):
    """Tests for admin functionality"""
    
    @patch('flask.g', MagicMock())
    def test_admin_required_decorator(self):
        """Test that admin_required decorator exists and works"""
        # Check that admin_required decorator is defined
        self.assertTrue(hasattr(self.app_module, 'admin_required'), 
                        "admin_required decorator should be defined")
        
        # Create a test function with the decorator
        @self.app_module.admin_required
        def test_func():
            return "Admin function"
        
        # Test with no user
        flask.g.user = None
        
        with patch.object(flask, 'redirect') as mock_redirect:
            test_func()
            mock_redirect.assert_called()
            
        # Test with non-admin user
        flask.g.user = {"user_id": "2", "role": "user"}
        
        with patch.object(flask, 'redirect') as mock_redirect:
            test_func()
            mock_redirect.assert_called()
            
        # Test with admin user
        flask.g.user = {"user_id": "1", "role": "admin"}
        
        with patch.object(flask, 'redirect') as mock_redirect:
            result = test_func()
            mock_redirect.assert_not_called()
            self.assertEqual(result, "Admin function")
            
class AnalyticsTests(AppTestCase):
    """Tests for analytics dashboard"""
    
    def test_analytics_route_exists(self):
        """Test that analytics route can be added to the app"""
        # Import analytics_dashboard module
        try:
            sys.path.append(os.path.dirname(os.path.abspath(__file__)))
            import analytics_dashboard
            
            # Add the route to the app
            @self.app.route('/analytics')
            @self.app_module.login_required
            def analytics():
                return analytics_dashboard.analytics_dashboard()
                
            # Check that the route exists
            response = self.client.get('/analytics')
            
            # Should redirect because not logged in
            self.assertEqual(response.status_code, 302, "Analytics should require login")
            
            # Set a user for testing
            with patch.object(flask, 'g') as g_mock:
                g_mock.user = {"user_id": "1", "role": "admin"}
                
                # Now attempt to render the analytics page
                with patch.object(analytics_dashboard, 'get_analytics_data', return_value={
                    'properties': [],
                    'total_income': 0,
                    'total_expenses': 0,
                    'net_profit': 0,
                    'total_work_records': 0,
                    'income_change_percent': 0,
                    'expense_change_percent': 0,
                    'profit_change_percent': 0,
                    'work_change_percent': 0,
                    'labels': '[]',
                    'income_data': '[]',
                    'expense_data': '[]',
                    'expense_categories': '{"wage": 0, "project_manager": 0, "material": 0, "miscellaneous": 0}',
                    'property_performance': '[]',
                    'work_heatmap_data': '[]',
                    'expense_trends': '{"labels": [], "wage": [], "project_manager": [], "material": [], "miscellaneous": []}',
                    'profit_margin': '{"labels": [], "margins": [], "profit": []}'
                }):
                    with patch.object(flask, 'render_template', return_value="Analytics Dashboard"):
                        response = analytics()
                        self.assertEqual(response, "Analytics Dashboard")
                        
        except ImportError as e:
            self.skipTest(f"Skipping analytics tests: {e}")
            
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