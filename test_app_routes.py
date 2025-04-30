#!/usr/bin/env python3
"""
Unit tests for PropIntel application routes
"""
import unittest
import os
import sys
import requests
import json
from time import sleep

# Local server info - adjust port if needed
SERVER_URL = "http://127.0.0.1:5002"
MAX_RETRIES = 5  # Number of retries for server connection

class TestAppRoutes(unittest.TestCase):
    """Test case for PropIntel application routes"""
    
    def setUp(self):
        """Setup before each test"""
        # Wait for server to be ready
        self._wait_for_server()
    
    def _wait_for_server(self):
        """Wait for server to be available"""
        for i in range(MAX_RETRIES):
            try:
                response = requests.get(f"{SERVER_URL}/", timeout=2)
                if response.status_code == 200:
                    return True
            except requests.RequestException:
                pass
            
            print(f"Waiting for server (attempt {i+1}/{MAX_RETRIES})...")
            sleep(2)
        
        self.fail("Server not available after multiple attempts")
    
    def test_home_page(self):
        """Test home page loads correctly"""
        response = requests.get(f"{SERVER_URL}/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"<title>", response.content)
    
    def test_map_view_route(self):
        """Test map_view route redirects properly"""
        response = requests.get(f"{SERVER_URL}/map_view", allow_redirects=False)
        self.assertEqual(response.status_code, 302)  # Should redirect
        self.assertIn("/map", response.headers.get("Location", ""))
    
    def test_map_route(self):
        """Test map route works"""
        response = requests.get(f"{SERVER_URL}/map")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"map", response.content.lower())
    
    def test_property_map_route(self):
        """Test property_map route works"""
        response = requests.get(f"{SERVER_URL}/property_map")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"property", response.content.lower())
    
    def test_api_routes(self):
        """Test API routes return proper JSON"""
        # Test properties API
        response = requests.get(f"{SERVER_URL}/api/properties")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers.get("Content-Type"), "application/json")
        
        try:
            data = response.json()
            self.assertIsInstance(data, list)
        except json.JSONDecodeError:
            self.fail("Response is not valid JSON")
    
    def test_budget_planner_route(self):
        """Test budget planner page loads"""
        # This will likely redirect to login, but should not 500
        response = requests.get(f"{SERVER_URL}/budget-planner", allow_redirects=True)
        self.assertIn(response.status_code, [200, 302])  # Either OK or redirect to login
        
        if response.status_code == 200:
            self.assertIn(b"budget", response.content.lower())

def run_tests():
    """Run the test suite"""
    unittest.main(argv=['first-arg-is-ignored'], exit=False)

if __name__ == "__main__":
    run_tests() 