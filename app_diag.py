#!/usr/bin/env python3
"""
Property Intelligence Application Diagnostic Tool

This script performs comprehensive checks on your Flask application to diagnose
deployment issues and can set up a production-like environment locally.
"""

import os
import sys
import platform
import subprocess
import importlib.util
import socket
import tempfile
import shutil
import json
import datetime
import time
import traceback
from pathlib import Path
import urllib.request
import urllib.error

# Color codes for terminal output
class Colors:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def print_header(text):
    """Print a formatted header"""
    print(f"\n{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD} {text}{Colors.ENDC}")
    print(f"{Colors.HEADER}{Colors.BOLD}{'=' * 80}{Colors.ENDC}\n")

def print_success(text):
    """Print a success message"""
    print(f"{Colors.GREEN}✓ {text}{Colors.ENDC}")

def print_warning(text):
    """Print a warning message"""
    print(f"{Colors.WARNING}⚠ {text}{Colors.ENDC}")

def print_error(text):
    """Print an error message"""
    print(f"{Colors.FAIL}✗ {text}{Colors.ENDC}")

def print_info(text):
    """Print an info message"""
    print(f"{Colors.CYAN}ℹ {text}{Colors.ENDC}")

def print_section(text):
    """Print a section header"""
    print(f"\n{Colors.BLUE}{Colors.BOLD}▶ {text}{Colors.ENDC}")

def is_command_available(command):
    """Check if a command is available on the system"""
    try:
        subprocess.run([command, '--version'], 
                       stdout=subprocess.PIPE, 
                       stderr=subprocess.PIPE, 
                       check=False)
        return True
    except FileNotFoundError:
        return False

def check_system_info():
    """Check system information"""
    print_section("System Information")
    
    # Python version
    python_version = platform.python_version()
    print(f"Python version: {python_version}")
    if python_version < "3.6":
        print_error("Python version is below 3.6. This may cause compatibility issues.")
    else:
        print_success("Python version is compatible.")
    
    # Operating system
    os_info = platform.platform()
    print(f"Operating system: {os_info}")
    
    # Check available commands
    commands = ['pip', 'gunicorn', 'docker', 'heroku', 'az']
    for cmd in commands:
        if is_command_available(cmd):
            print_success(f"{cmd} is installed")
        else:
            print_warning(f"{cmd} is not installed or not in PATH")
    
    # Available disk space
    if platform.system() != "Windows":
        try:
            df_output = subprocess.check_output(['df', '-h', '.']).decode('utf-8')
            print(f"Disk space: \n{df_output.split('Filesystem')[1]}")
        except:
            print_warning("Could not check disk space")
    
    # Check internet connectivity
    try:
        socket.create_connection(("www.google.com", 80))
        print_success("Internet connection is available")
    except OSError:
        print_error("No internet connection available")

def check_virtual_env():
    """Check if running in a virtual environment"""
    print_section("Virtual Environment")
    
    if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix):
        print_success("Running inside a virtual environment")
        print(f"Virtual environment path: {sys.prefix}")
    else:
        print_warning("Not running inside a virtual environment")
        print_info("It's recommended to use a virtual environment for better dependency management")

def check_app_structure():
    """Check the application structure"""
    print_section("Application Structure")
    
    current_dir = os.getcwd()
    print(f"Current directory: {current_dir}")
    
    # Check for critical files
    critical_files = ['app.py', 'Procfile', 'requirements.txt']
    missing_files = []
    
    for file in critical_files:
        if os.path.exists(file):
            print_success(f"Found {file}")
            
            # Check file content
            if file == 'Procfile':
                with open(file, 'r') as f:
                    content = f.read().strip()
                    if 'web: gunicorn' in content:
                        print_success("Procfile contains a valid web process")
                    else:
                        print_error(f"Procfile may not be valid: {content}")
        else:
            print_error(f"Missing {file}")
            missing_files.append(file)
    
    # Check for Python version file
    py_version_files = ['.python-version', 'runtime.txt']
    has_py_version = False
    
    for file in py_version_files:
        if os.path.exists(file):
            has_py_version = True
            with open(file, 'r') as f:
                content = f.read().strip()
                print_success(f"Found {file} with Python version: {content}")
    
    if not has_py_version:
        print_warning("No Python version specification found (.python-version or runtime.txt)")
    
    # Check directory structure
    important_dirs = ['templates', 'static', 'uploads']
    for dir_name in important_dirs:
        if os.path.exists(dir_name) and os.path.isdir(dir_name):
            file_count = len(os.listdir(dir_name))
            print_success(f"Found {dir_name}/ directory with {file_count} files")
        else:
            print_warning(f"Directory {dir_name}/ not found")
    
    # Check template files
    if os.path.exists('templates') and os.path.isdir('templates'):
        required_templates = ['base.html', 'index.html', 'properties.html', 'property_detail.html', 'map.html', 'upload.html']
        for template in required_templates:
            template_path = os.path.join('templates', template)
            if os.path.exists(template_path):
                print_success(f"Found template: {template}")
            else:
                print_error(f"Missing template: {template}")

def check_dependencies():
    """Check application dependencies"""
    print_section("Dependencies")
    
    if not os.path.exists('requirements.txt'):
        print_error("requirements.txt file not found")
        return
    
    print_info("Checking installed packages vs requirements.txt...")
    
    try:
        # Get installed packages
        installed_packages = {}
        result = subprocess.run([sys.executable, '-m', 'pip', 'freeze'], 
                               stdout=subprocess.PIPE, 
                               check=True)
        for line in result.stdout.decode('utf-8').splitlines():
            if '==' in line:
                package, version = line.split('==', 1)
                installed_packages[package.lower()] = version
        
        # Check requirements
        missing_packages = []
        version_mismatches = []
        
        with open('requirements.txt', 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                    
                if '==' in line:
                    package, version = line.split('==', 1)
                    package = package.lower()
                    
                    if package not in installed_packages:
                        missing_packages.append(line)
                    elif installed_packages[package] != version:
                        version_mismatches.append(
                            f"{package}: required {version}, installed {installed_packages[package]}"
                        )
                else:
                    # No version specified
                    package = line.lower()
                    if package not in installed_packages:
                        missing_packages.append(package)
        
        # Report results
        if not missing_packages and not version_mismatches:
            print_success("All required packages are installed with correct versions")
        
        if missing_packages:
            print_error("Missing packages:")
            for package in missing_packages:
                print(f"  - {package}")
            print_info("Run: pip install -r requirements.txt")
        
        if version_mismatches:
            print_warning("Version mismatches:")
            for mismatch in version_mismatches:
                print(f"  - {mismatch}")
    
    except subprocess.CalledProcessError as e:
        print_error(f"Error checking packages: {e}")

def check_database_config():
    """Check database configuration"""
    print_section("Database Configuration")
    
    # Look for database configuration
    db_config_found = False
    
    # Check if app.py contains database connection code
    if os.path.exists('app.py'):
        with open('app.py', 'r') as f:
            content = f.read()
            if 'get_db_connection' in content or 'psycopg2.connect' in content:
                print_success("Found database connection code in app.py")
                db_config_found = True
            else:
                print_warning("No database connection code found in app.py")
    
    # Check for db_config.ini
    if os.path.exists('db_config.ini'):
        print_success("Found db_config.ini file")
        db_config_found = True
        
        # Try to parse the config
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read('db_config.ini')
            
            if 'database' in config:
                db_params = config['database']
                has_all_params = all(param in db_params for param in ['host', 'port', 'database', 'user'])
                
                if has_all_params:
                    print_success("db_config.ini contains all required database parameters")
                    # Don't print password
                    safe_params = {k: (v if k != 'password' else '*****') for k, v in db_params.items()}
                    print_info(f"Database parameters: {safe_params}")
                else:
                    print_error("db_config.ini is missing some required database parameters")
            else:
                print_error("db_config.ini does not contain a [database] section")
        except Exception as e:
            print_error(f"Error parsing db_config.ini: {e}")
    
    if not db_config_found:
        print_error("No database configuration found")
        print_info("Make sure you have database configuration in app.py or db_config.ini")

def test_db_connection():
    """Test database connection"""
    print_section("Database Connection Test")
    
    # Try to import the application
    try:
        sys.path.insert(0, os.getcwd())
        
        # Direct import might be risky, so we'll use a more controlled approach
        if os.path.exists('app.py'):
            # Extract the get_db_connection function if it exists
            with open('app.py', 'r') as f:
                content = f.read()
            
            # Create a temporary file with just the necessary functions
            temp_dir = tempfile.mkdtemp()
            temp_file = os.path.join(temp_dir, 'db_test.py')
            
            with open(temp_file, 'w') as f:
                f.write("import os\n")
                f.write("import psycopg2\n")
                f.write("import configparser\n")
                f.write("from urllib.parse import urlparse\n\n")
                
                # Extract all necessary functions from app.py
                if 'def get_db_config' in content:
                    # Extract get_db_config function
                    start = content.find('def get_db_config')
                    end = content.find('\ndef ', start + 1)
                    if end == -1:  # If it's the last function
                        end = len(content)
                    f.write(content[start:end] + "\n\n")
                else:
                    # Provide a default implementation
                    f.write("""
def get_db_config():
    # Default connection parameters
    default_params = {
        "user": "prop_intel",
        "password": "nyrty7-cytrit-qePkyf",
        "host": "propintel.postgres.database.azure.com",
        "port": 5432,
        "database": "postgres",
    }
    
    # Check for DATABASE_URL
    database_url = os.environ.get('DATABASE_URL')
    if database_url:
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        result = urlparse(database_url)
        return {
            "user": result.username,
            "password": result.password,
            "host": result.hostname,
            "port": result.port or 5432,
            "database": result.path[1:],
        }
    
    # Check for config file
    if os.path.exists('db_config.ini'):
        config = configparser.ConfigParser()
        config.read('db_config.ini')
        if 'database' in config:
            return {
                "user": config['database'].get('user', default_params['user']),
                "password": config['database'].get('password', default_params['password']),
                "host": config['database'].get('host', default_params['host']),
                "port": int(config['database'].get('port', default_params['port'])),
                "database": config['database'].get('database', default_params['database']),
            }
    
    return default_params
""")
                
                if 'def get_db_connection' in content:
                    # Extract get_db_connection function
                    start = content.find('def get_db_connection')
                    end = content.find('\ndef ', start + 1)
                    if end == -1:  # If it's the last function
                        end = len(content)
                    f.write(content[start:end] + "\n\n")
                else:
                    # Provide a default implementation
                    f.write("""
def get_db_connection():
    conn_params = get_db_config()
    conn = psycopg2.connect(**conn_params)
    return conn
""")
                
                # Add test code
                f.write("""
def test_connection():
    try:
        conn_params = get_db_config()
        # Mask password for printing
        print_params = conn_params.copy()
        if 'password' in print_params:
            print_params['password'] = '*****'
        print(f"Connecting to database with params: {print_params}")
        
        conn = psycopg2.connect(**conn_params)
        cur = conn.cursor()
        cur.execute('SELECT version();')
        version = cur.fetchone()[0]
        print(f"Connected to database successfully.")
        print(f"Database version: {version}")
        
        # Check if our schema exists
        cur.execute("SELECT EXISTS(SELECT 1 FROM pg_namespace WHERE nspname = 'propintel');")
        schema_exists = cur.fetchone()[0]
        if schema_exists:
            print("Schema 'propintel' exists.")
            
            # Check tables
            tables = ['properties', 'work', 'money_in', 'money_out']
            for table in tables:
                cur.execute(f"SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname = 'propintel' AND tablename = '{table}');")
                table_exists = cur.fetchone()[0]
                if table_exists:
                    cur.execute(f"SELECT COUNT(*) FROM propintel.{table}")
                    count = cur.fetchone()[0]
                    print(f"Table 'propintel.{table}' exists with {count} rows.")
                else:
                    print(f"Table 'propintel.{table}' does not exist.")
        else:
            print("Schema 'propintel' does not exist.")
        
        conn.close()
        return True, "Database connection successful"
    except Exception as e:
        return False, str(e)

if __name__ == '__main__':
    success, message = test_connection()
    if success:
        print(f"SUCCESS: {message}")
        sys.exit(0)
    else:
        print(f"ERROR: {message}")
        sys.exit(1)
""")
            
            # Run the test
            print_info("Attempting to connect to the database...")
            try:
                result = subprocess.run([sys.executable, temp_file], 
                                     stdout=subprocess.PIPE, 
                                     stderr=subprocess.PIPE, 
                                     text=True,
                                     check=False)
                
                if result.returncode == 0:
                    print_success("Database connection test passed")
                    print(result.stdout)
                else:
                    print_error("Database connection test failed")
                    print(result.stdout)
                    print_error(result.stderr)
            except Exception as e:
                print_error(f"Error running database test: {e}")
            
            # Clean up
            shutil.rmtree(temp_dir)
        else:
            print_error("app.py not found, cannot test database connection")
    except Exception as e:
        print_error(f"Error importing application: {e}")

def check_flask_app():
    """Check Flask application configuration"""
    print_section("Flask Application")
    
    if not os.path.exists('app.py'):
        print_error("app.py not found")
        return
    
    # Check for Flask import
    with open('app.py', 'r') as f:
        content = f.read()
        
        if 'from flask import' in content:
            print_success("Flask import found")
        else:
            print_error("No Flask import found in app.py")
        
        # Check for app instance
        if 'app = Flask(' in content:
            print_success("Flask application instance found")
        else:
            print_error("No Flask application instance found in app.py")
        
        # Check for routes
        route_count = content.count('@app.route')
        if route_count > 0:
            print_success(f"Found {route_count} route(s) in app.py")
        else:
            print_error("No routes found in app.py")
        
        # Check for debug mode
        if "debug=True" in content:
            print_warning("Debug mode is enabled in app.py - should be disabled in production")
        
        # Check for template rendering
        if "render_template" in content:
            print_success("Template rendering found")
        else:
            print_warning("No template rendering found in app.py")
        
        # Check for environment variable usage
        env_vars = ['os.environ.get', 'os.getenv']
        if any(var in content for var in env_vars):
            print_success("Environment variable usage found")
        else:
            print_warning("No environment variable usage found - might cause issues in cloud deployment")

def test_flask_app_locally():
    """Test Flask application locally"""
    print_section("Local Flask Application Test")
    
    if not os.path.exists('app.py'):
        print_error("app.py not found")
        return
    
    print_info("Testing Flask application locally...")
    
    # Create a temporary script to test the Flask app
    temp_dir = tempfile.mkdtemp()
    temp_file = os.path.join(temp_dir, 'app_test.py')
    
    with open(temp_file, 'w') as f:
        f.write("""
import importlib.util
import sys
import os
import socket
import time
import threading
import signal
from urllib.request import urlopen
from urllib.error import URLError

# Add current directory to path
sys.path.insert(0, os.getcwd())

def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('', 0))
        return s.getsockname()[1]

def start_flask_app(port):
    try:
        # Import the app from app.py
        spec = importlib.util.spec_from_file_location("app", "app.py")
        app_module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(app_module)
        
        # Get the Flask app instance
        flask_app = getattr(app_module, 'app')
        
        # Start the Flask app
        flask_app.run(host='127.0.0.1', port=port, debug=False)
    except Exception as e:
        print(f"Error starting Flask app: {e}")
        sys.exit(1)

def test_flask_endpoints(port):
    base_url = f"http://127.0.0.1:{port}"
    
    # Wait for the server to start
    max_retries = 30
    retries = 0
    while retries < max_retries:
        try:
            response = urlopen(f"{base_url}/")
            break
        except URLError:
            retries += 1
            time.sleep(0.1)
    
    if retries == max_retries:
        print("ERROR: Flask server did not start properly")
        return False, "Server did not start"
    
    # Test the home page
    try:
        response = urlopen(f"{base_url}/")
        if response.status == 200:
            print(f"SUCCESS: Home page ({base_url}/) returned 200 OK")
        else:
            print(f"ERROR: Home page returned status {response.status}")
            return False, f"Home page returned status {response.status}"
    except Exception as e:
        print(f"ERROR: Failed to access home page: {e}")
        return False, f"Failed to access home page: {str(e)}"
    
    # Test other endpoints
    endpoints = ['/properties', '/map', '/upload']
    for endpoint in endpoints:
        try:
            response = urlopen(f"{base_url}{endpoint}")
            if response.status == 200:
                print(f"SUCCESS: Endpoint {endpoint} returned 200 OK")
            else:
                print(f"WARNING: Endpoint {endpoint} returned status {response.status}")
        except Exception as e:
            print(f"WARNING: Could not access {endpoint}: {e}")
    
    # Test the debug endpoint if it exists
    try:
        response = urlopen(f"{base_url}/debug")
        if response.status == 200:
            print(f"SUCCESS: Debug endpoint returned 200 OK")
            # Print first 1000 chars of response
            print(f"Debug info: {response.read().decode('utf-8')[:1000]}...")
        else:
            print(f"WARNING: Debug endpoint returned status {response.status}")
    except Exception as e:
        print(f"INFO: Debug endpoint not available: {e}")
    
    return True, "Flask app tests passed"

if __name__ == '__main__':
    # Find a free port
    port = find_free_port()
    print(f"Testing Flask app on port {port}")
    
    # Start the Flask app in a separate thread
    flask_thread = threading.Thread(target=start_flask_app, args=(port,))
    flask_thread.daemon = True
    flask_thread.start()
    
    # Test the Flask app
    try:
        success, message = test_flask_endpoints(port)
        if success:
            print(f"SUCCESS: {message}")
            sys.exit(0)
        else:
            print(f"ERROR: {message}")
            sys.exit(1)
    except KeyboardInterrupt:
        print("Test interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
""")
    
    # Run the test
    try:
        result = subprocess.run([sys.executable, temp_file], 
                             stdout=subprocess.PIPE, 
                             stderr=subprocess.PIPE, 
                             text=True,
                             timeout=20,
                             check=False)
        
        if result.returncode == 0:
            print_success("Flask application test passed")
            print(result.stdout)
        else:
            print_error("Flask application test failed")
            print(result.stdout)
            print_error(result.stderr)
    except subprocess.TimeoutExpired:
        print_error("Flask application test timed out")
    except Exception as e:
        print_error(f"Error running Flask application test: {e}")
    
    # Clean up
    shutil.rmtree(temp_dir)

def simulate_production_environment():
    """Simulate a production environment using Docker"""
    print_section("Production Environment Simulation")
    
    # Check if Docker is installed
    if not is_command_available('docker'):
        print_error("Docker is not installed or not in PATH")
        print_info("Please install Docker to simulate a production environment")
        return
    
    # Check if docker-compose is available
    docker_compose_available = is_command_available('docker-compose')
    
    # Create a directory for Docker files
    docker_dir = os.path.join(os.getcwd(), 'docker_test')
    os.makedirs(docker_dir, exist_ok=True)
    
    # Create a Dockerfile
    dockerfile_path = os.path.join(docker_dir, 'Dockerfile')
    with open(dockerfile_path, 'w') as f:
        f.write("""FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Create directories if they don't exist
RUN mkdir -p templates static uploads

# Set environment variables
ENV FLASK_ENV=production
ENV PORT=8000

# Expose the port
EXPOSE 8000

# Run the app with gunicorn
CMD gunicorn --bind 0.0.0.0:$PORT app:app
""")
    
    # Create a docker-compose.yml if docker-compose is available
    if docker_compose_available:
        docker_compose_path = os.path.join(docker_dir, 'docker-compose.yml')
        with open(docker_compose_path, 'w') as f:
            f.write("""version: '3'

services:
  web:
    build: ..
    ports:
      - "8000:8000"
    environment:
      - FLASK_ENV=production
      - PORT=8000
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/postgres
    depends_on:
      - db
    volumes:
      - ../:/app
    restart: always

  db:
    image: postgres:14
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init-db.sql:/docker-entrypoint-initdb.d/init-db.sql

volumes:
  postgres_data:
""")
        
        # Create an initialization script for the database
        init_db_path = os.path.join(docker_dir, 'init-db.sql')
        with open(init_db_path, 'w') as f:
            f.write("""-- Create schema
CREATE SCHEMA IF NOT EXISTS propintel;

-- Create tables
CREATE TABLE IF NOT EXISTS propintel.properties (
    property_id SERIAL PRIMARY KEY,
    property_name VARCHAR(255),
    address TEXT,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS propintel.work (
    work_id SERIAL PRIMARY KEY,
    property_id INT NOT NULL,
    work_description TEXT,
    work_date DATE,
    work_cost NUMERIC(10, 2),
    payment_method VARCHAR(50),
    FOREIGN KEY (property_id) REFERENCES propintel.properties (property_id)
);

CREATE TABLE IF NOT EXISTS propintel.money_in (
    money_in_id SERIAL PRIMARY KEY,
    property_id INT NOT NULL,
    income_amount NUMERIC(10,2),
    income_date DATE,
    income_details TEXT,
    payment_method VARCHAR(50),
    FOREIGN KEY (property_id) REFERENCES propintel.properties (property_id)
);

CREATE TABLE IF NOT EXISTS propintel.money_out (
    money_out_id SERIAL PRIMARY KEY,
    property_id INT NOT NULL,
    expense_amount NUMERIC(10,2),
    expense_date DATE,
    expense_details TEXT,
    payment_method VARCHAR(50),
    FOREIGN KEY (property_id) REFERENCES propintel.properties (property_id)
);

-- Insert sample data
INSERT INTO propintel.properties (property_name, address, latitude, longitude)
VALUES 
    ('Test Property 1', '123 Main St, Melbourne, Australia', -37.8136, 144.9631),
    ('Test Property 2', '456 High St, Sydney, Australia', -33.8688, 151.2093);
""")
    
    # Create a README with instructions
    readme_path = os.path.join(docker_dir, 'README.md')
    with open(readme_path, 'w') as f:
        f.write("""# Production Environment Simulation

This directory contains Docker files to simulate a production environment for your application.

## Using Docker Compose (Recommended)

If you have Docker Compose installed, you can start the entire stack with:

```bash
cd docker_test
docker-compose up --build
```

This will start the Flask application with a PostgreSQL database. The application will be available at http://localhost:8000.

## Using Docker Without Compose

If you don't have Docker Compose, you can build and run the Docker image manually:

```bash
# Build the image
docker build -t property-intel -f docker_test/Dockerfile .

# Run the container
docker run -p 8000:8000 -e PORT=8000 property-intel
```

The application will be available at http://localhost:8000, but you'll need to set up the database separately.

## Testing the Deployment

Once the application is running, you can test it by opening http://localhost:8000 in your browser.

## Cleaning Up

To stop and remove the containers:

```bash
# If using Docker Compose
docker-compose down

# If using Docker directly
docker stop $(docker ps -q --filter ancestor=property-intel)
```
""")
    
    print_success(f"Created Docker files in {docker_dir}")
    print_info("Follow the instructions in docker_test/README.md to simulate a production environment")
    
    if docker_compose_available:
        print_info("You can run the following commands to start the production environment:")
        print(f"cd {docker_dir}")
        print("docker-compose up --build")
    else:
        print_info("You can run the following commands to start the production environment:")
        print(f"docker build -t property-intel -f {dockerfile_path} .")
        print("docker run -p 8000:8000 -e PORT=8000 property-intel")

def check_for_common_issues():
    """Check for common deployment issues"""
    print_section("Common Deployment Issues")
    
    issues_found = []
    
    # Check for hardcoded paths
    if os.path.exists('app.py'):
        with open('app.py', 'r') as f:
            content = f.read()
            
            if "os.path.join(os.getcwd()" in content:
                issues_found.append(
                    "Using os.getcwd() can cause issues in production environments. "
                    "Use relative paths or os.path.dirname(__file__) instead."
                )
            
            # Check for hardcoded database credentials
            if "password" in content.lower() and not "os.environ.get" in content:
                issues_found.append(
                    "Hardcoded database credentials found. "
                    "Consider using environment variables for sensitive information."
                )
            
            # Check for debug mode
            if "app.run(debug=True)" in content:
                issues_found.append(
                    "Debug mode is enabled. This should be disabled in production."
                )
            
            # Check for potential port issues
            if "app.run(port=" in content and "os.environ.get('PORT'" not in content:
                issues_found.append(
                    "Hardcoded port found. Cloud platforms often assign their own ports through "
                    "environment variables. Use os.environ.get('PORT', default_port) instead."
                )
    
    # Check for missing Procfile (Heroku)
    if not os.path.exists('Procfile'):
        issues_found.append("Missing Procfile, which is required for Heroku deployment.")
    
    # Check for missing requirements
    essential_packages = ['flask', 'gunicorn', 'psycopg2-binary']
    if os.path.exists('requirements.txt'):
        with open('requirements.txt', 'r') as f:
            requirements = f.read().lower()
            for package in essential_packages:
                if package not in requirements:
                    issues_found.append(f"Missing {package} in requirements.txt")
    
    # Check for large files that might cause deployment issues
    large_files = []
    for root, dirs, files in os.walk('.'):
        if '.git' in root or 'venv' in root or 'env' in root or '__pycache__' in root:
            continue
        for file in files:
            file_path = os.path.join(root, file)
            try:
                size = os.path.getsize(file_path)
                if size > 20 * 1024 * 1024:  # 20 MB
                    large_files.append((file_path, size))
            except:
                pass
    
    if large_files:
        msg = "Large files found that might cause deployment issues:"
        for file_path, size in large_files:
            size_mb = size / (1024 * 1024)
            msg += f"\n  - {file_path}: {size_mb:.2f} MB"
        issues_found.append(msg)
    
    # Report issues
    if issues_found:
        print_warning("Potential issues found:")
        for i, issue in enumerate(issues_found):
            print(f"{i+1}. {issue}")
    else:
        print_success("No common deployment issues found")

def export_diagnostics_report():
    """Export diagnostics information to a JSON file"""
    print_section("Diagnostics Report")
    
    report = {
        "timestamp": datetime.datetime.now().isoformat(),
        "system": {
            "platform": platform.platform(),
            "python_version": platform.python_version(),
            "processor": platform.processor()
        },
        "application": {
            "directory": os.getcwd(),
            "files": {}
        },
        "diagnostic_results": {}
    }
    
    # Add information about key files
    key_files = ['app.py', 'Procfile', 'requirements.txt', '.python-version', 'runtime.txt']
    for file in key_files:
        if os.path.exists(file):
            report["application"]["files"][file] = {
                "exists": True,
                "size": os.path.getsize(file),
                "last_modified": datetime.datetime.fromtimestamp(os.path.getmtime(file)).isoformat()
            }
            
            # Add content for text files (limit size)
            if file.endswith(('.txt', '.py', '.md', 'Procfile')):
                try:
                    with open(file, 'r') as f:
                        content = f.read(10000)  # Limit to 10KB
                        if len(content) >= 10000:
                            content += "\n... (truncated)"
                        report["application"]["files"][file]["content"] = content
                except:
                    report["application"]["files"][file]["content"] = "Error reading file"
        else:
            report["application"]["files"][file] = {
                "exists": False
            }
    
    # Add information about directories
    for dir_name in ['templates', 'static', 'uploads']:
        if os.path.exists(dir_name) and os.path.isdir(dir_name):
            files = os.listdir(dir_name)
            report["application"]["files"][dir_name] = {
                "exists": True,
                "is_directory": True,
                "file_count": len(files),
                "files": files[:20]  # Limit to 20 files
            }
        else:
            report["application"]["files"][dir_name] = {
                "exists": False
            }
    
    # Add installed packages
    try:
        result = subprocess.run([sys.executable, '-m', 'pip', 'freeze'], 
                               stdout=subprocess.PIPE, 
                               check=True)
        report["application"]["installed_packages"] = result.stdout.decode('utf-8').splitlines()
    except:
        report["application"]["installed_packages"] = ["Error getting installed packages"]
    
    # Write the report to a file
    report_file = "property_intel_diagnostic_report.json"
    with open(report_file, 'w') as f:
        json.dump(report, f, indent=2)
    
    print_success(f"Diagnostic report saved to {report_file}")
    print_info(f"Share this file with support personnel for troubleshooting")

def main():
    """Run the diagnostic tool"""
    print_header("Property Intelligence Application Diagnostic Tool")
    
    print_info("This tool will analyze your Flask application and diagnose deployment issues.")
    print_info("It will also create Docker files to simulate a production environment.")
    print()
    
    # Run all checks
    check_system_info()
    check_virtual_env()
    check_app_structure()
    check_dependencies()
    check_database_config()
    test_db_connection()
    check_flask_app()
    test_flask_app_locally()
    check_for_common_issues()
    
    # Export diagnostics report
    export_diagnostics_report()
    
    # Create Docker files for production simulation
    simulate_production_environment()
    
    print()
    print_header("Diagnostic Complete")
    print_info("Review the output above for any issues with your application.")
    print_info("Check the diagnostic report and Docker files for more details.")

if __name__ == "__main__":
    main()