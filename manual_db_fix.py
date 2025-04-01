#!/usr/bin/env python3

"""
Manual database fix script for PropIntel
This script creates all necessary tables directly
"""

import os
import psycopg2
from werkzeug.security import generate_password_hash
import configparser
import uuid  # Add this import for generating UUIDs

def get_db_config():
    """Get database configuration from config file or environment variables"""
    # Check for DATABASE_URL environment variable
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Parse DATABASE_URL (for Heroku)
        from urllib.parse import urlparse
        
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
    else:
        # Try to read from config file
        config = configparser.ConfigParser()
        
        # Default connection parameters
        default_params = {
            "user": "postgres",
            "password": "1234",
            "host": "localhost",
            "port": 5432,
            "database": "postgres",
        }
        
        if os.path.exists('db_config.ini'):
            try:
                config.read('db_config.ini')
                if 'database' in config:
                    return {
                        "user": config['database'].get('user', default_params['user']),
                        "password": config['database'].get('password', default_params['password']),
                        "host": config['database'].get('host', default_params['host']),
                        "port": int(config['database'].get('port', default_params['port'])),
                        "database": config['database'].get('database', default_params['database']),
                    }
            except Exception as e:
                print(f"Error reading config file: {e}. Using default parameters.")
        
        return default_params

def fix_database():
    """Fix database tables manually"""
    print("PropIntel Manual Database Fix")
    print("=============================")
    
    # Get database connection parameters
    try:
        params = get_db_config()
        print(f"Using database: {params['host']}:{params['port']}/{params['database']}")
    except Exception as e:
        print(f"Error loading database configuration: {e}")
        return False

    try:
        # Connect to database
        print("\nConnecting to database...")
        conn = psycopg2.connect(**params)
        conn.autocommit = True
        cur = conn.cursor()
        
        # Create schema
        print("Creating schema...")
        cur.execute("CREATE SCHEMA IF NOT EXISTS propintel")
        
        # Create users table
        print("Creating users table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS propintel.users (
                user_id VARCHAR(50) PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                email VARCHAR(100) UNIQUE NOT NULL,
                full_name VARCHAR(100) NOT NULL,
                role VARCHAR(20) NOT NULL DEFAULT 'user',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )
        """)
        
        # Check if admin user exists
        cur.execute("SELECT COUNT(*) FROM propintel.users WHERE username = 'admin'")
        if cur.fetchone()[0] == 0:
            # Create admin user
            print("Creating admin user...")
            # Generate a UUID for the user_id
            admin_user_id = str(uuid.uuid4())
            # bcrypt hash for 'admin123'
            admin_password_hash = generate_password_hash('admin123')
            cur.execute("""
                INSERT INTO propintel.users (
                    user_id, username, password_hash, email, full_name, role
                ) VALUES (
                    %s, 'admin', %s, 'admin@propintel.com', 'System Administrator', 'admin'
                )
            """, (admin_user_id, admin_password_hash))
        else:
            print("Admin user already exists")
        
        # Create user_settings table
        print("Creating user_settings table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS propintel.user_settings (
                setting_id SERIAL PRIMARY KEY,
                user_id VARCHAR(50) REFERENCES propintel.users(user_id),
                map_theme VARCHAR(20) DEFAULT 'light',
                default_view VARCHAR(20) DEFAULT 'card',
                notifications_enabled BOOLEAN DEFAULT TRUE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create properties table
        print("Creating properties table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS propintel.properties (
                property_id SERIAL PRIMARY KEY,
                user_id VARCHAR(50) REFERENCES propintel.users(user_id),
                property_name VARCHAR(255) NOT NULL,
                project_name VARCHAR(255),
                status VARCHAR(50) DEFAULT 'Active',
                address TEXT NOT NULL,
                location VARCHAR(255),
                project_type VARCHAR(100),
                project_manager VARCHAR(100),
                due_date DATE,
                latitude NUMERIC(10, 6),
                longitude NUMERIC(10, 6),
                purchase_date DATE,
                purchase_price NUMERIC(12, 2),
                current_value NUMERIC(12, 2),
                total_income NUMERIC(12, 2) DEFAULT 0,
                total_expenses NUMERIC(12, 2) DEFAULT 0,
                profit NUMERIC(12, 2) DEFAULT 0,
                notes TEXT,
                is_hidden BOOLEAN DEFAULT FALSE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create work table
        print("Creating work table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS propintel.work (
                work_id SERIAL PRIMARY KEY,
                property_id INTEGER REFERENCES propintel.properties(property_id),
                user_id VARCHAR(50) REFERENCES propintel.users(user_id),
                work_description TEXT NOT NULL,
                work_date DATE NOT NULL,
                work_cost NUMERIC(10, 2),
                payment_method VARCHAR(50),
                status VARCHAR(50) DEFAULT 'Pending',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create money_in table
        print("Creating money_in table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS propintel.money_in (
                money_in_id SERIAL PRIMARY KEY,
                property_id INTEGER REFERENCES propintel.properties(property_id),
                user_id VARCHAR(50) REFERENCES propintel.users(user_id),
                income_details TEXT,
                income_date DATE NOT NULL,
                income_amount NUMERIC(10, 2) NOT NULL,
                payment_method VARCHAR(50),
                income_category VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create money_out table
        print("Creating money_out table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS propintel.money_out (
                money_out_id SERIAL PRIMARY KEY,
                property_id INTEGER REFERENCES propintel.properties(property_id),
                user_id VARCHAR(50) REFERENCES propintel.users(user_id),
                expense_details TEXT,
                expense_date DATE NOT NULL,
                expense_amount NUMERIC(10, 2) NOT NULL,
                payment_method VARCHAR(50),
                expense_category VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create property_images table
        print("Creating property_images table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS propintel.property_images (
                image_id SERIAL PRIMARY KEY,
                property_id INTEGER REFERENCES propintel.properties(property_id),
                user_id VARCHAR(50) REFERENCES propintel.users(user_id),
                work_id INTEGER REFERENCES propintel.work(work_id),
                image_path VARCHAR(255) NOT NULL,
                image_type VARCHAR(50) DEFAULT 'property',
                description TEXT,
                upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create audit_log table
        print("Creating audit_log table...")
        cur.execute("""
            CREATE TABLE IF NOT EXISTS propintel.audit_log (
                log_id SERIAL PRIMARY KEY,
                user_id VARCHAR(50) REFERENCES propintel.users(user_id),
                action_type VARCHAR(50) NOT NULL,
                table_name VARCHAR(50),
                record_id INTEGER,
                details TEXT,
                ip_address VARCHAR(45),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Create directories for static files
        static_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'static')
        images_dir = os.path.join(static_dir, 'images')
        
        print("\nCreating static directories...")
        if not os.path.exists(static_dir):
            os.makedirs(static_dir)
            print(f"Created directory: {static_dir}")
        
        if not os.path.exists(images_dir):
            os.makedirs(images_dir)
            print(f"Created directory: {images_dir}")
        
        # Create placeholder files
        logo_path = os.path.join(static_dir, 'logo.png')
        if not os.path.exists(logo_path):
            print(f"Creating placeholder logo: {logo_path}")
            with open(logo_path, 'w') as f:
                f.write('')
        
        placeholder_path = os.path.join(images_dir, 'property-placeholder.jpg')
        if not os.path.exists(placeholder_path):
            print(f"Creating property placeholder: {placeholder_path}")
            with open(placeholder_path, 'w') as f:
                f.write('')
        
        cur.close()
        conn.close()
        
        print("\nDatabase fix completed successfully!")
        print("\nYou can now log in with:")
        print("Username: admin")
        print("Password: admin123")
        
        return True
    except Exception as e:
        print(f"Error fixing database: {e}")
        return False

if __name__ == "__main__":
    fix_database()