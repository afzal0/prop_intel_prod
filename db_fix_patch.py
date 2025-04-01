#!/usr/bin/env python3

"""
Database fix patch script for PropIntel
This script creates necessary tables and handles session management fixes
"""

import os
import psycopg2
from psycopg2.extras import RealDictCursor
from werkzeug.security import generate_password_hash
import sys

def get_db_connection():
    """Simple database connection function using environment variables or defaults"""
    try:
        # Check for DATABASE_URL environment variable
        database_url = os.environ.get('DATABASE_URL')
        
        if database_url:
            # Parse Heroku DATABASE_URL
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
            conn = psycopg2.connect(database_url)
            return conn
        else:
            # Default connection parameters
            params = {
                "user": "postgres",
                "password": "1234", # This is just an example - you should change this
                "host": "localhost",
                "port": 5432,
                "database": "postgres",
            }
            
            # Override with environment variables if available
            if os.environ.get('DB_USER'):
                params['user'] = os.environ.get('DB_USER')
            if os.environ.get('DB_PASSWORD'):
                params['password'] = os.environ.get('DB_PASSWORD')
            if os.environ.get('DB_HOST'):
                params['host'] = os.environ.get('DB_HOST')
            if os.environ.get('DB_PORT'):
                params['port'] = int(os.environ.get('DB_PORT'))
            if os.environ.get('DB_NAME'):
                params['database'] = os.environ.get('DB_NAME')
                
            conn = psycopg2.connect(**params)
            return conn
    except Exception as e:
        print(f"Database connection error: {e}")
        raise

def fix_database():
    """Fix essential database tables for login and about page"""
    try:
        conn = get_db_connection()
        conn.autocommit = True
        
        with conn.cursor() as cur:
            print("Creating schema if it doesn't exist...")
            cur.execute("CREATE SCHEMA IF NOT EXISTS propintel")
            
            print("Creating users table if it doesn't exist...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS propintel.users (
                    user_id SERIAL PRIMARY KEY,
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
            
            print("Checking if admin user exists...")
            cur.execute("SELECT COUNT(*) FROM propintel.users WHERE username = 'admin'")
            admin_exists = cur.fetchone()[0] > 0
            
            if not admin_exists:
                print("Creating admin user...")
                # Generate password hash for 'admin123'
                admin_password_hash = generate_password_hash('admin123')
                
                cur.execute("""
                    INSERT INTO propintel.users (
                        username, password_hash, email, full_name, role, created_at
                    ) VALUES (
                        'admin', %s, 'admin@propintel.com', 'System Administrator', 'admin', CURRENT_TIMESTAMP
                    )
                """, (admin_password_hash,))
            else:
                print("Admin user already exists.")
            
            print("Creating user_settings table if it doesn't exist...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS propintel.user_settings (
                    setting_id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES propintel.users(user_id),
                    map_theme VARCHAR(20) DEFAULT 'light',
                    default_view VARCHAR(20) DEFAULT 'card',
                    notifications_enabled BOOLEAN DEFAULT TRUE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            print("Creating properties table if it doesn't exist...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS propintel.properties (
                    property_id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES propintel.users(user_id),
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
            
            print("Creating money_in table if it doesn't exist...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS propintel.money_in (
                    money_in_id SERIAL PRIMARY KEY,
                    property_id INTEGER REFERENCES propintel.properties(property_id),
                    user_id INTEGER REFERENCES propintel.users(user_id),
                    income_details TEXT,
                    income_date DATE NOT NULL,
                    income_amount NUMERIC(10, 2) NOT NULL,
                    payment_method VARCHAR(50),
                    income_category VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            print("Creating money_out table if it doesn't exist...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS propintel.money_out (
                    money_out_id SERIAL PRIMARY KEY,
                    property_id INTEGER REFERENCES propintel.properties(property_id),
                    user_id INTEGER REFERENCES propintel.users(user_id),
                    expense_details TEXT,
                    expense_date DATE NOT NULL,
                    expense_amount NUMERIC(10, 2) NOT NULL,
                    payment_method VARCHAR(50),
                    expense_category VARCHAR(100),
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
            print("Creating property_images table if it doesn't exist...")
            cur.execute("""
                CREATE TABLE IF NOT EXISTS propintel.property_images (
                    image_id SERIAL PRIMARY KEY,
                    property_id INTEGER REFERENCES propintel.properties(property_id),
                    user_id INTEGER REFERENCES propintel.users(user_id),
                    image_path VARCHAR(255) NOT NULL,
                    description TEXT,
                    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
            
        print("\nDatabase fix completed successfully!")
        print("\nYou can now run the application with:")
        print("python app.py")
        print("\nLogin credentials:")
        print("Username: admin")
        print("Password: admin123")
        
        conn.close()
        return True
    except Exception as e:
        print(f"Error fixing database: {e}")
        return False

if __name__ == "__main__":
    print("PropIntel Database Fix Utility")
    print("==============================")
    fix_database()