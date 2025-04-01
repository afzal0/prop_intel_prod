#!/usr/bin/env python3

import os
import psycopg2
from werkzeug.security import generate_password_hash
import datetime
from db_connect import get_db_config

def fix_login_database():
    """Fix database login tables and ensure essential tables exist."""
    print("Fixing database login tables...")
    
    # Get database connection parameters
    try:
        params = get_db_config()
        print("Database configuration loaded.")
    except Exception as e:
        print(f"Error loading database configuration: {e}")
        return False

    try:
        # Connect to PostgreSQL server
        print("Connecting to PostgreSQL database...")
        conn = psycopg2.connect(**params)
        conn.autocommit = True
        
        # Open a cursor to perform database operations
        cur = conn.cursor()
        
        # Create schema if it doesn't exist
        print("Ensuring schema exists...")
        cur.execute("CREATE SCHEMA IF NOT EXISTS propintel;")
        
        # Check if users table exists
        cur.execute("""
            SELECT EXISTS (
                SELECT FROM information_schema.tables 
                WHERE table_schema = 'propintel' AND table_name = 'users'
            );
        """)
        
        if not cur.fetchone()[0]:
            print("Creating users table...")
            cur.execute("""
                CREATE TABLE propintel.users (
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
                );
            """)
            
            # Create admin user
            print("Creating admin user...")
            admin_password_hash = generate_password_hash('admin123')
            cur.execute("""
                INSERT INTO propintel.users (
                    username, password_hash, email, full_name, role, created_at
                ) VALUES (
                    'admin', %s, 'admin@propintel.com', 'System Administrator', 'admin', CURRENT_TIMESTAMP
                ) ON CONFLICT (username) DO NOTHING;
            """, (admin_password_hash,))
        else:
            print("Users table already exists, ensuring admin user exists...")
            # Check if admin user exists
            cur.execute("SELECT user_id FROM propintel.users WHERE username = 'admin';")
            if not cur.fetchone():
                # Create admin user
                admin_password_hash = generate_password_hash('admin123')
                cur.execute("""
                    INSERT INTO propintel.users (
                        username, password_hash, email, full_name, role, created_at
                    ) VALUES (
                        'admin', %s, 'admin@propintel.com', 'System Administrator', 'admin', CURRENT_TIMESTAMP
                    );
                """, (admin_password_hash,))
                print("Admin user created.")
            else:
                print("Admin user already exists.")
                
        # Check if properties table has the required columns
        try:
            cur.execute("""
                SELECT EXISTS (
                    SELECT FROM information_schema.columns 
                    WHERE table_schema = 'propintel' 
                    AND table_name = 'properties' 
                    AND column_name = 'project_type'
                );
            """)
            if not cur.fetchone()[0]:
                print("Adding missing columns to properties table...")
                # Add missing columns to properties table
                cur.execute("""
                    ALTER TABLE propintel.properties 
                    ADD COLUMN IF NOT EXISTS project_name VARCHAR(255),
                    ADD COLUMN IF NOT EXISTS status VARCHAR(50) DEFAULT 'Active',
                    ADD COLUMN IF NOT EXISTS location VARCHAR(255),
                    ADD COLUMN IF NOT EXISTS project_type VARCHAR(100),
                    ADD COLUMN IF NOT EXISTS project_manager VARCHAR(100),
                    ADD COLUMN IF NOT EXISTS due_date DATE,
                    ADD COLUMN IF NOT EXISTS total_income NUMERIC(12, 2) DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS total_expenses NUMERIC(12, 2) DEFAULT 0,
                    ADD COLUMN IF NOT EXISTS profit NUMERIC(12, 2) DEFAULT 0;
                """)
                print("Missing columns added to properties table.")
        except Exception as e:
            print(f"Error checking or updating properties table: {e}")
            print("This is likely because the properties table doesn't exist yet.")
            print("Run the full database initialization script to create all tables.")
            
        # Close cursor and connection
        cur.close()
        conn.close()
        print("Database login fix completed successfully.")
        return True
    except Exception as e:
        print(f"Error fixing database login: {e}")
        return False

if __name__ == "__main__":
    fix_login_database()