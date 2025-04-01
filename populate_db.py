#!/usr/bin/env python3

import os
import psycopg2
from werkzeug.security import generate_password_hash
import datetime
from db_connect import get_db_config

def setup_database():
    """Set up database tables and populate with initial data."""
    print("Setting up database...")
    
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
        
        # Get path to the SQL file
        sql_file_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'init_db.sql')
        
        # Read and execute the SQL file
        print(f"Executing SQL file: {sql_file_path}")
        with open(sql_file_path, 'r') as f:
            sql_commands = f.read()
            cur.execute(sql_commands)
            
        # Close cursor and connection
        cur.close()
        conn.close()
        print("Database setup completed successfully.")
        return True
    except Exception as e:
        print(f"Error setting up database: {e}")
        return False

if __name__ == "__main__":
    setup_database()