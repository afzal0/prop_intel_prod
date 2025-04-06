#!/usr/bin/env python3
"""
Database Update Script for Property Intel
Reads SQL commands from db_update_script.sql and executes them against the database
Use environment variables for credentials (do not hardcode)
"""

import os
import sys
import psycopg2
from psycopg2 import sql
from datetime import datetime

def load_sql_from_file(filename):
    """Load SQL commands from a file"""
    with open(filename, 'r') as sql_file:
        return sql_file.read()

def connect_to_database():
    """Connect to PostgreSQL database using environment variables"""
    try:
        # Set these environment variables before running the script
        # Or use a .env file with a library like python-dotenv
        conn = psycopg2.connect(
            host=os.environ.get('DB_HOST'),
            database=os.environ.get('DB_NAME'),
            user=os.environ.get('DB_USER'),
            password=os.environ.get('DB_PASSWORD'),
            port=os.environ.get('DB_PORT', 5432)
        )
        print("Database connection established successfully!")
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        sys.exit(1)

def execute_sql_script(conn, sql_script):
    """Execute SQL commands from a string"""
    try:
        with conn.cursor() as cursor:
            cursor.execute(sql_script)
        conn.commit()
        print("SQL script executed successfully!")
    except Exception as e:
        conn.rollback()
        print(f"Error executing SQL script: {e}")
        sys.exit(1)

def main():
    """Main function to run the database update"""
    print(f"Starting database update at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    # Check if required environment variables are set
    required_vars = ['DB_HOST', 'DB_NAME', 'DB_USER', 'DB_PASSWORD']
    missing_vars = [var for var in required_vars if not os.environ.get(var)]
    
    if missing_vars:
        print(f"Error: Missing required environment variables: {', '.join(missing_vars)}")
        print("Please set these variables before running the script.")
        sys.exit(1)
    
    # Load SQL script
    try:
        sql_script = load_sql_from_file('db_update_script.sql')
    except Exception as e:
        print(f"Error loading SQL file: {e}")
        sys.exit(1)
    
    # Connect to database and execute script
    conn = connect_to_database()
    execute_sql_script(conn, sql_script)
    conn.close()
    
    print(f"Database update completed at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

if __name__ == "__main__":
    main()