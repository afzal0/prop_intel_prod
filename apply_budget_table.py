#!/usr/bin/env python3
"""
Script to create the budgets table in the PropIntel database
"""
import os
import psycopg2
from configparser import ConfigParser

def get_db_config():
    """Get database connection parameters from the config file"""
    config = ConfigParser()
    config_file = 'database.ini'
    if not os.path.exists(config_file):
        config_file = 'db_config.ini'
    
    if not os.path.exists(config_file):
        raise FileNotFoundError(f"Database config file not found: {config_file}")
    
    config.read(config_file)
    
    db_config = {}
    if config.has_section('postgresql'):
        params = config.items('postgresql')
        for param in params:
            db_config[param[0]] = param[1]
    else:
        raise Exception('Section "postgresql" not found in the database config file')
    
    return db_config

def create_budgets_table():
    """Create the budgets table using the SQL file"""
    conn = None
    try:
        # Connect to the PostgreSQL database
        db_config = get_db_config()
        print(f"Connecting to the PostgreSQL database...")
        conn = psycopg2.connect(**db_config)
        
        # Create a cursor
        with conn.cursor() as cur:
            # Read the SQL file
            with open('create_budgets_table.sql', 'r') as sql_file:
                sql = sql_file.read()
            
            # Execute the SQL commands
            print("Creating budgets table...")
            cur.execute(sql)
            
            # Commit the changes
            conn.commit()
            
            print("Budgets table created successfully!")
            
            # Verify the table was created
            cur.execute("""
                SELECT EXISTS (
                   SELECT FROM information_schema.tables 
                   WHERE table_schema = 'propintel'
                   AND table_name = 'budgets'
                );
            """)
            if cur.fetchone()[0]:
                print("Verification successful: budgets table exists.")
            else:
                print("Warning: budgets table was not created properly.")
    
    except Exception as e:
        print(f"Error creating budgets table: {e}")
        if conn:
            conn.rollback()
    finally:
        if conn:
            conn.close()
            print("Database connection closed.")

if __name__ == "__main__":
    create_budgets_table() 