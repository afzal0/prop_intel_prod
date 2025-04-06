import os
import sys
import psycopg2
import psycopg2.extras

# Database configuration
DB_CONFIG = {
    'user': 'postgres',
    'password': '1234',
    'host': 'localhost',
    'port': '5432',
    'database': 'postgres'
}

def get_db_connection():
    """Get a database connection using the provided configuration"""
    conn = psycopg2.connect(
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        host=DB_CONFIG['host'],
        port=DB_CONFIG['port'],
        dbname=DB_CONFIG['database']
    )
    conn.autocommit = False
    return conn

def apply_schema_updates():
    """Apply schema updates from schema_update.sql"""
    print("Applying schema updates...")
    
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor() as cur:
            # Read and execute the SQL file
            with open('schema_update.sql', 'r') as f:
                sql = f.read()
                cur.execute(sql)
            
            conn.commit()
            print("Schema updates applied successfully.")
    except Exception as e:
        print(f"Error applying schema updates: {e}")
        if conn:
            conn.rollback()
        return False
    finally:
        if conn:
            conn.close()
    
    return True

def create_directories():
    """Create necessary directories for image storage"""
    print("Creating image directories...")
    
    try:
        # Create directories for different image types
        os.makedirs('static/images/properties', exist_ok=True)
        os.makedirs('static/images/work', exist_ok=True)
        os.makedirs('static/images/receipts', exist_ok=True)
        print("Image directories created successfully.")
    except Exception as e:
        print(f"Error creating directories: {e}")
        return False
    
    return True

def main():
    """Main function to apply all updates"""
    print("Starting PropIntel updates application...")
    
    if not apply_schema_updates():
        print("Failed to apply schema updates. Aborting.")
        return False
    
    if not create_directories():
        print("Failed to create directories. Aborting.")
        return False
    
    print("\nAll updates applied successfully!")
    print("\nIMPORTANT: To use the new features, you need to:")
    print("1. Replace the routes in app.py with the ones from app_update.py")
    print("2. Restart the Flask application")
    
    return True

if __name__ == "__main__":
    success = main()
    sys.exit(0 if success else 1)