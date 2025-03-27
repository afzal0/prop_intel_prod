#!/usr/bin/env python3
"""
Database Update Script for PropIntel
Adds the is_hidden column to the properties table
"""
import psycopg2
import os
import sys

# Import our database connection function
try:
    from app import get_db_connection
    print("Using connection function from app.py")
except ImportError:
    print("Could not import from app.py, using environment variables")
    
    def get_db_connection():
        """Get a connection to the PostgreSQL database"""
        # Check for DATABASE_URL environment variable (for Heroku)
        database_url = os.environ.get('DATABASE_URL')
        
        if database_url:
            # Use environment variable if available
            if database_url.startswith('postgres://'):
                database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
            conn = psycopg2.connect(database_url)
            return conn
        else:
            # Local connection params
            params = {
                'host': 'localhost',
                'database': 'propintel',
                'user': 'postgres',
                'password': 'postgres'
            }
            conn = psycopg2.connect(**params)
            return conn

def update_properties_table():
    """Add the is_hidden column to properties table if it doesn't exist"""
    conn = get_db_connection()
    try:
        with conn.cursor() as cur:
            # Check if column exists
            cur.execute("""
                SELECT column_name 
                FROM information_schema.columns 
                WHERE table_schema = 'propintel' 
                  AND table_name = 'properties'
                  AND column_name = 'is_hidden'
            """)
            
            if cur.fetchone():
                print("Column 'is_hidden' already exists in properties table")
            else:
                print("Adding 'is_hidden' column to properties table...")
                cur.execute("""
                    ALTER TABLE propintel.properties 
                    ADD COLUMN is_hidden BOOLEAN DEFAULT false
                """)
                conn.commit()
                print("Column added successfully!")
                
            # Also make sure we have a placeholder image for properties
            print("Creating static directory if it doesn't exist...")
            os.makedirs('static', exist_ok=True)
            
            # Check if placeholder image exists
            placeholder_path = os.path.join('static', 'placeholder-property.jpg')
            if not os.path.exists(placeholder_path):
                print("Creating placeholder property image...")
                # Create a very basic placeholder image (this would be better with Pillow)
                with open(placeholder_path, 'wb') as f:
                    # Use a simple 1x1 pixel JPG (this is just a minimal example)
                    f.write(b'\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x01\x00H\x00H\x00\x00\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e\x1d\x1a\x1c\x1c $.\' ",#\x1c\x1c(7),01444\x1f\'9=82<.342\xff\xdb\x00C\x01\t\t\t\x0c\x0b\x0c\x18\r\r\x182!\x1c!22222222222222222222222222222222222222222222222222\xff\xc0\x00\x11\x08\x00\x01\x00\x01\x03\x01"\x00\x02\x11\x01\x03\x11\x01\xff\xc4\x00\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\x00\xb5\x10\x00\x02\x01\x03\x03\x02\x04\x03\x05\x05\x04\x04\x00\x00\x01}\x01\x02\x03\x00\x04\x11\x05\x12!1A\x06\x13Qa\x07"q\x142\x81\x91\xa1\x08#B\xb1\xc1\x15R\xd1\xf0$3br\x82\t\n\x16\x17\x18\x19\x1a%&\'()*456789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xc4\x00\x1f\x01\x00\x03\x01\x01\x01\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xc4\x00\xb5\x11\x00\x02\x01\x02\x04\x04\x03\x04\x07\x05\x04\x04\x00\x01\x02w\x00\x01\x02\x03\x11\x04\x05!1\x06\x12AQ\x07aq\x13"2\x81\x08\x14B\x91\xa1\xb1\xc1\t#3R\xf0\x15br\xd1\n\x16$4\xe1%\xf1\x17\x18\x19\x1a&\'()*56789:CDEFGHIJSTUVWXYZcdefghijstuvwxyz\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x92\x93\x94\x95\x96\x97\x98\x99\x9a\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xff\xda\x00\x0c\x03\x01\x00\x02\x11\x03\x11\x00?\x00\xfe\xfe(\xa2\x8a\x00\xff\xd9')
                print("Placeholder image created!")
    except Exception as e:
        conn.rollback()
        print(f"Error updating database: {e}")
        return False
    finally:
        conn.close()
    
    return True

if __name__ == "__main__":
    print("PropIntel Database Update Utility")
    print("--------------------------------")
    
    if update_properties_table():
        print("Database update completed successfully!")
        sys.exit(0)
    else:
        print("Database update failed.")
        sys.exit(1)