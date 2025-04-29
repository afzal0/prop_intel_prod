#!/usr/bin/env python3
"""
Script to alter the propintel.documents table to add latitude and longitude columns
"""
import os
import sys
import psycopg2
import configparser
from psycopg2.extras import DictCursor

def get_db_connection():
    """Get a database connection using configuration file"""
    config = configparser.ConfigParser()
    config.read('db_config.ini')
    
    conn = psycopg2.connect(
        user=config['database']['user'],
        password=config['database']['password'],
        host=config['database']['host'],
        port=config['database']['port'],
        dbname=config['database']['database']
    )
    
    conn.autocommit = True
    return conn

def alter_documents_table():
    """Add latitude and longitude columns to documents table"""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("""
        SELECT column_name
        FROM information_schema.columns
        WHERE table_schema = 'propintel' AND table_name = 'documents'
        AND column_name IN ('latitude', 'longitude')
        """)
        
        existing_columns = [row[0] for row in cursor.fetchall()]
        
        # Add latitude column if not exists
        if 'latitude' not in existing_columns:
            print("Adding latitude column to documents table...")
            cursor.execute("""
            ALTER TABLE propintel.documents
            ADD COLUMN latitude NUMERIC(10, 6)
            """)
            print("Latitude column added successfully.")
        else:
            print("Latitude column already exists.")
        
        # Add longitude column if not exists
        if 'longitude' not in existing_columns:
            print("Adding longitude column to documents table...")
            cursor.execute("""
            ALTER TABLE propintel.documents
            ADD COLUMN longitude NUMERIC(10, 6)
            """)
            print("Longitude column added successfully.")
        else:
            print("Longitude column already exists.")
        
        # Create spatial index if PostGIS is available
        try:
            cursor.execute("SELECT PostGIS_Version()")
            postgis_available = True
        except:
            postgis_available = False
        
        if postgis_available:
            print("PostGIS is available, creating spatial index...")
            # First check if geometry column exists
            cursor.execute("""
            SELECT column_name
            FROM information_schema.columns
            WHERE table_schema = 'propintel' AND table_name = 'documents'
            AND column_name = 'geom'
            """)
            
            if not cursor.fetchone():
                # Add geometry column
                cursor.execute("""
                ALTER TABLE propintel.documents
                ADD COLUMN geom geometry(Point, 4326)
                """)
                
                # Create spatial index
                cursor.execute("""
                CREATE INDEX IF NOT EXISTS documents_geom_idx
                ON propintel.documents
                USING GIST (geom)
                """)
                
                # Create trigger to update geometry when lat/long change
                cursor.execute("""
                CREATE OR REPLACE FUNCTION update_document_geom()
                RETURNS TRIGGER AS $$
                BEGIN
                    IF NEW.latitude IS NOT NULL AND NEW.longitude IS NOT NULL THEN
                        NEW.geom = ST_SetSRID(ST_MakePoint(NEW.longitude, NEW.latitude), 4326);
                    ELSE
                        NEW.geom = NULL;
                    END IF;
                    RETURN NEW;
                END;
                $$ LANGUAGE plpgsql;
                
                DROP TRIGGER IF EXISTS trigger_update_document_geom ON propintel.documents;
                
                CREATE TRIGGER trigger_update_document_geom
                BEFORE INSERT OR UPDATE OF latitude, longitude
                ON propintel.documents
                FOR EACH ROW
                EXECUTE FUNCTION update_document_geom();
                """)
                
                # Update existing rows
                cursor.execute("""
                UPDATE propintel.documents
                SET geom = ST_SetSRID(ST_MakePoint(longitude, latitude), 4326)
                WHERE latitude IS NOT NULL AND longitude IS NOT NULL
                """)
                
                print("Spatial index created and existing rows updated.")
            else:
                print("Geometry column already exists.")
        else:
            print("PostGIS not available, skipping spatial index creation.")
        
        conn.commit()
        print("Database update completed successfully.")
        
        cursor.close()
        conn.close()
        
        return True
    
    except Exception as e:
        print(f"Error: {e}")
        return False

if __name__ == "__main__":
    print("Starting database modification script...")
    success = alter_documents_table()
    if success:
        print("Script completed successfully.")
    else:
        print("Script encountered errors.")
        sys.exit(1)