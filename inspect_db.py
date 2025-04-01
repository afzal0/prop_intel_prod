#!/usr/bin/env python3
from app import get_db_connection
import psycopg2.extras

def main():
    conn = get_db_connection()
    cur = conn.cursor()
    
    # Get all tables in propintel schema
    cur.execute("SELECT table_name FROM information_schema.tables WHERE table_schema = 'propintel' ORDER BY table_name")
    tables = cur.fetchall()
    
    print('Tables in propintel schema:')
    for table in tables:
        print(f'- {table[0]}')
    print()
    
    # Get schema for each table
    for table in [row[0] for row in tables]:
        print(f'Schema for {table}:')
        cur.execute(f"SELECT column_name, data_type FROM information_schema.columns "
                    f"WHERE table_schema = 'propintel' AND table_name = '{table}' "
                    f"ORDER BY ordinal_position")
        columns = cur.fetchall()
        for col in columns:
            print(f'  - {col[0]}: {col[1]}')
        print()
    
    # Get sample data from properties table
    cur.execute("SELECT * FROM propintel.properties LIMIT 5")
    properties = cur.fetchall()
    if properties:
        print("Sample property data (up to 5 rows):")
        for prop in properties:
            print(prop)
    
    conn.close()

if __name__ == "__main__":
    main()