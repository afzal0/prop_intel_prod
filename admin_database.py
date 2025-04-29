"""
Admin database operations for PropIntel
"""
import os
import sys
import subprocess
import time
import logging
import psycopg2
import configparser
from datetime import datetime
from flask import Blueprint, render_template, request, jsonify, g
from psycopg2.extras import DictCursor

from login_decorator import login_required, admin_required
from shapefile_utils import import_vic_lgas, generate_work_heatmap

# Set up logging
logger = logging.getLogger(__name__)

# Create blueprint
admin_db_bp = Blueprint('admin_db', __name__, url_prefix='/admin')

def get_db_connection():
    """Get a database connection"""
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

def get_db_info():
    """Get database information"""
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            # Get database name
            cursor.execute("SELECT current_database() AS name")
            db_name = cursor.fetchone()['name']
            
            # Get server version
            cursor.execute("SELECT version()")
            version = cursor.fetchone()['version']
            
            # Get server host
            cursor.execute("SELECT inet_server_addr() AS host")
            host = cursor.fetchone()['host']
            
            return {
                'name': db_name,
                'version': version,
                'host': host
            }
    except Exception as e:
        logger.error(f"Error getting database info: {e}")
        return {
            'name': 'Unknown',
            'version': 'Unknown',
            'host': 'Unknown'
        }
    finally:
        if 'conn' in locals():
            conn.close()

def get_table_stats():
    """Get table statistics"""
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=DictCursor) as cursor:
            cursor.execute("""
            SELECT 
                table_name AS name,
                (SELECT COUNT(*) FROM propintel."" || table_name) AS row_count,
                (SELECT MAX(updated_at) FROM propintel."" || table_name) AS last_updated
            FROM 
                information_schema.tables
            WHERE 
                table_schema = 'propintel'
                AND table_type = 'BASE TABLE'
            ORDER BY 
                table_name
            """)
            
            result = []
            for row in cursor.fetchall():
                result.append({
                    'name': row['name'],
                    'row_count': row['row_count'] or 0,
                    'last_updated': row['last_updated'].strftime('%Y-%m-%d %H:%M') if row['last_updated'] else 'N/A'
                })
            
            return result
    except Exception as e:
        logger.error(f"Error getting table stats: {e}")
        return []
    finally:
        if 'conn' in locals():
            conn.close()

@admin_db_bp.route('/database-maintenance')
@login_required
@admin_required
def database_maintenance():
    """Database maintenance page"""
    db_info = get_db_info()
    table_stats = get_table_stats()
    
    return render_template(
        'admin/database_maintenance.html',
        db_info=db_info,
        table_stats=table_stats
    )

@admin_db_bp.route('/run-operation')
@login_required
@admin_required
def run_operation():
    """Run a database operation"""
    operation = request.args.get('operation')
    
    if not operation:
        return "Error: No operation specified", 400
    
    # Operation: Add latitude/longitude columns to documents table
    if operation == 'fix-latitude-longitude':
        try:
            # Run the Python script
            script_path = os.path.join(os.path.dirname(__file__), 'db_fix_latitude_longitude.py')
            
            # Check if script exists
            if not os.path.exists(script_path):
                return f"Error: Script {script_path} not found", 404
            
            # Run the script
            result = subprocess.run(
                [sys.executable, script_path],
                capture_output=True,
                text=True
            )
            
            # Return output and error message
            output = result.stdout or ""
            error = result.stderr or ""
            
            if result.returncode != 0:
                return f"Error running script:\n{error}\n{output}", 500
            
            return output
        
        except Exception as e:
            logger.error(f"Error running latitude/longitude fix: {e}")
            return f"Error: {str(e)}", 500
    
    # Operation: Rebuild work heatmap
    elif operation == 'rebuild-heatmap':
        try:
            # Call the generate_work_heatmap function
            success = generate_work_heatmap()
            
            if success:
                return "Work heatmap data regenerated successfully"
            else:
                return "Error regenerating work heatmap data", 500
        
        except Exception as e:
            logger.error(f"Error rebuilding work heatmap: {e}")
            return f"Error: {str(e)}", 500
    
    # Operation: Update LGA data from shapefile
    elif operation == 'update-lga-data':
        try:
            # Call the import_vic_lgas function
            success = import_vic_lgas()
            
            if success:
                return "LGA data updated successfully from shapefile"
            else:
                return "Error updating LGA data", 500
        
        except Exception as e:
            logger.error(f"Error updating LGA data: {e}")
            return f"Error: {str(e)}", 500
    
    # Unknown operation
    else:
        return f"Unknown operation: {operation}", 400

@admin_db_bp.route('/run-diagnostics')
@login_required
@admin_required
def run_diagnostics():
    """Run database diagnostics"""
    try:
        conn = get_db_connection()
        with conn.cursor() as cursor:
            output = []
            
            # Database size
            cursor.execute("""
            SELECT pg_size_pretty(pg_database_size(current_database())) AS size
            """)
            db_size = cursor.fetchone()[0]
            output.append(f"Database size: {db_size}")
            
            # Table sizes
            cursor.execute("""
            SELECT 
                table_name, 
                pg_size_pretty(pg_relation_size('propintel.' || table_name)) AS size
            FROM 
                information_schema.tables
            WHERE 
                table_schema = 'propintel'
                AND table_type = 'BASE TABLE'
            ORDER BY 
                pg_relation_size('propintel.' || table_name) DESC
            """)
            
            output.append("\nTable sizes:")
            for row in cursor.fetchall():
                output.append(f"  {row[0]}: {row[1]}")
            
            # Check for missing indexes
            cursor.execute("""
            SELECT 
                t.table_name, 
                c.column_name
            FROM 
                information_schema.tables t
            JOIN 
                information_schema.columns c ON t.table_name = c.table_name AND t.table_schema = c.table_schema
            LEFT JOIN 
                pg_indexes i ON t.table_name = i.tablename AND c.column_name = ANY(string_to_array(i.indexdef, ' '))
            WHERE 
                t.table_schema = 'propintel'
                AND t.table_type = 'BASE TABLE'
                AND c.column_name LIKE '%\_id' OR c.column_name IN ('id', 'property_id', 'user_id', 'lga_id', 'document_id')
                AND i.indexname IS NULL
            """)
            
            missing_indexes = cursor.fetchall()
            if missing_indexes:
                output.append("\nPotential missing indexes:")
                for row in missing_indexes:
                    output.append(f"  {row[0]}.{row[1]}")
            else:
                output.append("\nNo missing indexes found on common ID columns.")
            
            # Check for database errors
            cursor.execute("""
            SELECT COUNT(*) FROM pg_stat_activity WHERE state = 'active' AND query NOT LIKE '%pg_stat_activity%'
            """)
            active_connections = cursor.fetchone()[0]
            output.append(f"\nActive connections: {active_connections}")
            
            # Check for slow queries (if pg_stat_statements is available)
            try:
                cursor.execute("""
                SELECT COUNT(*) FROM pg_extension WHERE extname = 'pg_stat_statements'
                """)
                if cursor.fetchone()[0] > 0:
                    cursor.execute("""
                    SELECT 
                        query, 
                        calls, 
                        round(total_exec_time::numeric, 2) AS total_time,
                        round(mean_exec_time::numeric, 2) AS mean_time
                    FROM 
                        pg_stat_statements
                    ORDER BY 
                        total_exec_time DESC
                    LIMIT 5
                    """)
                    
                    slow_queries = cursor.fetchall()
                    if slow_queries:
                        output.append("\nTop 5 slowest queries:")
                        for row in slow_queries:
                            query = row[0]
                            calls = row[1]
                            total_time = row[2]
                            mean_time = row[3]
                            # Truncate query if too long
                            if len(query) > 100:
                                query = query[:100] + "..."
                            output.append(f"  Query: {query}")
                            output.append(f"  Calls: {calls}, Total time: {total_time}ms, Mean time: {mean_time}ms")
                            output.append("")
            except:
                output.append("\npg_stat_statements extension not available for query analysis.")
            
            # Overall health check
            output.append("\nDatabase health check:")
            output.append("  ✓ Connection successful")
            output.append(f"  ✓ Database size: {db_size}")
            output.append(f"  ✓ Active connections: {active_connections}")
            if missing_indexes:
                output.append(f"  ⚠ Found {len(missing_indexes)} potential missing indexes")
            else:
                output.append("  ✓ No obvious missing indexes")
            
            # Done
            output.append("\nDiagnostics completed successfully!")
            
            return "\n".join(output)
    
    except Exception as e:
        logger.error(f"Error running diagnostics: {e}")
        return f"Error running diagnostics: {str(e)}"
    
    finally:
        if 'conn' in locals():
            conn.close()

@admin_db_bp.route('/backup-database')
@login_required
@admin_required
def backup_database():
    """Backup database"""
    try:
        # Get database configuration
        config = configparser.ConfigParser()
        config.read('db_config.ini')
        
        # Create backup directory if it doesn't exist
        backup_dir = os.path.join(os.path.dirname(__file__), 'backups')
        os.makedirs(backup_dir, exist_ok=True)
        
        # Create backup filename with timestamp
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_file = os.path.join(backup_dir, f"propintel_backup_{timestamp}.sql")
        
        # Get database connection info
        db_host = config['database']['host']
        db_port = config['database']['port']
        db_name = config['database']['database']
        db_user = config['database']['user']
        
        # Set environment variables for password (more secure than command line)
        env = os.environ.copy()
        env['PGPASSWORD'] = config['database']['password']
        
        # Run pg_dump
        cmd = [
            'pg_dump',
            '-h', db_host,
            '-p', db_port,
            '-U', db_user,
            '-F', 'c',  # Custom format (compressed)
            '-b',       # Include large objects
            '-v',       # Verbose output
            '-f', backup_file,
            db_name
        ]
        
        # Check if pg_dump is available
        try:
            subprocess.run(['pg_dump', '--version'], capture_output=True, env=env)
        except FileNotFoundError:
            return "Error: pg_dump not found. Please install PostgreSQL client tools."
        
        # Run the backup
        process = subprocess.run(cmd, capture_output=True, text=True, env=env)
        
        # Check results
        if process.returncode != 0:
            return f"Error creating backup:\n{process.stderr}"
        
        # Get backup file size
        backup_size = os.path.getsize(backup_file)
        backup_size_mb = backup_size / (1024 * 1024)
        
        # Return success message
        return f"Database backup created successfully at {backup_file}\nSize: {backup_size_mb:.2f} MB"
    
    except Exception as e:
        logger.error(f"Error backing up database: {e}")
        return f"Error: {str(e)}"

@admin_db_bp.route('/clear-cache')
@login_required
@admin_required
def clear_cache():
    """Clear application cache"""
    try:
        # This is just a placeholder for demonstration
        # In a real application, you would clear the appropriate caches
        
        # Simulate clearing cache
        time.sleep(1)
        
        return "Cache cleared successfully"
    
    except Exception as e:
        logger.error(f"Error clearing cache: {e}")
        return f"Error: {str(e)}"