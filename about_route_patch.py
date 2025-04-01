"""
Patch for the about route in app.py
Copy this code and replace the existing about route in app.py
"""

@app.route('/about')
def about():
    """About page with application information"""
    # Initialize default values
    stats = {
        'property_count': 0,
        'user_count': 0,
        'total_income': 0,
        'total_expenses': 0,
        'project_types': [],
        'statuses': []
    }
    
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Safely get property count
            try:
                cur.execute("SELECT COUNT(*) as count FROM propintel.properties")
                stats['property_count'] = cur.fetchone()['count']
            except Exception as e:
                print(f"Error counting properties: {e}")
            
            # Safely get user count
            try:
                cur.execute("SELECT COUNT(*) as count FROM propintel.users WHERE is_active = TRUE")
                stats['user_count'] = cur.fetchone()['count']
            except Exception as e:
                print(f"Error counting users: {e}")
                # Ensure users table exists
                try:
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
                    conn.commit()
                except Exception as create_error:
                    print(f"Error creating users table: {create_error}")
            
            # Safely get financial totals
            try:
                cur.execute("""
                    SELECT 
                        COALESCE(SUM(total_income), 0) as income, 
                        COALESCE(SUM(total_expenses), 0) as expenses 
                    FROM propintel.properties
                """)
                result = cur.fetchone()
                if result:
                    stats['total_income'] = float(result['income'] or 0)
                    stats['total_expenses'] = float(result['expenses'] or 0)
            except Exception as e:
                print(f"Error calculating financials: {e}")
            
            # Safely get project type distribution
            try:
                cur.execute("""
                    SELECT project_type, COUNT(*) as count 
                    FROM propintel.properties 
                    WHERE project_type IS NOT NULL 
                    GROUP BY project_type 
                    ORDER BY count DESC
                """)
                stats['project_types'] = cur.fetchall() or []
            except Exception as e:
                print(f"Error getting project types: {e}")
                stats['project_types'] = []
            
            # Safely get status distribution
            try:
                cur.execute("""
                    SELECT status, COUNT(*) as count 
                    FROM propintel.properties 
                    WHERE status IS NOT NULL 
                    GROUP BY status 
                    ORDER BY count DESC
                """)
                stats['statuses'] = cur.fetchall() or []
            except Exception as e:
                print(f"Error getting statuses: {e}")
                stats['statuses'] = []
            
    except Exception as e:
        flash(f"Error loading about page: {e}", "danger")
    finally:
        conn.close()
    
    # Format data for charts
    project_type_labels = [pt['project_type'] for pt in stats['project_types']]
    project_type_data = [pt['count'] for pt in stats['project_types']]
    
    status_labels = [s['status'] for s in stats['statuses']]
    status_data = [s['count'] for s in stats['statuses']]
    
    return render_template('about.html',
                         property_count=stats['property_count'],
                         user_count=stats['user_count'],
                         total_income=stats['total_income'],
                         total_expenses=stats['total_expenses'],
                         profit=stats['total_income'] - stats['total_expenses'],
                         project_type_labels=json.dumps(project_type_labels),
                         project_type_data=json.dumps(project_type_data),
                         status_labels=json.dumps(status_labels),
                         status_data=json.dumps(status_data))