@app.route('/debug')
def debug_info():
    """Debug endpoint to help diagnose issues"""
    import sys
    import os
    import platform
    
    # Basic information
    debug_data = {
        'python_version': sys.version,
        'platform': platform.platform(),
        'working_directory': os.getcwd(),
        'environment': os.environ.get('FLASK_ENV', 'not set'),
    }
    
    # Check for essential directories
    directories = ['templates', 'static', 'uploads']
    dir_status = {}
    for dir_name in directories:
        dir_path = os.path.join(os.getcwd(), dir_name)
        dir_status[dir_name] = {
            'exists': os.path.exists(dir_path),
            'is_dir': os.path.isdir(dir_path) if os.path.exists(dir_path) else False
        }
        if dir_status[dir_name]['exists'] and dir_status[dir_name]['is_dir']:
            try:
                dir_status[dir_name]['contents'] = os.listdir(dir_path)[:10]  # First 10 files
            except:
                dir_status[dir_name]['contents'] = 'Error listing contents'
    
    debug_data['directories'] = dir_status
    
    # Test database connection
    db_status = 'Not tested'
    try:
        import psycopg2
        conn_params = get_db_config()
        # Mask password
        masked_params = conn_params.copy()
        if 'password' in masked_params:
            masked_params['password'] = '*****'
        debug_data['db_connection_params'] = masked_params
        
        # Try to connect
        conn = psycopg2.connect(**conn_params)
        with conn.cursor() as cur:
            cur.execute('SELECT version();')
            db_version = cur.fetchone()[0]
        conn.close()
        db_status = f'Connected: {db_version}'
    except Exception as e:
        db_status = f'Error: {str(e)}'
    
    debug_data['database_status'] = db_status
    
    return jsonify(debug_data)