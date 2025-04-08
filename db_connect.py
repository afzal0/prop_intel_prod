import os
import configparser
from urllib.parse import urlparse

def get_db_config():
    """
    Get database configuration from environment variable (for Heroku)
    or from config file (for local development)
    """
    # Check for DATABASE_URL environment variable (set by Heroku)
    database_url = os.environ.get('DATABASE_URL')
    
    if database_url:
        # Parse Heroku DATABASE_URL
        # Note: Heroku uses 'postgres://' but psycopg2 needs 'postgresql://'
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
            
        # Parse the URL
        result = urlparse(database_url)
        
        # Build connection parameters
        return {
            "user": result.username,
            "password": result.password,
            "host": result.hostname,
            "port": result.port or 5432,
            "database": result.path[1:],  # Remove leading slash
        }
    else:
        # Fallback to config file for local development
        config = configparser.ConfigParser()
        
        # Default connection parameters
        default_params = {
            "user": "u15p78tmoefhv2",
            "password": "p78dc6c2370076ee1ac7f23f370d707687e8400f94032cccdb35ddd1d7b37381f",
            "host": "c1i13pt05ja4ag.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com",
            "port": 5432,
            "database": "d1oncga6g47frr",
        }

        # Try to read from config file
        if os.path.exists('db_config.ini'):
            try:
                config.read('db_config.ini')
                if 'database' in config:
                    return {
                        "user": config['database'].get('user', default_params['user']),
                        "password": config['database'].get('password', default_params['password']),
                        "host": config['database'].get('host', default_params['host']),
                        "port": int(config['database'].get('port', default_params['port'])),
                        "database": config['database'].get('database', default_params['database']),
                    }
            except Exception as e:
                print(f"Error reading config file: {e}. Using default parameters.")
        
        return default_params