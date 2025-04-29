"""
Utility functions for centralized logging and log management
"""
import os
import re
import json
import logging
from datetime import datetime
from flask import request, g
from logging.handlers import RotatingFileHandler

# Configure base logging
logging.basicConfig(level=logging.INFO, 
                   format='%(asctime)s - %(levelname)s - %(message)s')

# Log files
LOG_DIR = os.path.dirname(os.path.abspath(__file__))
APP_LOG_FILE = os.path.join(LOG_DIR, 'app.log')
SESSION_LOG_FILE = os.path.join(LOG_DIR, 'session_debug.log')
IMPORT_LOG_FILE = os.path.join(LOG_DIR, 'propintel_import.log')

# Create custom logger
logger = logging.getLogger('propintel')
logger.setLevel(logging.INFO)

# Create handlers
app_handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=10485760, backupCount=5)
app_handler.setLevel(logging.INFO)

# Create formatters and add to handlers
formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
app_handler.setFormatter(formatter)

# Add handlers to logger
logger.addHandler(app_handler)

def setup_logging(app):
    """Setup application logging"""
    if not app.debug:
        # Set up file handler for app.logger
        file_handler = RotatingFileHandler(APP_LOG_FILE, maxBytes=10485760, backupCount=5)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(formatter)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        
        # Log application startup
        app.logger.info('PropIntel application started')
    
    # Ensure log directory exists
    os.makedirs(os.path.dirname(APP_LOG_FILE), exist_ok=True)
    
    return logger

def log_error(error, message=None):
    """Log an exception with traceback"""
    if message:
        logger.error(f"{message}: {str(error)}", exc_info=True)
    else:
        logger.error(str(error), exc_info=True)
    
    # Also log request information if available
    try:
        if request:
            user_info = f"User: {g.user['email'] if hasattr(g, 'user') and g.user else 'Anonymous'}"
            route_info = f"Route: {request.path}"
            logger.error(f"Request details - {route_info}, {user_info}")
    except Exception:
        pass

def get_logs(source=None, level=None, start_date=None, end_date=None, search_text=None, limit=100):
    """
    Get log entries from the specified log files
    
    Args:
        source (str): Log source filter ('app', 'session', 'import')
        level (str): Log level filter ('ERROR', 'WARNING', 'INFO', 'DEBUG')
        start_date (str): Start date filter (YYYY-MM-DD)
        end_date (str): End date filter (YYYY-MM-DD)
        search_text (str): Text to search for in log messages
        limit (int): Maximum number of log entries to return (0 = no limit)
        
    Returns:
        list: List of log entries
    """
    logs = []
    total_logs = 0
    log_id = 0
    
    # Determine which log files to read
    log_files = []
    if not source or source == 'app':
        log_files.append((APP_LOG_FILE, 'app'))
    if not source or source == 'session':
        log_files.append((SESSION_LOG_FILE, 'session'))
    if not source or source == 'import':
        log_files.append((IMPORT_LOG_FILE, 'import'))
    
    # Parse date filters
    if start_date:
        start_date = datetime.strptime(start_date, '%Y-%m-%d').date()
    if end_date:
        end_date = datetime.strptime(end_date, '%Y-%m-%d').date()
        
    # Regular expression for log line parsing
    # Format: "2025-04-29 19:22:19 - numexpr.utils - INFO - NumExpr defaulting to 8 threads."
    log_regex = r'(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}(?:\,\d{3})?) - ([^-]+) - ([A-Z]+) - (.+)'
    
    # Process each log file
    for log_file, source_name in log_files:
        if not os.path.exists(log_file) or os.path.getsize(log_file) == 0:
            continue
            
        try:
            with open(log_file, 'r') as f:
                for line in f:
                    # Try to parse the log line
                    match = re.match(log_regex, line.strip())
                    if match:
                        timestamp_str, log_source, log_level, message = match.groups()
                        
                        # Apply filters
                        if level and log_level != level:
                            continue
                            
                        if search_text and search_text.lower() not in line.lower():
                            continue
                            
                        # Parse timestamp
                        try:
                            if ',' in timestamp_str:
                                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S,%f')
                            else:
                                timestamp = datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S')
                                
                            # Apply date filters
                            if start_date and timestamp.date() < start_date:
                                continue
                            if end_date and timestamp.date() > end_date:
                                continue
                                
                            log_id += 1
                            logs.append({
                                'id': log_id,
                                'timestamp': timestamp_str,
                                'source': f"{source_name} - {log_source.strip()}",
                                'level': log_level,
                                'message': message.strip()
                            })
                            total_logs += 1
                            
                        except (ValueError, TypeError):
                            # Skip entries with invalid timestamp
                            continue
                    else:
                        # If it doesn't match the pattern, it could be a continuation
                        # of the previous log entry (e.g., a traceback)
                        if logs:
                            # Append to the previous message
                            logs[-1]['message'] += f"\n{line.strip()}"
                            
        except Exception as e:
            logger.error(f"Error reading log file {log_file}: {str(e)}")
    
    # Sort logs by timestamp (newest first)
    logs.sort(key=lambda x: x['timestamp'], reverse=True)
    
    # Apply limit
    if limit > 0 and len(logs) > limit:
        logs = logs[:limit]
    
    return logs, total_logs

def get_log_details(log_id):
    """
    Get detailed information for a specific log entry
    In a real implementation, we would need to store logs in a database
    For this example, we'll return a mock object
    """
    return {
        'id': log_id,
        'timestamp': '2025-04-29 19:22:19',
        'source': 'app.py',
        'level': 'ERROR',
        'message': 'Error details here',
        'stack_trace': 'Traceback (most recent call last):\n  File "app.py", line 100\n    ...',
        'context': {
            'User': 'admin@example.com',
            'IP Address': '127.0.0.1',
            'Request Path': '/builders-hub',
            'Method': 'GET'
        }
    }

def clear_logs(backup=False):
    """
    Clear all log files
    
    Args:
        backup (bool): If True, create a backup of log files before clearing
        
    Returns:
        bool: Success flag
    """
    log_files = [APP_LOG_FILE, SESSION_LOG_FILE, IMPORT_LOG_FILE]
    
    try:
        # Create backups if requested
        if backup:
            timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
            for log_file in log_files:
                if os.path.exists(log_file) and os.path.getsize(log_file) > 0:
                    backup_file = f"{log_file}.{timestamp}.bak"
                    with open(log_file, 'r') as src, open(backup_file, 'w') as dst:
                        dst.write(src.read())
        
        # Clear log files
        for log_file in log_files:
            if os.path.exists(log_file):
                with open(log_file, 'w') as f:
                    # Write a header line indicating the logs were cleared
                    f.write(f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - propintel - INFO - Log file cleared by admin\n")
        
        logger.info("All log files cleared")
        return True
    except Exception as e:
        logger.error(f"Error clearing logs: {str(e)}")
        return False

def export_logs(format='csv'):
    """
    Export logs to the specified format
    """
    logs, _ = get_logs(limit=0)  # No limit for exports
    
    if format == 'json':
        return json.dumps(logs, indent=2)
    elif format == 'csv':
        csv_content = "Timestamp,Level,Source,Message\n"
        for log in logs:
            # Escape quotes in message and wrap in quotes
            message = f'"{log["message"].replace(\'"\', \'""\'")}"'
            csv_content += f'{log["timestamp"]},{log["level"]},{log["source"]},{message}\n'
        return csv_content
    else:  # txt
        txt_content = ""
        for log in logs:
            txt_content += f'[{log["timestamp"]}] {log["level"]} - {log["source"]}: {log["message"]}\n'
        return txt_content