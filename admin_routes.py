"""
Admin routes for PropIntel application
"""
from flask import Blueprint, render_template, request, redirect, url_for, flash, jsonify, g, send_file
from psycopg2.extras import RealDictCursor
import json
import os
import io
from datetime import datetime

from logger_utils import get_logs, get_log_details, clear_logs, export_logs
from login_decorator import login_required, admin_required

# Create blueprint
admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

@admin_bp.before_request
@login_required
@admin_required
def before_request():
    """Ensure user is admin for all admin routes"""
    pass

@admin_bp.route('/logs')
def error_logs():
    """Show error logs page"""
    source = request.args.get('source')
    level = request.args.get('level')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    search_text = request.args.get('search_text')
    limit = request.args.get('limit', '100')
    
    try:
        if limit == 'all':
            limit_val = 0
        else:
            limit_val = int(limit)
    except (ValueError, TypeError):
        limit_val = 100
    
    logs, total_logs = get_logs(
        source=source,
        level=level,
        start_date=start_date,
        end_date=end_date,
        search_text=search_text,
        limit=limit_val
    )
    
    return render_template(
        'admin/error_logs.html',
        logs=logs,
        total_logs=total_logs,
        selected_source=source,
        selected_level=level,
        start_date=start_date,
        end_date=end_date,
        search_text=search_text,
        limit=limit
    )

@admin_bp.route('/api/logs')
def api_logs():
    """API endpoint to get logs"""
    source = request.args.get('source')
    level = request.args.get('level')
    start_date = request.args.get('start_date')
    end_date = request.args.get('end_date')
    search_text = request.args.get('search_text')
    limit = request.args.get('limit', '100')
    
    try:
        if limit == 'all':
            limit_val = 0
        else:
            limit_val = int(limit)
    except (ValueError, TypeError):
        limit_val = 100
    
    logs, total_logs = get_logs(
        source=source,
        level=level,
        start_date=start_date,
        end_date=end_date,
        search_text=search_text,
        limit=limit_val
    )
    
    return jsonify({
        'logs': logs,
        'total': total_logs
    })

@admin_bp.route('/api/logs/<int:log_id>')
def api_log_detail(log_id):
    """API endpoint to get log details"""
    log_details = get_log_details(log_id)
    return jsonify(log_details)

@admin_bp.route('/api/logs/clear', methods=['POST'])
def api_clear_logs():
    """API endpoint to clear logs"""
    data = request.get_json()
    backup = data.get('backup', False) if data else False
    
    success = clear_logs(backup=backup)
    
    return jsonify({
        'success': success,
        'message': 'Logs cleared successfully' if success else 'Failed to clear logs'
    })

@admin_bp.route('/api/logs/export')
def api_export_logs():
    """API endpoint to export logs"""
    format_type = request.args.get('format', 'csv')
    if format_type not in ['csv', 'json', 'txt']:
        format_type = 'csv'
    
    content = export_logs(format=format_type)
    
    # Set the appropriate mime type
    mime_types = {
        'csv': 'text/csv',
        'json': 'application/json',
        'txt': 'text/plain'
    }
    
    # Create a date string for the filename
    date_str = datetime.now().strftime('%Y%m%d')
    filename = f"propintel_logs_{date_str}.{format_type}"
    
    # Create an in-memory file
    buffer = io.BytesIO(content.encode('utf-8'))
    buffer.seek(0)
    
    # Return the file as an attachment
    return send_file(
        buffer,
        as_attachment=True,
        download_name=filename,
        mimetype=mime_types[format_type]
    )