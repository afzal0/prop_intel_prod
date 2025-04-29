"""
Additional routes for PropIntel application
"""
from flask import Blueprint, jsonify, g, request
from shapefile_utils import get_work_heatmap_data

# Create blueprint
extra_bp = Blueprint('extra', __name__)

@extra_bp.route('/api/work-heatmap-data')
def work_heatmap_data_api():
    """API endpoint for work heatmap data"""
    try:
        # Get heatmap data
        heatmap_data = get_work_heatmap_data()
        return jsonify(heatmap_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500