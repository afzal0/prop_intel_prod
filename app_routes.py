"""
Additional routes for PropIntel application
"""
from flask import Blueprint, jsonify, g, request
from shapefile_utils import get_work_heatmap_data, generate_work_heatmap

# Create blueprint
extra_bp = Blueprint('extra', __name__)

@extra_bp.route('/api/work-heatmap-data')
def work_heatmap_data_api():
    """API endpoint for work heatmap data"""
    try:
        # Regenerate heatmap data first to ensure it's up to date
        generate_work_heatmap()
        
        # Get heatmap data
        heatmap_data = get_work_heatmap_data()
        
        # Ensure data is in the format expected by Leaflet.heat
        formatted_data = []
        for point in heatmap_data:
            # Each point should be [lat, lng, intensity]
            formatted_data.append([
                float(point[0]),  # latitude
                float(point[1]),  # longitude
                float(point[2])   # intensity
            ])
            
        return jsonify(formatted_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500