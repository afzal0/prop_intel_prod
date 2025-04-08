"""
Analytics Dashboard for PropIntel application.

This module provides the route handler and data processing logic for the 
property analytics dashboard page.
"""

import json
import datetime
import random
import decimal
import urllib.request
import time
from collections import defaultdict
from flask import render_template, g, request, jsonify
from psycopg2.extras import RealDictCursor
import calendar

def get_db_connection():
    """Get a database connection using the provided configuration"""
    import psycopg2
    import os
    from urllib.parse import urlparse
    
    # Check if running on Heroku
    if 'DATABASE_URL' in os.environ:
        # Parse database URL for Heroku
        database_url = os.environ['DATABASE_URL']
        # Check for postgres:// prefix and replace with postgresql://
        if database_url.startswith('postgres://'):
            database_url = database_url.replace('postgres://', 'postgresql://', 1)
        conn = psycopg2.connect(database_url, sslmode='require')
    else:
        # Try to load from .env file first
        try:
            from dotenv import load_dotenv
            load_dotenv()
            
            db_host = os.environ.get('DB_HOST')
            db_name = os.environ.get('DB_NAME')
            db_user = os.environ.get('DB_USER')
            db_password = os.environ.get('DB_PASSWORD')
            db_port = os.environ.get('DB_PORT', '5432')
            
            if db_host and db_name and db_user and db_password:
                conn = psycopg2.connect(
                    user=db_user,
                    password=db_password,
                    host=db_host,
                    port=db_port,
                    dbname=db_name
                )
                print("Connected using .env configuration")
                conn.autocommit = False
                return conn
        except Exception as e:
            print(f"Failed to load from .env: {e}")
        
        # Try to load from config file
        try:
            import configparser
            config = configparser.ConfigParser()
            config.read('db_config.ini')
            
            conn = psycopg2.connect(
                user=config['database']['user'],
                password=config['database']['password'],
                host=config['database']['host'],
                port=config['database']['port'],
                dbname=config['database']['database']
            )
            print("Connected using db_config.ini")
        except Exception as e:
            print(f"Failed to load config: {e}")
            # Use the database parameters from db_connect.py default values
            conn = psycopg2.connect(
                user="u15p78tmoefhv2",
                password="p78dc6c2370076ee1ac7f23f370d707687e8400f94032cccdb35ddd1d7b37381f",
                host="c1i13pt05ja4ag.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com",
                port="5432",
                database="d1oncga6g47frr"
            )
            print("Connected using fallback credentials")
    
    conn.autocommit = False
    return conn

def decimal_to_float(dec):
    """Convert decimal.Decimal to float safely"""
    if isinstance(dec, decimal.Decimal):
        return float(dec)
    return dec

def get_analytics_data(property_id=None, date_range=365, category=None):
    """
    Retrieve and process analytics data for the dashboard.
    
    Args:
        property_id: Optional ID of a specific property to filter on
        date_range: Number of days to include in the date range (30, 90, 180, 365)
        category: Optional expense category to filter on
    
    Returns:
        A dictionary containing all the data needed for visualizations.
    """
    conn = None
    try:
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get list of properties
            cur.execute("""
                SELECT property_id, property_name, 
                       address, location,
                       latitude, longitude
                FROM propintel.properties
                WHERE is_hidden IS NOT TRUE
                ORDER BY property_name
            """)
            properties = cur.fetchall()
            
            # Prepare property GeoJSON for map (without polygon fetching for analytics dashboard for faster loading)
            geojson = prepare_property_geojson(properties, fetch_polygons=False)
            
            # Build property filter condition
            property_filter = ""
            if property_id and property_id != 'all':
                property_filter = f"AND mi.property_id = '{property_id}'"
            
            # Build category filter condition
            category_filter = ""
            if category and category != 'all':
                category_filter = f"AND expense_category = '{category}'"
            
            # Get total income
            cur.execute(f"""
                SELECT COALESCE(SUM(income_amount), 0) as total_income
                FROM propintel.money_in mi
                WHERE income_date >= current_date - interval '{date_range} days'
                {property_filter}
            """)
            total_income = decimal_to_float(cur.fetchone()['total_income'] or 0)
            
            # Get total expenses
            cur.execute(f"""
                SELECT COALESCE(SUM(expense_amount), 0) as total_expenses
                FROM propintel.money_out mo
                WHERE expense_date >= current_date - interval '{date_range} days'
                {property_filter.replace('mi.', 'mo.')}
                {category_filter}
            """)
            total_expenses = decimal_to_float(cur.fetchone()['total_expenses'] or 0)
            
            # Get total work records
            cur.execute(f"""
                SELECT COUNT(*) as total_work_records,
                       COALESCE(SUM(work_cost), 0) as total_work_cost
                FROM propintel.work w
                WHERE work_date >= current_date - interval '{date_range} days'
                {property_filter.replace('mi.', 'w.')}
            """)
            work_data = cur.fetchone()
            total_work_records = int(work_data['total_work_records'] or 0)
            total_work_cost = decimal_to_float(work_data['total_work_cost'] or 0)
            
            # Get monthly income and expense data for the selected period
            cur.execute(f"""
                WITH months AS (
                    SELECT generate_series(
                        date_trunc('month', current_date - interval '{date_range} days'),
                        date_trunc('month', current_date),
                        interval '1 month'
                    ) as month
                ),
                monthly_income AS (
                    SELECT 
                        date_trunc('month', income_date) as month,
                        COALESCE(SUM(income_amount), 0) as income
                    FROM propintel.money_in mi
                    WHERE income_date >= current_date - interval '{date_range} days'
                    {property_filter}
                    GROUP BY month
                ),
                monthly_expenses AS (
                    SELECT 
                        date_trunc('month', expense_date) as month,
                        COALESCE(SUM(expense_amount), 0) as expenses
                    FROM propintel.money_out mo
                    WHERE expense_date >= current_date - interval '{date_range} days'
                    {property_filter.replace('mi.', 'mo.')}
                    {category_filter}
                    GROUP BY month
                ),
                monthly_work AS (
                    SELECT 
                        date_trunc('month', work_date) as month,
                        COALESCE(SUM(work_cost), 0) as work_cost
                    FROM propintel.work w
                    WHERE work_date >= current_date - interval '{date_range} days'
                    {property_filter.replace('mi.', 'w.')}
                    GROUP BY month
                )
                SELECT 
                    to_char(m.month, 'Mon YYYY') as month_label,
                    m.month as month_date,
                    COALESCE(mi.income, 0) as income,
                    COALESCE(me.expenses, 0) as expenses,
                    COALESCE(mw.work_cost, 0) as work_cost
                FROM months m
                LEFT JOIN monthly_income mi ON m.month = mi.month
                LEFT JOIN monthly_expenses me ON m.month = me.month
                LEFT JOIN monthly_work mw ON m.month = mw.month
                ORDER BY m.month
            """)
            monthly_data = cur.fetchall()
            
            # Prepare month labels and data series
            labels = [record['month_label'] for record in monthly_data]
            income_data = [decimal_to_float(record['income']) for record in monthly_data]
            expense_data = [decimal_to_float(record['expenses']) for record in monthly_data]
            work_cost_data = [decimal_to_float(record['work_cost']) for record in monthly_data]
            
            # Get expense breakdown by category
            cur.execute(f"""
                SELECT
                    expense_category,
                    COALESCE(SUM(expense_amount), 0) as total_amount
                FROM propintel.money_out mo
                WHERE expense_date >= current_date - interval '{date_range} days'
                {property_filter.replace('mi.', 'mo.')}
                GROUP BY expense_category
                ORDER BY total_amount DESC
            """)
            expense_category_data = cur.fetchall()
            
            # Organize expense categories
            expense_categories = {
                'wage': 0,
                'project_manager': 0,
                'material': 0,
                'miscellaneous': 0
            }
            
            for record in expense_category_data:
                category = record['expense_category']
                amount = decimal_to_float(record['total_amount'])
                
                if category in expense_categories:
                    expense_categories[category] = amount
                else:
                    expense_categories['miscellaneous'] += amount
            
            # Get top expense categories for each property
            cur.execute(f"""
                WITH property_expenses AS (
                    SELECT 
                        p.property_id,
                        p.property_name,
                        COALESCE(SUM(m.expense_amount), 0) as total_expenses,
                        string_agg(DISTINCT m.expense_category, ', ') as categories
                    FROM propintel.properties p
                    LEFT JOIN propintel.money_out m ON p.property_id = m.property_id
                    AND m.expense_date >= current_date - interval '{date_range} days'
                    {category_filter.replace('expense_category', 'm.expense_category')}
                    {property_filter.replace('mi.property_id', 'p.property_id') if property_id and property_id != 'all' else ''}
                    GROUP BY p.property_id, p.property_name
                )
                SELECT * FROM property_expenses
                ORDER BY total_expenses DESC
            """)
            property_expenses = cur.fetchall()
            
            # Convert decimal values in property_expenses
            for item in property_expenses:
                if 'total_expenses' in item:
                    item['total_expenses'] = decimal_to_float(item['total_expenses'])
            
            # Get property performance metrics
            property_performance = []
            for prop in properties:
                cur.execute(f"""
                    SELECT 
                        COALESCE(SUM(mi.income_amount), 0) as income,
                        COALESCE(SUM(mo.expense_amount), 0) as expenses,
                        COALESCE(SUM(w.work_cost), 0) as work_cost
                    FROM propintel.properties p
                    LEFT JOIN propintel.money_in mi ON p.property_id = mi.property_id
                    AND mi.income_date >= current_date - interval '{date_range} days'
                    LEFT JOIN propintel.money_out mo ON p.property_id = mo.property_id
                    AND mo.expense_date >= current_date - interval '{date_range} days'
                    {category_filter.replace('expense_category', 'mo.expense_category')}
                    LEFT JOIN propintel.work w ON p.property_id = w.property_id
                    AND w.work_date >= current_date - interval '{date_range} days'
                    WHERE p.property_id = %s
                """, (prop['property_id'],))
                
                performance = cur.fetchone()
                income = decimal_to_float(performance['income'] if performance['income'] else 0)
                expenses = decimal_to_float(performance['expenses'] if performance['expenses'] else 0)
                work_cost = decimal_to_float(performance['work_cost'] if performance['work_cost'] else 0)
                profit = income - expenses - work_cost
                
                property_performance.append({
                    'id': prop['property_id'],
                    'name': prop['property_name'],
                    'income': income,
                    'expenses': expenses,
                    'work_cost': work_cost,
                    'profit': profit
                })
            
            # Get work activity data for heatmap
            work_heatmap_data = get_work_heatmap_data(cur, property_id, date_range)
            
            # Get expense trends by category for selected period
            expense_trends = get_expense_trends(cur, property_id, date_range, category)
            trend_labels = expense_trends['labels']
            
            # Calculate profit margins by month
            profit_margin = {
                'labels': labels,
                'margins': [],
                'profit': []
            }
            
            for i in range(len(labels)):
                income = income_data[i]
                expense = expense_data[i] + work_cost_data[i]
                profit = income - expense
                margin = (profit / income * 100) if income > 0 else 0
                
                profit_margin['margins'].append(margin)
                profit_margin['profit'].append(profit)
            
            # Get pending work and upcoming expenses
            cur.execute(f"""
                SELECT 
                    w.work_id, 
                    p.property_name,
                    w.work_description,
                    w.work_date,
                    w.work_cost,
                    w.status
                FROM propintel.work w
                JOIN propintel.properties p ON w.property_id = p.property_id
                WHERE w.status = 'Pending'
                AND w.work_date >= current_date
                {' AND w.property_id = %s' if property_id and property_id != 'all' else ''}
                ORDER BY w.work_date ASC
                LIMIT 10
            """, (property_id,) if property_id and property_id != 'all' else ())
            pending_work = cur.fetchall()
            
            # Convert decimal values in pending_work
            for item in pending_work:
                if 'work_cost' in item:
                    item['work_cost'] = decimal_to_float(item['work_cost'])
            
            # Calculate change percentages compared to previous period
            if date_range > 30:
                prev_period_start = datetime.datetime.now() - datetime.timedelta(days=date_range*2)
                prev_period_end = datetime.datetime.now() - datetime.timedelta(days=date_range)
                
                # Previous period income
                cur.execute(f"""
                    SELECT COALESCE(SUM(income_amount), 0) as prev_income
                    FROM propintel.money_in
                    WHERE income_date BETWEEN %s AND %s
                    {property_filter}
                """, (prev_period_start, prev_period_end))
                prev_income = decimal_to_float(cur.fetchone()['prev_income'] or 0)
                
                # Previous period expenses
                cur.execute(f"""
                    SELECT COALESCE(SUM(expense_amount), 0) as prev_expenses
                    FROM propintel.money_out
                    WHERE expense_date BETWEEN %s AND %s
                    {property_filter}
                    {category_filter}
                """, (prev_period_start, prev_period_end))
                prev_expenses = decimal_to_float(cur.fetchone()['prev_expenses'] or 0)
                
                # Previous period work records
                cur.execute(f"""
                    SELECT COUNT(*) as prev_work_count,
                           COALESCE(SUM(work_cost), 0) as prev_work_cost
                    FROM propintel.work
                    WHERE work_date BETWEEN %s AND %s
                    {property_filter}
                """, (prev_period_start, prev_period_end))
                prev_work = cur.fetchone()
                prev_work_count = int(prev_work['prev_work_count'] or 0)
                prev_work_cost = decimal_to_float(prev_work['prev_work_cost'] or 0)
                
                # Calculate change percentages
                income_change_percent = ((total_income - prev_income) / prev_income * 100) if prev_income > 0 else 100
                expense_change_percent = ((total_expenses - prev_expenses) / prev_expenses * 100) if prev_expenses > 0 else 100
                work_change_percent = ((total_work_records - prev_work_count) / prev_work_count * 100) if prev_work_count > 0 else 100
                
                # Calculate profit change
                prev_profit = prev_income - prev_expenses - prev_work_cost
                current_profit = total_income - total_expenses - total_work_cost
                profit_change_percent = ((current_profit - prev_profit) / abs(prev_profit) * 100) if prev_profit != 0 else 100
            else:
                # If date range is too short, just use demo values
                income_change_percent = 12.5
                expense_change_percent = 8.3
                profit_change_percent = 15.7
                work_change_percent = 20.1
            
            return {
                'properties': properties,
                'total_income': total_income,
                'total_expenses': total_expenses,
                'total_work_cost': total_work_cost,
                'net_profit': total_income - total_expenses - total_work_cost,
                'total_work_records': total_work_records,
                'income_change_percent': round(income_change_percent, 1),
                'expense_change_percent': round(expense_change_percent, 1),
                'profit_change_percent': round(profit_change_percent, 1),
                'work_change_percent': round(work_change_percent, 1),
                'labels': json.dumps(labels),
                'income_data': json.dumps(income_data),
                'expense_data': json.dumps(expense_data),
                'work_cost_data': json.dumps(work_cost_data),
                'expense_categories': json.dumps({
                    'wage': expense_categories['wage'],
                    'project_manager': expense_categories['project_manager'],
                    'material': expense_categories['material'],
                    'miscellaneous': expense_categories['miscellaneous']
                }),
                'property_performance': json.dumps(property_performance),
                'work_heatmap_data': json.dumps(work_heatmap_data),
                'expense_trends': json.dumps({
                    'labels': trend_labels,
                    'wage': expense_trends['wage'],
                    'project_manager': expense_trends['project_manager'],
                    'material': expense_trends['material'],
                    'miscellaneous': expense_trends['miscellaneous']
                }),
                'profit_margin': json.dumps(profit_margin),
                'pending_work': pending_work,
                'property_expenses': property_expenses,
                'geojson': json.dumps(geojson),
                'selected_property': property_id if property_id else 'all',
                'selected_date_range': date_range,
                'selected_category': category if category else 'all'
            }
    except Exception as e:
        # In case of errors, provide some baseline demo data
        print(f"Error retrieving analytics data: {e}")
        return get_demo_data()
    finally:
        if conn:
            conn.close()

def get_work_heatmap_data(cursor, property_id=None, date_range=365):
    """
    Get work activity data for the heatmap visualization.
    
    Retrieves actual work records from the database and organizes them by day and month.
    """
    # Build property filter
    property_filter = ""
    if property_id and property_id != 'all':
        property_filter = f"AND property_id = '{property_id}'"
    
    try:
        # Get work records grouped by day of week and month
        cursor.execute(f"""
            SELECT 
                to_char(work_date, 'Dy') as day,
                to_char(work_date, 'Mon') as month,
                EXTRACT(DOW FROM work_date) as day_idx,  -- 0 = Sunday, 6 = Saturday
                EXTRACT(MONTH FROM work_date) as month_idx,
                COUNT(*) as count
            FROM propintel.work
            WHERE work_date >= current_date - interval '{date_range} days'
            {property_filter.replace("property_id", "propintel.work.property_id") if property_id and property_id != 'all' else ''}
            GROUP BY day, month, day_idx, month_idx
            ORDER BY month_idx, day_idx
        """)
        work_records = cursor.fetchall()
        
        days_of_week = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
        months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
        
        heatmap_data = []
        
        # Find the max count for normalization
        max_count = 1  # Default to 1 to avoid division by zero
        for record in work_records:
            max_count = max(max_count, int(record['count']))
        
        # Create a record for each day/month combination
        for day_idx, day in enumerate(days_of_week):
            for month_idx, month in enumerate(months, 1):  # Database EXTRACT(MONTH) returns 1-12
                # Find matching record if it exists
                matching_record = next((r for r in work_records if r['day'].startswith(day) and r['month'] == month), None)
                
                if matching_record:
                    count = int(matching_record['count'])
                    intensity = count / max_count
                else:
                    count = 0
                    intensity = 0
                
                heatmap_data.append({
                    'day': day,
                    'month': month,
                    'day_idx': day_idx,
                    'month_idx': month_idx - 1,  # JavaScript months are 0-11
                    'count': count,
                    'intensity': intensity
                })
        
        return heatmap_data
    except Exception as e:
        print(f"Error getting heatmap data: {e}")
        return []

def get_expense_trends(cursor, property_id=None, date_range=365, category=None):
    """
    Get expense trends by category for the selected period.
    
    Retrieves actual expense records from the database.
    """
    # Build property filter
    property_filter = ""
    if property_id and property_id != 'all':
        property_filter = f"AND property_id = '{property_id}'"
    
    # Build category filter
    category_filter = ""
    if category and category != 'all':
        category_filter = f"AND expense_category = '{category}'"
    
    try:
        # Calculate number of months to include based on date range
        months_count = min(max(int(date_range / 30), 1), 12)
        
        # Get expense data grouped by month and category
        cursor.execute(f"""
            WITH months AS (
                SELECT generate_series(
                    date_trunc('month', current_date - interval '{months_count} months'),
                    date_trunc('month', current_date),
                    interval '1 month'
                ) as month
            ),
            expense_categories AS (
                SELECT DISTINCT
                    CASE 
                        WHEN expense_category IS NULL THEN 'miscellaneous'
                        ELSE expense_category
                    END as category
                FROM propintel.money_out mo
                WHERE expense_date >= current_date - interval '{date_range} days'
                {property_filter.replace("property_id", "mo.property_id")}
                {category_filter.replace("expense_category", "mo.expense_category")}
            ),
            expense_data AS (
                SELECT 
                    date_trunc('month', expense_date) as month,
                    CASE 
                        WHEN expense_category IS NULL THEN 'miscellaneous'
                        ELSE expense_category
                    END as category,
                    COALESCE(SUM(expense_amount), 0) as amount
                FROM propintel.money_out mo
                WHERE expense_date >= current_date - interval '{date_range} days'
                {property_filter.replace("property_id", "mo.property_id")}
                {category_filter.replace("expense_category", "mo.expense_category")}
                GROUP BY month, category
            )
            SELECT 
                to_char(m.month, 'Mon YYYY') as month_label,
                m.month as month_date,
                ec.category,
                COALESCE(ed.amount, 0) as amount
            FROM months m
            CROSS JOIN expense_categories ec
            LEFT JOIN expense_data ed ON m.month = ed.month AND ec.category = ed.category
            ORDER BY m.month, ec.category
        """)
        expenses = cursor.fetchall()
        
        # Organize expense data by month and category
        trend_data = defaultdict(list)
        trend_labels = []
        current_month = None
        
        for record in expenses:
            month_label = record['month_label']
            category = record['category']
            amount = decimal_to_float(record['amount'])
            
            # If we're starting a new month, add the label
            if current_month != month_label:
                current_month = month_label
                trend_labels.append(month_label)
            
            # Add amount to the appropriate category list
            trend_data[category].append(amount)
        
        # Ensure we have data for all standard categories
        standard_categories = ['wage', 'project_manager', 'material', 'miscellaneous']
        for category in standard_categories:
            if category not in trend_data:
                trend_data[category] = [0] * len(trend_labels)
            elif len(trend_data[category]) < len(trend_labels):
                # Fill in missing months with zeros
                trend_data[category].extend([0] * (len(trend_labels) - len(trend_data[category])))
        
        return {
            'labels': trend_labels,
            'wage': trend_data['wage'],
            'project_manager': trend_data['project_manager'],
            'material': trend_data['material'],
            'miscellaneous': trend_data['miscellaneous']
        }
    except Exception as e:
        print(f"Error getting expense trends: {e}")
        # Return empty data structure
        return {
            'labels': [],
            'wage': [],
            'project_manager': [],
            'material': [],
            'miscellaneous': []
        }


def get_osm_building_polygon(lat, lng):
    """
    Fetch building polygon geometry from OpenStreetMap via Overpass API.
    
    Args:
        lat: Latitude of the property
        lng: Longitude of the property
        
    Returns:
        List of coordinate pairs representing the polygon, or None if not found
    """
    try:
        # Define search radius (in meters)
        radius = 50
        
        # Construct Overpass API query to find buildings near the coordinates
        overpass_url = "https://overpass-api.de/api/interpreter"
        overpass_query = f"""
        [out:json];
        way(around:{radius},{lat},{lng})["building"];
        (._;>;);
        out body;
        """
        
        # Make the API request
        request = urllib.request.Request(
            overpass_url, 
            data=overpass_query.encode('utf-8'),
            headers={'Content-Type': 'application/x-www-form-urlencoded'}
        )
        
        response = urllib.request.urlopen(request).read()
        data = json.loads(response.decode('utf-8'))
        
        # Find the closest building
        if data and 'elements' in data:
            buildings = []
            nodes = {}
            
            # First, collect all nodes
            for element in data['elements']:
                if element['type'] == 'node':
                    nodes[element['id']] = (element['lon'], element['lat'])
            
            # Then, process ways (buildings)
            for element in data['elements']:
                if element['type'] == 'way' and 'tags' in element and 'building' in element['tags']:
                    if 'nodes' in element and len(element['nodes']) > 2:
                        # Get coordinates for all nodes in the way
                        coords = []
                        for node_id in element['nodes']:
                            if node_id in nodes:
                                coords.append(nodes[node_id])
                        
                        # Ensure the polygon is closed (first point = last point)
                        if coords and coords[0] != coords[-1]:
                            coords.append(coords[0])
                        
                        if coords:
                            buildings.append(coords)
            
            # Return the first building polygon found (could be enhanced to find the closest one)
            if buildings:
                return buildings[0]
        
        return None
    except Exception as e:
        print(f"Error fetching OSM building data: {e}")
        return None

def prepare_property_geojson(properties, fetch_polygons=False):
    """
    Prepare GeoJSON for property map display.
    
    Uses actual coordinates from the database if available, otherwise generates random positions.
    Includes financial data and budget status for advanced visualization.
    
    Args:
        properties: List of property dictionaries
        fetch_polygons: Whether to fetch building polygons from OpenStreetMap (can be slow)
    """
    # Central coordinates (for fallback)
    center_lat = 40.7128  # New York City latitude
    center_lng = -74.0060  # New York City longitude
    
    features = []
    for prop in properties:
        # Use actual coordinates if available, otherwise generate random ones
        if prop.get('latitude') and prop.get('longitude'):
            lat = decimal_to_float(prop['latitude'])
            lng = decimal_to_float(prop['longitude'])
        else:
            # Generate random coordinates near the center point
            lat = center_lat + (random.random() - 0.5) * 0.1
            lng = center_lng + (random.random() - 0.5) * 0.1
        
        # Create address string
        address = prop.get('address', "Address not available")
        if prop.get('location'):
            address += f", {prop['location']}"
        
        # Get financial data for budget analysis
        total_expenses = decimal_to_float(prop.get('total_expenses', 0)) if prop.get('total_expenses') else 0
        work_costs = decimal_to_float(prop.get('work_cost', 0)) if prop.get('work_cost') else 0
        total_income = decimal_to_float(prop.get('total_income', 0)) if prop.get('total_income') else 0
        
        # Determine if property is over budget
        is_over_budget = (total_expenses + work_costs) > total_income
        
        # Create GeoJSON feature
        feature = {
            "type": "Feature",
            "properties": {
                "id": prop['property_id'],
                "name": prop['property_name'],
                "address": address,
                "url": f"/property/{prop['property_id']}",
                "income": total_income,
                "expenses": total_expenses,
                "work_cost": work_costs,
                "is_over_budget": is_over_budget
            }
        }
        
        # Try to get building polygon from OpenStreetMap if requested
        polygon_coords = None
        if fetch_polygons:
            try:
                # Add a timeout to avoid long delays
                polygon_coords = get_osm_building_polygon(lat, lng)
                # Small delay to avoid overwhelming the API
                time.sleep(0.2)
            except Exception as e:
                print(f"Error getting building polygon: {e}")
        
        # Use polygon geometry if available, otherwise fallback to point
        if polygon_coords:
            feature["geometry"] = {
                "type": "Polygon",
                "coordinates": [polygon_coords]  # OpenStreetMap returns [lon, lat], which matches GeoJSON format
            }
        else:
            feature["geometry"] = {
                "type": "Point",
                "coordinates": [lng, lat]
            }
        
        features.append(feature)
    
    return {
        "type": "FeatureCollection",
        "features": features
    }

def get_demo_data():
    """Try to retrieve real property data but generate demo data as fallback"""
    
    # First try to get real property data from the database
    try:
        import psycopg2
        properties = []
        
        # Try to get a connection using our better connection function
        conn = get_db_connection()
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            cur.execute("""
                SELECT property_id, property_name, address, location,
                       latitude, longitude
                FROM propintel.properties
                WHERE is_hidden IS NOT TRUE
                ORDER BY property_name
            """)
            properties = cur.fetchall()
        conn.close()
        
        if properties and len(properties) > 0:
            print(f"Found {len(properties)} real properties to use")
            
            # Convert properties to the format we need
            demo_properties = []
            for prop in properties:
                demo_properties.append({
                    'property_id': prop['property_id'],
                    'property_name': prop['property_name'],
                    'address': prop['address'] or "No address",
                    'location': prop['location'] or "No location"
                })
            
            # Get real data for properties
            conn = get_db_connection()
            try:
                property_performance = []
                property_expenses = []
                
                with conn.cursor(cursor_factory=RealDictCursor) as cur:
                    # Try to get actual financial data first
                    for prop in demo_properties:
                        prop_id = prop['property_id']
                        
                        # Get income, expenses, and work costs for this property
                        cur.execute("""
                            SELECT 
                                COALESCE(SUM(mi.income_amount), 0) as income,
                                COALESCE(SUM(mo.expense_amount), 0) as expenses,
                                COALESCE(SUM(w.work_cost), 0) as work_cost
                            FROM propintel.properties p
                            LEFT JOIN propintel.money_in mi ON p.property_id = mi.property_id
                            LEFT JOIN propintel.money_out mo ON p.property_id = mo.property_id  
                            LEFT JOIN propintel.work w ON p.property_id = w.property_id
                            WHERE p.property_id = %s
                        """, (prop_id,))
                        
                        result = cur.fetchone()
                        income = decimal_to_float(result['income']) if result and result['income'] else 0
                        expenses = decimal_to_float(result['expenses']) if result and result['expenses'] else 0
                        work_cost = decimal_to_float(result['work_cost']) if result and result['work_cost'] else 0
                        profit = income - expenses - work_cost
                        
                        # If we have no data, use reasonable random values
                        if income == 0 and expenses == 0 and work_cost == 0:
                            income = random.uniform(25000, 45000)
                            expenses = random.uniform(15000, 30000)
                            work_cost = random.uniform(3000, 10000)
                            profit = income - expenses - work_cost
                        
                        property_performance.append({
                            'id': prop_id,
                            'name': prop['property_name'],
                            'income': income,
                            'expenses': expenses,
                            'work_cost': work_cost,
                            'profit': profit
                        })
                        
                        # Get expense categories for this property
                        cur.execute("""
                            SELECT 
                                string_agg(DISTINCT expense_category, ', ') as categories,
                                COALESCE(SUM(expense_amount), 0) as total_expenses
                            FROM propintel.money_out
                            WHERE property_id = %s
                        """, (prop_id,))
                        
                        expense_result = cur.fetchone()
                        categories = expense_result['categories'] if expense_result and expense_result['categories'] else ""
                        total_expenses = decimal_to_float(expense_result['total_expenses']) if expense_result else 0
                        
                        # If no categories, generate some
                        if not categories:
                            categories = random.choice([
                                'wage, material',
                                'project_manager, material',
                                'wage, miscellaneous',
                                'material, project_manager'
                            ])
                        
                        property_expenses.append({
                            'property_id': prop_id,
                            'property_name': prop['property_name'],
                            'total_expenses': expenses,
                            'categories': categories
                        })
            except Exception as e:
                print(f"Error getting financial data: {e}")
                # Fall back to synthetic data based on real property names
                property_performance = []
                property_expenses = []
                
                for prop in demo_properties:
                    # Create realistic performance data
                    income = random.uniform(25000, 45000)
                    expenses = random.uniform(15000, 30000)
                    work_cost = random.uniform(3000, 10000)
                    profit = income - expenses - work_cost
                    
                    property_performance.append({
                        'id': prop['property_id'],
                        'name': prop['property_name'],
                        'income': income,
                        'expenses': expenses,
                        'work_cost': work_cost,
                        'profit': profit
                    })
                    
                    # Create realistic expense data
                    categories = random.choice([
                        'wage, material',
                        'project_manager, material',
                        'wage, miscellaneous',
                        'material, project_manager'
                    ])
                    
                    property_expenses.append({
                        'property_id': prop['property_id'],
                        'property_name': prop['property_name'],
                        'total_expenses': expenses,
                        'categories': categories
                    })
            finally:
                conn.close()  
        else:
            # If no properties found, use demo properties
            demo_properties = [
                {'property_id': '1', 'property_name': 'Property A', 'address': '123 Main St', 'location': 'New York, NY 10001'},
                {'property_id': '2', 'property_name': 'Property B', 'address': '456 Broadway', 'location': 'New York, NY 10002'},
                {'property_id': '3', 'property_name': 'Property C', 'address': '789 5th Ave', 'location': 'New York, NY 10003'},
                {'property_id': '4', 'property_name': 'Property D', 'address': '101 Park Ave', 'location': 'New York, NY 10004'}
            ]
            
            # Demo property performance data
            property_performance = [
                {'id': '1', 'name': 'Property A', 'income': 45000, 'expenses': 30000, 'work_cost': 10000, 'profit': 5000},
                {'id': '2', 'name': 'Property B', 'income': 35000, 'expenses': 20000, 'work_cost': 5000, 'profit': 10000},
                {'id': '3', 'name': 'Property C', 'income': 25000, 'expenses': 15000, 'work_cost': 3000, 'profit': 7000},
                {'id': '4', 'name': 'Property D', 'income': 30000, 'expenses': 18000, 'work_cost': 7000, 'profit': 5000}
            ]
            
            # Demo property expenses
            property_expenses = [
                {'property_id': '1', 'property_name': 'Property A', 'total_expenses': 30000, 'categories': 'wage, material'},
                {'property_id': '2', 'property_name': 'Property B', 'total_expenses': 20000, 'categories': 'project_manager, material'},
                {'property_id': '3', 'property_name': 'Property C', 'total_expenses': 15000, 'categories': 'wage, miscellaneous'},
                {'property_id': '4', 'property_name': 'Property D', 'total_expenses': 18000, 'categories': 'material, project_manager'}
            ]
    except Exception as e:
        print(f"Error fetching property data: {e}")
        # Fallback to demo properties
        demo_properties = [
            {'property_id': '1', 'property_name': 'Property A', 'address': '123 Main St', 'location': 'New York, NY 10001'},
            {'property_id': '2', 'property_name': 'Property B', 'address': '456 Broadway', 'location': 'New York, NY 10002'},
            {'property_id': '3', 'property_name': 'Property C', 'address': '789 5th Ave', 'location': 'New York, NY 10003'},
            {'property_id': '4', 'property_name': 'Property D', 'address': '101 Park Ave', 'location': 'New York, NY 10004'}
        ]
        
        # Demo property performance data
        property_performance = [
            {'id': '1', 'name': 'Property A', 'income': 45000, 'expenses': 30000, 'work_cost': 10000, 'profit': 5000},
            {'id': '2', 'name': 'Property B', 'income': 35000, 'expenses': 20000, 'work_cost': 5000, 'profit': 10000},
            {'id': '3', 'name': 'Property C', 'income': 25000, 'expenses': 15000, 'work_cost': 3000, 'profit': 7000},
            {'id': '4', 'name': 'Property D', 'income': 30000, 'expenses': 18000, 'work_cost': 7000, 'profit': 5000}
        ]
        
        # Demo property expenses
        property_expenses = [
            {'property_id': '1', 'property_name': 'Property A', 'total_expenses': 30000, 'categories': 'wage, material'},
            {'property_id': '2', 'property_name': 'Property B', 'total_expenses': 20000, 'categories': 'project_manager, material'},
            {'property_id': '3', 'property_name': 'Property C', 'total_expenses': 15000, 'categories': 'wage, miscellaneous'},
            {'property_id': '4', 'property_name': 'Property D', 'total_expenses': 18000, 'categories': 'material, project_manager'}
        ]
    
    # Create GeoJSON for map (without polygon fetching for demo data)
    geojson = prepare_property_geojson(demo_properties, fetch_polygons=False)
    
    # Generate 12 months of data
    now = datetime.datetime.now()
    labels = []
    income_data = []
    expense_data = []
    work_cost_data = []
    
    for i in range(12):
        month_date = now - datetime.timedelta(days=30*(11-i))
        labels.append(month_date.strftime('%b %Y'))
        income_data.append(random.uniform(10000, 20000))
        expense_data.append(random.uniform(5000, 12000))
        work_cost_data.append(random.uniform(2000, 5000))
    
    # Demo expense categories
    expense_categories = {
        'wage': 25000,
        'project_manager': 15000,
        'material': 30000,
        'miscellaneous': 10000
    }
    
    # Demo expense trends
    trend_labels = labels[-6:]  # Last 6 months
    expense_trends = {
        'labels': trend_labels,
        'wage': [random.uniform(2000, 5000) for _ in range(6)],
        'project_manager': [random.uniform(1000, 3000) for _ in range(6)],
        'material': [random.uniform(3000, 7000) for _ in range(6)],
        'miscellaneous': [random.uniform(500, 2000) for _ in range(6)]
    }
    
    # Demo profit margins
    profit_margin = {
        'labels': labels,
        'margins': [],
        'profit': []
    }
    
    for i in range(len(labels)):
        income = income_data[i]
        expense = expense_data[i] + work_cost_data[i]
        profit = income - expense
        margin = (profit / income * 100) if income > 0 else 0
        
        profit_margin['margins'].append(margin)
        profit_margin['profit'].append(profit)
    
    # Generate work heatmap data
    days_of_week = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    
    work_heatmap_data = []
    for day_idx, day in enumerate(days_of_week):
        for month_idx, month in enumerate(months):
            count = random.randint(0, 10)
            work_heatmap_data.append({
                'day': day,
                'month': month,
                'day_idx': day_idx,
                'month_idx': month_idx,
                'count': count,
                'intensity': min(count / 10, 1.0)
            })
    
    # Demo pending work
    now = datetime.datetime.now()
    pending_work = [
        {'work_id': 1, 'property_name': 'Property A', 'work_description': 'Repair roof', 'work_date': now + datetime.timedelta(days=5), 'work_cost': 1500, 'status': 'Pending'},
        {'work_id': 2, 'property_name': 'Property B', 'work_description': 'Replace windows', 'work_date': now + datetime.timedelta(days=10), 'work_cost': 3000, 'status': 'Pending'},
        {'work_id': 3, 'property_name': 'Property C', 'work_description': 'Paint exterior', 'work_date': now + datetime.timedelta(days=15), 'work_cost': 2500, 'status': 'Pending'}
    ]
    
    return {
        'properties': demo_properties,
        'total_income': sum(income_data),
        'total_expenses': sum(expense_data),
        'total_work_cost': sum(work_cost_data),
        'net_profit': sum(income_data) - sum(expense_data) - sum(work_cost_data),
        'total_work_records': 48,
        'income_change_percent': 12.5,
        'expense_change_percent': 8.3,
        'profit_change_percent': 15.7,
        'work_change_percent': 20.1,
        'labels': json.dumps(labels),
        'income_data': json.dumps(income_data),
        'expense_data': json.dumps(expense_data),
        'work_cost_data': json.dumps(work_cost_data),
        'expense_categories': json.dumps(expense_categories),
        'property_performance': json.dumps(property_performance),
        'work_heatmap_data': json.dumps(work_heatmap_data),
        'expense_trends': json.dumps(expense_trends),
        'profit_margin': json.dumps(profit_margin),
        'pending_work': pending_work,
        'property_expenses': property_expenses,
        'geojson': json.dumps(geojson),
        'selected_property': 'all',
        'selected_date_range': 365,
        'selected_category': 'all'
    }

def update_dashboard_data():
    """API endpoint handler to fetch updated dashboard data based on filters"""
    property_id = request.args.get('property_id', 'all')
    if property_id == 'all':
        property_id = None
        
    date_range = request.args.get('date_range', '365')
    try:
        date_range = int(date_range)
    except ValueError:
        date_range = 365
    
    category = request.args.get('category', 'all')
    if category == 'all':
        category = None
        
    data = get_analytics_data(property_id, date_range, category)
    return jsonify(data)

# Flask route handler to be added to app.py
def analytics_dashboard():
    """Analytics dashboard page route handler"""
    property_id = request.args.get('property_id')
    date_range = request.args.get('date_range', '365')
    category = request.args.get('category', 'all')
    
    try:
        date_range = int(date_range)
    except ValueError:
        date_range = 365
        
    data = get_analytics_data(property_id, date_range, category)
    return render_template('analytics_dashboard.html', **data)