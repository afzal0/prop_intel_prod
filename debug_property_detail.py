import os
import sys
import psycopg2
from psycopg2.extras import RealDictCursor
import logging

# Setup logging
logging.basicConfig(level=logging.DEBUG, 
                    format='%(asctime)s - %(levelname)s - %(message)s',
                    handlers=[logging.StreamHandler()])

logger = logging.getLogger(__name__)

# Database configuration
DB_CONFIG = {
    'user': 'postgres',
    'password': '1234',
    'host': 'localhost',
    'port': '5432',
    'database': 'postgres'
}

def get_db_connection():
    """Get a database connection using the provided configuration"""
    logger.info(f"Connecting to database: {DB_CONFIG['host']}:{DB_CONFIG['port']}/{DB_CONFIG['database']} as {DB_CONFIG['user']}")
    conn = psycopg2.connect(
        user=DB_CONFIG['user'],
        password=DB_CONFIG['password'],
        host=DB_CONFIG['host'],
        port=DB_CONFIG['port'],
        dbname=DB_CONFIG['database']
    )
    conn.autocommit = False
    return conn

def debug_property_detail(property_id):
    """Debug version of property_detail function to find index errors"""
    conn = None
    try:
        logger.info(f"Starting debug for property_id: {property_id}")
        conn = get_db_connection()
        
        with conn.cursor(cursor_factory=RealDictCursor) as cur:
            # Get property details
            logger.info("Querying property details")
            cur.execute("""
                SELECT * FROM propintel.properties WHERE property_id = %s
            """, (property_id,))
            property_data = cur.fetchone()
            
            if not property_data:
                logger.error(f"Property {property_id} not found")
                return
            
            logger.info(f"Property found: {property_data['property_name']}")
            
            # Initialize empty lists for records that might not exist
            property_images = []
            work_images = []
            
            # Get work records
            logger.info("Querying work records")
            cur.execute("""
                SELECT * FROM propintel.work 
                WHERE property_id = %s
                ORDER BY work_date DESC
            """, (property_id,))
            work_records = cur.fetchall()
            logger.info(f"Found {len(work_records)} work records")
            
            # Get income records
            logger.info("Querying income records")
            cur.execute("""
                SELECT * FROM propintel.money_in 
                WHERE property_id = %s
                ORDER BY income_date DESC
            """, (property_id,))
            income_records = cur.fetchall()
            logger.info(f"Found {len(income_records)} income records")
            
            # Get expense records
            logger.info("Querying expense records")
            cur.execute("""
                SELECT * FROM propintel.money_out 
                WHERE property_id = %s
                ORDER BY expense_date DESC
            """, (property_id,))
            expense_records = cur.fetchall()
            logger.info(f"Found {len(expense_records)} expense records")
            
            # Initialize expense category totals
            expense_categories = {
                'wage_total': 0,
                'pm_total': 0,
                'material_total': 0,
                'misc_total': 0
            }
            
            # Calculate expense totals by category
            logger.info("Calculating expense categories")
            try:
                cur.execute("""
                    SELECT
                        COALESCE(SUM(CASE WHEN expense_category = 'wage' OR 
                                            expense_details ILIKE '%wage%' OR 
                                            expense_details ILIKE '%salary%' 
                                    THEN expense_amount ELSE 0 END), 0) as wage_total,
                        COALESCE(SUM(CASE WHEN expense_category = 'project_manager' OR 
                                            expense_details ILIKE '%project manager%' OR 
                                            expense_details ILIKE '%pm %' 
                                    THEN expense_amount ELSE 0 END), 0) as pm_total,
                        COALESCE(SUM(CASE WHEN expense_category = 'material' OR 
                                            expense_details ILIKE '%material%' OR 
                                            expense_details ILIKE '%supplies%' 
                                    THEN expense_amount ELSE 0 END), 0) as material_total,
                        COALESCE(SUM(CASE WHEN (expense_category IS NULL OR expense_category = 'miscellaneous') AND 
                                            expense_details NOT ILIKE '%wage%' AND 
                                            expense_details NOT ILIKE '%salary%' AND
                                            expense_details NOT ILIKE '%project manager%' AND
                                            expense_details NOT ILIKE '%pm %' AND
                                            expense_details NOT ILIKE '%material%' AND
                                            expense_details NOT ILIKE '%supplies%'
                                    THEN expense_amount ELSE 0 END), 0) as misc_total
                    FROM propintel.money_out
                    WHERE property_id = %s
                """, (property_id,))
                
                category_result = cur.fetchone()
                logger.info(f"Category result: {category_result}")
                
                if category_result:
                    expense_categories = category_result
                    logger.info(f"Expense categories: wage={expense_categories['wage_total']}, pm={expense_categories['pm_total']}, material={expense_categories['material_total']}, misc={expense_categories['misc_total']}")
            except Exception as e:
                logger.error(f"Error in expense category calculation: {e}")
                # If expense_category column doesn't exist, categorize manually
                logger.info("Falling back to manual categorization")
                for record in expense_records:
                    try:
                        amount = record['expense_amount'] or 0
                        details = (record.get('expense_details', '') or '').lower()
                        
                        if 'wage' in details or 'salary' in details:
                            expense_categories['wage_total'] += amount
                        elif 'project manager' in details or 'pm ' in details:
                            expense_categories['pm_total'] += amount
                        elif 'material' in details or 'supplies' in details:
                            expense_categories['material_total'] += amount
                        else:
                            expense_categories['misc_total'] += amount
                    except Exception as inner_e:
                        logger.error(f"Error processing expense record: {inner_e}")
                        logger.error(f"Record data: {record}")
            
            # Calculate totals
            try:
                logger.info("Calculating financial totals")
                income_total = sum(record['income_amount'] for record in income_records)
                expense_total = sum(record['expense_amount'] for record in expense_records)
                work_total = sum(record['work_cost'] for record in work_records if record.get('work_cost'))
                net_total = income_total - expense_total
                
                logger.info(f"Income total: {income_total}")
                logger.info(f"Expense total: {expense_total}")
                logger.info(f"Work total: {work_total}")
                logger.info(f"Net total: {net_total}")
            except Exception as e:
                logger.error(f"Error calculating totals: {e}")
            
            # Get monthly trend data for charts
            try:
                logger.info("Calculating trend data")
                trend_months = {}
                for record in income_records:
                    month_key = record['income_date'].strftime('%Y-%m')
                    if month_key not in trend_months:
                        trend_months[month_key] = {'income': 0, 'expense': 0}
                    trend_months[month_key]['income'] += record['income_amount']
                
                for record in expense_records:
                    month_key = record['expense_date'].strftime('%Y-%m')
                    if month_key not in trend_months:
                        trend_months[month_key] = {'income': 0, 'expense': 0}
                    trend_months[month_key]['expense'] += record['expense_amount']
                
                # Sort months for chart display
                sorted_months = sorted(trend_months.keys())
                trend_labels = [month for month in sorted_months]
                income_data = [trend_months[month]['income'] for month in sorted_months]
                expense_data = [trend_months[month]['expense'] for month in sorted_months]
                
                logger.info(f"Trend data: {len(trend_labels)} months")
            except Exception as e:
                logger.error(f"Error calculating trend data: {e}")
            
            # Check for latitude/longitude
            try:
                logger.info("Checking map coordinates")
                map_lat = property_data.get('latitude')
                map_lng = property_data.get('longitude')
                logger.info(f"Map coordinates: lat={map_lat}, lng={map_lng}")
            except Exception as e:
                logger.error(f"Error checking map coordinates: {e}")
            
            logger.info("All property data processed successfully")
            
    except Exception as e:
        logger.error(f"Error in property_detail: {e}")
    finally:
        if conn:
            conn.close()
            logger.info("Database connection closed")

if __name__ == "__main__":
    if len(sys.argv) > 1:
        property_id = int(sys.argv[1])
        debug_property_detail(property_id)
    else:
        logger.error("Please provide a property_id as an argument")
        print("Usage: python debug_property_detail.py property_id")
        sys.exit(1)