#!/bin/bash

# Check if Python is installed
if ! command -v python3 &> /dev/null
then
    echo "Error: Python 3 is not installed. Please install Python 3 to run this application."
    exit 1
fi

# Check if PostgreSQL is installed
if ! command -v psql &> /dev/null
then
    echo "Warning: PostgreSQL command line tools not found. This may affect database operations."
fi

# Check if required Python packages are installed
echo "Checking required Python packages..."
python3 -c "
import sys
try:
    import flask, psycopg2, werkzeug, PIL
    print('All required packages are installed.')
except ImportError as e:
    print(f'Error: {e}')
    print('Please run: pip install -r requirements.txt')
    sys.exit(1)
"

if [ $? -ne 0 ]; then
    exit 1
fi

# Database setup options
echo "Database Setup Options:"
echo "1. Full setup with sample data (creates all tables and sample data)"
echo "2. Fix login issues only (creates/updates essential tables for login)"
echo "3. Skip database setup"
echo "Choose an option (1-3):"
read db_option

case $db_option in
    1)
        echo "Setting up full database with sample data..."
        python3 populate_db.py
        ;;
    2)
        echo "Fixing login database tables..."
        python3 fix_login_db.py
        ;;
    3)
        echo "Skipping database setup."
        ;;
    *)
        echo "Invalid option. Skipping database setup."
        ;;
esac

# Run the application
echo "Starting PropIntel application..."
echo "Open http://localhost:5000 in your browser to access the application"
echo "Admin username: admin"
echo "Admin password: admin123"
echo ""
echo "Press Ctrl+C to stop the application"
python3 app.py