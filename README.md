# PropIntel - Property Investment Management System

PropIntel is a comprehensive property investment management system designed to help property investors and managers track properties, expenses, income, and work activities in a centralized platform.

## Features

- User authentication with role-based access control (admin, user, guest)
- Property management with extensive details (location, status, project type, etc.)
- Financial tracking (income and expenses with automatic calculation of profits)
- Work tracking for property maintenance and improvements
- Image uploads for properties and work activities
- Interactive map view with property locations
- Card/list view toggle for property display
- Advanced search and filtering functionality
- Responsive design for desktop and mobile devices
- Admin dashboard for user management

## Prerequisites

- Python 3.8+
- PostgreSQL 12+
- Web browser (Chrome, Firefox, Safari, Edge)

## Installation

1. Clone the repository:
   ```
   git clone https://your-repository-url/propintel.git
   cd propintel
   ```

2. Install required Python packages:
   ```
   pip install -r requirements.txt
   ```

3. Configure database connection:
   - Create a file named `db_config.ini` with the following structure:
     ```
     [database]
     user = your_database_user
     password = your_database_password
     host = your_database_host
     port = 5432
     database = your_database_name
     ```
   - Or set the DATABASE_URL environment variable (for Heroku deployment)

## Running the Application

1. Use the provided run script to start the application:
   ```
   ./run.sh
   ```

2. The script will:
   - Check for required dependencies
   - Offer database setup options
   - Start the web application

3. Access the application at: http://localhost:5000

## Database Setup Options

When running the application, you'll be presented with three database setup options:

1. **Full setup with sample data**
   - Creates all tables and populates them with sample data
   - Best for new installations or when you want to start fresh

2. **Fix login issues only**
   - Only creates or updates essential tables for login functionality
   - Ensures the admin user exists
   - Best when experiencing login issues but wanting to preserve existing data

3. **Skip database setup**
   - Proceeds directly to application startup
   - Use this if your database is already properly configured

## Default Login Credentials

- **Admin Access**:
  - Username: `admin`
  - Password: `admin123`

- **Guest Access**:
  - Username: `guest`
  - No password required

## Application Structure

- **app.py**: Main application file with all routes and core functionality
- **db_connect.py**: Database connection handling
- **property_data_extractor.py**: Helper functions for data extraction
- **templates/**: HTML templates for web pages
- **static/**: CSS, JavaScript, and image files
- **uploads/**: Uploaded property and work images
- **schema.sql**: Database schema definition
- **init_db.sql**: SQL commands for database initialization

## Database Schema

The application uses the following main tables in the `propintel` schema:

- **users**: User accounts and authentication
- **properties**: Property details and financial summary
- **money_in**: Income records
- **money_out**: Expense records
- **work**: Work/maintenance records
- **property_images**: Image uploads for properties and work
- **user_settings**: User preferences (map theme, default view)
- **audit_log**: System audit trail

## Troubleshooting

### Login Issues
- If you cannot log in, try running with option 2 (Fix login issues only)
- This will ensure the admin user exists and has the correct password
- If using a custom database, ensure it has the correct schema structure

### Database Connection Errors
- Check that your PostgreSQL server is running
- Verify the connection details in db_config.ini
- Ensure the database user has appropriate permissions

### Image Upload Issues
- Ensure the uploads/ directory exists and is writable
- Check that the UPLOAD_FOLDER path in app.py is correct for your environment

## Development

### Adding New Features
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

### Coding Style
- Follow PEP 8 style guidelines for Python code
- Use 4 spaces for indentation
- Include docstrings for functions and classes

## License

[Include license information here]

## Contact

For support or inquiries, please contact [your contact information here].