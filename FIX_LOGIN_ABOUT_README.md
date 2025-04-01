# PropIntel Login and About Page Fix

This guide will help you fix the login and about page issues in PropIntel.

## Error Details

You're experiencing these errors:
- `relation "propintel.users" does not exist` when trying to access the about page
- Missing static files: `/static/logo.png` and `/static/images/property-placeholder.jpg`
- Login session persistence issues

## Quick Fix Instructions

1. **Run the manual database fix script**:
   ```
   python manual_db_fix.py
   ```
   This script will:
   - Create all required database tables
   - Add an admin user
   - Create the static directories and placeholder files

2. **Or run the SQL script directly**:
   If you prefer to use SQL directly, connect to your PostgreSQL database and run:
   ```
   psql -U your_username -d your_database -f fix_database_manual.sql
   ```
   Then create the static directories manually:
   ```
   mkdir -p "/Users/afzalkhan/prop_intel_prod back/static/images"
   touch "/Users/afzalkhan/prop_intel_prod back/static/logo.png"
   touch "/Users/afzalkhan/prop_intel_prod back/static/images/property-placeholder.jpg"
   ```

3. **Restart your application**:
   ```
   python app.py
   ```

## What Gets Fixed

1. **Database Tables**:
   The script creates all required tables in the `propintel` schema:
   - `users` (for authentication)
   - `properties` (property records)
   - `work` (work records)
   - `money_in` (income records)
   - `money_out` (expense records)
   - `property_images` (image uploads)
   - `user_settings` (user preferences)
   - `audit_log` (activity tracking)

2. **Admin User**:
   Creates an admin user with credentials:
   - Username: `admin`
   - Password: `admin123`

3. **Static Files**:
   Creates the directories and placeholder files for:
   - `/static/logo.png`
   - `/static/images/property-placeholder.jpg`

## Customizing the Fix

If you need to customize the database connection:

1. Edit your `db_config.ini` file:
   ```ini
   [database]
   user = your_username
   password = your_password
   host = your_host
   port = 5432
   database = your_database
   ```

2. Or set environment variables:
   - `DATABASE_URL` - Complete database URL (Heroku style)
   - Or individual parameters:
     - `DB_USER`
     - `DB_PASSWORD`
     - `DB_HOST`
     - `DB_PORT`
     - `DB_NAME`

## Troubleshooting

If you still encounter issues:

1. **Check database connection**:
   Make sure your PostgreSQL server is running and accessible with the credentials in `db_config.ini`.

2. **Verify tables were created**:
   Connect to your database and run:
   ```sql
   \dn  -- List schemas
   \dt propintel.*  -- List tables in propintel schema
   ```

3. **Check for existing admin user**:
   ```sql
   SELECT * FROM propintel.users WHERE username = 'admin';
   ```

4. **Check application logs**:
   Look for specific error messages that might indicate other issues.

5. **Initialize with sample data**:
   If you want to populate the database with sample data, run the full initialization script:
   ```
   python populate_db.py
   ```