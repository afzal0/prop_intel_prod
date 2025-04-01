# PropIntel Login and About Page Fix

This document provides instructions to fix the login session persistence and about page database errors in PropIntel.

## Quick Fix

1. **Run the database fix utility**:
   ```
   python db_fix_patch.py
   ```
   
   This will:
   - Create the propintel schema if it doesn't exist
   - Create all required tables including users, properties, etc.
   - Create an admin user if one doesn't exist

2. **Update your app.py with the provided patches**:
   - Copy the contents of `about_route_patch.py` to replace the existing `/about` route
   - Copy the contents of `before_request_patch.py` to replace the existing `before_request` function

3. **Restart the application**:
   ```
   python app.py
   ```

## What These Fixes Address

1. **Login Session Persistence**
   - Improves session handling to prevent users from being logged out
   - Adds fallback handling for admin user when database connection fails
   - Better error handling around database operations

2. **About Page Errors**
   - Handles missing tables gracefully
   - Creates required tables if they don't exist
   - Prevents "relation 'propintel.users' does not exist" errors

3. **Account Creation**
   - Ensures the users table exists before attempting to create accounts
   - Better error messages for account creation issues

## Login Credentials

After applying the fixes, you can login with:

- **Admin User**:
  - Username: `admin`
  - Password: `admin123`

- **Guest Access**:
  - Username: `guest`
  - No password required

## Database Structure

The fix ensures the following tables exist:

- `propintel.users` - For user authentication
- `propintel.properties` - For property details
- `propintel.money_in` - For income records
- `propintel.money_out` - For expense records
- `propintel.property_images` - For property images
- `propintel.user_settings` - For user preferences

## Manual Application

If you prefer not to use the automatic fix, you can manually:

1. Connect to your database and run the SQL commands from `fix_db_quick.sql`
2. Update the specific route handlers in your app.py as needed

## Troubleshooting

If you still experience issues after applying these fixes:

1. Check database connection parameters in `db_config.ini`
2. Ensure PostgreSQL is running and accessible
3. Verify the admin user exists in the database by running:
   ```sql
   SELECT * FROM propintel.users WHERE username = 'admin';
   ```
4. Check the application logs for specific error messages