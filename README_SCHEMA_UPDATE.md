# Property Intel Database Schema Rebuild

This document provides instructions for rebuilding the entire database schema for the Property Intel application.

## WARNING

**The rebuild_schema.sql script will DROP and RECREATE all tables in the database.** 
This will permanently delete all existing data. Make sure you have a complete backup before proceeding.

## Usage Instructions

### Option 1: Using psql command line

```bash
# Connect to your database
psql -h hostname -d database_name -U username -p port -f rebuild_schema.sql

# Example with actual credentials (replace with your values)
# psql -h c1i13pt05ja4ag.cluster-czrs8kj4isg7.us-east-1.rds.amazonaws.com -d d1oncga6g47frr -U u15p78tmoefhv2 -p 5432 -f rebuild_schema.sql
```

When prompted, enter your database password.

### Option 2: Using Heroku CLI

If your database is hosted on Heroku:

```bash
# Pipe the SQL file to the Heroku psql command
cat rebuild_schema.sql | heroku pg:psql postgresql-transparent-19084 --app prop-intelv2
```

### Option 3: Using a database management tool

1. Open your preferred database management tool (pgAdmin, DBeaver, etc.)
2. Connect to your database
3. Open a new SQL query window
4. Copy and paste the contents of rebuild_schema.sql into the query window
5. Execute the query

## Post-Update Tasks

After rebuilding the schema:

1. The script creates an admin user with username 'admin' and password 'admin123'
2. **Important**: Change the admin password immediately after the first login
3. Restore any important data from your backup as needed
4. Verify the application works correctly with the new schema

## Schema Overview

The rebuild script creates the following tables:

- `users`: User accounts and authentication
- `properties`: Property listings and details
- `property_images`: Images associated with properties
- `transactions`: Financial transactions
- `property_analytics`: Usage statistics for properties
- `income`: Income records for budget planning
- `expenses`: Expense records for budget planning
- `work`: Work/tasks associated with properties
- `user_sessions`: User session tracking

It also creates appropriate indexes for performance optimization.

## Support

If you encounter any issues with this schema update, please contact the development team.