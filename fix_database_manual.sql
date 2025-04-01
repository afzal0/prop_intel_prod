-- Manual database fix for PropIntel
-- Run this directly in your PostgreSQL database using:
-- psql -U your_username -d your_database -f fix_database_manual.sql

-- Create schema
CREATE SCHEMA IF NOT EXISTS propintel;

-- Create users table
CREATE TABLE IF NOT EXISTS propintel.users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Create admin user (password is 'admin123')
INSERT INTO propintel.users (
    username, password_hash, email, full_name, role, created_at
) VALUES (
    'admin', 
    '$2b$12$lF0JLUbjHLmeBz5BTw3GOec3/KFUXdtb0JFR1WV1YAbSj.TYMpWNe', 
    'admin@propintel.com',
    'System Administrator',
    'admin',
    CURRENT_TIMESTAMP
) ON CONFLICT (username) DO NOTHING;

-- Create user_settings table
CREATE TABLE IF NOT EXISTS propintel.user_settings (
    setting_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES propintel.users(user_id),
    map_theme VARCHAR(20) DEFAULT 'light',
    default_view VARCHAR(20) DEFAULT 'card',
    notifications_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create properties table
CREATE TABLE IF NOT EXISTS propintel.properties (
    property_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES propintel.users(user_id),
    property_name VARCHAR(255) NOT NULL,
    project_name VARCHAR(255),
    status VARCHAR(50) DEFAULT 'Active',
    address TEXT NOT NULL,
    location VARCHAR(255),
    project_type VARCHAR(100),
    project_manager VARCHAR(100),
    due_date DATE,
    latitude NUMERIC(10, 6),
    longitude NUMERIC(10, 6),
    purchase_date DATE,
    purchase_price NUMERIC(12, 2),
    current_value NUMERIC(12, 2),
    total_income NUMERIC(12, 2) DEFAULT 0,
    total_expenses NUMERIC(12, 2) DEFAULT 0,
    profit NUMERIC(12, 2) DEFAULT 0,
    notes TEXT,
    is_hidden BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create money_in table
CREATE TABLE IF NOT EXISTS propintel.money_in (
    money_in_id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    user_id INTEGER REFERENCES propintel.users(user_id),
    income_details TEXT,
    income_date DATE NOT NULL,
    income_amount NUMERIC(10, 2) NOT NULL,
    payment_method VARCHAR(50),
    income_category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create money_out table
CREATE TABLE IF NOT EXISTS propintel.money_out (
    money_out_id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    user_id INTEGER REFERENCES propintel.users(user_id),
    expense_details TEXT,
    expense_date DATE NOT NULL,
    expense_amount NUMERIC(10, 2) NOT NULL,
    payment_method VARCHAR(50),
    expense_category VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create work table
CREATE TABLE IF NOT EXISTS propintel.work (
    work_id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    user_id INTEGER REFERENCES propintel.users(user_id),
    work_description TEXT NOT NULL,
    work_date DATE NOT NULL,
    work_cost NUMERIC(10, 2),
    payment_method VARCHAR(50),
    status VARCHAR(50) DEFAULT 'Pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create property_images table
CREATE TABLE IF NOT EXISTS propintel.property_images (
    image_id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    user_id INTEGER REFERENCES propintel.users(user_id),
    work_id INTEGER REFERENCES propintel.work(work_id),
    image_path VARCHAR(255) NOT NULL,
    image_type VARCHAR(50) DEFAULT 'property',
    description TEXT,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create audit_log table
CREATE TABLE IF NOT EXISTS propintel.audit_log (
    log_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES propintel.users(user_id),
    action_type VARCHAR(50) NOT NULL,
    table_name VARCHAR(50),
    record_id INTEGER,
    details TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Add sample data for testing
-- Add a sample property
INSERT INTO propintel.properties (
    user_id, property_name, address, latitude, longitude
) VALUES (
    1, 'Test Property', '123 Test St, Test City', 37.7749, -122.4194
) ON CONFLICT DO NOTHING;

-- Create missing directories for static content
-- NOTE: This command won't run in SQL directly - you need to do this manually
-- mkdir -p /Users/afzalkhan/prop_intel_prod\ back/static/images
-- touch /Users/afzalkhan/prop_intel_prod\ back/static/logo.png
-- touch /Users/afzalkhan/prop_intel_prod\ back/static/images/property-placeholder.jpg