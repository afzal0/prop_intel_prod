-- Create schema
CREATE SCHEMA IF NOT EXISTS propintel;

-- Create users table if it doesn't exist
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

-- Check if admin user exists and create if not
INSERT INTO propintel.users (
    username, password_hash, email, full_name, role, created_at
) VALUES (
    'admin', 
    '$2b$12$lF0JLUbjHLmeBz5BTw3GOec3/KFUXdtb0JFR1WV1YAbSj.TYMpWNe', -- bcrypt hash for 'admin123'
    'admin@propintel.com',
    'System Administrator',
    'admin',
    CURRENT_TIMESTAMP
) ON CONFLICT (username) DO NOTHING;

-- Create user_settings table if it doesn't exist
CREATE TABLE IF NOT EXISTS propintel.user_settings (
    setting_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES propintel.users(user_id),
    map_theme VARCHAR(20) DEFAULT 'light',
    default_view VARCHAR(20) DEFAULT 'card',
    notifications_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert admin settings if not exists
INSERT INTO propintel.user_settings (user_id, map_theme, default_view)
SELECT user_id, 'light', 'card' FROM propintel.users WHERE username = 'admin'
ON CONFLICT DO NOTHING;

-- Make sure properties table exists with needed columns
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