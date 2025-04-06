-- Property Intel Complete Database Schema Rebuild Script
-- WARNING: This script will DROP and RECREATE all tables
-- Make sure you have a backup before running this

-- Start transaction
BEGIN;

-- Drop existing schema (cascade will remove all dependent objects)
DROP SCHEMA IF EXISTS public CASCADE;
CREATE SCHEMA public;

-- Set default privileges
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO public;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO public;

-- Create users table
CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(200) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    first_name VARCHAR(100),
    last_name VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create properties table
CREATE TABLE properties (
    id SERIAL PRIMARY KEY,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    address VARCHAR(200),
    city VARCHAR(100),
    state VARCHAR(50),
    zip_code VARCHAR(20),
    country VARCHAR(100) DEFAULT 'USA',
    property_type VARCHAR(50),
    status VARCHAR(20) DEFAULT 'active',
    bedrooms INTEGER,
    bathrooms NUMERIC(3,1),
    square_feet INTEGER,
    year_built INTEGER,
    list_price NUMERIC(12,2),
    estimated_value NUMERIC(12,2),
    latitude NUMERIC(10,6),
    longitude NUMERIC(10,6),
    owner_id INTEGER REFERENCES users(id),
    energy_rating VARCHAR(10),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create property_images table
CREATE TABLE property_images (
    id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES properties(id) ON DELETE CASCADE,
    image_path VARCHAR(255) NOT NULL,
    description VARCHAR(200),
    is_primary BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create transactions table
CREATE TABLE transactions (
    id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES properties(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id),
    transaction_type VARCHAR(50) NOT NULL,
    amount NUMERIC(12,2) NOT NULL,
    transaction_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    description TEXT,
    status VARCHAR(20) DEFAULT 'completed',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create property_analytics table
CREATE TABLE property_analytics (
    id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES properties(id) ON DELETE CASCADE,
    view_count INTEGER DEFAULT 0,
    search_impressions INTEGER DEFAULT 0,
    last_viewed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create income table for budget planning
CREATE TABLE income (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    property_id INTEGER REFERENCES properties(id) ON DELETE CASCADE,
    amount NUMERIC(12,2) NOT NULL,
    income_date DATE NOT NULL,
    category VARCHAR(100),
    description TEXT,
    recurring BOOLEAN DEFAULT FALSE,
    frequency VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create expenses table for budget planning
CREATE TABLE expenses (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    property_id INTEGER REFERENCES properties(id) ON DELETE CASCADE,
    amount NUMERIC(12,2) NOT NULL,
    expense_date DATE NOT NULL,
    category VARCHAR(100),
    description TEXT,
    receipt_path VARCHAR(255),
    recurring BOOLEAN DEFAULT FALSE,
    frequency VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create work table for property work/tasks
CREATE TABLE work (
    id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES properties(id) ON DELETE CASCADE,
    title VARCHAR(200) NOT NULL,
    description TEXT,
    status VARCHAR(50) DEFAULT 'pending',
    priority VARCHAR(20) DEFAULT 'medium',
    estimated_cost NUMERIC(12,2),
    actual_cost NUMERIC(12,2),
    assigned_to INTEGER REFERENCES users(id),
    start_date DATE,
    end_date DATE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create user sessions table
CREATE TABLE user_sessions (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    session_id VARCHAR(255) UNIQUE NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL
);

-- Create indexes for performance
CREATE INDEX idx_property_location ON properties(city, state);
CREATE INDEX idx_property_type ON properties(property_type);
CREATE INDEX idx_property_status ON properties(status);
CREATE INDEX idx_property_owner ON properties(owner_id);
CREATE INDEX idx_transaction_property ON transactions(property_id);
CREATE INDEX idx_transaction_user ON transactions(user_id);
CREATE INDEX idx_income_user ON income(user_id);
CREATE INDEX idx_income_property ON income(property_id);
CREATE INDEX idx_expense_user ON expenses(user_id);
CREATE INDEX idx_expense_property ON expenses(property_id);
CREATE INDEX idx_work_property ON work(property_id);
CREATE INDEX idx_work_status ON work(status);
CREATE INDEX idx_session_user ON user_sessions(user_id);

-- Create admin user (password should be changed after first login)
INSERT INTO users (username, password, email, first_name, last_name, role)
VALUES (
    'admin', 
    -- This is a placeholder hash for 'admin123' - DO NOT USE IN PRODUCTION
    '$2b$12$QqUZm.JHnrSh9RpYJ2Qc/.RTjwkn/iCPMTX9GUZGjVsN8Gso6e8bu', 
    'admin@propintel.example', 
    'System', 
    'Administrator', 
    'admin'
);

-- Commit the transaction
COMMIT;