-- Create schema
CREATE SCHEMA IF NOT EXISTS propintel;

-- Drop existing tables if they exist (for clean setup)
DROP TABLE IF EXISTS propintel.audit_log;
DROP TABLE IF EXISTS propintel.user_settings;
DROP TABLE IF EXISTS propintel.property_images;
DROP TABLE IF EXISTS propintel.money_out;
DROP TABLE IF EXISTS propintel.money_in;
DROP TABLE IF EXISTS propintel.work;
DROP TABLE IF EXISTS propintel.properties;
DROP TABLE IF EXISTS propintel.users;

-- Create the users table
CREATE TABLE IF NOT EXISTS propintel.users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    role VARCHAR(20) NOT NULL DEFAULT 'user', -- 'admin', 'user', 'manager', etc.
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Properties table (updated with new fields)
CREATE TABLE IF NOT EXISTS propintel.properties (
    property_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES propintel.users(user_id),
    property_name VARCHAR(255) NOT NULL,
    project_name VARCHAR(255),
    status VARCHAR(50) DEFAULT 'Active', -- 'Active', 'Completed', 'On Hold', 'Cancelled'
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

-- Work records table
CREATE TABLE IF NOT EXISTS propintel.work (
    work_id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    user_id INTEGER REFERENCES propintel.users(user_id),
    work_description TEXT NOT NULL,
    work_date DATE NOT NULL,
    work_cost NUMERIC(10, 2),
    payment_method VARCHAR(50),
    status VARCHAR(50) DEFAULT 'Pending', -- 'Completed', 'Pending', 'In Progress'
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Money in (income) table
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

-- Money out (expenses) table
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

-- Property images table
CREATE TABLE IF NOT EXISTS propintel.property_images (
    image_id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    user_id INTEGER REFERENCES propintel.users(user_id),
    work_id INTEGER REFERENCES propintel.work(work_id),
    image_path VARCHAR(255) NOT NULL,
    image_type VARCHAR(50) DEFAULT 'property', -- 'property', 'work', 'document'
    description TEXT,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- User settings table
CREATE TABLE IF NOT EXISTS propintel.user_settings (
    setting_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES propintel.users(user_id),
    map_theme VARCHAR(20) DEFAULT 'light', -- 'light', 'dark', 'satellite'
    default_view VARCHAR(20) DEFAULT 'card', -- 'card', 'list', 'map'
    notifications_enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Audit log for tracking important changes
CREATE TABLE IF NOT EXISTS propintel.audit_log (
    log_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES propintel.users(user_id),
    action_type VARCHAR(50) NOT NULL, -- 'create', 'update', 'delete', 'login', etc.
    table_name VARCHAR(50),
    record_id INTEGER,
    details TEXT,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create function to update timestamp
CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Create triggers for updated_at timestamps
CREATE TRIGGER update_properties_modtime
    BEFORE UPDATE ON propintel.properties
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_work_modtime
    BEFORE UPDATE ON propintel.work
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_money_in_modtime
    BEFORE UPDATE ON propintel.money_in
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_money_out_modtime
    BEFORE UPDATE ON propintel.money_out
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_users_modtime
    BEFORE UPDATE ON propintel.users
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_user_settings_modtime
    BEFORE UPDATE ON propintel.user_settings
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

-- Function to update property totals (income, expenses, profit)
CREATE OR REPLACE FUNCTION update_property_totals()
RETURNS TRIGGER AS $$
DECLARE
    p_id INTEGER;
    total_in NUMERIC(12, 2);
    total_out NUMERIC(12, 2);
BEGIN
    -- Determine which property to update
    IF TG_TABLE_NAME = 'money_in' THEN
        IF TG_OP = 'DELETE' THEN
            p_id := OLD.property_id;
        ELSE
            p_id := NEW.property_id;
        END IF;
    ELSIF TG_TABLE_NAME = 'money_out' THEN
        IF TG_OP = 'DELETE' THEN
            p_id := OLD.property_id;
        ELSE
            p_id := NEW.property_id;
        END IF;
    END IF;
    
    -- Calculate new totals
    SELECT COALESCE(SUM(income_amount), 0) INTO total_in 
    FROM propintel.money_in 
    WHERE property_id = p_id;
    
    SELECT COALESCE(SUM(expense_amount), 0) INTO total_out 
    FROM propintel.money_out 
    WHERE property_id = p_id;
    
    -- Update the property record
    UPDATE propintel.properties
    SET total_income = total_in,
        total_expenses = total_out,
        profit = total_in - total_out
    WHERE property_id = p_id;
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create triggers to update property totals
CREATE TRIGGER update_property_totals_insert_income
    AFTER INSERT OR UPDATE OR DELETE ON propintel.money_in
    FOR EACH ROW
    EXECUTE FUNCTION update_property_totals();

CREATE TRIGGER update_property_totals_insert_expense
    AFTER INSERT OR UPDATE OR DELETE ON propintel.money_out
    FOR EACH ROW
    EXECUTE FUNCTION update_property_totals();

-- Insert admin user (password: admin123)
INSERT INTO propintel.users (
    username, password_hash, email, full_name, role, created_at
) VALUES (
    'admin', 
    '$2b$12$lF0JLUbjHLmeBz5BTw3GOec3/KFUXdtb0JFR1WV1YAbSj.TYMpWNe', -- bcrypt hash for 'admin123'
    'admin@propintel.com',
    'System Administrator',
    'admin',
    CURRENT_TIMESTAMP
);

-- Sample project types
INSERT INTO propintel.properties (
    user_id, property_name, project_name, status, address, location, project_type, project_manager, 
    latitude, longitude, purchase_date, purchase_price, current_value, notes
) VALUES 
(1, 'Oceanview Terrace', 'Oceanview Development', 'Active', '123 Beach Rd, Melbourne', 'Melbourne', 
'Residential Complex', 'John Smith', -37.8136, 144.9631, '2023-01-15', 1500000, 1750000, 'Luxury apartment complex with ocean views'),

(1, 'Central Office Tower', 'Business District Expansion', 'In Progress', '456 City Center, Melbourne', 'CBD', 
'Commercial Building', 'Emma Johnson', -37.8125, 144.9623, '2022-11-10', 3200000, 3200000, 'Class A office building in prime location'),

(1, 'Greenside Villas', 'Suburbia Project', 'On Hold', '789 Forest Ave, Melbourne', 'Eastern Suburbs', 
'Residential Subdivision', 'Michael Williams', -37.8118, 144.9610, '2023-03-22', 2100000, 2300000, 'Gated community with 15 luxury homes'),

(1, 'Riverside Plaza', 'River Retail Development', 'Active', '101 River St, Melbourne', 'Southbank', 
'Retail Complex', 'Sarah Davis', -37.8192, 144.9683, '2022-08-05', 4500000, 4750000, 'Mixed-use development with shops and offices'),

(1, 'Tech Hub', 'Innovation Center', 'Planning', '202 Digital Dr, Melbourne', 'Northern Suburbs', 
'Industrial Conversion', 'David Chen', -37.8050, 144.9650, '2023-05-10', 1800000, 1800000, 'Conversion of old warehouse to tech workspace');

-- Add some income records
INSERT INTO propintel.money_in (
    property_id, user_id, income_details, income_date, income_amount, payment_method, income_category
) VALUES
(1, 1, 'Tenant deposit', '2023-02-01', 25000, 'Bank Transfer', 'Deposit'),
(1, 1, 'Monthly rent', '2023-03-01', 15000, 'Bank Transfer', 'Rent'),
(1, 1, 'Monthly rent', '2023-04-01', 15000, 'Bank Transfer', 'Rent'),
(2, 1, 'Lease payment', '2023-01-15', 45000, 'Bank Transfer', 'Lease'),
(2, 1, 'Lease payment', '2023-02-15', 45000, 'Bank Transfer', 'Lease'),
(3, 1, 'Property sale', '2023-05-01', 750000, 'Wire Transfer', 'Sale'),
(4, 1, 'Monthly rent', '2023-02-01', 35000, 'Bank Transfer', 'Rent'),
(4, 1, 'Monthly rent', '2023-03-01', 35000, 'Bank Transfer', 'Rent'),
(5, 1, 'Investment funding', '2023-06-01', 500000, 'Wire Transfer', 'Investment');

-- Add some expense records
INSERT INTO propintel.money_out (
    property_id, user_id, expense_details, expense_date, expense_amount, payment_method, expense_category
) VALUES
(1, 1, 'Property tax', '2023-02-15', 12500, 'Bank Transfer', 'Taxes'),
(1, 1, 'Maintenance', '2023-03-10', 5000, 'Credit Card', 'Maintenance'),
(1, 1, 'Insurance', '2023-01-05', 8500, 'Bank Transfer', 'Insurance'),
(2, 1, 'Building repairs', '2023-02-20', 15000, 'Check', 'Repairs'),
(2, 1, 'Security system upgrade', '2023-03-15', 22000, 'Credit Card', 'Security'),
(3, 1, 'Landscaping', '2023-04-10', 18500, 'Check', 'Landscaping'),
(4, 1, 'Property tax', '2023-02-15', 22000, 'Bank Transfer', 'Taxes'),
(4, 1, 'Roof repair', '2023-04-05', 9500, 'Check', 'Repairs'),
(5, 1, 'Demolition work', '2023-05-15', 32000, 'Bank Transfer', 'Construction');

-- Add some work records
INSERT INTO propintel.work (
    property_id, user_id, work_description, work_date, work_cost, payment_method, status
) VALUES
(1, 1, 'Install new air conditioning system', '2023-02-10', 25000, 'Check', 'Completed'),
(1, 1, 'Repaint exterior', '2023-03-15', 12000, 'Credit Card', 'In Progress'),
(2, 1, 'Upgrade elevator system', '2023-02-25', 85000, 'Wire Transfer', 'Completed'),
(2, 1, 'Renovate lobby', '2023-03-20', 45000, 'Check', 'In Progress'),
(3, 1, 'Site preparation', '2023-04-15', 35000, 'Check', 'Completed'),
(4, 1, 'Replace storefront glass', '2023-03-05', 18000, 'Credit Card', 'Completed'),
(4, 1, 'Install security cameras', '2023-03-25', 12500, 'Credit Card', 'Completed'),
(5, 1, 'Asbestos removal', '2023-05-20', 42000, 'Check', 'In Progress');

-- Add user settings
INSERT INTO propintel.user_settings (
    user_id, map_theme, default_view, notifications_enabled
) VALUES
(1, 'light', 'card', TRUE);