-- Create schema
CREATE SCHEMA IF NOT EXISTS propintel;

-- Make sure PostGIS extension is installed
CREATE EXTENSION IF NOT EXISTS postgis;

-- Users table
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

-- LGA (Local Government Areas) table to store shapefile data
CREATE TABLE IF NOT EXISTS propintel.lgas (
    lga_id SERIAL PRIMARY KEY,
    lga_code VARCHAR(50) NOT NULL,
    lga_name VARCHAR(255) NOT NULL,
    state_code VARCHAR(10),
    state_name VARCHAR(50),
    area_sqkm NUMERIC(10, 2),
    geom GEOMETRY(MULTIPOLYGON, 4326),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Documents table for builder's hub
CREATE TABLE IF NOT EXISTS propintel.documents (
    document_id SERIAL PRIMARY KEY,
    lga_id INTEGER REFERENCES propintel.lgas(lga_id),
    user_id INTEGER REFERENCES propintel.users(user_id),
    document_name VARCHAR(255) NOT NULL,
    document_type VARCHAR(50), -- 'permit', 'regulation', 'form', etc.
    description TEXT,
    file_path VARCHAR(255) NOT NULL,
    file_size INTEGER,
    is_public BOOLEAN DEFAULT TRUE,
    download_count INTEGER DEFAULT 0,
    address TEXT,
    latitude NUMERIC(10, 6),
    longitude NUMERIC(10, 6),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Work heatmap data to store precalculated density
CREATE TABLE IF NOT EXISTS propintel.work_heatmap (
    heatmap_id SERIAL PRIMARY KEY,
    latitude NUMERIC(10, 6) NOT NULL,
    longitude NUMERIC(10, 6) NOT NULL,
    intensity INTEGER NOT NULL,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    work_count INTEGER DEFAULT 0,
    last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
    
-- Triggers for new tables
CREATE TRIGGER update_lgas_modtime
    BEFORE UPDATE ON propintel.lgas
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();

CREATE TRIGGER update_documents_modtime
    BEFORE UPDATE ON propintel.documents
    FOR EACH ROW
    EXECUTE FUNCTION update_modified_column();
    
CREATE TRIGGER update_work_heatmap_modtime
    BEFORE UPDATE ON propintel.work_heatmap
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