-- Create schema
CREATE SCHEMA IF NOT EXISTS propintel;

-- Properties table
CREATE TABLE IF NOT EXISTS propintel.properties (
    property_id SERIAL PRIMARY KEY,
    property_name VARCHAR(255) NOT NULL,
    address TEXT NOT NULL,
    latitude NUMERIC(10, 6),
    longitude NUMERIC(10, 6),
    purchase_date DATE,
    purchase_price NUMERIC(12, 2),
    current_value NUMERIC(12, 2),
    notes TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Work records table
CREATE TABLE IF NOT EXISTS propintel.work (
    work_id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    work_description TEXT NOT NULL,
    work_date DATE NOT NULL,
    work_cost NUMERIC(10, 2),
    payment_method VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Money in (income) table
CREATE TABLE IF NOT EXISTS propintel.money_in (
    money_in_id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    income_details TEXT,
    income_date DATE NOT NULL,
    income_amount NUMERIC(10, 2) NOT NULL,
    payment_method VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Money out (expenses) table
CREATE TABLE IF NOT EXISTS propintel.money_out (
    money_out_id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    expense_details TEXT,
    expense_date DATE NOT NULL,
    expense_amount NUMERIC(10, 2) NOT NULL,
    payment_method VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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