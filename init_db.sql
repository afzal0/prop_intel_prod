-- Create schema
CREATE SCHEMA IF NOT EXISTS propintel;

-- Create tables within the 'propintel' schema
CREATE TABLE IF NOT EXISTS propintel.properties (
    property_id SERIAL PRIMARY KEY,
    property_name VARCHAR(255),
    address TEXT,
    latitude DOUBLE PRECISION,
    longitude DOUBLE PRECISION
);

CREATE TABLE IF NOT EXISTS propintel.work (
    work_id SERIAL PRIMARY KEY,
    property_id INT NOT NULL,
    work_description TEXT,
    work_date DATE,
    work_cost NUMERIC(10, 2),
    payment_method VARCHAR(50),
    FOREIGN KEY (property_id) REFERENCES propintel.properties (property_id)
);

CREATE TABLE IF NOT EXISTS propintel.money_in (
    money_in_id SERIAL PRIMARY KEY,
    property_id INT NOT NULL,
    income_amount NUMERIC(10,2),
    income_date DATE,
    income_details TEXT,
    payment_method VARCHAR(50),
    FOREIGN KEY (property_id) REFERENCES propintel.properties (property_id)
);

CREATE TABLE IF NOT EXISTS propintel.money_out (
    money_out_id SERIAL PRIMARY KEY,
    property_id INT NOT NULL,
    expense_amount NUMERIC(10,2),
    expense_date DATE,
    expense_details TEXT,
    payment_method VARCHAR(50),
    FOREIGN KEY (property_id) REFERENCES propintel.properties (property_id)
);

-- Insert a sample property for testing
INSERT INTO propintel.properties (property_name, address, latitude, longitude)
VALUES 
    ('Sample Property', '123 Test Street, Melbourne, Australia', -37.8136, 144.9631);

-- Insert some sample work records
INSERT INTO propintel.work (property_id, work_description, work_date, work_cost, payment_method)
VALUES 
    (1, 'Initial repairs', '2024-01-15', 2500.00, 'TRANSFER'),
    (1, 'Painting interior', '2024-02-10', 1800.00, 'CARD');

-- Insert some sample income records
INSERT INTO propintel.money_in (property_id, income_amount, income_date, income_details, payment_method)
VALUES 
    (1, 5000.00, '2024-02-01', 'Monthly rent', 'TRANSFER'),
    (1, 5000.00, '2024-03-01', 'Monthly rent', 'TRANSFER');

-- Insert some sample expense records
INSERT INTO propintel.money_out (property_id, expense_amount, expense_date, expense_details, payment_method)
VALUES 
    (1, 1200.00, '2024-02-15', 'Property insurance', 'CARD'),
    (1, 450.00, '2024-03-10', 'Utilities', 'TRANSFER');