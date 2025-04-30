-- Add budgets table to the propintel schema
CREATE TABLE IF NOT EXISTS propintel.budgets (
    budget_id SERIAL PRIMARY KEY,
    property_id INTEGER NOT NULL REFERENCES propintel.properties(property_id) ON DELETE CASCADE,
    user_id VARCHAR(100) NOT NULL,
    budget_name VARCHAR(255) NOT NULL,
    budget_description TEXT,
    budget_amount NUMERIC(10, 2) NOT NULL DEFAULT 0,
    start_date DATE,
    end_date DATE,
    wage_allocation NUMERIC(10, 2) NOT NULL DEFAULT 0,
    pm_allocation NUMERIC(10, 2) NOT NULL DEFAULT 0,
    material_allocation NUMERIC(10, 2) NOT NULL DEFAULT 0,
    misc_allocation NUMERIC(10, 2) NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'active'
);

-- Add index for faster lookups
CREATE INDEX idx_budgets_property_id ON propintel.budgets(property_id);
CREATE INDEX idx_budgets_user_id ON propintel.budgets(user_id);

-- Add comment to describe the table
COMMENT ON TABLE propintel.budgets IS 'Stores budget plans for properties'; 