-- Add expense_category field to money_out table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_schema = 'propintel' 
        AND table_name = 'money_out' 
        AND column_name = 'expense_category'
    ) THEN
        ALTER TABLE propintel.money_out ADD COLUMN expense_category VARCHAR(50);
    END IF;
END
$$;

-- Add expense_type field to work table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_schema = 'propintel' 
        AND table_name = 'work' 
        AND column_name = 'expense_type'
    ) THEN
        ALTER TABLE propintel.work ADD COLUMN expense_type VARCHAR(50);
    END IF;
END
$$;

-- Add project_manager field to properties table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_schema = 'propintel' 
        AND table_name = 'properties' 
        AND column_name = 'project_manager'
    ) THEN
        ALTER TABLE propintel.properties ADD COLUMN project_manager VARCHAR(100);
    END IF;
END
$$;

-- Create property_images table if it doesn't exist
CREATE TABLE IF NOT EXISTS propintel.property_images (
    image_id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES propintel.properties(property_id),
    user_id INTEGER REFERENCES propintel.users(user_id),
    image_path VARCHAR(255) NOT NULL,
    image_type VARCHAR(50) DEFAULT 'property', -- 'property', 'work', 'receipt'
    description TEXT,
    upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Update expense categories on existing records
UPDATE propintel.money_out
SET expense_category = 
    CASE 
        WHEN expense_details ILIKE '%wage%' OR expense_details ILIKE '%salary%' THEN 'wage'
        WHEN expense_details ILIKE '%project manager%' OR expense_details ILIKE '%pm %' THEN 'project_manager'
        WHEN expense_details ILIKE '%material%' OR expense_details ILIKE '%supplies%' THEN 'material'
        ELSE 'miscellaneous'
    END
WHERE expense_category IS NULL;

-- Update expense types on existing work records
UPDATE propintel.work
SET expense_type = 
    CASE 
        WHEN work_description ILIKE '%wage%' OR work_description ILIKE '%salary%' THEN 'wage'
        WHEN work_description ILIKE '%project manager%' OR work_description ILIKE '%pm %' THEN 'project_manager'
        WHEN work_description ILIKE '%material%' OR work_description ILIKE '%supplies%' THEN 'material'
        ELSE 'miscellaneous'
    END
WHERE expense_type IS NULL;

-- Add required columns to documents table if they don't exist
DO $$
BEGIN
    -- Add upload_date column if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_schema = 'propintel' 
        AND table_name = 'documents' 
        AND column_name = 'upload_date'
    ) THEN
        ALTER TABLE propintel.documents ADD COLUMN upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    END IF;

    -- Remove address, latitude, longitude columns constraint if they exist
    ALTER TABLE propintel.documents 
    ALTER COLUMN address DROP NOT NULL,
    ALTER COLUMN latitude DROP NOT NULL,
    ALTER COLUMN longitude DROP NOT NULL;
    
EXCEPTION WHEN undefined_column THEN
    -- It's okay if columns don't exist, just continue
END;
$$;

-- Create trigger function to auto-generate expense from work if it doesn't exist
CREATE OR REPLACE FUNCTION create_expense_from_work()
RETURNS TRIGGER AS $$
BEGIN
    INSERT INTO propintel.money_out
    (property_id, user_id, expense_details, expense_date, expense_amount, payment_method, expense_category)
    VALUES
    (NEW.property_id, NEW.user_id, NEW.work_description, NEW.work_date, NEW.work_cost, NEW.payment_method, NEW.expense_type);
    
    RETURN NULL;
END;
$$ LANGUAGE plpgsql;

-- Create trigger on work table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_trigger WHERE tgname = 'create_expense_on_work_insert'
    ) THEN
        CREATE TRIGGER create_expense_on_work_insert
        AFTER INSERT ON propintel.work
        FOR EACH ROW
        EXECUTE FUNCTION create_expense_from_work();
    END IF;
END
$$;