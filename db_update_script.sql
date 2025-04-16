-- Property Intel Database Update Script
-- Script to perform common database updates and maintenance

-- Add upload_date to documents table if it doesn't exist
DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_schema = 'propintel' 
        AND table_name = 'documents' 
        AND column_name = 'upload_date'
    ) THEN
        ALTER TABLE propintel.documents ADD COLUMN upload_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    END IF;
END
$$;

-- Make address, latitude, longitude nullable in documents table
DO $$
BEGIN
    -- Check if columns exist first
    IF EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_schema = 'propintel' 
        AND table_name = 'documents' 
        AND column_name = 'address'
    ) THEN
        -- Alter columns to be nullable
        ALTER TABLE propintel.documents ALTER COLUMN address DROP NOT NULL;
    END IF;
    
    IF EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_schema = 'propintel' 
        AND table_name = 'documents' 
        AND column_name = 'latitude'
    ) THEN
        ALTER TABLE propintel.documents ALTER COLUMN latitude DROP NOT NULL;
    END IF;
    
    IF EXISTS (
        SELECT 1 
        FROM information_schema.columns 
        WHERE table_schema = 'propintel' 
        AND table_name = 'documents' 
        AND column_name = 'longitude'
    ) THEN
        ALTER TABLE propintel.documents ALTER COLUMN longitude DROP NOT NULL;
    END IF;
END
$$;