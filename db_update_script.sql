-- Property Intel Database Update Script
-- Script to perform common database updates and maintenance

-- Update property status for inactive listings
UPDATE properties
SET status = 'inactive'
WHERE last_updated < NOW() - INTERVAL '90 days';

-- Add index to improve query performance
CREATE INDEX IF NOT EXISTS idx_property_location ON properties(city, state);

-- Update property values based on recent comparable sales
UPDATE properties
SET estimated_value = estimated_value * 1.05
WHERE city IN ('Boston', 'Cambridge') AND property_type = 'residential';

-- Clean up orphaned records
DELETE FROM property_images
WHERE property_id NOT IN (SELECT id FROM properties);

-- Add new field for energy efficiency rating (if it doesn't exist)
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='properties' AND column_name='energy_rating') THEN
        ALTER TABLE properties ADD COLUMN energy_rating VARCHAR(10);
    END IF;
END $$;

-- Optimize database by analyzing tables
ANALYZE properties;
ANALYZE users;
ANALYZE transactions;

-- Add audit timestamps if they don't exist
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns 
                   WHERE table_name='properties' AND column_name='updated_at') THEN
        ALTER TABLE properties ADD COLUMN updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP;
    END IF;
END $$;

-- Example of how to safely add a new table if needed
CREATE TABLE IF NOT EXISTS property_analytics (
    id SERIAL PRIMARY KEY,
    property_id INTEGER REFERENCES properties(id),
    view_count INTEGER DEFAULT 0,
    search_impressions INTEGER DEFAULT 0,
    last_viewed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Grant appropriate permissions
GRANT SELECT, INSERT, UPDATE ON property_analytics TO current_user;