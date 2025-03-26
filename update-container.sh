#!/bin/bash

# Stop and remove existing containers
echo "Stopping existing containers..."
docker-compose down

# Remove old images (optional, comment out if you want to keep them)
echo "Removing old images..."
docker rmi propintel-app:latest

# Build and start new containers
echo "Building and starting updated containers..."
docker-compose up -d --build

# Wait for database to be ready
echo "Waiting for database to initialize..."
sleep 10

# Apply schema to database (in case the init script didn't run)
echo "Ensuring database schema is up to date..."
docker-compose exec db psql -U postgres -d propintel -f /docker-entrypoint-initdb.d/1-schema.sql

echo "Container update complete!"
echo "PropIntel is running at http://localhost:5000"
echo "Login with username: admin, password: admin123"