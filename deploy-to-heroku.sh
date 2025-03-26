#!/bin/bash

# Deploy PropIntel to Heroku using container deployment

# Instructions:
# 1. Make sure you're logged in to Heroku CLI (heroku login)
# 2. Create a Heroku app if you don't have one (heroku create your-app-name)
# 3. Make sure you have Heroku PostgreSQL addon (heroku addons:create heroku-postgresql:hobby-dev)
# 4. Run this script

# Exit on error
set -e

# Variables (change these)
HEROKU_APP_NAME="prop-intelv2"

# Check if Heroku CLI is installed
if ! command -v heroku &> /dev/null; then
  echo "Heroku CLI is not installed. Please install it first: https://devcenter.heroku.com/articles/heroku-cli"
  exit 1
fi

# Check if Docker is running
if ! docker info &> /dev/null; then
  echo "Docker is not running. Please start Docker first."
  exit 1
fi

# Confirm Heroku login
echo "Checking Heroku login status..."
heroku whoami || (echo "Please login to Heroku first using: heroku login" && exit 1)

# Create heroku.yml for container deployment
cat > heroku.yml << EOL
build:
  docker:
    web: Dockerfile
EOL

# Modify Dockerfile for Heroku
# We need to use the PORT environment variable provided by Heroku
cp Dockerfile Dockerfile.bak
cat > Dockerfile << EOL
FROM python:3.9-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \\
    gcc \\
    postgresql-client \\
    libpq-dev \\
    && apt-get clean \\
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create necessary directories
RUN mkdir -p uploads static

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Run the application using the PORT environment variable assigned by Heroku
CMD gunicorn --bind 0.0.0.0:\$PORT app:app
EOL

# Set the stack to container
echo "Setting Heroku stack to container..."
heroku stack:set container -a $HEROKU_APP_NAME

# Initialize a git repo if not already
if [ ! -d .git ]; then
  git init
  git add .
  git commit -m "Initial commit for Heroku deployment"
fi

# Create/check Heroku git remote
if ! git remote | grep heroku > /dev/null; then
  heroku git:remote -a $HEROKU_APP_NAME
fi

# Push to Heroku
echo "Pushing to Heroku (this may take some time)..."
git add .
git commit -m "Deploying to Heroku with Container" || true
git push heroku master || git push heroku main

# Apply database schema
echo "Applying database schema to Heroku PostgreSQL..."
cat schema.sql | heroku pg:psql -a $HEROKU_APP_NAME

echo "Deployment complete!"
echo "Your app should be running at: https://$HEROKU_APP_NAME.herokuapp.com"