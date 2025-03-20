#!/bin/bash
# Property Intelligence Local Environment Setup Script

# Text colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}====================================================================${NC}"
echo -e "${BLUE}       Property Intelligence Local Environment Setup Script         ${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo

# Check if Python is installed
echo -e "${YELLOW}Checking for Python...${NC}"
if command -v python3 &>/dev/null; then
    PYTHON="python3"
    echo -e "${GREEN}Python 3 is installed.${NC}"
elif command -v python &>/dev/null; then
    PYTHON="python"
    echo -e "${GREEN}Python is installed.${NC}"
else
    echo -e "${RED}Python is not installed. Please install Python 3.6+ to continue.${NC}"
    exit 1
fi

# Check Python version
PY_VERSION=$($PYTHON --version 2>&1 | cut -d' ' -f2)
echo -e "${GREEN}Python version: $PY_VERSION${NC}"

# Make sure pip is installed
echo -e "${YELLOW}Checking for pip...${NC}"
if ! command -v pip &>/dev/null && ! command -v pip3 &>/dev/null; then
    echo -e "${RED}pip is not installed. Please install pip to continue.${NC}"
    exit 1
else
    if command -v pip3 &>/dev/null; then
        PIP="pip3"
    else
        PIP="pip"
    fi
    echo -e "${GREEN}pip is installed.${NC}"
fi

# Check if docker is installed
echo -e "${YELLOW}Checking for Docker...${NC}"
if command -v docker &>/dev/null; then
    DOCKER_AVAILABLE=true
    echo -e "${GREEN}Docker is installed.${NC}"
else
    DOCKER_AVAILABLE=false
    echo -e "${YELLOW}Docker is not installed. Some features may not be available.${NC}"
fi

# Check if docker-compose is installed
echo -e "${YELLOW}Checking for Docker Compose...${NC}"
if command -v docker-compose &>/dev/null; then
    DOCKER_COMPOSE_AVAILABLE=true
    echo -e "${GREEN}Docker Compose is installed.${NC}"
else
    DOCKER_COMPOSE_AVAILABLE=false
    echo -e "${YELLOW}Docker Compose is not installed. Some features may not be available.${NC}"
fi

# Check which directory we're in
echo -e "${YELLOW}Checking current directory...${NC}"
if [ -f "app.py" ]; then
    echo -e "${GREEN}Found app.py in current directory.${NC}"
else
    echo -e "${RED}app.py not found in current directory.${NC}"
    echo -e "${YELLOW}Please run this script from the root of your project.${NC}"
    exit 1
fi

# Create virtual environment
echo -e "${YELLOW}Setting up virtual environment...${NC}"
if [ -d "venv" ]; then
    echo -e "${YELLOW}Virtual environment already exists. Skipping creation.${NC}"
else
    $PYTHON -m venv venv
    echo -e "${GREEN}Created virtual environment.${NC}"
fi

# Activate virtual environment
echo -e "${YELLOW}Activating virtual environment...${NC}"
if [ -f "venv/bin/activate" ]; then
    source venv/bin/activate
elif [ -f "venv/Scripts/activate" ]; then
    source venv/Scripts/activate
else
    echo -e "${RED}Could not find activation script. Something went wrong.${NC}"
    exit 1
fi
echo -e "${GREEN}Virtual environment activated.${NC}"

# Install dependencies
echo -e "${YELLOW}Installing dependencies...${NC}"
if [ -f "requirements.txt" ]; then
    $PIP install -r requirements.txt
    echo -e "${GREEN}Installed dependencies from requirements.txt.${NC}"
else
    echo -e "${RED}requirements.txt not found.${NC}"
    echo -e "${YELLOW}Installing minimal requirements for Flask...${NC}"
    $PIP install flask gunicorn psycopg2-binary
    $PIP freeze > requirements.txt
    echo -e "${GREEN}Created requirements.txt with minimal Flask dependencies.${NC}"
fi

# Create necessary directories
echo -e "${YELLOW}Creating necessary directories...${NC}"
mkdir -p templates static uploads
echo -e "${GREEN}Created directories: templates, static, uploads.${NC}"

# Create a basic configuration file for local development
echo -e "${YELLOW}Creating local database configuration...${NC}"
if [ ! -f "db_config.ini" ]; then
    echo "[database]" > db_config.ini
    echo "user = postgres" >> db_config.ini
    echo "password = postgres" >> db_config.ini
    echo "host = localhost" >> db_config.ini
    echo "port = 5432" >> db_config.ini
    echo "database = postgres" >> db_config.ini
    echo -e "${GREEN}Created db_config.ini file.${NC}"
else
    echo -e "${YELLOW}db_config.ini already exists. Skipping creation.${NC}"
fi

# Check if Docker is available to run PostgreSQL
if [ "$DOCKER_AVAILABLE" = true ]; then
    echo -e "${YELLOW}Setting up PostgreSQL using Docker...${NC}"
    
    # Check if PostgreSQL container is already running
    POSTGRES_RUNNING=$(docker ps --filter "name=propintel-postgres" --format "{{.Names}}")
    
    if [ -z "$POSTGRES_RUNNING" ]; then
        # Run PostgreSQL container
        echo -e "${GREEN}Starting PostgreSQL container...${NC}"
        docker run --name propintel-postgres \
            -e POSTGRES_USER=postgres \
            -e POSTGRES_PASSWORD=postgres \
            -e POSTGRES_DB=postgres \
            -p 5432:5432 \
            -d postgres:14

        # Wait for PostgreSQL to start
        echo -e "${YELLOW}Waiting for PostgreSQL to start...${NC}"
        sleep 5
        
        # Initialize database schema
        if [ -f "init_db.sql" ]; then
            echo -e "${GREEN}Initializing database schema...${NC}"
            docker exec -i propintel-postgres psql -U postgres < init_db.sql
        else
            echo -e "${YELLOW}init_db.sql not found. Creating a basic one...${NC}"
            cat > init_db.sql << EOL
-- Create schema
CREATE SCHEMA IF NOT EXISTS propintel;

-- Create tables
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

-- Insert a sample property
INSERT INTO propintel.properties (property_name, address, latitude, longitude)
VALUES ('Sample Property', '123 Test Street, Melbourne, Australia', -37.8136, 144.9631);
EOL
            echo -e "${GREEN}Created init_db.sql file.${NC}"
            docker exec -i propintel-postgres psql -U postgres < init_db.sql
        fi
        
        echo -e "${GREEN}PostgreSQL container is running.${NC}"
    else
        echo -e "${GREEN}PostgreSQL container is already running.${NC}"
    fi
else
    echo -e "${YELLOW}Docker not available. Skipping PostgreSQL setup.${NC}"
    echo -e "${YELLOW}Please ensure you have a PostgreSQL server running and update db_config.ini accordingly.${NC}"
fi

# Create sample run script
echo -e "${YELLOW}Creating run script...${NC}"
if [ ! -f "run_local.sh" ]; then
    cat > run_local.sh << EOL
#!/bin/bash
source venv/bin/activate 2>/dev/null || source venv/Scripts/activate 2>/dev/null
export FLASK_APP=app.py
export FLASK_ENV=development
export PORT=5000

echo "Starting Flask development server on port 5000..."
flask run --host=0.0.0.0 --port=5000
EOL
    chmod +x run_local.sh
    echo -e "${GREEN}Created run_local.sh script.${NC}"
else
    echo -e "${YELLOW}run_local.sh already exists. Skipping creation.${NC}"
fi

# Create run script for Windows
if [ ! -f "run_local.bat" ]; then
    cat > run_local.bat << EOL
@echo off
call venv\Scripts\activate.bat
set FLASK_APP=app.py
set FLASK_ENV=development
set PORT=5000

echo Starting Flask development server on port 5000...
flask run --host=0.0.0.0 --port=5000
EOL
    echo -e "${GREEN}Created run_local.bat script for Windows.${NC}"
fi

# Create Docker environment if Docker is available
if [ "$DOCKER_AVAILABLE" = true ] && [ ! -f "Dockerfile" ]; then
    echo -e "${YELLOW}Creating Docker environment...${NC}"
    
    # Create Dockerfile
    cat > Dockerfile << EOL
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p templates static uploads

# Copy application code
COPY . .

# Set environment variables
ENV FLASK_ENV=production
ENV PORT=8000

# Make sure uploads directory is writable
RUN chmod 777 uploads

# Expose the port the app runs on
EXPOSE 8000

# Command to run the application
CMD gunicorn --bind 0.0.0.0:\$PORT app:app
EOL
    
    # Create docker-compose.yml if Docker Compose is available
    if [ "$DOCKER_COMPOSE_AVAILABLE" = true ]; then
        cat > docker-compose.yml << EOL
version: '3'

services:
  # Web application
  web:
    build:
      context: .
      dockerfile: Dockerfile
    ports:
      - "8000:8000"
    environment:
      - FLASK_ENV=production
      - PORT=8000
      - SECRET_KEY=dev_secret_key_change_in_production
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/postgres
    depends_on:
      - db
    volumes:
      - ./uploads:/app/uploads
    restart: always
    command: gunicorn --bind 0.0.0.0:8000 app:app

  # PostgreSQL database
  db:
    image: postgres:14
    environment:
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
      - POSTGRES_DB=postgres
    ports:
      - "5432:5432"
    volumes:
      - postgres_data:/var/lib/postgresql/data
      - ./init_db.sql:/docker-entrypoint-initdb.d/init_db.sql
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 5s
      retries: 5

volumes:
  postgres_data:
EOL
        echo -e "${GREEN}Created docker-compose.yml file.${NC}"
        
        # Create Docker run script
        cat > run_docker.sh << EOL
#!/bin/bash
echo "Starting application using Docker Compose..."
docker-compose up --build
EOL
        chmod +x run_docker.sh
        echo -e "${GREEN}Created run_docker.sh script.${NC}"
    fi
    
    echo -e "${GREEN}Docker environment created.${NC}"
fi

# Run the diagnostics script
echo -e "${YELLOW}Running diagnostics...${NC}"
$PYTHON app_diagnostic.py

echo -e "${BLUE}====================================================================${NC}"
echo -e "${GREEN}Setup complete!${NC}"
echo -e "${BLUE}====================================================================${NC}"
echo -e "${YELLOW}You can now run your application using:${NC}"
echo -e "${GREEN}./run_local.sh${NC}  (Linux/macOS)"
echo -e "${GREEN}run_local.bat${NC}  (Windows)"

if [ "$DOCKER_COMPOSE_AVAILABLE" = true ]; then
    echo -e "${YELLOW}Or using Docker Compose:${NC}"
    echo -e "${GREEN}./run_docker.sh${NC}"
    echo -e "${GREEN}docker-compose up --build${NC}"
fi

echo
echo -e "${YELLOW}Your application will be available at:${NC}"
echo -e "${GREEN}http://localhost:5000${NC}  (local development)"
if [ "$DOCKER_COMPOSE_AVAILABLE" = true ]; then
    echo -e "${GREEN}http://localhost:8000${NC}  (Docker)"
fi

echo
echo -e "${BLUE}====================================================================${NC}"