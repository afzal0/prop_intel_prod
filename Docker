# Use a base image that already has Python
FROM python:3.10-slim

# Create a directory in the container for your code
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt /app

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of your application code
COPY . /app

# Expose the port where Gunicorn will listen (e.g., 8000)
EXPOSE 8000

# Optional: if you have a db_config.ini or other config files, be sure you COPY them if needed
# COPY db_config.ini /app

# The command to run your app with Gunicorn
CMD ["gunicorn", "app:app", "--bind", "0.0.0.0:8000"]
