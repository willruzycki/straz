FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Expose ports
EXPOSE 5000 6000

# Create necessary directories
RUN mkdir -p wallets

# Set environment variables
ENV PYTHONUNBUFFERED=1

# Run the application
CMD ["python", "api.py"] 