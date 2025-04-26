# Use an official Python image
FROM python:3.13-slim

# Set work directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libgl1-mesa-glx \
    libglib2.0-0 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy app files
COPY ./app /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt