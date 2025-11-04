# Use official Python slim image
FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies needed by Pillow (image libs)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg62-turbo-dev libpng-dev build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app source
COPY . .

# Expose port 5000
EXPOSE 5000

# Run the app with gunicorn (better for production than flask dev server)
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app", "--timeout", "120", "--workers", "1"]

