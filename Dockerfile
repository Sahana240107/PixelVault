# -----------------------------------------------------
# Secure Dockerfile for PixelVault
# -----------------------------------------------------
FROM python:3.11-slim

# Prevent Python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1

# Create a non-root user and switch to it
RUN adduser --disabled-password --gecos "" appuser

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Install dependencies safely
RUN pip install --no-cache-dir -r requirements.txt

# Change ownership to non-root user
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port and run Flask app
EXPOSE 5000
CMD ["python", "app.py"]
