FROM python:3.11-slim

# Prevent Python from buffering stdout/stderr
ENV PYTHONUNBUFFERED=1

# ==========================
#  STEP 2: Set Working Directory
# ==========================
WORKDIR /app

# ==========================
#  STEP 3: Copy Files
# ==========================
COPY . .

# ==========================
#  STEP 4: Install Dependencies
# ==========================
# Combine all RUN instructions to reduce image layers
RUN apt-get update && \
    apt-get install -y --no-install-recommends libjpeg-dev zlib1g-dev && \
    pip install --no-cache-dir flask pillow && \
    rm -rf /var/lib/apt/lists/*

# ==========================
#  STEP 5: Expose Port
# ==========================
EXPOSE 5000

# ==========================
#  STEP 6: Run the App
# ==========================
CMD ["python", "app.py"]
