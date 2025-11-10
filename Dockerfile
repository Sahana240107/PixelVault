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
# Install Pillow dependencies (image libraries)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libjpeg-dev zlib1g-dev && \
    rm -rf /var/lib/apt/lists/*

# If you have a requirements.txt, use it:
# RUN pip install --no-cache-dir -r requirements.txt
# Otherwise, install Flask + Pillow manually:
RUN pip install --no-cache-dir flask pillow

# ==========================
#  STEP 5: Expose Port
# ==========================
EXPOSE 5000

# ==========================
#  STEP 6: Run the App
# ==========================
CMD ["python", "app.py"]
