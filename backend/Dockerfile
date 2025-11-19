FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    curl \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for running services
RUN groupadd -r appuser && useradd -r -g appuser -u 1000 appuser

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p /app/logs

# Change ownership of app directory
RUN chown -R appuser:appuser /app

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Default command (can be overridden in docker-compose)
# CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
CMD ["sh", "-c", "\
if [ \"$WORKER_TYPE\" = 'domain_worker' ]; then \
    celery -A app.core.celery_app worker -Q domain_verification_queue --loglevel=info --concurrency=2 -n domain_worker@%h -E; \
elif [ \"$WORKER_TYPE\" = 'scan_worker' ]; then \
    celery -A app.core.celery_app worker -Q scan_queue --loglevel=info --concurrency=3 -n scan_worker@%h -E; \
elif [ \"$WORKER_TYPE\" = 'beat' ]; then \
    celery -A app.core.celery_app beat --loglevel=info; \
else \
    uvicorn app.main:app --host 0.0.0.0 --port 8000; \
fi"]
