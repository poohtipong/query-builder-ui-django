# Use official Python image
FROM python:3.12-slim

# Install system libraries for mysqlclient
RUN apt-get update && apt-get install -y \
    build-essential \
    default-libmysqlclient-dev \
    pkg-config \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Python dependencies first (for caching)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy project files
COPY . .

# Collect static files
RUN python manage.py collectstatic --noinput

# Expose port (Railway autodetects, but optional)
EXPOSE 8000

# Run the Django app with Gunicorn
CMD ["gunicorn", "searchByQuery.wsgi:application", "--bind", "0.0.0.0:8000"]
