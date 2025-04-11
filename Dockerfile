FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ssh_switch_manager.py .
COPY app/credential_manager.py .
COPY app/encrypted_db_manager.py .
COPY app/netmapper.py .

# Create data and config directories
RUN mkdir -p /app/data /app/config

# Set entrypoint
ENTRYPOINT ["python", "netmapper.py"]

# Default command (can be overridden)
CMD ["--help"]
