FROM python:3.11-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y wget unzip chromium chromium-driver && \
    rm -rf /var/lib/apt/lists/*

# Install Katana from GitHub releases (pre-built binary)
# Using v1.0.5 (stable release compatible with most systems)
RUN wget https://github.com/projectdiscovery/katana/releases/download/v1.0.5/katana_1.0.5_linux_amd64.zip && \
    unzip katana_1.0.5_linux_amd64.zip && \
    mv katana /usr/local/bin/katana && \
    chmod +x /usr/local/bin/katana && \
    rm katana_1.0.5_linux_amd64.zip README.md LICENSE.md

# Verify installation
RUN katana -version

# Install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy API server
COPY katana_api.py .
COPY katana_server.py .

# Expose HTTP port for JSON-RPC compatibility
EXPOSE 9015

CMD ["uvicorn", "katana_api:app", "--host", "0.0.0.0", "--port", "9015"]
