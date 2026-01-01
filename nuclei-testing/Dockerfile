FROM python:3.11-slim

# Install dependencies
RUN apt-get update && \
    apt-get install -y wget git && \
    rm -rf /var/lib/apt/lists/*

# Install Go for Nuclei
RUN wget https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

ENV PATH="/usr/local/go/bin:${PATH}"
ENV GOPATH="/root/go"
ENV PATH="${GOPATH}/bin:${PATH}"

# Install Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest && \
    nuclei -update-templates

# Install Python dependencies
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy API server
COPY nuclei_api.py .
COPY nuclei_server.py .

# Expose HTTP port for JSON-RPC compatibility
EXPOSE 9014

CMD ["uvicorn", "nuclei_api:app", "--host", "0.0.0.0", "--port", "9014"]
