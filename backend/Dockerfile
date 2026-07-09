FROM python:3.11-slim

# System deps for Scapy + psycopg2
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    libpq-dev \
    gcc \
    iproute2 \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Non-root user for security (note: packet capture still needs CAP_NET_RAW from compose)
RUN useradd -m -u 1000 dtacir && chown -R dtacir:dtacir /app
USER dtacir

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1"]
