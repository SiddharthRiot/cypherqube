# ─── Build stage ──────────────────────────────────────────────────────────────
FROM python:3.13-slim AS base

# python:3.13-slim is based on Debian Bookworm which ships OpenSSL 3.x
# Install the OpenSSL CLI tool so `openssl version` works inside the container
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy and install Python dependencies first (layer-cache friendly)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# ─── Runtime ──────────────────────────────────────────────────────────────────
EXPOSE 8501

# Health-check: confirm Streamlit is reachable
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8501/_stcore/health')" || exit 1

# Default: launch the Streamlit dashboard
CMD ["python", "-m", "streamlit", "run", "app.py", \
     "--server.port=8501", "--server.address=0.0.0.0"]
