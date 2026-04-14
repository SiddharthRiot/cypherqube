# CypherQube — Python 3.13 + OpenSSL 3.x
FROM python:3.13-slim-bookworm

# Bookworm ships OpenSSL 3.x by default — verify at build time
#RUN openssl version | grep -E "^OpenSSL 3\." || (echo "ERROR: OpenSSL 3.x required" && exit 1)

# System deps: OpenSSL headers, build tools (for any compiled wheels)
RUN apt-get update && apt-get install -y --no-install-recommends \
    openssl \
    libssl-dev \
    libffi-dev \
    gcc \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies first (layer caching)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
 && pip install --no-cache-dir -r requirements.txt

# Copy project
COPY . .

# Expose Streamlit default port
EXPOSE 8501

# Health check — Streamlit responds on /_stcore/health
HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8501/_stcore/health || exit 1

# Default: run the Streamlit app
CMD ["streamlit", "run", "app.py"]