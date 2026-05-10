FROM python:3.10-slim

WORKDIR /app

# Install network debugging tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY src/server/requirements.txt ./src/server/
RUN pip install --no-cache-dir -r ./src/server/requirements.txt

# Copy source code and entry point
COPY src/ ./src/
COPY run_server.py .
COPY certs/ /app/certs/

# PYTHONPATH should point to src/ for package resolution
ENV PYTHONPATH=/app/src

EXPOSE 3478 3479 8765

CMD ["python", "run_server.py"]