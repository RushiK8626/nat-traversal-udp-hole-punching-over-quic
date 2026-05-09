FROM python:3.10-slim

WORKDIR /app

# Install network debugging tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    iproute2 \
    curl \
    && rm -rf /var/lib/apt/lists/*

COPY server/requirements.txt ./server/
RUN pip install --no-cache-dir -r ./server/requirements.txt

COPY server/ ./server/
COPY certs/ /app/certs/
COPY common/ ./common/

ENV PYTHONPATH=/app

EXPOSE 3478 3479 8765

CMD ["python", "server/rendezvous.py"]