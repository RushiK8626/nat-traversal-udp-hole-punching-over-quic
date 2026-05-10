FROM python:3.10-slim

WORKDIR /app

COPY src/peer/requirements.txt ./src/peer/
RUN pip install --no-cache-dir -r ./src/peer/requirements.txt

# Copy source code and entry point
COPY src/ ./src/
COPY run_peer.py .
COPY certs/ /app/certs/

# PYTHONPATH should point to src/ for package resolution
ENV PYTHONPATH=/app/src

EXPOSE 3478 3479 8765 9090

CMD ["python", "run_peer.py"]