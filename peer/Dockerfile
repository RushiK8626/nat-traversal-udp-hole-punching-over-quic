FROM python:3.10-slim

WORKDIR /app

COPY peer/requirements.txt ./peer/
COPY common/ ./common/
RUN pip install --no-cache-dir -r ./peer/requirements.txt

COPY peer/ ./peer/
COPY certs/ /app/certs/

ENV PYTHONPATH=/app

EXPOSE 3478 3479 8765 9090

CMD ["python", "peer/main.py"]