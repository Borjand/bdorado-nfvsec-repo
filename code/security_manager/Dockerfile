FROM python:3.11-slim

WORKDIR /app

RUN pip install fastapi kafka-python uvicorn cryptography

COPY main.py ./

# Copy keys (fixed for experimentation)
COPY keys/ /app/keys/
RUN chmod -R 444 /app/keys

ENV KEYS_DIR=/app/keys

ENV BROKER_ADDRESS=kafka:9092

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
