FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    HF_HOME=/models \
    OMP_NUM_THREADS=2

WORKDIR /app
RUN pip install --no-cache-dir "fastembed>=0.7,<1"
COPY server.py /app/server.py

EXPOSE 8080
CMD ["python", "/app/server.py"]
