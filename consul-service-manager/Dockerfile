FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY dns-failover-service-manager.py .
USER nobody
CMD ["python", "-u", "dns-failover-service-manager.py"]
