FROM python:3.13-slim
RUN apt-get update && apt-get install -y --no-install-recommends iputils-ping \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
RUN pip install --no-cache-dir "requests>=2.34" "PyYAML>=6.0.3"
COPY dns-failover-service-manager.py .
USER nobody
CMD ["python", "-u", "dns-failover-service-manager.py"]
