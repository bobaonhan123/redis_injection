FROM python:3.12-slim

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends redis-tools \
    && rm -rf /var/lib/apt/lists/*

COPY scheduler.py .

CMD ["python", "scheduler.py"]
