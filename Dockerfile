FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY republisher.py .

# HTTP status page
EXPOSE 8080

# non-root
USER 1000:1000

ENTRYPOINT ["python", "-u", "republisher.py"]
