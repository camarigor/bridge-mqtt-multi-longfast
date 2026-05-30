FROM python:3.12-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY republisher.py .
COPY entrypoint.sh /app/entrypoint.sh
RUN chmod +x /app/entrypoint.sh

# HTTP status page
EXPOSE 8080

# non-root
USER 1000:1000

# entrypoint optionally sources ${BRIDGE_ENV_FILE:-/data/bridge.env} then runs the app
ENTRYPOINT ["/app/entrypoint.sh"]
