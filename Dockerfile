# The backend (FastAPI + uvicorn). Built by docker-compose.yml, see DEPLOYMENT.md.
FROM python:3.12.15-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY backend ./backend

# Run as a normal user. /data holds the SQLite database (a Docker volume).
RUN useradd --system --no-create-home sentinel && mkdir /data && chown sentinel /data
USER sentinel

EXPOSE 8000
# --proxy-headers: take the client IP and https scheme from cloudflared's X-Forwarded-* headers.
# "*" is safe here because only containers on the compose network can reach port 8000.
CMD ["uvicorn", "backend.app:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers", "--forwarded-allow-ips", "*"]
