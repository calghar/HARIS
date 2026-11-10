FROM python:3.13-alpine@sha256:1e1f6334529d1fb26a2ef619d7cffb30a7c7d7cc1cc7338ebee283a58d1aeaca
RUN adduser -S -u 10001 fixture
WORKDIR /app
COPY server.py .
USER fixture
EXPOSE 9090
HEALTHCHECK CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:9090/health', timeout=3)"]
CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "9090"]
