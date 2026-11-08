FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90
RUN useradd --system --uid 10001 fixture
WORKDIR /app
COPY server.py .
USER fixture
EXPOSE 8080
HEALTHCHECK CMD ["python", "-c", "import urllib.request as u; u.urlopen('http://127.0.0.1:8080/healthz', timeout=3)"]
CMD ["python", "server.py", "--host", "0.0.0.0", "--port", "8080"]
