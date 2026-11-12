FROM python:3.13-slim@sha256:e48f59cdba69a3cbd9ed2cf0f348d90d45a8d350d98134cf1070bc106ee9ed90

ENV PYTHONDONTWRITEBYTECODE=1
COPY tunnel.py /opt/tunnel.py
RUN chmod 644 /opt/tunnel.py && mkdir -p /work && chown 65534:65534 /work
USER 65534:65534
