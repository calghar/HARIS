FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1
COPY tunnel.py /opt/tunnel.py
RUN chmod 644 /opt/tunnel.py && mkdir -p /work && chown 65534:65534 /work
USER 65534:65534
