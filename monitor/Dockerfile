# ============================================================
#  SecureHealth-Net — Moniteur réseau
# ============================================================
FROM python:3.11-slim

LABEL maintainer="SecureHealth-Net"
LABEL description="Surveillance réseau et détection d'intrusions"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    tcpdump \
    net-tools \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir scapy==2.5.0

WORKDIR /app
COPY . /app/

RUN mkdir -p /app/logs

CMD ["python", "port_scan_detector.py"]
