# ============================================================
#  SecureHealth-Net — Postfix (Serveur SMTP)
# ============================================================
FROM debian:bookworm-slim

LABEL maintainer="SecureHealth-Net"
LABEL description="Serveur SMTP Postfix pour messagerie médicale sécurisée"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    postfix \
    postfix-mysql \
    sasl2-bin \
    libsasl2-modules \
    ca-certificates \
    openssl \
    mailutils \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers de configuration
COPY config/ /etc/postfix/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Ports SMTP
EXPOSE 25 587

ENTRYPOINT ["/entrypoint.sh"]
