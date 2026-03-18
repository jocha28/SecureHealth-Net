# ============================================================
#  SecureHealth-Net — Dovecot (Serveur IMAP)
# ============================================================
FROM debian:bookworm-slim

LABEL maintainer="SecureHealth-Net"
LABEL description="Serveur IMAP Dovecot pour messagerie médicale sécurisée"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    dovecot-core \
    dovecot-imapd \
    dovecot-lmtpd \
    openssl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copier les fichiers de configuration
COPY config/ /etc/dovecot/conf.d/
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Ports IMAP
EXPOSE 143 993

ENTRYPOINT ["/entrypoint.sh"]
