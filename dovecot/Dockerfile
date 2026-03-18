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
COPY config/dovecot.conf /etc/dovecot/dovecot.conf
COPY config/10-mail.conf /etc/dovecot/conf.d/10-mail.conf
COPY config/10-auth.conf /etc/dovecot/conf.d/10-auth.conf
COPY config/10-ssl.conf /etc/dovecot/conf.d/10-ssl.conf
COPY config/users.passwd /etc/dovecot/users.passwd
RUN chown root:dovecot /etc/dovecot/users.passwd && chmod 640 /etc/dovecot/users.passwd
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Ports IMAP
EXPOSE 143 993

ENTRYPOINT ["/entrypoint.sh"]
