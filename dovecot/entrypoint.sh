#!/bin/bash
# ============================================================
#  Dovecot — Script de démarrage
#  SecureHealth-Net
# ============================================================

set -e

echo "[SecureHealth] Démarrage du serveur IMAP Dovecot..."

# Nettoyer les sockets résiduels (évite les crashs au redémarrage)
rm -f /var/run/dovecot/auth-* /var/run/dovecot/*.pid

# Créer les dossiers de stockage des mails
mkdir -p /var/mail
chown -R mail:mail /var/mail

# Vérifier que le certificat TLS existe
if [ ! -f /etc/ssl/certs/securehealth/server.crt ]; then
    echo "[SecureHealth] En attente du certificat TLS (généré par Postfix)..."
    sleep 5
fi

echo "[SecureHealth] Dovecot prêt sur les ports 143 (IMAP) et 993 (IMAPS)"
exec /usr/sbin/dovecot -F
