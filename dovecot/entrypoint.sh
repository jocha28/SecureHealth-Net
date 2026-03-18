#!/bin/bash
# ============================================================
#  Dovecot — Script de démarrage
#  SecureHealth-Net
# ============================================================

set -e

echo "[SecureHealth] Démarrage du serveur IMAP Dovecot..."

# Créer les dossiers de stockage des mails
mkdir -p /var/mail
chown -R mail:mail /var/mail

# Copier le fichier des utilisateurs si présent
if [ -f /etc/dovecot/conf.d/users.passwd ]; then
    cp /etc/dovecot/conf.d/users.passwd /etc/dovecot/users.passwd
    chmod 600 /etc/dovecot/users.passwd
fi

# Vérifier que le certificat TLS existe
if [ ! -f /etc/ssl/certs/securehealth/server.crt ]; then
    echo "[SecureHealth] En attente du certificat TLS (généré par Postfix)..."
    sleep 5
fi

echo "[SecureHealth] Dovecot prêt sur les ports 143 (IMAP) et 993 (IMAPS)"
exec /usr/sbin/dovecot -F
