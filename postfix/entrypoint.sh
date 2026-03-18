#!/bin/bash
# ============================================================
#  Postfix — Script de démarrage
#  SecureHealth-Net
# ============================================================

set -e

echo "[SecureHealth] Démarrage du serveur SMTP Postfix..."

# Générer un certificat TLS auto-signé si absent
if [ ! -f /etc/ssl/certs/securehealth/server.crt ]; then
    echo "[SecureHealth] Génération du certificat TLS auto-signé..."
    mkdir -p /etc/ssl/certs/securehealth
    openssl req -new -x509 -days 3650 -nodes \
        -out /etc/ssl/certs/securehealth/server.crt \
        -keyout /etc/ssl/certs/securehealth/server.key \
        -subj "/C=BJ/ST=Littoral/L=Cotonou/O=SecureHealth-Net/CN=mail.securehealth.local"
    echo "[SecureHealth] Certificat TLS généré."
fi

# Appliquer les variables d'environnement à la configuration
postconf -e "myhostname=${MAIL_HOSTNAME:-mail.securehealth.local}"
postconf -e "mydomain=${MAIL_DOMAIN:-securehealth.local}"

# Créer les dossiers nécessaires
mkdir -p /var/spool/postfix/private
mkdir -p /var/mail

# Démarrer Postfix au premier plan
echo "[SecureHealth] Postfix prêt sur les ports 25 (SMTP) et 587 (Submission)"
exec /usr/sbin/postfix start-fg
