# ============================================================
#  SecureHealth-Net — Roundcube (Webmail)
# ============================================================
FROM roundcube/roundcubemail:latest-apache

LABEL maintainer="SecureHealth-Net"
LABEL description="Webmail Roundcube pour le personnel médical"

# Copier la configuration personnalisée
COPY config/config.inc.php /var/roundcube/config/config.inc.php

EXPOSE 80
