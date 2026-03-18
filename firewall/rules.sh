#!/bin/bash
# ============================================================
#  SecureHealth-Net — Règles de pare-feu iptables
#  Protection de l'infrastructure médicale
#
#  UTILISATION : sudo bash firewall/rules.sh
# ============================================================

set -e

RESEAU_INTERNE="172.20.0.0/24"
LOG_PREFIX="[SECUREHEALTH]"

echo "[$LOG_PREFIX] Application des règles de pare-feu..."

# ============================================================
# 1. RÉINITIALISATION — Supprimer toutes les règles existantes
# ============================================================
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X
iptables -t mangle -F
iptables -t mangle -X

# ============================================================
# 2. POLITIQUE PAR DÉFAUT — Tout bloquer, autoriser sélectivement
# ============================================================
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT

# ============================================================
# 3. AUTORISER LES CONNEXIONS ÉTABLIES (suivi d'état TCP)
#    Concept vu en cours : connexion tracking TCP
# ============================================================
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A INPUT -m conntrack --ctstate INVALID -j DROP

# ============================================================
# 4. AUTORISER LE LOOPBACK
# ============================================================
iptables -A INPUT -i lo -j ACCEPT

# ============================================================
# 5. RÈGLES SMTP — Serveur d'envoi de mails (Postfix)
# ============================================================
# Port 25 : uniquement depuis le réseau interne
iptables -A INPUT -p tcp --dport 25 -s $RESEAU_INTERNE \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# Port 587 : authentification SMTP (médecins → serveur)
iptables -A INPUT -p tcp --dport 587 -s $RESEAU_INTERNE \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# Bloquer SMTP depuis l'extérieur et logger la tentative
iptables -A INPUT -p tcp --dport 25 \
    -m limit --limit 5/min --limit-burst 10 \
    -j LOG --log-prefix "$LOG_PREFIX SMTP-EXTERNE-BLOQUE: " --log-level 4
iptables -A INPUT -p tcp --dport 25 -j DROP

# ============================================================
# 6. RÈGLES IMAP — Serveur de réception de mails (Dovecot)
# ============================================================
# Port 143 : IMAP depuis le réseau interne uniquement
iptables -A INPUT -p tcp --dport 143 -s $RESEAU_INTERNE \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# Port 993 : IMAPS (IMAP chiffré) depuis le réseau interne
iptables -A INPUT -p tcp --dport 993 -s $RESEAU_INTERNE \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# Bloquer IMAP depuis l'extérieur
iptables -A INPUT -p tcp -m multiport --dports 143,993 \
    -m limit --limit 5/min \
    -j LOG --log-prefix "$LOG_PREFIX IMAP-EXTERNE-BLOQUE: " --log-level 4
iptables -A INPUT -p tcp -m multiport --dports 143,993 -j DROP

# ============================================================
# 7. RÈGLES WEBMAIL — Interface Roundcube
# ============================================================
# Port 8080 : accès webmail depuis le réseau interne uniquement
iptables -A INPUT -p tcp --dport 8080 -s $RESEAU_INTERNE \
    -m conntrack --ctstate NEW \
    -j ACCEPT

iptables -A INPUT -p tcp --dport 8080 \
    -m limit --limit 3/min \
    -j LOG --log-prefix "$LOG_PREFIX WEBMAIL-EXTERNE-BLOQUE: " --log-level 4
iptables -A INPUT -p tcp --dport 8080 -j DROP

# ============================================================
# 8. PROTECTION CONTRE LES SCANS DE PORTS
#    Concept vu en cours : détection d'idle port scan
# ============================================================

# Bloquer les paquets TCP suspects (flags anormaux)
# Scan NULL (aucun flag)
iptables -A INPUT -p tcp --tcp-flags ALL NONE \
    -m limit --limit 3/min \
    -j LOG --log-prefix "$LOG_PREFIX SCAN-NULL: " --log-level 4
iptables -A INPUT -p tcp --tcp-flags ALL NONE -j DROP

# Scan XMAS (tous les flags allumés)
iptables -A INPUT -p tcp --tcp-flags ALL ALL \
    -m limit --limit 3/min \
    -j LOG --log-prefix "$LOG_PREFIX SCAN-XMAS: " --log-level 4
iptables -A INPUT -p tcp --tcp-flags ALL ALL -j DROP

# Scan FIN (seulement FIN)
iptables -A INPUT -p tcp --tcp-flags ALL FIN \
    -m limit --limit 3/min \
    -j LOG --log-prefix "$LOG_PREFIX SCAN-FIN: " --log-level 4
iptables -A INPUT -p tcp --tcp-flags ALL FIN -j DROP

# Protection brute-force SSH (si activé)
iptables -A INPUT -p tcp --dport 22 \
    -m conntrack --ctstate NEW \
    -m recent --set --name SSH_BRUTE
iptables -A INPUT -p tcp --dport 22 \
    -m conntrack --ctstate NEW \
    -m recent --update --seconds 60 --hitcount 5 --name SSH_BRUTE \
    -j LOG --log-prefix "$LOG_PREFIX BRUTE-FORCE-SSH: " --log-level 4
iptables -A INPUT -p tcp --dport 22 \
    -m conntrack --ctstate NEW \
    -m recent --update --seconds 60 --hitcount 5 --name SSH_BRUTE \
    -j DROP

# ============================================================
# 9. AUTORISER SSH (administration du serveur)
# ============================================================
iptables -A INPUT -p tcp --dport 22 -s $RESEAU_INTERNE \
    -m conntrack --ctstate NEW \
    -j ACCEPT

# ============================================================
# 10. LOGGER ET BLOQUER TOUT LE RESTE
# ============================================================
iptables -A INPUT \
    -m limit --limit 5/min --limit-burst 10 \
    -j LOG --log-prefix "$LOG_PREFIX TRAFIC-NON-AUTORISE: " --log-level 4
iptables -A INPUT -j DROP

echo "[$LOG_PREFIX] Règles de pare-feu appliquées avec succès."
echo ""
echo "Ports autorisés (réseau interne $RESEAU_INTERNE uniquement) :"
echo "  - 25   : SMTP (Postfix)"
echo "  - 587  : SMTP Submission (Postfix)"
echo "  - 143  : IMAP (Dovecot)"
echo "  - 993  : IMAPS (Dovecot)"
echo "  - 8080 : Webmail (Roundcube)"
echo "  - 22   : SSH (administration)"
echo ""
echo "Protections actives :"
echo "  - Suivi d'état TCP (ESTABLISHED/RELATED)"
echo "  - Blocage scans de ports (NULL, XMAS, FIN)"
echo "  - Protection brute-force SSH"
echo "  - Logging de tout trafic suspect"
