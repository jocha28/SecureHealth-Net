#!/bin/bash
# ============================================================
#  SecureHealth-Net — Script d'alertes pare-feu (HÔTE)
#
#  Compagnon de firewall/rules.sh : ce script s'exécute SUR L'HÔTE
#  (comme les règles iptables), et NON dans un conteneur. Il lit le
#  journal système, repère les entrées iptables préfixées [SECUREHEALTH]
#  et génère des alertes classées (scan, brute-force, accès externe).
#
#  UTILISATION : sudo bash monitor/alert.sh
#
#  Pré-requis : firewall/rules.sh doit avoir été appliqué (règles LOG).
#  NB : la détection applicative en temps réel (Scapy) est assurée
#       par le conteneur monitor (port_scan_detector.py).
# ============================================================

# Journal système (Debian/Ubuntu : /var/log/syslog ; Fedora/RHEL : /var/log/messages)
LOG_SYSTEME="${SYSLOG_PATH:-/var/log/syslog}"
[ -f "$LOG_SYSTEME" ] || LOG_SYSTEME="/var/log/messages"

# Répertoire de logs du projet (relatif au dépôt)
LOG_DIR="${LOG_DIR:-logs}"
LOG_ALERTES="$LOG_DIR/alertes_firewall.log"
EMAIL_ADMIN="${ALERT_EMAIL:-admin@securehealth.local}"

mkdir -p "$LOG_DIR"

echo "[SecureHealth] Surveillance des logs iptables démarrée..."
echo "[SecureHealth] Alertes envoyées à : $EMAIL_ADMIN"

# Surveiller en temps réel les logs du pare-feu
tail -F "$LOG_SYSTEME" 2>/dev/null | while read -r ligne; do

    # Détecter les entrées iptables de SecureHealth
    if echo "$ligne" | grep -q "\[SECUREHEALTH\]"; then

        HORODATAGE=$(date '+%d/%m/%Y %H:%M:%S')
        echo "[$HORODATAGE] $ligne" >> "$LOG_ALERTES"

        # Catégoriser l'alerte
        if echo "$ligne" | grep -q "SCAN-NULL\|SCAN-XMAS\|SCAN-FIN"; then
            TYPE="SCAN DE PORTS"
        elif echo "$ligne" | grep -q "BRUTE-FORCE"; then
            TYPE="BRUTE FORCE"
        elif echo "$ligne" | grep -q "EXTERNE-BLOQUE"; then
            TYPE="ACCÈS EXTERNE BLOQUÉ"
        else
            TYPE="TRAFIC SUSPECT"
        fi

        # Extraire l'IP source
        IP_SOURCE=$(echo "$ligne" | grep -oP 'SRC=\K[\d.]+' || echo "Inconnue")

        echo "[$HORODATAGE] ALERTE $TYPE | IP: $IP_SOURCE" | \
            tee -a "$LOG_ALERTES"

        # En production : envoyer un mail d'alerte via sendmail
        # echo "Alerte SecureHealth-Net: $TYPE depuis $IP_SOURCE" | \
        #     mail -s "[ALERTE] SecureHealth-Net - $TYPE" "$EMAIL_ADMIN"
    fi
done
