#!/bin/bash
# ============================================================
#  SecureHealth-Net — Script d'alertes réseau
#  Surveille les logs iptables et envoie des alertes internes
# ============================================================

LOG_SYSTEME="/var/log/syslog"
LOG_ALERTES="/app/logs/alertes_firewall.log"
EMAIL_ADMIN="${ALERT_EMAIL:-admin@securehealth.local}"

mkdir -p /app/logs

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
