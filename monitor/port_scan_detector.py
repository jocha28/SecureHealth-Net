#!/usr/bin/env python3
# ============================================================
#  SecureHealth-Net — Détecteur de scans de ports
#  Surveillance du réseau médical contre les intrusions
#
#  Concepts appliqués du cours :
#  - Analyse des paquets TCP (Partie 1 & 2)
#  - Détection d'idle port scan (Partie 1)
#  - Suivi d'état des connexions TCP (Partie 2)
# ============================================================

import os
import time
import logging
from datetime import datetime
from collections import defaultdict
from scapy.all import sniff, TCP, IP, conf

# --- Configuration ---
PORTS_SURVEILLES   = [25, 143, 587, 993, 8080]   # Ports de l'infrastructure
SEUIL_SCAN         = 10    # Nombre de ports touchés avant alerte
FENETRE_TEMPS      = 60    # Secondes pour la fenêtre de détection
SEUIL_SYN          = 20    # Flood SYN : nb de SYN depuis la même IP / fenêtre
LOG_FILE           = "/app/logs/securehealth_monitor.log"

# --- Configuration du journal ---
os.makedirs("/app/logs", exist_ok=True)
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%d/%m/%Y %H:%M:%S",
    handlers=[
        logging.FileHandler(LOG_FILE),
        logging.StreamHandler()
    ]
)
log = logging.getLogger("SecureHealth-Monitor")

# --- Structures de suivi ---
# ip_src -> liste de timestamps de connexion (pour détecter flood/scan)
connexions_par_ip: dict = defaultdict(list)

# ip_src -> set de ports touchés
ports_par_ip: dict = defaultdict(set)


def analyser_paquet(paquet):
    """
    Analyse chaque paquet capturé et détecte les comportements suspects.
    Concepts du cours :
      - Paquet TCP avec flags anormaux → scan de ports
      - Trop de SYN → SYN flood (DDoS)
      - Touches sur plusieurs ports → scan horizontal
    """
    if not paquet.haslayer(IP) or not paquet.haslayer(TCP):
        return

    ip_src  = paquet[IP].src
    port_dst = paquet[TCP].dport
    flags   = paquet[TCP].flags
    now     = time.time()

    # Nettoyer les entrées expirées (hors fenêtre de temps)
    connexions_par_ip[ip_src] = [
        t for t in connexions_par_ip[ip_src]
        if now - t < FENETRE_TEMPS
    ]

    # Enregistrer cette connexion
    connexions_par_ip[ip_src].append(now)

    # --------------------------------------------------------
    # DÉTECTION 1 : Scans de ports par flags TCP anormaux
    # (Technique vue en cours — Partie 1)
    # --------------------------------------------------------

    # Scan NULL : aucun flag activé (furtif, contourne certains pare-feux)
    if flags == 0:
        log.warning(
            f"SCAN NULL détecté | Source: {ip_src} | "
            f"Port cible: {port_dst} | "
            f"Technique: Scan furtif sans flags TCP"
        )
        enregistrer_alerte("SCAN_NULL", ip_src, port_dst)
        return

    # Scan XMAS : FIN + PSH + URG activés (comme un sapin de Noël)
    if flags & 0x29 == 0x29:  # FIN=0x01, PSH=0x08, URG=0x20
        log.warning(
            f"SCAN XMAS détecté | Source: {ip_src} | "
            f"Port cible: {port_dst} | "
            f"Technique: Tous les flags allumés"
        )
        enregistrer_alerte("SCAN_XMAS", ip_src, port_dst)
        return

    # Scan FIN : seulement le flag FIN (connexion fermée sans ouverture)
    if flags == 0x01:  # Seulement FIN
        log.warning(
            f"SCAN FIN détecté | Source: {ip_src} | "
            f"Port cible: {port_dst} | "
            f"Technique: Flag FIN sans connexion établie"
        )
        enregistrer_alerte("SCAN_FIN", ip_src, port_dst)
        return

    # --------------------------------------------------------
    # DÉTECTION 2 : Scan horizontal (balayage de ports)
    # L'attaquant essaie plusieurs ports sur le même serveur
    # --------------------------------------------------------
    if flags & 0x02:  # Flag SYN (tentative de connexion)
        ports_par_ip[ip_src].add(port_dst)

        if len(ports_par_ip[ip_src]) >= SEUIL_SCAN:
            ports_liste = sorted(ports_par_ip[ip_src])
            log.warning(
                f"SCAN DE PORTS HORIZONTAL détecté | Source: {ip_src} | "
                f"Ports touchés ({len(ports_liste)}): {ports_liste} | "
                f"Fenêtre: {FENETRE_TEMPS}s"
            )
            enregistrer_alerte("SCAN_HORIZONTAL", ip_src, port_dst, extra=ports_liste)
            # Réinitialiser pour éviter les doublons d'alertes
            ports_par_ip[ip_src] = set()

    # --------------------------------------------------------
    # DÉTECTION 3 : SYN Flood (tentative de DDoS)
    # Trop de paquets SYN sans compléter le handshake TCP
    # --------------------------------------------------------
    if flags & 0x02:  # SYN
        nb_connexions = len(connexions_par_ip[ip_src])
        if nb_connexions >= SEUIL_SYN:
            log.warning(
                f"SYN FLOOD détecté | Source: {ip_src} | "
                f"{nb_connexions} tentatives en {FENETRE_TEMPS}s | "
                f"Port cible: {port_dst}"
            )
            enregistrer_alerte("SYN_FLOOD", ip_src, port_dst, extra=nb_connexions)
            connexions_par_ip[ip_src] = []  # Réinitialiser

    # --------------------------------------------------------
    # DÉTECTION 4 : Accès aux ports critiques depuis l'extérieur
    # --------------------------------------------------------
    if port_dst in PORTS_SURVEILLES and not ip_src.startswith("172.25."):
        log.info(
            f"ACCÈS PORT SENSIBLE | Source externe: {ip_src} | "
            f"Port: {port_dst} | Flags: {flags}"
        )


def enregistrer_alerte(type_alerte: str, ip_src: str, port: int, extra=None):
    """Enregistre une alerte dans le fichier de journal structuré."""
    alerte = {
        "date":       datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
        "type":       type_alerte,
        "source_ip":  ip_src,
        "port_cible": port,
        "details":    extra
    }
    with open("/app/logs/alertes.log", "a") as f:
        f.write(str(alerte) + "\n")


def demarrer_surveillance():
    """Lance la capture des paquets réseau."""
    log.info("=" * 60)
    log.info("SecureHealth-Net — Surveillance réseau démarrée")
    log.info(f"Ports surveillés : {PORTS_SURVEILLES}")
    log.info(f"Seuil scan de ports : {SEUIL_SCAN} ports / {FENETRE_TEMPS}s")
    log.info(f"Seuil SYN flood : {SEUIL_SYN} paquets / {FENETRE_TEMPS}s")
    log.info(f"Journaux : {LOG_FILE}")
    log.info("=" * 60)

    # Filtrer uniquement les paquets TCP vers nos ports
    filtre_bpf = "tcp and (" + " or ".join(
        f"port {p}" for p in PORTS_SURVEILLES
    ) + ")"

    log.info(f"Filtre BPF actif : {filtre_bpf}")
    log.info("En écoute... (Ctrl+C pour arrêter)")

    try:
        sniff(
            filter=filtre_bpf,
            prn=analyser_paquet,
            store=False      # Ne pas stocker en mémoire (économie RAM)
        )
    except KeyboardInterrupt:
        log.info("Surveillance arrêtée par l'opérateur.")
    except Exception as e:
        log.error(f"Erreur lors de la capture : {e}")


if __name__ == "__main__":
    demarrer_surveillance()
