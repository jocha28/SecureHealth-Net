# SecureHealth-Net

> Infrastructure de messagerie interne sécurisée et de surveillance réseau pour les urgences médicales au Bénin.

---

## Technologies

![Docker](https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white)
![Postfix](https://img.shields.io/badge/Postfix-SMTP-FF6600?style=for-the-badge&logo=mail.ru&logoColor=white)
![Dovecot](https://img.shields.io/badge/Dovecot-IMAP-1A73E8?style=for-the-badge&logo=gmail&logoColor=white)
![Roundcube](https://img.shields.io/badge/Roundcube-Webmail-37B24D?style=for-the-badge&logo=roundcube&logoColor=white)
![MySQL](https://img.shields.io/badge/MySQL-4479A1?style=for-the-badge&logo=mysql&logoColor=white)
![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Scapy](https://img.shields.io/badge/Scapy-Analyse_réseau-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Debian](https://img.shields.io/badge/Debian-Linux-A81D33?style=for-the-badge&logo=debian&logoColor=white)
![iptables](https://img.shields.io/badge/iptables-Pare--feu-EE0000?style=for-the-badge&logo=linux&logoColor=white)
![TLS](https://img.shields.io/badge/TLS_1.2+-Chiffrement-00897B?style=for-the-badge&logo=letsencrypt&logoColor=white)
![Bash](https://img.shields.io/badge/Bash-Scripting-4EAA25?style=for-the-badge&logo=gnubash&logoColor=white)

---

## Contexte

Lors d'une crise sanitaire (épidémie, urgence hospitalière), les professionnels de santé échangent en permanence des informations critiques et confidentielles sur les patients. L'utilisation de messageries publiques comme Gmail ou Yahoo expose ces données à des risques majeurs de confidentialité.

**SecureHealth-Net** est une infrastructure de communication interne **100 % autonome, sécurisée et déployable localement**, conçue spécifiquement pour les centres de santé et hôpitaux au Bénin. Elle élimine toute dépendance à des services cloud externes et protège les données médicales contre les intrusions réseau.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│                    SecureHealth-Net                         │
│                  Réseau : 172.25.0.0/24                     │
│                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐  │
│  │   Postfix    │    │   Dovecot    │    │  Roundcube   │  │
│  │    SMTP      │◄──►│    IMAP      │◄──►│   Webmail    │  │
│  │ Port 25/587  │    │ Port 143/993 │    │  Port 8080   │  │
│  │ 172.25.0.2   │    │ 172.25.0.3   │    │ 172.25.0.4   │  │
│  └──────────────┘    └──────────────┘    └──────────────┘  │
│                                                  │          │
│  ┌──────────────┐    ┌──────────────────────┐    │          │
│  │   Moniteur   │    │       MySQL          │◄───┘          │
│  │   Réseau     │    │  (Base Roundcube)    │               │
│  │   Python     │    │   172.25.0.5         │               │
│  └──────────────┘    └──────────────────────┘               │
│          │                                                  │
│    ┌─────▼──────┐                                           │
│    │  iptables  │  ← Pare-feu (réseau hôte)                 │
│    └────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

---

## Fonctionnalités

### Pôle 1 — Messagerie interne (SMTP / IMAP)

- **Postfix** : serveur d'envoi de mails (SMTP) sur les ports 25 et 587
- **Dovecot** : serveur de réception et synchronisation (IMAP/IMAPS) sur les ports 143 et 993
- **Roundcube** : interface webmail moderne en français, accessible depuis n'importe quel terminal du centre de santé
- Stockage des mails au format **Maildir** (un fichier par message, plus fiable)
- Chiffrement **TLS 1.2 minimum** sur toutes les communications
- Boîtes mail virtuelles : Envoyés, Brouillons, Corbeille, Indésirables

### Pôle 2 — Sécurité et surveillance réseau (TCP/IP)

- **Pare-feu iptables** avec suivi d'état des connexions TCP (`ESTABLISHED`, `RELATED`, `INVALID`)
- Accès aux ports sensibles limité au seul réseau interne `172.25.0.0/24`
- Blocage des scans de ports furtifs : **NULL**, **XMAS**, **FIN**
- Protection contre le **brute-force SSH** (limite de 5 tentatives / 60 secondes)
- **Détecteur Python (Scapy)** : analyse en temps réel des paquets TCP suspects
  - Scan NULL (aucun flag)
  - Scan XMAS (FIN + PSH + URG)
  - Scan FIN
  - Scan horizontal (balayage multi-ports)
  - SYN Flood

### Pôle 3 — Déploiement conteneurisé

- **Docker Compose** : déploiement reproductible en une seule commande
- Réseau interne isolé `172.25.0.0/24`
- Volumes persistants pour les mails et la base de données
- Certificats TLS auto-signés générés automatiquement au premier démarrage

---

## Prérequis

- **Linux** (Ubuntu / Debian recommandé)
- **Docker** ≥ 24.x
- **Docker Compose** ≥ 2.x

```bash
docker --version
docker compose version
```

---

## Installation et démarrage

```bash
# 1. Cloner le dépôt
git clone https://github.com/jocha28/SecureHealth-Net.git
cd SecureHealth-Net

# 2. Lancer toute l'infrastructure
docker compose up --build -d

# 3. Vérifier que tous les conteneurs sont actifs
docker ps
```

L'infrastructure est prête en 2 à 3 minutes au premier lancement.

---

## Accès aux services

| Service | Adresse | Description |
| ------- | ------- | ----------- |
| Webmail | [http://localhost:8080](http://localhost:8080) | Interface Roundcube |
| SMTP | localhost:587 | Envoi de mails (authentifié + TLS) |
| IMAP | localhost:993 | Réception de mails (SSL) |

---

## Comptes médicaux par défaut

> ⚠️ Modifier les mots de passe avant tout déploiement en production.

| Adresse mail | Mot de passe | Rôle |
| ------------ | ------------ | ---- |
| `dr.kofi@securehealth.local` | `Medecin2024!` | Médecin |
| `dr.amina@securehealth.local` | `Medecin2024!` | Médecin |
| `dr.jean@securehealth.local` | `Medecin2024!` | Médecin |
| `infirmier.akosua@securehealth.local` | `Infirmier2024!` | Infirmier |
| `admin@securehealth.local` | `Admin2024!` | Administrateur |

---

## Pare-feu

```bash
sudo bash firewall/rules.sh
```

**Ports autorisés (réseau interne uniquement) :**

| Port | Service |
| ---- | ------- |
| 25 | SMTP (réception) |
| 587 | SMTP Submission (envoi authentifié) |
| 143 | IMAP |
| 993 | IMAPS (chiffré) |
| 8080 | Webmail Roundcube |
| 22 | SSH (administration) |

---

## Surveillance réseau

```bash
# Logs en direct
docker logs -f securehealth_monitor

# Fichiers de journaux
# logs/securehealth_monitor.log  → Activité générale
# logs/alertes.log               → Alertes de sécurité
```

**Exemple de détection :**

```text
[WARNING] SCAN NULL       | 192.168.1.45 → port 143
[WARNING] SCAN XMAS       | 192.168.1.45 → port 993
[WARNING] SCAN HORIZONTAL | 192.168.1.45 | 12 ports balayés en 60s
```

---

## Structure du projet

```text
SecureHealth-Net/
├── docker-compose.yml
├── firewall/
│   └── rules.sh                   # Règles iptables
├── postfix/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── config/
│       ├── main.cf                # Configuration SMTP
│       ├── master.cf              # Services Postfix
│       └── vmailbox               # Boîtes virtuelles
├── dovecot/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   └── config/
│       ├── dovecot.conf
│       ├── 10-auth.conf           # Authentification
│       ├── 10-mail.conf           # Stockage Maildir
│       ├── 10-ssl.conf            # TLS
│       └── users.passwd           # Comptes
├── roundcube/
│   ├── Dockerfile
│   └── config/
│       └── config.inc.php
└── monitor/
    ├── Dockerfile
    ├── port_scan_detector.py      # Détecteur Scapy
    └── alert.sh                   # Surveillance iptables
```

---

## Tests validés

| Test | Résultat |
| ---- | -------- |
| Connexion IMAP (3 comptes médicaux) | ✅ |
| Envoi de mail entre médecins (SMTP) | ✅ `delivered to maildir` |
| Lecture du mail reçu (IMAP FETCH) | ✅ |
| Rejet d'un mauvais mot de passe | ✅ `AUTHENTICATIONFAILED` |
| Détection scan de ports (NULL, XMAS, horizontal) | ✅ 17 paquets interceptés |

---

## Concepts réseau appliqués

| Concept | Application |
| ------- | ----------- |
| SMTP | Postfix — envoi et routage des mails |
| IMAP | Dovecot — synchronisation des boîtes mail |
| Suivi d'état TCP | `conntrack ESTABLISHED,RELATED` (pare-feu) |
| Scan NULL | Détection par absence de flags TCP |
| Scan XMAS | Détection par combinaison FIN+PSH+URG |
| Idle Port Scan | Analyse des SYN sans handshake complet |
| SYN Flood | Détection par seuil de connexions par IP/fenêtre |
| TLS 1.2+ | Chiffrement de bout en bout SMTP et IMAP |

---

## Auteur

**jocha28** — [GitHub](https://github.com/jocha28)
