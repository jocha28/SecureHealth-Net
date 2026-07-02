# Fiche projet — SecureHealth-Net

## 1. Problème identifié

Lors des crises sanitaires (épidémies, urgences hospitalières), le personnel médical
échange en permanence des **informations confidentielles sur les patients**. Or, dans de
nombreux centres de santé au Bénin, ces échanges passent par des **messageries publiques**
(Gmail, Yahoo…), ce qui pose plusieurs problèmes :

- **Confidentialité non garantie** : les données médicales transitent par des serveurs
  étrangers, hors de tout contrôle.
- **Dépendance à Internet** : une coupure de connexion paralyse la communication.
- **Absence de maîtrise** : aucune traçabilité, aucune protection contre l'interception
  ou l'intrusion réseau.
- **Non-conformité** au principe de protection des données de santé (secret médical).

## 2. Objectif général

Concevoir et déployer une **infrastructure de messagerie interne, sécurisée et 100 %
autonome**, permettant au personnel d'un centre de santé de communiquer de façon
confidentielle **sans dépendre d'aucun service cloud externe**.

## 3. Objectifs spécifiques

1. **Mettre en place un serveur de messagerie complet** (envoi + réception) fonctionnant en local.
2. **Chiffrer toutes les communications** (TLS 1.2 minimum) pour empêcher l'interception.
3. **Authentifier les utilisateurs** de façon sécurisée (mots de passe hachés, jamais en clair).
4. **Offrir une interface web accessible** depuis n'importe quel poste du centre.
5. **Protéger l'infrastructure réseau** par un pare-feu (iptables) et une **détection
   d'intrusions** en temps réel.
6. **Rendre le déploiement reproductible** via la conteneurisation (une seule commande).

## 4. Résultats attendus

| Objectif | Résultat mesurable |
|----------|--------------------|
| Messagerie fonctionnelle | Un médecin envoie et reçoit un mail de bout en bout |
| Chiffrement | Aucune communication en clair (TLS imposé) |
| Authentification | Mots de passe stockés hachés (SHA512-CRYPT) |
| Interface | Webmail accessible sur `http://localhost:8080` |
| Sécurité réseau | Scans (NULL/XMAS/FIN), SYN flood et brute-force détectés/bloqués |
| Déploiement | `docker compose up` lance toute l'infra en ~2-3 min |

## 5. Méthodologie

Approche **incrémentale et modulaire**, en trois pôles :

1. **Analyse des besoins** : identification des flux (envoi, réception, lecture) et des
   menaces (interception, scan, intrusion).
2. **Conception de l'architecture** : découpage en services isolés (SMTP, IMAP, webmail,
   base de données, monitoring) sur un réseau Docker dédié.
3. **Implémentation par composant** :
   - Pôle 1 — Messagerie (Postfix + Dovecot + Roundcube)
   - Pôle 2 — Sécurité réseau (iptables + détecteur Scapy)
   - Pôle 3 — Conteneurisation (Docker Compose)
4. **Tests et validation** : vérification de bout en bout (envoi authentifié → livraison
   Maildir → lecture IMAP), tests TLS, simulation de scans.
5. **Documentation** : README, schémas de flux, fiche de soutenance.

## 6. Description du projet

**SecureHealth-Net** est une infrastructure de messagerie conteneurisée reposant sur
**5 services** interconnectés dans un réseau isolé `172.25.0.0/24` :

- **Postfix (SMTP)** — achemine les mails (envoi et réception entre comptes).
- **Dovecot (IMAP)** — permet la lecture des boîtes et fournit l'authentification.
- **Roundcube (Webmail)** — interface web en français pour le personnel.
- **MySQL** — stocke les données de Roundcube (préférences, contacts).
- **Monitor (Python/Scapy)** — analyse le trafic réseau et détecte les intrusions.

Postfix et Dovecot **partagent un même stockage** au format Maildir : Postfix y écrit les
mails reçus, Dovecot les lit. Toutes les communications sont **chiffrées TLS**, les mots de
passe **hachés**, et le tout est **protégé par un pare-feu et un système de détection
d'intrusions**.

## 7. Axe de différenciation (comparaison avec l'existant)

L'axe de différenciation se mesure par rapport à deux solutions existantes représentatives :
- **Gmail / Google Workspace** — le *statu quo* actuellement utilisé dans les centres de santé.
- **Mailcow** — la solution open-source de messagerie dockerisée la plus proche techniquement
  (Postfix + Dovecot + webmail + antispam, orchestrés par Docker Compose).

### Tableau comparatif

| Critère | Gmail / Workspace | Mailcow (self-hosted) | **SecureHealth-Net** |
|---------|-------------------|-----------------------|----------------------|
| Hébergement des données | Cloud étranger | Serveur propre | **Serveur propre, réseau isolé** |
| Souveraineté / secret médical | ❌ Aucune maîtrise | ✅ Maîtrisée | ✅ **Totale (LAN fermé)** |
| Fonctionne sans Internet | ❌ Non | ⚠️ Partiel (DNS/MX publics attendus) | ✅ **Oui, 100 % hors-ligne** |
| Détection d'intrusions réseau | ❌ Boîte noire | ⚠️ Fail2ban (logs) | ✅ **IDS paquet (Scapy) + iptables dédié** |
| Empreinte ressources | N/A (cloud) | Lourde (~6 Go RAM, nombreux services) | ✅ **Légère (~4 Go RAM, 5 services)** |
| Complexité de déploiement | Compte à créer | Élevée (config avancée) | ✅ **Une commande `docker compose up`** |
| Coût | Abonnement/utilisateur | Gratuit (matériel) | ✅ **Gratuit, 100 % libre** |
| Transparence / valeur pédagogique | ❌ Fermé | ⚠️ Config abstraite | ✅ **Configs lisibles et commentées** |
| Richesse fonctionnelle (agenda, antivirus…) | ✅ Très riche | ✅ Riche | ⚠️ **Ciblée sur l'essentiel** |

### Ce qui distingue vraiment SecureHealth-Net

- **Conçu pour l'isolement** : contrairement à Mailcow (pensé pour une messagerie exposée à
  Internet avec DNS et certificats publics), SecureHealth-Net est optimisé pour un **réseau
  local fermé sans connectivité externe** — le cas réel d'un centre de santé au Bénin.
- **Sécurité réseau intégrée par conception** : au-delà de l'antispam classique, il embarque
  un **détecteur d'intrusions au niveau paquet (Scapy)** et un **pare-feu iptables explicite**
  (scans NULL/XMAS/FIN, SYN flood, brute-force) — une dimension absente des suites mail standard.
- **Légèreté et simplicité** : 5 services seulement, déployables en une commande sur un poste
  modeste, là où Mailcow exige davantage de ressources et d'expertise.
- **Transparence pédagogique** : chaque configuration est écrite à la main et commentée, ce qui
  en fait aussi un support d'apprentissage — impossible avec une solution « boîte noire ».

> En résumé : SecureHealth-Net ne cherche pas à rivaliser en fonctionnalités avec les suites
> généralistes, mais à proposer une messagerie **souveraine, hors-ligne et sécurisée au niveau
> réseau**, taillée pour un contexte médical à connectivité limitée.

## 8. Domaine d'application et public cible

**Domaine d'application :**
- Santé (hôpitaux, centres de santé, cliniques).
- Plus largement : toute organisation manipulant des **données sensibles** en réseau fermé
  (cabinets juridiques, administrations, ONG, laboratoires).

**Public cible :**
- **Utilisateurs finaux** : médecins, infirmiers, personnel administratif d'un centre de santé.
- **Administrateurs** : responsable informatique de l'établissement qui déploie et maintient l'infra.
- **Décideurs** : direction d'hôpital soucieuse de confidentialité et d'indépendance technologique.

## 9. Ressources nécessaires

**Matérielles**
- Un serveur ou poste Linux (Ubuntu/Debian/Fedora), ~2 CPU, 4 Go RAM, 20 Go disque.
- Un réseau local (les postes clients accèdent au webmail via navigateur).

**Logicielles** (toutes libres et gratuites)
- Docker ≥ 24 & Docker Compose ≥ 2
- Postfix, Dovecot, Roundcube, MySQL, Python 3 + Scapy, iptables, OpenSSL

**Humaines**
- 1 développeur/administrateur système pour le déploiement et la maintenance.
- Formation courte des utilisateurs à l'interface webmail.

**Temporelles**
- Déploiement initial : quelques minutes (build + lancement).
- Développement/mise au point du projet : selon planning du semestre.
