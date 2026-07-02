# SecureHealth-Net — Préparation à la soutenance

> Document d'aide à la présentation. Trois parties :
> 1. Schémas de flux détaillés (envoi / réception)
> 2. Fiche de démonstration pas-à-pas (live devant le jury)
> 3. Questions / réponses probables

---

## 1. Schémas de flux détaillés

### 1.1 — Envoi d'un mail (Dr Kofi → Dr Amina)

```text
┌──────────┐         ┌───────────┐        ┌──────────┐        ┌──────────┐
│ Dr Kofi  │         │ Roundcube │        │ Postfix  │        │ Dovecot  │
│(navigateur)        │  :8080    │        │ :587     │        │ :12345   │
└────┬─────┘         └─────┬─────┘        └────┬─────┘        └────┬─────┘
     │  1. Rédige + Envoyer │                   │                   │
     │─────────────────────►│                   │                   │
     │                      │ 2. SMTP + STARTTLS│                   │
     │                      │──────────────────►│                   │
     │                      │                   │ 3. AUTH LOGIN     │
     │                      │                   │──── vérifie ─────►│
     │                      │                   │  identité + hash  │
     │                      │                   │◄─── 235 OK ───────│
     │                      │ 4. MAIL/RCPT/DATA │                   │
     │                      │──────────────────►│                   │
     │                      │                   │ 5. Dépôt Maildir  │
     │                      │                   │   /var/mail/...    │
     │                      │                   │   /dr.amina/new/   │
     │                      │◄── 250 Queued ────│                   │
     │◄── "Message envoyé" ─│                   │                   │
```

**Points clés à dire à l'oral :**
- Le port **587** exige une authentification (`AUTH`) **après STARTTLS** — un anonyme ne peut pas envoyer.
- Postfix **ne vérifie pas** les mots de passe : il **délègue à Dovecot** (SASL) sur le port 12345.
- Le mail est déposé sous forme de fichier dans le **Maildir** du destinataire.

### 1.2 — Réception / lecture (Dr Amina lit son mail)

```text
┌──────────┐         ┌───────────┐        ┌──────────┐        ┌────────────┐
│ Dr Amina │         │ Roundcube │        │ Dovecot  │        │  Volume    │
│(navigateur)        │  :8080    │        │ :993     │        │ data/mail  │
└────┬─────┘         └─────┬─────┘        └────┬─────┘        └─────┬──────┘
     │ 1. Connexion        │                   │                    │
     │────────────────────►│                   │                    │
     │                     │ 2. IMAPS (TLS) 993│                    │
     │                     │──────────────────►│                    │
     │                     │                   │ 3. Vérifie hash    │
     │                     │                   │    SHA512-CRYPT     │
     │                     │                   │ 4. Lit le Maildir  │
     │                     │                   │───────────────────►│
     │                     │                   │◄── liste des mails │
     │                     │◄── mails (INBOX) ─│                    │
     │◄── affichage boîte ─│                   │                    │
```

**Le lien envoi ↔ lecture :** Postfix (envoi) **écrit** dans `data/mail`, Dovecot (lecture)
**lit** le même volume. C'est le volume partagé qui relie les deux services.

### 1.3 — Vue sécurité (ce qui protège chaque étape)

```text
   Internet / réseau hôte
            │
     ┌──────▼───────┐   Bloque scans (NULL/XMAS/FIN), brute-force,
     │  iptables    │   n'autorise que 172.25.0.0/24 sur les bons ports
     └──────┬───────┘
            │                    ┌─────────────┐  Analyse chaque paquet TCP,
   ┌────────▼─────────┐          │  Monitor    │  détecte scans & SYN flood,
   │ Réseau Docker    │◄─────────│  (Scapy)    │  journalise les alertes
   │ 172.25.0.0/24    │  observe └─────────────┘
   └────────┬─────────┘
            │  Tout chiffré en TLS 1.2+ (SMTP 587, IMAPS 993)
            │  Auth par mot de passe haché (SHA512-CRYPT)
   ┌────────▼─────────────────────────────┐
   │ Postfix · Dovecot · Roundcube · MySQL │
   └───────────────────────────────────────┘
```

---

## 2. Fiche de démonstration pas-à-pas (live)

> Objectif : prouver en ~5 min que l'infra est **fonctionnelle et sécurisée**.

### Étape 0 — Avant de commencer
```bash
cd ~/Github/SecureHealth-Net
docker compose up --build -d      # lancer toute l'infra
docker compose ps                 # montrer les 5 conteneurs "Up"
```
> À dire : « Une seule commande déploie toute l'infrastructure — reproductibilité. »

### Étape 1 — Montrer que le webmail répond
```bash
curl -I http://localhost:8080     # doit répondre 200 OK
```
Puis ouvrir **http://localhost:8080** dans le navigateur.

### Étape 2 — Connexion d'un médecin
- Se connecter avec `dr.kofi@securehealth.local` / `Medecin2024!`
> À dire : « Le mot de passe n'est **jamais** stocké en clair : il est haché en SHA512-CRYPT. »
```bash
# Preuve : montrer le fichier des comptes
grep dr.kofi dovecot/config/users.passwd   # montre {SHA512-CRYPT}$6$...
```

### Étape 3 — Envoyer un mail (le cœur du projet)
- Depuis Roundcube, écrire un mail à `dr.amina@securehealth.local` et l'envoyer.
> À dire : « L'envoi passe par le port 587, chiffré TLS, avec authentification déléguée à Dovecot. »
```bash
# Preuve côté serveur : la livraison
docker logs securehealth_postfix | grep "status=sent"
```

### Étape 4 — Vérifier la réception
- Se déconnecter, se reconnecter en `dr.amina@securehealth.local` / `Medecin2024!`
- Le mail est dans la boîte de réception.
```bash
# Preuve : le mail existe physiquement en Maildir
sudo ls data/mail/securehealth.local/dr.amina/Maildir/new/
```
> À dire : « Format Maildir : un fichier = un mail, robuste contre la corruption. »

### Étape 5 — Montrer le chiffrement TLS
```bash
# Le serveur impose TLS 1.2 minimum
openssl s_client -connect localhost:993 -tls1_1 2>&1 | grep -i "alert\|error"
# (échoue en TLS 1.1 → preuve que le downgrade est refusé)
```

### Étape 6 — Montrer la surveillance réseau
```bash
docker logs -f securehealth_monitor    # le détecteur Scapy est en écoute
```
Dans un autre terminal, simuler un scan (nmap doit être installé) :
```bash
sudo nmap -sN localhost -p 143      # scan NULL
sudo nmap -sX localhost -p 993      # scan XMAS
```
> Revenir sur les logs du monitor → les alertes SCAN NULL / SCAN XMAS apparaissent.

### Étape 7 — Montrer le pare-feu (optionnel, sur l'hôte)
```bash
sudo bash firewall/rules.sh          # applique les règles iptables
sudo iptables -L INPUT -n --line-numbers | head -20
```

---

## 3. Questions / réponses probables du jury

**Q1 — Pourquoi Postfix ET Dovecot, deux serveurs ?**
Ce sont deux rôles différents : Postfix gère l'**acheminement** des mails (protocole SMTP,
envoi + réception entre serveurs), Dovecot gère la **consultation** des boîtes par les
utilisateurs (protocole IMAP) et sert aussi de service d'**authentification**. C'est
l'architecture standard d'un serveur mail moderne.

**Q2 — Comment Postfix vérifie-t-il les mots de passe à l'envoi (port 587) ?**
Il ne les vérifie pas lui-même : il **délègue à Dovecot** via SASL. Dovecot expose son
service d'authentification sur le port TCP 12345, Postfix l'interroge. Un seul référentiel
de comptes (`users.passwd`) sert donc à la fois pour l'IMAP et le SMTP.

**Q3 — Où sont stockés les mails ?**
Dans un **volume Docker persistant** (`data/mail`) au format **Maildir**. Postfix y écrit,
Dovecot y lit. Le volume survit aux redémarrages et suppressions de conteneurs.

**Q4 — Les mots de passe sont-ils sécurisés ?**
Oui, hachés en **SHA512-CRYPT** (algorithme avec sel). Même si le fichier fuite, les mots
de passe ne sont pas récupérables. De plus, l'authentification en clair est interdite sans TLS.

**Q5 — Qu'est-ce qui chiffre les communications ?**
**TLS 1.2 minimum** sur SMTP (587), IMAPS (993) et le webmail. Certificat auto-signé généré
au premier démarrage (acceptable en réseau interne ; en production on utiliserait une
autorité de certification interne ou Let's Encrypt).

**Q6 — Différence entre le pare-feu et le détecteur Scapy ?**
Deux niveaux complémentaires : **iptables** *bloque* activement (prévention), le **détecteur
Scapy** *observe et alerte* sur les comportements suspects (détection). L'un empêche, l'autre
informe/journalise.

**Q7 — Comment détectez-vous un scan de ports ?**
Par l'analyse des **flags TCP** : un scan NULL n'a aucun flag, un scan XMAS a FIN+PSH+URG,
un scan FIN n'a que FIN — aucun ne correspond à une vraie connexion. On détecte aussi le
scan **horizontal** (≥10 ports touchés en 60s par la même IP) et le **SYN flood** (≥20 SYN/60s).

**Q8 — Pourquoi Docker / la conteneurisation ?**
**Reproductibilité** (une commande déploie tout à l'identique), **isolation** (réseau interne
dédié 172.25.0.0/24), et **portabilité** (fonctionne sur n'importe quel hôte Linux avec Docker).

**Q9 — Quelles limites / améliorations en production ?**
- Certificat signé par une CA (au lieu d'auto-signé)
- Antivirus/antispam (ClamAV, SpamAssassin, rspamd)
- Sauvegardes automatisées des volumes
- Haute disponibilité (réplication IMAP, plusieurs MX)
- Gestion centralisée des comptes (LDAP) au lieu d'un fichier plat

**Q10 — Pourquoi le réseau 172.25.0.0/24 et des IP fixes ?**
Pour **isoler** l'infrastructure du reste de la machine et permettre aux services de se
référencer par des **adresses stables** (ex. Postfix cible Dovecot en 172.25.0.3), ce qui
évite les problèmes de résolution DNS entre conteneurs.

---

### Aide-mémoire — comptes de démonstration

| Adresse | Mot de passe | Rôle |
|---------|--------------|------|
| dr.kofi@securehealth.local | Medecin2024! | Médecin |
| dr.amina@securehealth.local | Medecin2024! | Médecin |
| dr.jean@securehealth.local | Medecin2024! | Médecin |
| infirmier.akosua@securehealth.local | Infirmier2024! | Infirmier |
| admin@securehealth.local | Admin2024! | Administrateur |
