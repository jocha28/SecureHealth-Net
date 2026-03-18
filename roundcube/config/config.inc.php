<?php
// ============================================================
//  Roundcube — Configuration principale
//  SecureHealth-Net : Messagerie médicale interne sécurisée
// ============================================================

// --- Connexion à la base de données ---
$config['db_dsnw'] = 'mysql://roundcube:securehealth2024@roundcube_db/roundcubemail';

// --- Serveur IMAP (Dovecot) ---
$config['default_host'] = 'ssl://securehealth_dovecot';
$config['default_port'] = 993;
$config['imap_conn_options'] = [
    'ssl' => [
        'verify_peer'       => false,  // Auto-signé en local
        'verify_peer_name'  => false,
    ]
];

// --- Serveur SMTP (Postfix) ---
$config['smtp_server'] = 'tls://securehealth_postfix';
$config['smtp_port']   = 587;
$config['smtp_user']   = '%u';
$config['smtp_pass']   = '%p';
$config['smtp_conn_options'] = [
    'ssl' => [
        'verify_peer'       => false,
        'verify_peer_name'  => false,
    ]
];

// --- Interface utilisateur ---
$config['product_name']  = 'SecureHealth-Net — Messagerie Médicale';
$config['language']      = 'fr_FR';
$config['timezone']      = 'Africa/Porto-Novo';  // Fuseau horaire Bénin
$config['skin']          = 'elastic';            // Interface moderne
$config['support_url']   = '';

// --- Sécurité ---
$config['des_key']            = 'securehealth_key_2024_ben';  // Clé de chiffrement session (24 chars)
$config['ip_check']           = true;    // Vérifier l'IP de session
$config['session_lifetime']   = 30;     // Session expire après 30 min d'inactivité
$config['login_autocomplete'] = 0;      // Désactiver l'autocomplétion du mot de passe

// --- Dossiers par défaut ---
$config['sent_mbox']    = 'Envoyés';
$config['trash_mbox']   = 'Corbeille';
$config['drafts_mbox']  = 'Drafts';
$config['junk_mbox']    = 'Indésirables';

// --- Composition des mails ---
$config['htmleditor']         = 1;    // Éditeur HTML activé
$config['spellcheck_engine']  = '';
$config['default_charset']    = 'UTF-8';

// --- Plugins activés ---
$config['plugins'] = [
    'archive',          // Archivage des mails
    'zipdownload',      // Téléchargement en ZIP
    'markasjunk',       // Marquer comme indésirable
];

// --- Messages par page ---
$config['pagesize'] = 50;
