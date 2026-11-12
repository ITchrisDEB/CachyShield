//! Réglages du serveur SSH (sshd) : catalogue des options, validation, lecture, écriture dans UN fichier géré par l'application.
//!
//! • Fichier géré : /etc/ssh/sshd_config.d/10-cachy-shield.conf. sshd garde la PREMIÈRE valeur trouvée pour chaque mot-clé et lit
//!   le dossier sshd_config.d dans l'ordre alphabétique : « 10- » passe avant « 99-archlinux.conf » et avant le reste de sshd_config.
//! • Écriture : script CONSTANT (APPLY_SCRIPT), droits administrateur. Il refuse tout mot-clé hors liste (donc pas de « Match »,
//!   « Include », « ForceCommand », « AuthorizedKeysCommand »…), sauvegarde, contrôle « sshd -t », recharge (jamais redémarre) et
//!   revient en arrière si la configuration est invalide. Il ne démarre ni n'active jamais le service.
//! • Chaque valeur est validée ici (Rust) puis revérifiée caractère par caractère dans le script.

use regex::Regex;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

pub const MANAGED: &str = "/etc/ssh/sshd_config.d/10-cachy-shield.conf";
pub const MAIN_CONF: &str = "/etc/ssh/sshd_config";
pub const DROPIN_DIR: &str = "/etc/ssh/sshd_config.d";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pat {
    /// utilisateurs, groupes ou motifs (AllowUsers…)
    Names,
    /// liste d'algorithmes séparés par des virgules, contrôlée avec « ssh -Q <type> »
    Algs(&'static str),
    /// adresses d'écoute
    Addrs,
    /// chemin absolu ou « none »
    Path,
    /// chemins relatifs possibles (AuthorizedKeysFile : .ssh/authorized_keys, %h/…)
    KeyFiles,
    /// méthodes d'authentification
    AuthMethods,
    /// MaxStartups : début[:taux:max]
    Startups,
    /// variables d'environnement acceptées
    Env,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Bool,
    Enum(&'static [&'static str]),
    Int(u32, u32),
    Text(Pat),
}

#[derive(Clone, Copy, Debug)]
pub struct Opt {
    pub key: &'static str,
    pub cat: &'static str,
    pub label: &'static str,
    pub desc: &'static str,
    pub kind: Kind,
    /// valeur par défaut d'OpenSSH (affichage)
    pub default: &'static str,
    /// valeur de durcissement courante (CIS, guides OpenSSH), si elle existe
    pub rec: Option<&'static str>,
    /// mise en garde affichée sous l'option
    pub risk: Option<&'static str>,
}

const fn o(key: &'static str, cat: &'static str, label: &'static str, desc: &'static str, kind: Kind, default: &'static str, rec: Option<&'static str>, risk: Option<&'static str>) -> Opt {
    Opt { key, cat, label, desc, kind, default, rec, risk }
}

pub const CAT_CONN: &str = "Connexion";
pub const CAT_AUTH: &str = "Authentification";
pub const CAT_ACCESS: &str = "Qui peut se connecter";
pub const CAT_FWD: &str = "Redirections et tunnels";
pub const CAT_CRYPTO: &str = "Chiffrement";
pub const CAT_LOG: &str = "Journal et messages";
pub const CATEGORIES: [&str; 6] = [CAT_CONN, CAT_AUTH, CAT_ACCESS, CAT_FWD, CAT_CRYPTO, CAT_LOG];

const YN: Kind = Kind::Bool;

/// Catalogue des options proposées (ordre d'affichage). Valeurs par défaut : sshd_config(5), OpenSSH 10.
pub const CATALOGUE: &[Opt] = &[
    // ───── Connexion
    o("Port", CAT_CONN, "Port d'écoute", "Le port sur lequel SSH attend les connexions.", Kind::Int(1, 65535), "22", None, Some("Si vous changez le port, ouvrez le nouveau dans le pare-feu et prévenez vos clients : sinon vous ne pourrez plus vous connecter.")),
    o("AddressFamily", CAT_CONN, "Familles d'adresses", "IPv4 seulement, IPv6 seulement, ou les deux.", Kind::Enum(&["any", "inet", "inet6"]), "any", None, None),
    o("ListenAddress", CAT_CONN, "Adresses d'écoute", "Limite SSH à certaines adresses de cet ordinateur (séparées par des espaces), par exemple votre adresse sur le réseau local.", Kind::Text(Pat::Addrs), "toutes", None, Some("Une adresse fausse rend SSH injoignable. Vérifiez qu'elle existe sur cet ordinateur.")),
    o("LoginGraceTime", CAT_CONN, "Délai pour s'identifier (secondes)", "Au-delà, la connexion non identifiée est coupée. Plus court = moins de connexions inutiles qui traînent.", Kind::Int(1, 600), "120", Some("30"), None),
    o("MaxStartups", CAT_CONN, "Connexions non identifiées simultanées", "Format « début:taux:max » (ex. 10:30:60) ou un nombre : au-delà, des connexions sont refusées. Limite les attaques par saturation.", Kind::Text(Pat::Startups), "10:30:100", None, None),
    o("MaxSessions", CAT_CONN, "Sessions par connexion", "Nombre de sessions ouvertes en même temps sur une même connexion.", Kind::Int(0, 100), "10", Some("4"), None),
    o("ClientAliveInterval", CAT_CONN, "Vérifier que le client répond (secondes)", "Toutes les N secondes, SSH vérifie que l'autre côté est toujours là. 0 = jamais.", Kind::Int(0, 86400), "0", Some("300"), None),
    o("ClientAliveCountMax", CAT_CONN, "Réponses manquées avant de couper", "Après ce nombre de vérifications sans réponse, la session est fermée.", Kind::Int(0, 100), "3", Some("2"), None),
    o("TCPKeepAlive", CAT_CONN, "Messages « keep-alive » TCP", "Détecte les connexions mortes. Désactivé, une coupure réseau peut laisser des sessions fantômes.", YN, "yes", None, None),
    o("UseDNS", CAT_CONN, "Vérifier le nom DNS du client", "Inutile pour la sécurité et ralentit la connexion si le DNS est lent.", YN, "no", Some("no"), None),
    o("Compression", CAT_CONN, "Compression", "Compresse les données : peu utile aujourd'hui sur un réseau rapide.", YN, "yes", None, None),
    // ───── Authentification
    o("PermitRootLogin", CAT_AUTH, "Connexion du compte « root »", "« no » : personne ne peut se connecter en root par SSH. « prohibit-password » : root seulement avec une clé.", Kind::Enum(&["yes", "prohibit-password", "forced-commands-only", "no"]), "prohibit-password", Some("no"), Some("Gardez un compte normal avec sudo avant d'interdire root.")),
    o("PasswordAuthentication", CAT_AUTH, "Connexion par mot de passe", "Désactivez-la une fois vos clés SSH en place : les attaques par force brute deviennent inutiles.", YN, "yes", None, Some("Sans clé SSH enregistrée sur ce compte, vous ne pourrez plus vous connecter à distance. Testez une connexion par clé AVANT.")),
    o("PubkeyAuthentication", CAT_AUTH, "Connexion par clé SSH", "Le moyen recommandé de se connecter.", YN, "yes", Some("yes"), Some("Désactivée avec le mot de passe désactivé, plus personne ne peut se connecter.")),
    o("KbdInteractiveAuthentication", CAT_AUTH, "Connexion « clavier interactif »", "Mots de passe à usage unique, questions-réponses. Arch la désactive déjà.", YN, "yes", Some("no"), None),
    o("PermitEmptyPasswords", CAT_AUTH, "Mots de passe vides", "Autoriser un compte sans mot de passe à se connecter. À éviter.", YN, "no", Some("no"), None),
    o("MaxAuthTries", CAT_AUTH, "Essais par connexion", "Nombre de tentatives avant de couper la connexion (valeur courante : 3 à 4).", Kind::Int(1, 20), "6", Some("3"), None),
    o("AuthenticationMethods", CAT_AUTH, "Méthodes exigées", "Exemple : « publickey » (clé seulement) ou « publickey,password » (clé ET mot de passe).", Kind::Text(Pat::AuthMethods), "selon les réglages ci-dessus", None, Some("Une méthode impossible à satisfaire verrouille tout le monde dehors.")),
    o("UsePAM", CAT_AUTH, "Utiliser PAM", "Intègre SSH au système d'authentification (comptes, sessions). Arch le règle déjà sur « yes » dans son propre fichier : laissez-le.", YN, "no", None, Some("« no » désactive aussi la connexion par mot de passe système : risque de ne plus pouvoir se connecter.")),
    o("HostbasedAuthentication", CAT_AUTH, "Authentification par machine de confiance", "Ancienne méthode (hôtes de confiance). À éviter.", YN, "no", Some("no"), None),
    o("IgnoreRhosts", CAT_AUTH, "Ignorer les fichiers .rhosts", "Ancienne méthode non sûre. Laissez à « yes ».", YN, "yes", Some("yes"), None),
    o("GSSAPIAuthentication", CAT_AUTH, "Authentification Kerberos (GSSAPI)", "Utile seulement avec un annuaire d'entreprise.", YN, "no", None, None),
    o("StrictModes", CAT_AUTH, "Vérifier les droits des fichiers de clés", "Refuse les clés si leur dossier est modifiable par d'autres.", YN, "yes", Some("yes"), None),
    o("AuthorizedKeysFile", CAT_AUTH, "Fichier(s) des clés autorisées", "Où SSH cherche les clés autorisées (défaut : .ssh/authorized_keys dans le dossier personnel).", Kind::Text(Pat::KeyFiles), ".ssh/authorized_keys .ssh/authorized_keys2", None, Some("Un chemin faux = plus aucune clé reconnue. Ne changez que si vous savez pourquoi.")),
    // ───── Qui peut se connecter
    o("AllowUsers", CAT_ACCESS, "Utilisateurs autorisés", "Liste (séparée par des espaces) : SEULS ces comptes peuvent se connecter. Vide = tous.", Kind::Text(Pat::Names), "tous", None, Some("N'oubliez pas votre propre compte, sinon vous serez exclu.")),
    o("DenyUsers", CAT_ACCESS, "Utilisateurs interdits", "Ces comptes ne peuvent jamais se connecter.", Kind::Text(Pat::Names), "aucun", None, None),
    o("AllowGroups", CAT_ACCESS, "Groupes autorisés", "SEULS les membres de ces groupes peuvent se connecter.", Kind::Text(Pat::Names), "tous", None, Some("Vérifiez que votre compte est dans l'un de ces groupes.")),
    o("DenyGroups", CAT_ACCESS, "Groupes interdits", "Les membres de ces groupes ne peuvent jamais se connecter.", Kind::Text(Pat::Names), "aucun", None, None),
    o("PermitUserEnvironment", CAT_ACCESS, "Variables d'environnement des utilisateurs", "Laisse un utilisateur imposer des variables via ~/.ssh/environment. À éviter.", YN, "no", Some("no"), None),
    o("PermitTTY", CAT_ACCESS, "Terminal interactif", "Désactivé, seuls les transferts et commandes sans terminal fonctionnent.", YN, "yes", None, None),
    o("AcceptEnv", CAT_ACCESS, "Variables acceptées du client", "Noms de variables que le client peut transmettre (ex. LANG LC_*).", Kind::Text(Pat::Env), "aucune", None, None),
    // ───── Redirections
    o("AllowTcpForwarding", CAT_FWD, "Redirection de ports (tunnels TCP)", "Permet de passer par SSH pour atteindre d'autres machines. « local » ou « remote » : un seul sens.", Kind::Enum(&["yes", "no", "local", "remote"]), "yes", None, None),
    o("AllowAgentForwarding", CAT_FWD, "Redirection de l'agent SSH", "Permet d'utiliser vos clés depuis le serveur. À couper si inutile.", YN, "yes", None, None),
    o("X11Forwarding", CAT_FWD, "Redirection graphique (X11)", "Afficher des programmes graphiques du serveur sur votre écran.", YN, "no", Some("no"), None),
    o("GatewayPorts", CAT_FWD, "Ports redirigés visibles du réseau", "Permet à d'autres machines d'utiliser vos redirections de ports.", Kind::Enum(&["no", "yes", "clientspecified"]), "no", Some("no"), None),
    o("PermitTunnel", CAT_FWD, "Tunnels réseau (VPN sur SSH)", "Autorise les interfaces tun/tap.", Kind::Enum(&["no", "yes", "point-to-point", "ethernet"]), "no", Some("no"), None),
    o("AllowStreamLocalForwarding", CAT_FWD, "Redirection de sockets locaux", "Redirige des sockets Unix.", Kind::Enum(&["yes", "no", "all", "local", "remote"]), "yes", None, None),
    o("DisableForwarding", CAT_FWD, "Interdire TOUTES les redirections", "Coupe d'un coup X11, agent, ports, sockets et tunnels.", YN, "no", None, None),
    // ───── Chiffrement
    o("Ciphers", CAT_CRYPTO, "Algorithmes de chiffrement", "Laissez vide : les valeurs d'OpenSSH sont à jour. Préfixes « + » (ajouter), « - » (retirer), « ^ » (en premier) possibles.", Kind::Text(Pat::Algs("cipher")), "valeurs d'OpenSSH", None, Some("Une liste trop stricte empêche les anciens clients de se connecter.")),
    o("KexAlgorithms", CAT_CRYPTO, "Échange de clés", "Idem : laissez vide sauf besoin précis.", Kind::Text(Pat::Algs("kex")), "valeurs d'OpenSSH", None, Some("Une liste trop stricte empêche les anciens clients de se connecter.")),
    o("MACs", CAT_CRYPTO, "Codes d'intégrité (MAC)", "Idem : laissez vide sauf besoin précis.", Kind::Text(Pat::Algs("mac")), "valeurs d'OpenSSH", None, Some("Une liste trop stricte empêche les anciens clients de se connecter.")),
    // ───── Journal
    o("LogLevel", CAT_LOG, "Niveau de détail du journal", "VERBOSE enregistre l'empreinte de la clé utilisée pour chaque connexion : utile pour retrouver qui s'est connecté.", Kind::Enum(&["QUIET", "FATAL", "ERROR", "INFO", "VERBOSE", "DEBUG"]), "INFO", Some("VERBOSE"), Some("DEBUG enregistre énormément de données sensibles : seulement pour dépanner.")),
    o("SyslogFacility", CAT_LOG, "Catégorie du journal système", "Où le système classe les messages de SSH.", Kind::Enum(&["DAEMON", "USER", "AUTH", "LOCAL0", "LOCAL1", "LOCAL2", "LOCAL3", "LOCAL4", "LOCAL5", "LOCAL6", "LOCAL7"]), "AUTH", None, None),
    o("PrintMotd", CAT_LOG, "Afficher le message du jour", "Texte affiché après la connexion.", YN, "yes", None, None),
    o("PrintLastLog", CAT_LOG, "Afficher la dernière connexion", "Rappelle la date de votre dernière connexion : utile pour repérer une intrusion.", YN, "yes", Some("yes"), None),
    o("Banner", CAT_LOG, "Bannière avant la connexion", "Chemin d'un fichier texte affiché avant l'identification (avertissement légal). « none » = aucune.", Kind::Text(Pat::Path), "none", None, None),
];

pub fn opt(key: &str) -> Option<&'static Opt> {
    CATALOGUE.iter().find(|o| o.key.eq_ignore_ascii_case(key))
}

/// Mots-clés dont plusieurs lignes sont possibles (une ligne par valeur).
fn multi(key: &str) -> bool {
    matches!(key, "ListenAddress" | "AcceptEnv")
}

// ───────────────────────────────── validation ─────────────────────────────────

fn squash(v: &str) -> String {
    v.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn addr_ok(a: &str) -> bool {
    if a == "*" {
        return true;
    }
    if let Some(rest) = a.strip_prefix('[') {
        let Some((ip, port)) = rest.split_once("]:") else { return rest.strip_suffix(']').is_some_and(|ip| ip.parse::<Ipv6Addr>().is_ok()) };
        return ip.parse::<Ipv6Addr>().is_ok() && port.parse::<u16>().is_ok_and(|p| p > 0);
    }
    if a.parse::<Ipv4Addr>().is_ok() || a.parse::<Ipv6Addr>().is_ok() {
        return true;
    }
    a.split_once(':').is_some_and(|(ip, p)| ip.parse::<Ipv4Addr>().is_ok() && p.parse::<u16>().is_ok_and(|p| p > 0))
}

/// Valide et normalise une valeur. `known` donne la liste des algorithmes connus pour un type (« ssh -Q cipher »…).
pub fn validate_with(o: &Opt, raw: &str, known: &dyn Fn(&str) -> Vec<String>) -> Result<String, String> {
    let v = squash(raw);
    if v.is_empty() {
        return Err("valeur vide".into());
    }
    if v.len() > 600 {
        return Err("valeur trop longue".into());
    }
    match o.kind {
        Kind::Bool => match v.as_str() {
            "yes" | "no" => Ok(v),
            _ => Err("choisissez oui ou non".into()),
        },
        Kind::Enum(vals) => vals.contains(&v.as_str()).then_some(v).ok_or_else(|| "valeur non reconnue".to_string()),
        Kind::Int(a, b) => match v.parse::<u32>() {
            Ok(n) if (a..=b).contains(&n) => Ok(n.to_string()),
            _ => Err(format!("un nombre entre {a} et {b} est attendu")),
        },
        Kind::Text(p) => match p {
            Pat::Names => {
                let re = Regex::new(r"^[A-Za-z0-9_.@*?!][A-Za-z0-9_.@*?!:-]*$").unwrap();
                let toks: Vec<&str> = v.split(' ').collect();
                (toks.len() <= 50 && toks.iter().all(|t| t.len() <= 64 && re.is_match(t))).then_some(v).ok_or_else(|| "noms invalides (lettres, chiffres, _ . - @ * ? ! seulement, séparés par des espaces)".to_string())
            }
            Pat::Algs(q) => {
                let list = known(q);
                let toks: Vec<&str> = v.split(',').collect();
                for (i, t) in toks.iter().enumerate() {
                    let name = if i == 0 { t.trim_start_matches(['+', '-', '^']) } else { t };
                    if name.is_empty() || name.contains(['+', '^']) || (!list.is_empty() && !list.iter().any(|k| k == name) && !name.contains('*')) {
                        return Err(format!("algorithme inconnu : {t}"));
                    }
                    if !name.chars().all(|c| c.is_ascii_alphanumeric() || "-@.*_".contains(c)) {
                        return Err(format!("algorithme invalide : {t}"));
                    }
                }
                Ok(v)
            }
            Pat::Addrs => {
                let toks: Vec<&str> = v.split(' ').collect();
                (toks.len() <= 16 && toks.iter().all(|t| addr_ok(t))).then_some(v).ok_or_else(|| "adresse invalide (IPv4, IPv6, ou adresse:port)".to_string())
            }
            Pat::Path => {
                if v == "none" {
                    return Ok(v);
                }
                (v.starts_with('/') && !v.contains("..") && v.chars().all(|c| c.is_ascii_alphanumeric() || "/_.-".contains(c))).then_some(v).ok_or_else(|| "chemin absolu attendu (ou « none »)".to_string())
            }
            Pat::KeyFiles => {
                let toks: Vec<&str> = v.split(' ').collect();
                (toks.len() <= 4 && toks.iter().all(|t| !t.starts_with('-') && !t.contains("..") && t.chars().all(|c| c.is_ascii_alphanumeric() || "/_.-%".contains(c)))).then_some(v).ok_or_else(|| "chemin invalide".to_string())
            }
            Pat::AuthMethods => {
                let ok = ["publickey", "password", "keyboard-interactive", "hostbased", "gssapi-with-mic", "any", "none"];
                let toks: Vec<&str> = v.split(' ').collect();
                (toks.len() <= 4 && toks.iter().all(|t| t.split(',').all(|m| ok.contains(&m)))).then_some(v).ok_or_else(|| "méthodes possibles : publickey, password, keyboard-interactive, hostbased, gssapi-with-mic".to_string())
            }
            Pat::Startups => {
                let re = Regex::new(r"^(\d{1,4})(?::(\d{1,3}):(\d{1,4}))?$").unwrap();
                match re.captures(&v) {
                    Some(c) => {
                        let start: u32 = c[1].parse().unwrap_or(0);
                        if let (Some(r), Some(m)) = (c.get(2), c.get(3)) {
                            let (rate, max): (u32, u32) = (r.as_str().parse().unwrap_or(0), m.as_str().parse().unwrap_or(0));
                            if rate > 100 || max < start {
                                return Err("taux de 0 à 100 et maximum au moins égal au début".into());
                            }
                        }
                        if start == 0 {
                            return Err("le début doit être au moins 1".into());
                        }
                        Ok(v)
                    }
                    None => Err("format : nombre ou début:taux:max (ex. 10:30:60)".into()),
                }
            }
            Pat::Env => {
                let re = Regex::new(r"^[A-Za-z0-9_*?]+$").unwrap();
                let toks: Vec<&str> = v.split(' ').collect();
                (toks.len() <= 30 && toks.iter().all(|t| re.is_match(t))).then_some(v).ok_or_else(|| "noms de variables invalides".to_string())
            }
        },
    }
}

/// Algorithmes connus d'OpenSSH pour un type : « ssh -Q cipher », « kex », « mac » (lecture seule, sans droits).
pub fn known_algs(kind: &str) -> Vec<String> {
    if !matches!(kind, "cipher" | "kex" | "mac") {
        return vec![];
    }
    let Some(ssh) = crate::util::abs_prog("ssh") else { return vec![] };
    std::process::Command::new(ssh).args(["-Q", kind]).output().map(|o| String::from_utf8_lossy(&o.stdout).lines().map(|l| l.trim().to_string()).filter(|l| !l.is_empty()).collect()).unwrap_or_default()
}

pub fn validate(o: &Opt, raw: &str) -> Result<String, String> {
    validate_with(o, raw, &known_algs)
}

// ─────────────────────────── lecture et écriture du fichier ───────────────────────────

/// Lit les lignes « Mot-clé valeur » d'un fichier de configuration (sans commentaires), en s'arrêtant à un bloc « Match ».
pub fn parse_lines(text: &str) -> Vec<(String, String)> {
    let mut v = Vec::new();
    for l in text.lines() {
        let l = l.trim();
        if l.is_empty() || l.starts_with('#') {
            continue;
        }
        let cut = l.find(|c: char| c.is_whitespace() || c == '=').unwrap_or(l.len());
        let (k, rest) = (&l[..cut], l[cut..].trim_start());
        let rest = rest.strip_prefix('=').map(str::trim).unwrap_or(rest);
        if k.eq_ignore_ascii_case("Match") {
            break;
        }
        v.push((k.to_string(), squash(rest)));
    }
    v
}

/// Réglages du fichier géré : clé canonique → valeur (plusieurs lignes d'une option multiple sont réunies par des espaces).
pub fn parse_managed(text: &str) -> HashMap<&'static str, String> {
    let mut m: HashMap<&'static str, String> = HashMap::new();
    for (k, v) in parse_lines(text) {
        if let Some(o) = opt(&k) {
            m.entry(o.key).and_modify(|e| if multi(o.key) { *e = format!("{e} {v}") }).or_insert(v);
        }
    }
    m
}

pub fn read_managed() -> HashMap<&'static str, String> {
    parse_managed(&std::fs::read_to_string(MANAGED).unwrap_or_default())
}

/// Valeurs en vigueur d'après les fichiers (première valeur gagnante) : dossier sshd_config.d aux emplacements des « Include », dans l'ordre.
pub fn effective_from_files(skip_managed: bool) -> HashMap<String, String> {
    fn walk(path: &str, out: &mut HashMap<String, String>, depth: u8, skip: bool) {
        if skip && path == MANAGED {
            return;
        }
        let Ok(text) = std::fs::read_to_string(path) else { return };
        for (k, v) in parse_lines(&text) {
            if k.eq_ignore_ascii_case("Include") && depth < 3 {
                for pat in v.split(' ') {
                    if let Some(dir) = pat.strip_suffix("/*.conf") {
                        if dir == DROPIN_DIR {
                            let mut files: Vec<String> = std::fs::read_dir(dir).map(|rd| rd.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).filter(|n| n.ends_with(".conf")).collect()).unwrap_or_default();
                            files.sort();
                            for f in files {
                                walk(&format!("{dir}/{f}"), out, depth + 1, skip);
                            }
                        }
                    }
                }
                continue;
            }
            if let Some(o) = opt(&k) {
                out.entry(o.key.to_string()).or_insert(v);
            }
        }
    }
    let mut out = HashMap::new();
    walk(MAIN_CONF, &mut out, 0, skip_managed);
    out
}

/// Contenu du fichier géré (vide si aucun réglage : le script supprime alors le fichier). Ordre du catalogue ; une ligne par valeur pour les options multiples.
pub fn render(settings: &[(&'static str, String)]) -> String {
    let mut out = String::new();
    for o in CATALOGUE {
        for (k, v) in settings {
            if *k != o.key {
                continue;
            }
            if multi(o.key) {
                for part in v.split(' ') {
                    out += &format!("{} {}\n", o.key, part);
                }
            } else {
                out += &format!("{} {}\n", o.key, v);
            }
        }
    }
    if out.is_empty() {
        return out;
    }
    format!("# Géré par Cachy Shield. Supprimez ce fichier pour annuler.\n{out}")
}

// ─────────────────────────────── risques de verrouillage ───────────────────────────────

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// impossible : l'application refuse
    Block,
    /// possible mais dangereux : confirmation explicite
    Confirm,
}

#[derive(Clone, Debug)]
pub struct SshEnv {
    pub user: String,
    pub has_keys: bool,
}

pub fn detect_env() -> SshEnv {
    let user = crate::util::current_user();
    let has_keys = crate::util::home_dir()
        .map(|h| h.join(".ssh/authorized_keys"))
        .and_then(|p| std::fs::read_to_string(p).ok())
        .is_some_and(|t| t.lines().any(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#')));
    SshEnv { user, has_keys }
}

/// Un motif de nom (« *», « ch?s ») correspond-il à ce nom ?
fn pattern_matches(pat: &str, name: &str) -> bool {
    let re = format!("^{}$", regex::escape(pat).replace("\\*", ".*").replace("\\?", "."));
    Regex::new(&re).is_ok_and(|r| r.is_match(name))
}

/// Verrouillages possibles avec ces réglages (valeurs finales : réglages choisis, sinon valeurs actuelles des fichiers).
pub fn risks(chosen: &HashMap<&'static str, String>, current: &HashMap<String, String>, env: &SshEnv) -> Vec<(Level, String)> {
    let get = |k: &str| chosen.get(k).cloned().or_else(|| current.get(k).cloned());
    let yes = |k: &str, default: bool| get(k).map(|v| v == "yes").unwrap_or(default);
    let mut r: Vec<(Level, String)> = Vec::new();
    let (pw, key, kbd) = (yes("PasswordAuthentication", true), yes("PubkeyAuthentication", true), yes("KbdInteractiveAuthentication", true));
    if !pw && !key && !kbd {
        r.push((Level::Block, "Aucune méthode de connexion ne resterait active (ni mot de passe, ni clé, ni clavier interactif) : plus personne ne pourrait se connecter.".into()));
    } else if !pw && !kbd && key && !env.has_keys {
        r.push((Level::Confirm, format!("Sans mot de passe, il ne reste que les clés SSH, et aucune n'est enregistrée pour {} (~/.ssh/authorized_keys est vide ou absent). Vous ne pourriez plus vous connecter à distance avec ce compte. Ajoutez une clé et testez-la avant de continuer.", env.user)));
    }
    if let Some(m) = get("AuthenticationMethods") {
        if m.split(' ').all(|alt| alt.split(',').any(|x| x == "publickey")) && !env.has_keys {
            r.push((Level::Confirm, "Les méthodes exigées demandent une clé SSH, mais aucune clé n'est enregistrée pour votre compte.".into()));
        }
        if m.split(' ').all(|alt| alt.split(',').any(|x| x == "password") && !pw) {
            r.push((Level::Block, "Les méthodes exigées demandent un mot de passe, mais la connexion par mot de passe est désactivée.".into()));
        }
    }
    if let Some(u) = get("AllowUsers") {
        if !u.split(' ').any(|p| pattern_matches(p.split('@').next().unwrap_or(p), &env.user)) {
            r.push((Level::Block, format!("« AllowUsers » n'inclut pas votre compte ({}) : vous seriez exclu.", env.user)));
        }
    }
    if let Some(u) = get("DenyUsers") {
        if u.split(' ').any(|p| pattern_matches(p, &env.user)) {
            r.push((Level::Block, format!("« DenyUsers » interdit votre compte ({}).", env.user)));
        }
    }
    if get("AllowGroups").is_some() {
        r.push((Level::Confirm, "« AllowGroups » restreint la connexion aux membres de certains groupes : vérifiez que votre compte en fait partie.".into()));
    }
    if let Some(p) = chosen.get("Port") {
        if p != "22" {
            r.push((Level::Confirm, format!("Le port SSH passe à {p}. Ouvrez-le dans votre pare-feu et utilisez « -p {p} » pour vous connecter : l'ancien port ne répondra plus.")));
        }
    }
    if chosen.contains_key("ListenAddress") {
        r.push((Level::Confirm, "SSH n'écoutera que sur les adresses indiquées. Si l'une n'existe pas sur cet ordinateur, SSH ne démarrera plus au prochain lancement.".into()));
    }
    if chosen.get("UsePAM").is_some_and(|v| v == "no") {
        r.push((Level::Confirm, "Sans PAM, la connexion par mot de passe système ne fonctionne généralement plus.".into()));
    }
    r
}

// ───────────────────────────────────── script ─────────────────────────────────────

/// Écrit le fichier géré. Argument 1 : le contenu complet (vide = supprimer le fichier). Voir l'en-tête du module pour les garde-fous.
pub const APPLY_SCRIPT: &str = r#"f=/etc/ssh/sshd_config.d/10-cachy-shield.conf
content="$1"
allowed=" Port AddressFamily ListenAddress LoginGraceTime MaxStartups MaxSessions ClientAliveInterval ClientAliveCountMax TCPKeepAlive UseDNS Compression PermitRootLogin PasswordAuthentication PubkeyAuthentication KbdInteractiveAuthentication PermitEmptyPasswords MaxAuthTries AuthenticationMethods UsePAM HostbasedAuthentication IgnoreRhosts GSSAPIAuthentication StrictModes AuthorizedKeysFile AllowUsers DenyUsers AllowGroups DenyGroups PermitUserEnvironment PermitTTY AcceptEnv AllowTcpForwarding AllowAgentForwarding X11Forwarding GatewayPorts PermitTunnel AllowStreamLocalForwarding DisableForwarding Ciphers KexAlgorithms MACs LogLevel SyslogFacility PrintMotd PrintLastLog Banner "
[ -d /etc/ssh/sshd_config.d ] || { echo "Dossier sshd_config.d introuvable : aucune modification."; exit 3; }
grep -qE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/' /etc/ssh/sshd_config || { echo "sshd_config n'inclut pas sshd_config.d : aucune modification."; exit 4; }
[ "${#content}" -le 8000 ] || { echo "Contenu trop long."; exit 2; }
printf '%s\n' "$content" | while IFS= read -r line; do
  case "$line" in
    ''|'# '*) continue;;
  esac
  k="${line%% *}"
  case "$allowed" in *" $k "*) ;; *) echo "Mot-clé refusé : $k"; exit 9;; esac
  printf '%s\n' "$line" | grep -Eq '^[A-Za-z]+ [][A-Za-z0-9_.:/@*?!,+^%=-]+( [][A-Za-z0-9_.:/@*?!,+^%=-]+)*$' || { echo "Ligne refusée : $line"; exit 9; }
done || exit 2
if printf '%s\n' "$content" | grep -qx 'PermitRootLogin no' && who | grep -qE '^root[[:space:]].*\('; then echo "Une session root distante est ouverte : modification refusée pour ne pas vous couper."; exit 6; fi
echo "1/4 Instantané de secours (snapper)…"
snapper -c root create -d "Cachy Shield : avant réglages SSH" 2>/dev/null || echo "(instantané impossible : la modification reste réversible)"
bak=""
[ -f "$f" ] && { bak="$f.bak.$$"; cp -p "$f" "$bak" || exit 1; }
if [ -z "$content" ]; then
  echo "2/4 Retrait des réglages de l'application…"
  rm -f "$f"
else
  echo "2/4 Écriture des réglages…"
  printf '%s\n' "$content" > "$f.new" || exit 1
  chmod 0644 "$f.new"
  mv "$f.new" "$f"
fi
restore() { if [ -n "$bak" ]; then mv -f "$bak" "$f"; else rm -f "$f"; fi; }
echo "3/4 Contrôle de la configuration (sshd -t)…"
if ! /usr/bin/sshd -t; then restore; echo "Configuration invalide : modification annulée, rien n'a changé."; exit 5; fi
eff="$(/usr/bin/sshd -T 2>/dev/null)"
printf '%s\n' "$content" | while IFS= read -r line; do
  case "$line" in ''|'# '*) continue;; esac
  k="${line%% *}"; v="${line#* }"
  case "$v" in *' '*|*,*) continue;; esac
  want="$(printf '%s' "$k $v" | tr 'A-Z' 'a-z')"
  got="$(printf '%s\n' "$eff" | grep -i "^$k " | head -1 | tr 'A-Z' 'a-z')"
  [ "$got" = "$want" ] || echo "⚠ $k : la valeur en vigueur diffère (« $got ») : un autre réglage prioritaire ou une normalisation de sshd."
done
echo "4/4 Rechargement de SSH (les sessions ouvertes ne sont pas coupées)…"
reloaded=0
for u in sshd ssh; do
  if systemctl is-active --quiet "$u" 2>/dev/null; then systemctl reload "$u" && reloaded=1; fi
done
[ "$reloaded" = 1 ] || echo "(SSH n'est pas actif : les réglages s'appliqueront à son démarrage)"
[ -n "$bak" ] && rm -f "$bak"
echo "Terminé. Gardez cette session ouverte et testez une NOUVELLE connexion avant de la fermer."
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn known(_: &str) -> Vec<String> {
        vec!["aes256-gcm@openssh.com".into(), "chacha20-poly1305@openssh.com".into(), "aes128-ctr".into()]
    }
    fn v(k: &str, raw: &str) -> Result<String, String> {
        validate_with(opt(k).unwrap(), raw, &known)
    }

    #[test]
    fn catalogue_coherent() {
        let mut seen = std::collections::HashSet::new();
        for o in CATALOGUE {
            assert!(seen.insert(o.key), "doublon {}", o.key);
            assert!(CATEGORIES.contains(&o.cat), "catégorie inconnue pour {}", o.key);
            if let Some(r) = o.rec {
                assert!(validate_with(o, r, &known).is_ok(), "valeur recommandée invalide pour {} : {r}", o.key);
            }
            if let Kind::Enum(vals) = o.kind {
                if o.default != "any" && !o.default.is_empty() && vals.contains(&o.default) {
                    assert!(vals.contains(&o.default));
                }
            }
        }
        assert!(CATALOGUE.len() >= 40);
    }

    /// Compare les valeurs par défaut du catalogue à celles de sshd lui-même (configuration vide, clé d'hôte temporaire : sans droits
    /// administrateur, rien n'est modifié). `cargo test defauts_ssh -- --ignored`
    #[test]
    #[ignore]
    fn defauts_ssh_conformes_a_sshd() {
        let dir = std::env::temp_dir().join(format!("cs-sshdef-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let key = dir.join("hk");
        assert!(std::process::Command::new("/usr/bin/ssh-keygen").args(["-q", "-t", "ed25519", "-N", ""]).arg("-f").arg(&key).status().unwrap().success());
        let out = std::process::Command::new("/usr/bin/sshd").args(["-T", "-f", "/dev/null", "-h"]).arg(&key).output().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        assert!(out.status.success(), "sshd -T a échoué");
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let mut got: HashMap<String, String> = HashMap::new();
        for l in text.lines() {
            if let Some((k, v)) = l.split_once(' ') {
                let e = got.entry(k.to_lowercase()).or_default();
                if !e.is_empty() {
                    e.push(' ');
                }
                e.push_str(v);
            }
        }
        let mut bad = Vec::new();
        for o in CATALOGUE {
            // options sans valeur simple en sortie de sshd (listes vides, textes d'aide, valeurs calculées)
            if matches!(o.key, "ListenAddress" | "AllowUsers" | "DenyUsers" | "AllowGroups" | "DenyGroups" | "AcceptEnv" | "Ciphers" | "KexAlgorithms" | "MACs" | "AuthenticationMethods" | "PrintLastLog" | "Banner") {
                continue;
            }
            let Some(v) = got.get(&o.key.to_lowercase()) else {
                bad.push(format!("{} : absent de la sortie de sshd", o.key));
                continue;
            };
            let v = match v.as_str() {
                "true" => "yes",
                "false" => "no",
                x => x,
            };
            if !v.eq_ignore_ascii_case(o.default) {
                bad.push(format!("{} : catalogue « {} », sshd « {} »", o.key, o.default, v));
            }
        }
        assert!(bad.is_empty(), "défauts du catalogue différents de ceux de sshd :\n{}", bad.join("\n"));
    }

    #[test]
    fn le_script_autorise_exactement_le_catalogue() {

        let line = APPLY_SCRIPT.lines().find(|l| l.starts_with("allowed=")).unwrap();
        let mut script: Vec<&str> = line.trim_start_matches("allowed=\"").trim_end_matches('"').split_whitespace().collect();
        let mut cat: Vec<&str> = CATALOGUE.iter().map(|o| o.key).collect();
        script.sort();
        cat.sort();
        assert_eq!(script, cat, "la liste du script et le catalogue doivent rester identiques");
        for banned in ["Match", "Include", "ForceCommand", "AuthorizedKeysCommand", "HostKey", "ChrootDirectory", "Subsystem"] {
            assert!(!script.contains(&banned), "{banned} ne doit jamais être modifiable");
        }
    }

    #[test]
    fn valeurs_valides_et_refusees() {
        assert_eq!(v("Port", " 2222 ").unwrap(), "2222");
        assert!(v("Port", "0").is_err() && v("Port", "70000").is_err() && v("Port", "22;ls").is_err() && v("Port", "-1").is_err());
        assert_eq!(v("PermitRootLogin", "no").unwrap(), "no");
        assert!(v("PermitRootLogin", "maybe").is_err() && v("PermitRootLogin", "no; reboot").is_err());
        assert!(v("X11Forwarding", "oui").is_err() && v("X11Forwarding", "yes").is_ok());
        assert_eq!(v("LogLevel", "VERBOSE").unwrap(), "VERBOSE");
        assert!(v("LogLevel", "verbose").is_err());
        assert_eq!(v("AllowUsers", "demo  admin@192.168.0.* ").unwrap(), "demo admin@192.168.0.*");
        assert!(v("AllowUsers", "a;b").is_err() && v("AllowUsers", "$(id)").is_err() && v("AllowUsers", "-x").is_err());
        assert!(v("ListenAddress", "192.168.0.5 [::1]:2222 0.0.0.0:22").is_ok());
        assert!(v("ListenAddress", "999.1.1.1").is_err() && v("ListenAddress", "host.example").is_err());
        assert!(v("Banner", "/etc/issue.net").is_ok() && v("Banner", "none").is_ok());
        assert!(v("Banner", "etc/issue").is_err() && v("Banner", "/etc/../shadow").is_err() && v("Banner", "/etc/a b;c").is_err());
        assert!(v("AuthenticationMethods", "publickey,password").is_ok() && v("AuthenticationMethods", "publickey password").is_ok());
        assert!(v("AuthenticationMethods", "magic").is_err());
        assert!(v("MaxStartups", "10:30:100").is_ok() && v("MaxStartups", "5").is_ok());
        assert!(v("MaxStartups", "10:30").is_err() && v("MaxStartups", "10:200:100").is_err() && v("MaxStartups", "0").is_err());
        assert!(v("AcceptEnv", "LANG LC_*").is_ok() && v("AcceptEnv", "LANG;x").is_err());
        assert!(v("AuthorizedKeysFile", ".ssh/authorized_keys %h/.ssh/keys").is_ok() && v("AuthorizedKeysFile", "/etc/../x").is_err());
    }

    #[test]
    fn algorithmes_controles() {
        assert!(v("Ciphers", "aes256-gcm@openssh.com,chacha20-poly1305@openssh.com").is_ok());
        assert!(v("Ciphers", "+aes128-ctr").is_ok() && v("Ciphers", "-aes128-ctr").is_ok() && v("Ciphers", "^aes128-ctr,aes256-gcm@openssh.com").is_ok());
        assert!(v("Ciphers", "rot13").is_err(), "algorithme inconnu refusé");
        assert!(v("Ciphers", "aes128-ctr,,aes128-ctr").is_err());
        assert!(v("Ciphers", "aes128-ctr;reboot").is_err());
    }

    #[test]
    fn fichier_gere_aller_retour() {
        let s: Vec<(&'static str, String)> = vec![("PermitRootLogin", "no".into()), ("Port", "2222".into()), ("ListenAddress", "10.0.0.1 [::1]:22".into()), ("MaxAuthTries", "3".into())];
        let t = render(&s);
        assert!(t.starts_with("# Géré par Cachy Shield."));
        assert!(t.contains("Port 2222\n") && t.contains("ListenAddress 10.0.0.1\nListenAddress [::1]:22\n"));
        let back = parse_managed(&t);
        assert_eq!(back.get("PermitRootLogin").map(String::as_str), Some("no"));
        assert_eq!(back.get("ListenAddress").map(String::as_str), Some("10.0.0.1 [::1]:22"));
        assert_eq!(render(&[]), "", "aucun réglage : fichier supprimé");
        // l'ordre suit le catalogue (Port avant PermitRootLogin)
        assert!(t.find("Port ").unwrap() < t.find("PermitRootLogin").unwrap());
    }

    #[test]
    fn lecture_ignore_commentaires_et_match() {
        let l = parse_lines("# c\nPort 22\n  PermitRootLogin   no \nPasswordAuthentication=yes\nMatch User x\nX11Forwarding yes\n");
        assert_eq!(l, vec![("Port".to_string(), "22".to_string()), ("PermitRootLogin".to_string(), "no".to_string()), ("PasswordAuthentication".to_string(), "yes".to_string())]);
    }

    fn map(p: &[(&'static str, &str)]) -> HashMap<&'static str, String> {
        p.iter().map(|(k, v)| (*k, v.to_string())).collect()
    }

    #[test]
    fn risques_de_verrouillage() {
        let env = SshEnv { user: "demo".into(), has_keys: false };
        let cur = HashMap::new();
        // le clavier interactif (avec PAM = mot de passe) reste ouvert par défaut : pas de verrouillage
        assert!(risks(&map(&[("PasswordAuthentication", "no")]), &cur, &env).is_empty());
        // Arch le désactive (99-archlinux.conf) : sans mot de passe ni clé enregistrée, on est enfermé dehors
        let mut arch0 = HashMap::new();
        arch0.insert("KbdInteractiveAuthentication".to_string(), "no".to_string());
        let r = risks(&map(&[("PasswordAuthentication", "no")]), &arch0, &env);
        assert!(r.iter().any(|(l, m)| *l == Level::Confirm && m.contains("aucune n'est enregistrée")), "{r:?}");
        let with_keys = SshEnv { has_keys: true, ..env.clone() };
        assert!(risks(&map(&[("PasswordAuthentication", "no")]), &cur, &with_keys).is_empty(), "avec une clé, désactiver le mot de passe est permis sans alerte");
        let r = risks(&map(&[("PasswordAuthentication", "no"), ("PubkeyAuthentication", "no"), ("KbdInteractiveAuthentication", "no")]), &cur, &with_keys);
        assert!(r.iter().any(|(l, _)| *l == Level::Block));
        // Arch désactive déjà le clavier interactif (valeur lue dans les fichiers)
        let mut arch = HashMap::new();
        arch.insert("KbdInteractiveAuthentication".to_string(), "no".to_string());
        assert!(risks(&map(&[("PasswordAuthentication", "no"), ("PubkeyAuthentication", "no")]), &arch, &with_keys).iter().any(|(l, _)| *l == Level::Block));
        assert!(risks(&map(&[("AllowUsers", "alice bob")]), &cur, &env).iter().any(|(l, m)| *l == Level::Block && m.contains("demo")));
        assert!(risks(&map(&[("AllowUsers", "de*")]), &cur, &env).iter().all(|(l, _)| *l != Level::Block), "le motif correspond à votre compte");
        assert!(risks(&map(&[("DenyUsers", "demo")]), &cur, &env).iter().any(|(l, _)| *l == Level::Block));
        assert!(risks(&map(&[("Port", "2222")]), &cur, &with_keys).iter().any(|(l, m)| *l == Level::Confirm && m.contains("2222")));
        assert!(risks(&map(&[("Port", "22")]), &cur, &with_keys).is_empty());
        assert!(risks(&map(&[("AuthenticationMethods", "password")]), &cur, &with_keys).iter().all(|(l, _)| *l != Level::Block));
        assert!(risks(&map(&[("AuthenticationMethods", "password"), ("PasswordAuthentication", "no")]), &cur, &with_keys).iter().any(|(l, _)| *l == Level::Block));
    }

    /// Exécute le script avec de faux programmes (sshd, systemctl, snapper, who) : valide ses garde-fous sans toucher au système.
    fn run(content: &str, sshd_ok: bool) -> (i32, String, Option<String>) {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("cs-ssh-{}-{}-{}", std::process::id(), content.len(), sshd_ok));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("etc/ssh/sshd_config.d")).unwrap();
        std::fs::create_dir_all(dir.join("bin")).unwrap();
        let etc = dir.join("etc").to_string_lossy().into_owned();
        std::fs::write(dir.join("etc/ssh/sshd_config"), format!("Include {etc}/ssh/sshd_config.d/*.conf\n")).unwrap();
        let mk = |n: &str, body: &str| {
            let p = dir.join("bin").join(n);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let sshd = mk("sshd", if sshd_ok { "case \"$1\" in -T) echo 'permitrootlogin no'; echo 'port 2222';; esac; exit 0" } else { "exit 1" });
        let sysctl = mk("systemctl", "echo \"SYSTEMCTL:$*\"; exit 0");
        let _snap = mk("snapper", "exit 0");
        let _who = mk("who", "exit 0");
        let script = APPLY_SCRIPT.replace("/etc/ssh", &format!("{etc}/ssh")).replace("/usr/bin/sshd", &sshd.to_string_lossy());
        let path = format!("{}:{}", dir.join("bin").display(), std::env::var("PATH").unwrap_or_default());
        let _ = sysctl;
        let o = std::process::Command::new("/bin/sh").arg("-c").arg(script).arg("sh").arg(content).env("PATH", path).output().unwrap();
        let managed = std::fs::read_to_string(dir.join("etc/ssh/sshd_config.d/10-cachy-shield.conf")).ok();
        let _ = std::fs::remove_dir_all(&dir);
        (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned(), managed)
    }

    #[test]
    fn le_script_ecrit_valide_et_recharge() {
        let content = render(&[("PermitRootLogin", "no".into()), ("Port", "2222".into())]);
        let (code, out, file) = run(&content, true);
        assert_eq!(code, 0, "{out}");
        assert!(file.as_deref().is_some_and(|f| f.contains("PermitRootLogin no") && f.contains("Port 2222")), "{file:?}");
        assert!(out.contains("SYSTEMCTL:") || out.contains("n'est pas actif"), "{out}");
        assert!(!out.contains('⚠'), "valeurs en vigueur identiques : aucune alerte ({out})");
    }

    #[test]
    fn le_script_annule_si_sshd_refuse() {
        let content = render(&[("PermitRootLogin", "no".into())]);
        let (code, out, file) = run(&content, false);
        assert_eq!(code, 5, "{out}");
        assert!(file.is_none(), "retour arrière : aucun fichier ne reste");
    }

    #[test]
    fn le_script_refuse_tout_ce_qui_sort_du_cadre() {
        for bad in ["Match User x\nPermitRootLogin yes", "Include /etc/passwd", "ForceCommand /bin/sh", "AuthorizedKeysCommand /x", "HostKey /etc/ssh/ssh_host_rsa_key", "Subsystem sftp /x", "Port 22; reboot", "Port $(id)", "Port 22 `id`", "PermitRootLogin no && reboot", "Banner /etc/a b|c", "Port"] {
            let (code, out, file) = run(bad, true);
            assert_ne!(code, 0, "{bad:?} doit être refusé : {out}");
            assert!(file.is_none(), "rien n'est écrit pour {bad:?}");
        }
        // contenu vide : retrait du fichier géré, sans erreur
        let (code, _, file) = run("", true);
        assert_eq!(code, 0);
        assert!(file.is_none());
    }
}
