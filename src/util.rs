//! Utilitaires de sécurité : validation des entrées, chemins absolus, persistance privée.

use crate::model::ScanResult;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

pub const PKEXEC: &str = "/usr/bin/pkexec";
pub const SH: &str = "/bin/sh";
pub const OUT_END: &str = "@@CS-OUTPUT-END@@";

/// Script exécuté en root. Il est CONSTANT : aucune donnée externe n'y est jamais insérée,
/// les valeurs arrivent uniquement en arguments positionnels. Root écrit dans un dossier
/// créé par `mktemp -d` (propriété de root, 0700) puis renvoie le contenu sur la sortie :
/// aucun fichier appartenant à l'utilisateur n'est écrit ni modifié en root (pas de lien symbolique exploitable).
pub const HELPER_SCRIPT: &str = r#"flag="$1"; shift
d=$(mktemp -d) || exit 1
trap 'rm -rf "$d"' EXIT
"$@" "$flag" "$d/out"
rc=$?
printf '\n@@CS-OUTPUT-BEGIN@@\n'
cat "$d/out" 2>/dev/null
printf '\n@@CS-OUTPUT-END@@\n'
exit $rc
"#;

/// Programme par chemin absolu (jamais de recherche dans $PATH, modifiable par l'utilisateur).
pub fn abs_prog(name: &str) -> Option<PathBuf> {
    ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/bin", "/sbin"]
        .iter()
        .map(|d| Path::new(d).join(name))
        .find(|p| p.exists())
}

// ───────────────────────── validation des entrées ──────────────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Pat {
    Any,
    AbsPath,
    Url,
    UrlOrPath,
    Ident,
    Duration,
    Lang,
    Name,
}

macro_rules! re {
    ($name:ident, $pat:expr) => {
        static $name: LazyLock<Regex> = LazyLock::new(|| Regex::new($pat).expect("regex valide"));
    };
}
re!(RE_ABS, r"^/[^\x00-\x1f\x7f]*$");
re!(RE_URL, r"^(https?|socks5h?)://[^\s\x00-\x1f\x7f]+$");
re!(RE_URL_PATH, r"^(https?://[^\s\x00-\x1f\x7f]+|/[^\x00-\x1f\x7f]+)$");
re!(RE_IDENT, r"^[A-Za-z0-9 _,.:*-]+$");
re!(RE_DURATION, r"^[0-9]{1,6}[smh]$");
re!(RE_LANG, r"^[a-z]{2}(_[A-Z]{2})?$");
re!(RE_NAME, r"^[\w .-]{1,64}$");
re!(RE_ADVISORY, r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$");
re!(RE_ANSI, r"\x1b\[[0-9;?]*[A-Za-z]");

/// Une valeur saisie par l'utilisateur devient un argument de commande : on refuse tout ce qui
/// pourrait être pris pour une option (« -x »), les caractères de contrôle et les formats inattendus.
pub fn validate(label: &str, v: &str, pat: Pat) -> Result<(), String> {
    if v.len() > 4096 {
        return Err(format!("{label} : valeur trop longue"));
    }
    if v.starts_with('-') {
        return Err(format!("{label} : une valeur ne peut pas commencer par « - »"));
    }
    if v.chars().any(|c| c.is_control()) {
        return Err(format!("{label} : caractères de contrôle interdits"));
    }
    let ok = match pat {
        Pat::Any => true,
        Pat::AbsPath => RE_ABS.is_match(v),
        Pat::Url => RE_URL.is_match(v),
        Pat::UrlOrPath => RE_URL_PATH.is_match(v),
        Pat::Ident => RE_IDENT.is_match(v),
        Pat::Duration => RE_DURATION.is_match(v),
        Pat::Lang => RE_LANG.is_match(v),
        Pat::Name => RE_NAME.is_match(v),
    };
    if ok { Ok(()) } else { Err(format!("{label} : format invalide")) }
}

pub fn is_advisory_id(s: &str) -> bool {
    RE_ADVISORY.is_match(s)
}

pub fn strip_ansi(s: &str) -> String {
    RE_ANSI.replace_all(s, "").replace('\r', "\n")
}

// ──────────────────────────── état persistant privé ────────────────────────

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Saved {
    pub result: ScanResult,
    pub rows: Vec<Vec<String>>,
}

/// Règle de pare-feu écrite par l'utilisateur : action (allow/deny/limit), protocole, port, adresse source (vide = n'importe où).
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FwRule {
    pub action: String,
    pub proto: String,
    pub port: u16,
    pub from: String,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct State {
    pub tools: BTreeMap<String, Saved>,
    /// Processus / ports qui écoutent volontairement sur toutes les interfaces (None = jamais initialisé).
    pub allowed: Option<Vec<String>>,
    /// Dernière mise à jour réussie ou non de chaque source de données.
    #[serde(default)]
    pub db: BTreeMap<String, Stamp>,
    #[serde(default)]
    pub settings: Settings,
    /// CVE du catalogue CISA déjà signalées comme concernant vos logiciels (pour ne notifier que les nouvelles).
    #[serde(default)]
    pub kev_seen: Vec<String>,
    /// Date de la dernière analyse intelligente.
    #[serde(default)]
    pub last_smart: i64,
    /// Alertes que l'utilisateur a marquées « c'est normal » (elles ne sont plus signalées, mais peuvent être réaffichées).
    #[serde(default)]
    pub ignored: Vec<String>,
    /// Blocages réseau posés par l'application (valables jusqu'au redémarrage : le pare-feu est en mémoire).
    #[serde(default)]
    pub blocks: Vec<BlockRec>,
    /// Règles de pare-feu personnalisées (modifiables sans activer le pare-feu ; appliquées à son activation).
    #[serde(default)]
    pub fw_rules: Vec<FwRule>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlockRec {
    /// "port" (accès depuis le réseau) ou "host" (connexions sortantes vers un serveur)
    pub kind: String,
    pub proto: String,
    pub port: u16,
    pub ip: String,
    pub time: i64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Stamp {
    pub time: i64,
    pub ok: bool,
}

const MAX_ROWS: usize = 3000;
const MAX_CELL: usize = 2000;
const MAX_STATE_BYTES: u64 = 64 * 1024 * 1024;

/// Identifiant numérique de l'utilisateur courant (lu dans /proc, sans code non sûr).
fn current_uid() -> Option<u32> {
    std::fs::read_to_string("/proc/self/status").ok()?.lines().find_map(|l| l.strip_prefix("Uid:")).and_then(|r| r.split_whitespace().next()).and_then(|v| v.parse().ok())
}

/// Entrée de l'utilisateur courant dans /etc/passwd : (nom, dossier personnel).
fn passwd_entry() -> Option<(String, PathBuf)> {
    let uid = current_uid()?;
    std::fs::read_to_string("/etc/passwd").ok()?.lines().find_map(|l| {
        let f: Vec<&str> = l.split(':').collect();
        (f.len() >= 6 && f[2].parse::<u32>().ok() == Some(uid)).then(|| (f[0].to_string(), PathBuf::from(f[5])))
    })
}

/// Dossier personnel de l'utilisateur courant : la variable d'environnement HOME si elle est valide, sinon l'entrée de /etc/passwd.
/// Jamais un chemin écrit en dur.
pub fn home_dir() -> Option<PathBuf> {
    std::env::var_os("HOME").map(PathBuf::from).filter(|p| p.is_absolute() && p.is_dir()).or_else(|| passwd_entry().map(|(_, h)| h).filter(|p| p.is_absolute() && p.is_dir()))
}

/// Nom de l'utilisateur courant : /etc/passwd (fiable), sinon USER / LOGNAME.
pub fn current_user() -> String {
    passwd_entry().map(|(n, _)| n).or_else(|| std::env::var("USER").ok()).or_else(|| std::env::var("LOGNAME").ok()).unwrap_or_default()
}

/// Nom de la distribution de l'utilisateur, lu dans /etc/os-release (PRETTY_NAME, sinon NAME) ; « Linux » à défaut. Jamais écrit en dur.
pub fn distro_name() -> String {
    let text = std::fs::read_to_string("/etc/os-release").or_else(|_| std::fs::read_to_string("/usr/lib/os-release")).unwrap_or_default();
    parse_distro(&text)
}

pub fn parse_distro(text: &str) -> String {
    let get = |k: &str| text.lines().find_map(|l| l.strip_prefix(k).and_then(|r| r.strip_prefix('=')).map(|v| v.trim().trim_matches(['"', '\'']).to_string())).filter(|v| !v.is_empty());
    get("PRETTY_NAME").or_else(|| get("NAME")).unwrap_or_else(|| "Linux".into())
}

/// Dossier de base XDG
/// (`var` = XDG_DATA_HOME, XDG_CONFIG_HOME, XDG_CACHE_HOME) ou, à défaut, `~/<repli>`.
pub fn xdg_dir(var: &str, fallback: &str) -> Option<PathBuf> {
    std::env::var_os(var).map(PathBuf::from).filter(|p| p.is_absolute()).or_else(|| home_dir().map(|h| h.join(fallback)))
}

pub fn state_dir() -> PathBuf {
    // sans dossier personnel utilisable : un dossier PRIVÉ de /tmp propre à l'utilisateur (jamais un nom partagé)
    let base = xdg_dir("XDG_DATA_HOME", ".local/share").unwrap_or_else(|| PathBuf::from(format!("/tmp/cachy-shield-{}", current_uid().unwrap_or(0))));
    base.join("cachy-shield")
}

/// Ancien nom du programme : ses dossiers (réglages, résultats, cache) sont repris sous le nom actuel,
/// une seule fois et sans jamais rien écraser.
const LEGACY_DIR: &str = "centre-securite";

fn migrate_in(base: &Path) {
    let (old, new) = (base.join(LEGACY_DIR), base.join("cachy-shield"));
    if old.is_dir() && !new.exists() {
        let _ = fs::rename(&old, &new);
    }
}

pub fn migrate_legacy_dirs() {
    for (var, fallback) in [("XDG_DATA_HOME", ".local/share"), ("XDG_CONFIG_HOME", ".config"), ("XDG_CACHE_HOME", ".cache")] {
        if let Some(base) = xdg_dir(var, fallback) {
            migrate_in(&base);
        }
    }
}


pub fn load_state() -> State {
    let path = state_dir().join("state-v2.json");
    let Ok(meta) = fs::metadata(&path) else { return State::default() };
    if meta.len() > MAX_STATE_BYTES || !meta.is_file() {
        return State::default();
    }
    let Ok(bytes) = fs::read(&path) else { return State::default() };
    let mut st: State = serde_json::from_slice(&bytes).unwrap_or_default();
    for s in st.tools.values_mut() {
        s.rows.truncate(MAX_ROWS);
    }
    st
}

/// Écriture atomique (fichier temporaire + rename), dossier 0700 et fichier 0600 :
/// les résultats d'un audit de sécurité ne doivent pas être lisibles par les autres comptes.
pub fn save_state(state: &State) -> std::io::Result<()> {
    let dir = state_dir();
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    let mut copy = state.clone();
    for s in copy.tools.values_mut() {
        s.rows.truncate(MAX_ROWS);
        for r in &mut s.rows {
            for c in r.iter_mut() {
                if c.len() > MAX_CELL {
                    c.truncate(c.floor_char_boundary(MAX_CELL));
                }
            }
        }
    }
    let tmp = dir.join(format!(".state-{}.tmp", std::process::id()));
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(&serde_json::to_vec(&copy)?)?;
    f.sync_all()?;
    fs::rename(&tmp, dir.join("state-v2.json")).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

pub fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reprise_des_anciens_dossiers() {
        let base = std::env::temp_dir().join(format!("cs-migr-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join(LEGACY_DIR)).unwrap();
        fs::write(base.join(LEGACY_DIR).join("state-v2.json"), "{}").unwrap();
        migrate_in(&base);
        assert!(base.join("cachy-shield").join("state-v2.json").is_file() && !base.join(LEGACY_DIR).exists());
        // un dossier déjà présent n'est jamais écrasé
        fs::create_dir_all(base.join(LEGACY_DIR)).unwrap();
        migrate_in(&base);
        assert!(base.join(LEGACY_DIR).is_dir() && base.join("cachy-shield").join("state-v2.json").is_file());
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn refuse_injection_d_options() {
        assert!(validate("x", "-rf", Pat::Any).is_err());
        assert!(validate("x", "a\nb", Pat::Any).is_err());
        assert!(validate("x", "ok", Pat::Any).is_ok());
    }

    #[test]
    fn formats() {
        assert!(validate("x", "/etc/lynis/custom.prf", Pat::AbsPath).is_ok());
        assert!(validate("x", "/", Pat::AbsPath).is_ok(), "la racine est la cible par défaut de Trivy");
        assert!(validate("x", "relatif/chemin", Pat::AbsPath).is_err());
        assert!(validate("x", "https://security.archlinux.org/", Pat::Url).is_ok());
        assert!(validate("x", "file:///etc/passwd", Pat::Url).is_err());
        assert!(validate("x", "10m", Pat::Duration).is_ok());
        assert!(validate("x", "10; rm -rf /", Pat::Duration).is_err());
        assert!(validate("x", "SSH-7440 FIRE-4590", Pat::Ident).is_ok());
        assert!(validate("x", "a;b", Pat::Ident).is_err());
    }

    #[test]
    fn identifiants_cve() {
        assert!(is_advisory_id("CVE-2025-6020"));
        assert!(is_advisory_id("GHSA-23c5-xmqv-rm74"));
        assert!(!is_advisory_id("CVE/../../evil"));
        assert!(!is_advisory_id("a b"));
        assert!(!is_advisory_id("x"));
    }

    #[test]
    fn ansi() {
        assert_eq!(strip_ansi("\x1b[1;32mok\x1b[0m"), "ok");
    }
}

// ──────────────────────────── cache privé de données ───────────────────────

/// Écrit un fichier de cache (0600, atomique) dans le dossier privé de l'application.
pub fn save_private(name: &str, bytes: &[u8]) -> std::io::Result<()> {
    if name.contains('/') || name.starts_with('.') {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "nom de fichier invalide"));
    }
    let dir = state_dir();
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    let tmp = dir.join(format!(".{name}-{}.tmp", std::process::id()));
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    f.write_all(bytes)?;
    f.sync_all()?;
    fs::rename(&tmp, dir.join(name)).inspect_err(|_| {
        let _ = fs::remove_file(&tmp);
    })
}

pub fn load_private(name: &str, max: u64) -> Option<String> {
    let p = state_dir().join(name);
    let m = fs::metadata(&p).ok()?;
    (m.is_file() && m.len() <= max).then(|| fs::read_to_string(p).ok()).flatten()
}

/// Réglages de l'utilisateur.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default)]
pub struct Settings {
    /// Met à jour automatiquement les bases de CVE (catalogue CISA, base Trivy), sans droits administrateur.
    pub auto_update: bool,
    /// Inclut Lynis et rkhunter dans l'analyse intelligente (demande le mot de passe administrateur).
    pub include_admin: bool,
    /// Dossiers de projets à analyser (choisis par l'utilisateur) ; vide = aucun.
    pub project_dirs: Vec<String>,
    /// L'assistant de premier lancement a été terminé (ou fermé).
    pub first_run_done: bool,
    /// Journaliser les connexions refusées par le pare-feu.
    pub fw_log: bool,
    /// Icône dans la zone de notification (la fermeture de la fenêtre la laisse alors active en arrière-plan).
    pub tray: bool,
    /// Notifications du bureau (nouveau port exposé, tentatives d'intrusion, analyse terminée…).
    pub notifications: bool,
    /// Les anciens résultats Trivy (qui incluaient vos dossiers personnels) ont été retirés une fois.
    pub sys_scope_v2: bool,
    /// Autorisation administrateur demandée une seule fois, au démarrage (assistant root), plutôt qu'à chaque action.
    pub single_auth: bool,
    /// Signature des dernières mises à jour déjà notifiées (évite de répéter la même notification).
    pub notified_updates: String,
    /// Heure (Unix) de la dernière notification de mises à jour : rappel au bout de 24 h si elles sont toujours en attente.
    pub notified_at: i64,
    /// Pare-feu choisi par l'utilisateur : « auto » (détecté), « ufw », « firewalld » ou « nftables ».
    pub fw_backend: String,
    /// Langue de l'interface : « auto » (langue du système) ou un code (fr, en, de…).
    pub language: String,
}

impl Default for Settings {
    fn default() -> Self {
        Settings { auto_update: true, include_admin: false, project_dirs: Vec::new(), first_run_done: false, fw_log: false, tray: true, notifications: true, sys_scope_v2: false, single_auth: true, notified_updates: String::new(), notified_at: 0, fw_backend: "auto".into(), language: "auto".into() }
    }
}

#[cfg(test)]
mod tests_home {
    use super::*;

    #[test]
    fn nom_de_distribution_lu_dans_os_release() {
        assert_eq!(parse_distro("NAME=\"Demo Linux\"\nPRETTY_NAME=\"DemoOS\"\nID=demo\n"), "DemoOS");
        assert_eq!(parse_distro("NAME='Other'\nID=o\n"), "Other");
        assert_eq!(parse_distro(""), "Linux");
        assert!(!distro_name().is_empty());
    }

    #[test]
    fn dossier_personnel_jamais_en_dur() {
        let h = home_dir().expect("un dossier personnel valide");
        assert!(h.is_absolute() && h.is_dir());
        assert!(!current_user().is_empty());
        // le dossier de données dérive de l'environnement de l'utilisateur courant, jamais d'une valeur fixe
        let s = state_dir();
        assert!(s.ends_with("cachy-shield"));
        if std::env::var_os("XDG_DATA_HOME").is_none() {
            assert_eq!(s, h.join(".local/share/cachy-shield"));
        }
    }
}
