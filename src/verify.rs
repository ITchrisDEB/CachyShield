//! Vérification d'une alerte de fichier contre la base de paquets : « ce fichier est-il bien celui du paquet officiel ? »
//! pacman compare chaque fichier à l'empreinte SHA256 enregistrée à l'installation (`pacman -Qkk`).
//! Une alerte rkhunter sur un fichier intact d'un paquet officiel est un faux positif.

use crate::util::abs_prog;
use regex::Regex;
use std::collections::HashMap;
use std::process::Command;
use std::sync::LazyLock;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Fichier fourni par un paquet officiel, identique à l'empreinte d'origine.
    Official { pkg: String, version: String },
    /// Fichier d'un paquet mais DIFFÉRENT de l'original.
    Modified { pkg: String },
    /// Aucun paquet ne possède ce fichier.
    Unknown,
    /// Fichier de service créé par le système lui-même (ex. marqueur de mise à jour de systemd).
    Marker { what: String },
    /// Fichier temporaire d'un programme en cours d'exécution (ex. mémoire partagée de PostgreSQL).
    Runtime { program: String },
}

static RE_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(/(?:usr|bin|sbin|lib|lib64|etc|opt|var|dev)/[A-Za-z0-9._+/-]+)").unwrap());
static RE_OWNER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r" is owned by (\S+) (\S+)\s*$").unwrap());
#[cfg(test)]
static RE_TOTAL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(\d+) total files, (\d+) altered files").unwrap());

/// Premier chemin de fichier cité dans le texte d'une alerte.
pub fn path_in(text: &str) -> Option<String> {
    RE_PATH.captures(text).map(|c| c[1].to_string())
}

/// « /usr/bin/egrep is owned by grep 3.12-2.1 » → (grep, 3.12-2.1)
pub fn parse_owner(out: &str) -> Option<(String, String)> {
    out.lines().find_map(|l| RE_OWNER.captures(l.trim()).map(|c| (c[1].to_string(), c[2].to_string())))
}

/// Le fichier `path` figure-t-il parmi les fichiers altérés d'après la sortie de `pacman -Qkk` ?
/// (les fichiers de configuration « backup file » modifiés par l'utilisateur sont normaux et ignorés)
pub fn is_altered(qkk: &str, path: &str) -> bool {
    qkk.lines().any(|l| {
        let l = l.trim();
        !l.starts_with("backup file:") && l.contains(path) && (l.contains("mismatch") || l.contains("missing") || l.contains("Permissions"))
    })
}

#[cfg(test)]
pub fn total_altered(qkk: &str) -> Option<usize> {
    RE_TOTAL.captures(qkk).and_then(|c| c[2].parse().ok())
}

fn pacman(args: &[&str]) -> String {
    abs_prog("pacman").and_then(|p| Command::new(p).args(args).env("LC_ALL", "C").output().ok()).map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))).unwrap_or_default()
}

/// Vérifie une liste de chemins (en lecture seule, sans droits administrateur). Un paquet n'est contrôlé qu'une fois.
pub fn verify_all(paths: &[String]) -> HashMap<String, Verdict> {
    let mut qkk_cache: HashMap<String, String> = HashMap::new();
    let mut out = HashMap::new();
    for p in paths {
        if out.contains_key(p) || !p.starts_with('/') || p.contains("..") {
            continue;
        }
        let verdict = match parse_owner(&pacman(&["-Qo", p])) {
            None => known_runtime_file(p).unwrap_or(Verdict::Unknown),
            Some((pkg, version)) => {
                let qkk = qkk_cache.entry(pkg.clone()).or_insert_with(|| pacman(&["-Qkk", &pkg]));
                if is_altered(qkk, p) { Verdict::Modified { pkg } } else { Verdict::Official { pkg, version } }
            }
        };
        out.insert(p.clone(), verdict);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chemin_dans_une_alerte() {
        assert_eq!(path_in("/usr/bin/egrep  [ Warning ]").as_deref(), Some("/usr/bin/egrep"));
        assert_eq!(path_in("Checking if SSH root access is allowed  [ Warning ]"), None);
    }

    #[test]
    fn proprietaire_du_fichier() {
        assert_eq!(parse_owner("/usr/bin/egrep is owned by grep 3.12-2.1\n"), Some(("grep".into(), "3.12-2.1".into())));
        assert_eq!(parse_owner("error: No package owns /tmp/x"), None);
    }

    #[test]
    fn fichier_intact_malgre_un_fichier_de_config_modifie() {
        let qkk = "backup file: glibc: /etc/locale.gen (Size mismatch)\nbackup file: glibc: /etc/locale.gen (SHA256 checksum mismatch)\nglibc: 1637 total files, 0 altered files\n";
        assert!(!is_altered(qkk, "/usr/bin/ldd"));
        assert!(!is_altered(qkk, "/etc/locale.gen"), "un backup file modifié par l'utilisateur est normal");
        assert_eq!(total_altered(qkk), Some(0));
    }

    #[test]
    fn fichier_systeme_modifie_detecte() {
        let qkk = "warning: grep: /usr/bin/egrep (SHA256 checksum mismatch)\ngrep: 120 total files, 1 altered files\n";
        assert!(is_altered(qkk, "/usr/bin/egrep"));
        assert!(!is_altered(qkk, "/usr/bin/fgrep"));
        assert_eq!(total_altered(qkk), Some(1));
    }
}

/// Le contenu est-il bien celui d'un marqueur écrit par systemd-update-done ?
pub fn is_systemd_marker(content: &str) -> bool {
    content.contains("created by systemd-update-done") && content.lines().any(|l| l.starts_with("TIMESTAMP_NSEC="))
}

/// Un nom de fichier de mémoire partagée de PostgreSQL ?
pub fn is_postgres_shm(path: &str) -> bool {
    path.starts_with("/dev/shm/PostgreSQL.") && path[20..].chars().all(|c| c.is_ascii_digit()) && path.len() > 20
}

fn username_of(uid: u32) -> Option<String> {
    std::fs::read_to_string("/etc/passwd").ok()?.lines().find_map(|l| {
        let p: Vec<&str> = l.split(':').collect();
        (p.len() > 2 && p[2].parse::<u32>().ok() == Some(uid)).then(|| p[0].to_string())
    })
}

fn process_running(user: &str, comm: &str) -> bool {
    abs_prog("ps")
        .and_then(|p| Command::new(p).args(["-eo", "user=,comm="]).output().ok())
        .map(|o| String::from_utf8_lossy(&o.stdout).lines().any(|l| l.split_whitespace().collect::<Vec<_>>() == [user, comm]))
        .unwrap_or(false)
}

/// Fichiers qu'aucun paquet ne possède mais qui sont normaux : vérifié par le contenu et le propriétaire, pas seulement par le nom.
pub fn known_runtime_file(path: &str) -> Option<Verdict> {
    use std::os::unix::fs::MetadataExt;
    if matches!(path, "/etc/.updated" | "/var/.updated") {
        let c = std::fs::read_to_string(path).ok()?;
        return is_systemd_marker(&c).then(|| Verdict::Marker { what: "Marqueur de mise à jour créé par systemd (systemd-update-done)".into() });
    }
    if is_postgres_shm(path) {
        let uid = std::fs::metadata(path).ok()?.uid();
        let user = username_of(uid)?;
        return process_running(&user, "postgres").then(|| Verdict::Runtime { program: format!("PostgreSQL (utilisateur {user})") });
    }
    None
}

#[cfg(test)]
mod tests_runtime {
    use super::*;

    #[test]
    fn marqueur_systemd() {
        assert!(is_systemd_marker("# This file was created by systemd-update-done. The timestamp\nTIMESTAMP_NSEC=1793690303962342956\n"));
        assert!(!is_systemd_marker("TIMESTAMP_NSEC=1\n"), "le nom seul ne suffit pas");
        assert!(!is_systemd_marker("rootkit"));
    }

    #[test]
    fn memoire_partagee_postgres() {
        assert!(is_postgres_shm("/dev/shm/PostgreSQL.2594536624"));
        assert!(!is_postgres_shm("/dev/shm/PostgreSQL."));
        assert!(!is_postgres_shm("/dev/shm/PostgreSQL.12;rm"));
        assert!(!is_postgres_shm("/tmp/PostgreSQL.123"));
    }
}
