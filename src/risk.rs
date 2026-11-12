//! Évaluation du risque des correctifs : prévient AVANT d'appliquer une mise à jour
//! ou une mise à niveau de dépendances qui pourrait bloquer le système ou casser un projet.

use regex::Regex;
use serde_json::Value;
use std::sync::LazyLock;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RiskLevel {
    High,
    Medium,
}

#[derive(Clone, Debug)]
pub struct Risk {
    pub level: RiskLevel,
    pub message: &'static str,
    pub packages: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Update {
    pub name: String,
    pub old: String,
    pub new: String,
}

struct Rule {
    pat: Regex,
    level: RiskLevel,
    message: &'static str,
}

const KERNEL_MSG: &str = "Noyau : redémarrage obligatoire ensuite. Les modules externes (NVIDIA, VirtualBox, DKMS) doivent correspondre au nouveau noyau, sinon l'affichage graphique ou les machines virtuelles peuvent ne plus démarrer.";

/// Paquets de noyau installés sur CETTE machine : chaque noyau Arch (et dérivés) installe /usr/lib/modules/<version>/pkgbase avec le nom de son paquet.
fn installed_kernels() -> Vec<String> {
    let Ok(rd) = std::fs::read_dir("/usr/lib/modules") else { return vec![] };
    rd.flatten().filter_map(|e| std::fs::read_to_string(e.path().join("pkgbase")).ok()).map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

const PYTHON_MSG: &str = "Python change de version mineure : vos environnements virtuels (venv) et paquets pip doivent être recréés, vos projets Python peuvent cesser de fonctionner.";

static RULES: LazyLock<Vec<Rule>> = LazyLock::new(|| {
    use RiskLevel::*;
    [
        (r"^linux(-(lts|zen|hardened|rt)(-.*)?)?$", High, KERNEL_MSG),
        (r"^(nvidia.*|.*-dkms|virtualbox-host.*|vboxhost.*)$", High, "Module noyau / pilote graphique : une incompatibilité peut empêcher l'affichage au prochain démarrage."),
        (r"^(grub.*|mkinitcpio.*|systemd-boot.*|refind|limine.*)$", High, "Démarrage : une erreur peut empêcher le système de démarrer (snapper permet de revenir en arrière)."),
        (r"^(linux-firmware.*|intel-ucode|amd-ucode)$", Medium, "Firmware / microcode : pris en compte au prochain redémarrage."),
        (r"^(glibc|gcc-libs|systemd(-libs|-sysvcompat)?|pam|shadow|util-linux(-libs)?|sudo|polkit|openssl|coreutils|bash|filesystem)$", Medium, "Composant essentiel du système : redémarrez juste après la mise à jour."),
        (r"^(plasma-.*|kwin|sddm.*|qt6-base|kde-.*|kf6-.*)$", Medium, "Bureau KDE / Qt : fermez et rouvrez la session (ou redémarrez) après la mise à jour."),
        (r"^openssh$", Medium, "sshd redémarre : une session SSH ouverte peut être coupée."),
        (r"^(libvirt|qemu(-.*)?|virtualbox)$", Medium, "Virtualisation : arrêtez vos machines virtuelles avant."),
    ]
    .into_iter()
    .map(|(p, level, message)| Rule { pat: Regex::new(p).unwrap(), level, message })
    .collect()
});

/// Analyse la sortie de `checkupdates` / `pacman -Qu` (« nom ancienne -> nouvelle »).
pub fn parse_updates(out: &str) -> Vec<Update> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(\S+)\s+(\S+)\s+->\s+(\S+)").unwrap());
    out.lines()
        .filter_map(|l| RE.captures(l.trim()))
        .map(|c| Update { name: c[1].into(), old: c[2].into(), new: c[3].into() })
        .collect()
}

fn minor_of(v: &str) -> Option<String> {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?:\d+:)?(\d+\.\d+)").unwrap());
    RE.captures(v).map(|c| c[1].to_string())
}

/// Regroupe les mises à jour à risque par explication, les plus graves d'abord.
pub fn assess(updates: &[Update]) -> Vec<Risk> {
    let mut groups: Vec<Risk> = Vec::new();
    let kernels = installed_kernels();
    for u in updates {
        let hit = if u.name == "python" && minor_of(&u.old) != minor_of(&u.new) && minor_of(&u.old).is_some() {
            Some((RiskLevel::Medium, PYTHON_MSG))
        } else {
            RULES.iter().find(|r| r.pat.is_match(&u.name)).map(|r| (r.level, r.message)).or_else(|| kernels.contains(&u.name).then_some((RiskLevel::High, KERNEL_MSG)))
        };
        if let Some((level, message)) = hit {
            match groups.iter_mut().find(|g| g.message == message) {
                Some(g) => g.packages.push(u.name.clone()),
                None => groups.push(Risk { level, message, packages: vec![u.name.clone()] }),
            }
        }
    }
    groups.sort_by_key(|g| g.level != RiskLevel::High);
    groups
}

// ───────────────────── mises à niveau de dépendances npm ───────────────────

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    Major,
    Minor,
    Patch,
}

#[derive(Clone, Debug)]
pub struct Change {
    pub name: String,
    pub old: String,
    pub new: String,
    pub kind: Kind,
}

fn nums(v: &str) -> [u64; 3] {
    let mut it = v.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()).map(|s| s.parse().unwrap_or(0));
    [it.next().unwrap_or(0), it.next().unwrap_or(0), it.next().unwrap_or(0)]
}

/// Compare deux package-lock.json et classe chaque changement (majeur = risque de casse).
pub fn lock_changes(old: &str, new: &str) -> Vec<Change> {
    let (Ok(a), Ok(b)) = (serde_json::from_str::<Value>(old), serde_json::from_str::<Value>(new)) else { return vec![] };
    let (Some(a), Some(b)) = (a.get("packages").and_then(Value::as_object), b.get("packages").and_then(Value::as_object)) else { return vec![] };
    let mut out = Vec::new();
    for (k, nv) in b {
        let (Some(ov), Some(n)) = (a.get(k), nv.get("version").and_then(Value::as_str)) else { continue };
        let Some(o) = ov.get("version").and_then(Value::as_str) else { continue };
        if k.is_empty() || o == n {
            continue;
        }
        let (x, y) = (nums(o), nums(n));
        let kind = if x[0] != y[0] { Kind::Major } else if x[1] != y[1] { Kind::Minor } else { Kind::Patch };
        out.push(Change { name: k.rsplit("node_modules/").next().unwrap_or(k).into(), old: o.into(), new: n.into(), kind });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noyau_et_pilote_sont_a_risque_eleve() {
        let ups = parse_updates("linux-zen 7.3.0-5 -> 7.3.1-1\nnvidia-utils 570.1-1 -> 575.2-1\nfirefox 1-1 -> 2-1\nglibc 2.42-1 -> 2.43-1\n");
        assert_eq!(ups.len(), 4);
        let r = assess(&ups);
        assert_eq!(r[0].level, RiskLevel::High);
        assert!(r.iter().any(|x| x.packages.contains(&"glibc".to_string())));
        assert!(!r.iter().any(|x| x.packages.contains(&"firefox".to_string())));
    }

    #[test]
    fn python_mineure_signalee_mais_pas_le_correctif() {
        let r = assess(&parse_updates("python 3.13.5-1 -> 3.14.0-1\n"));
        assert_eq!(r.len(), 1);
        assert!(r[0].message.contains("venv"));
        assert!(assess(&parse_updates("python 3.13.5-1 -> 3.13.6-1\n")).is_empty());
    }

    #[test]
    fn changements_majeurs_detectes() {
        let old = r#"{"packages":{"":{},"node_modules/vite":{"version":"4.5.0"},"node_modules/a/node_modules/lodash":{"version":"4.17.20"},"node_modules/x":{"version":"1.2.3"}}}"#;
        let new = r#"{"packages":{"":{},"node_modules/vite":{"version":"5.0.1"},"node_modules/a/node_modules/lodash":{"version":"4.17.21"},"node_modules/x":{"version":"1.2.3"}}}"#;
        let c = lock_changes(old, new);
        assert_eq!(c.len(), 2);
        assert_eq!(c.iter().find(|x| x.name == "vite").unwrap().kind, Kind::Major);
        assert_eq!(c.iter().find(|x| x.name == "lodash").unwrap().kind, Kind::Patch);
    }
}
