//! Dernière version connue d'un paquet installé : dépôts officiels (`pacman -Si`) ou AUR (interface publique, https).
//! Sert à dire clairement « il existe une mise à jour » ou « votre version est la plus récente qui existe ».
//! Seul le NOM du paquet est envoyé à l'AUR, uniquement pour les paquets qui ne viennent pas des dépôts officiels.

use crate::util::{abs_prog, now_unix};
use std::collections::HashMap;
use std::process::{Command, Stdio};
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub installed: String,
    pub latest: String,
    /// « dépôts <votre distribution> » (nom lu dans /etc/os-release) ou « AUR ».
    pub source: String,
}

const TTL: i64 = 3600;

fn cache() -> &'static Mutex<HashMap<String, (i64, Option<Info>)>> {
    static C: OnceLock<Mutex<HashMap<String, (i64, Option<Info>)>>> = OnceLock::new();
    C.get_or_init(|| Mutex::new(HashMap::new()))
}

fn name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 100 && !n.starts_with('-') && n.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c))
}

fn pacman(args: &[&str]) -> Option<String> {
    let o = Command::new(abs_prog("pacman")?).env("LC_ALL", "C").args(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    o.status.success().then(|| String::from_utf8_lossy(&o.stdout).into_owned())
}

/// Première valeur du champ « Version » d'une sortie `pacman -Si`.
pub fn parse_si_version(out: &str) -> Option<String> {
    out.lines().find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim() == "Version").then(|| v.trim().to_string()).filter(|v| !v.is_empty())
    })
}

/// Version d'un paquet dans la réponse JSON de l'AUR (`/rpc/v5/info`).
pub fn parse_aur_version(json: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    v.get("results")?.as_array()?.first()?.get("Version")?.as_str().map(String::from)
}

fn aur_version(name: &str) -> Option<String> {
    let curl = abs_prog("curl")?;
    let url = format!("https://aur.archlinux.org/rpc/v5/info?arg[]={name}");
    let o = Command::new(curl)
        .args(["--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "--fail", "--silent", "--globoff", "--max-time", "10", "--max-filesize", "1000000", &url])
        .stdin(Stdio::null())
        .stderr(Stdio::null())
        .output()
        .ok()?;
    o.status.success().then(|| parse_aur_version(&String::from_utf8_lossy(&o.stdout))).flatten()
}

fn one(name: &str) -> Option<Info> {
    if !name_ok(name) {
        return None;
    }
    let installed = pacman(&["-Q", name])?.split_whitespace().nth(1)?.to_string();
    if let Some(v) = pacman(&["-Si", name]).as_deref().and_then(parse_si_version) {
        return Some(Info { installed, latest: v, source: crate::i18n::tr("dépôts {distro}").replace("{distro}", &crate::util::distro_name()) });
    }
    aur_version(name).map(|latest| Info { installed, latest, source: "AUR".into() })
}

/// Informations sur ces paquets (résultats gardés une heure en mémoire).
pub fn lookup(pkgs: &[String]) -> HashMap<String, Info> {
    let mut out = HashMap::new();
    for p in pkgs {
        let cached = cache().lock().ok().and_then(|c| c.get(p).filter(|(t, _)| now_unix() - t < TTL).map(|(_, i)| i.clone()));
        let info = match cached {
            Some(i) => i,
            None => {
                let i = one(p);
                if let Ok(mut c) = cache().lock() {
                    c.insert(p.clone(), (now_unix(), i.clone()));
                }
                i
            }
        };
        if let Some(i) = info {
            out.insert(p.clone(), i);
        }
    }
    out
}

/// Ligne affichée dans le détail d'une bibliothèque (les segments séparés par « · » sont traduits un à un).
pub fn describe(pkg: &str, i: &Info) -> String {
    let rel = match crate::tracker::vercmp_native(&i.latest, &i.installed) {
        0 => "identique à la vôtre : aucune mise à jour n'existe",
        x if x > 0 => "plus récente que la vôtre : une mise à jour existe",
        _ => "plus ancienne que la vôtre : rien à mettre à jour",
    };
    format!("Paquet « {pkg} » · version installée {} · dernière version connue {} ({}) · {rel}", i.installed, i.latest, i.source)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lecture_pacman_et_aur() {
        let si = "Repository      : extra\nName            : duf\nVersion         : 0.9.1-1.1\nDescription     : Version : x\n";
        assert_eq!(parse_si_version(si), Some("0.9.1-1.1".into()));
        assert_eq!(parse_si_version("rien"), None);
        let aur = r#"{"version":5,"resultcount":1,"results":[{"Name":"example-ide-bin","Version":"2.3.10-1"}],"type":"multiinfo"}"#;
        assert_eq!(parse_aur_version(aur), Some("2.3.10-1".into()));
        assert_eq!(parse_aur_version(r#"{"resultcount":0,"results":[]}"#), None);
        assert_eq!(parse_aur_version("pas du json"), None);
    }

    #[test]
    fn nom_de_paquet_valide_seulement() {
        assert!(name_ok("example-ide-bin") && name_ok("python-pillow") && name_ok("libc++"));
        assert!(!name_ok("-rf") && !name_ok("a b") && !name_ok("a;b") && !name_ok("") && !name_ok("a/../b") && !name_ok("a&arg[]=b"));
    }

    #[test]
    fn phrase_selon_la_comparaison() {
        let mk = |i: &str, l: &str| Info { installed: i.into(), latest: l.into(), source: "AUR".into() };
        assert!(describe("x", &mk("2.3.10-1", "2.3.10-1")).contains("identique à la vôtre : aucune mise à jour n'existe"));
        assert!(describe("x", &mk("2.3.9-1", "2.3.10-1")).contains("une mise à jour existe"));
        assert!(describe("x", &mk("2.4-1", "2.3-1")).contains("rien à mettre à jour"));
    }
}
