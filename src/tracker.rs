//! Arch Security Tracker : une entrée « Vulnerable » sans correctif noté ne concerne pas forcément votre version.
//! On compare la version AFFECTÉE (selon le tracker) à la version INSTALLÉE : si la vôtre est plus récente,
//! l'entrée est très probablement obsolète (le tracker ne note jamais de correctif pour elle).
//! Ce n'est pas une certitude absolue : le tracker ne dit pas quelle version corrige.

use serde::Deserialize;
use std::collections::{HashMap, HashSet};
use std::process::Command;

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Avg {
    pub name: String,
    pub packages: Vec<String>,
    pub status: String,
    pub affected: String,
    pub fixed: Option<String>,
    pub issues: Vec<String>,
}

pub fn parse(json: &str) -> Vec<Avg> {
    serde_json::from_str(json).unwrap_or_default()
}

/// Comparaison de versions d'Arch (celle de pacman). 1 si `a` est plus récente que `b`, -1 si plus ancienne, 0 sinon ou en cas d'erreur.
pub fn vercmp(a: &str, b: &str) -> i32 {
    if a.is_empty() || b.is_empty() || a.starts_with('-') || b.starts_with('-') {
        return 0;
    }
    Command::new("/usr/bin/vercmp").arg(a).arg(b).output().ok().and_then(|o| String::from_utf8_lossy(&o.stdout).trim().parse().ok()).unwrap_or(0)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Obsolete {
    pub avg: String,
    pub affected: String,
    pub installed: String,
}

/// Paquets dont TOUTES les entrées ouvertes visent une version plus ancienne que celle installée.
/// `only` : paquets à examiner (ceux qu'arch-audit signale).
pub fn obsolete_packages(avgs: &[Avg], installed: &HashMap<String, String>, only: &HashSet<String>, cmp: &dyn Fn(&str, &str) -> i32) -> HashMap<String, Vec<Obsolete>> {
    let mut stale: HashMap<String, Vec<Obsolete>> = HashMap::new();
    let mut concerned: HashSet<String> = HashSet::new();
    for e in avgs.iter().filter(|e| e.status == "Vulnerable" && e.fixed.as_deref().unwrap_or("").is_empty()) {
        for p in e.packages.iter().filter(|p| only.contains(*p)) {
            let Some(iv) = installed.get(p) else {
                concerned.insert(p.clone());
                continue;
            };
            if cmp(iv, &e.affected) > 0 {
                stale.entry(p.clone()).or_default().push(Obsolete { avg: e.name.clone(), affected: e.affected.clone(), installed: iv.clone() });
            } else {
                concerned.insert(p.clone());
            }
        }
    }
    stale.retain(|p, _| !concerned.contains(p));
    stale
}

#[cfg(test)]
mod tests {
    use super::*;

    fn naive(a: &str, b: &str) -> i32 {
        let n = |s: &str| s.split(|c: char| !c.is_ascii_digit()).filter(|x| !x.is_empty()).map(|x| x.parse::<u64>().unwrap_or(0)).collect::<Vec<_>>();
        match n(a).cmp(&n(b)) {
            std::cmp::Ordering::Greater => 1,
            std::cmp::Ordering::Less => -1,
            _ => 0,
        }
    }

    fn avg(name: &str, pkg: &str, affected: &str, fixed: Option<&str>) -> Avg {
        Avg { name: name.into(), packages: vec![pkg.into()], status: "Vulnerable".into(), affected: affected.into(), fixed: fixed.map(String::from), issues: vec![] }
    }

    #[test]
    fn version_installee_plus_recente_est_obsolete() {
        let inst = HashMap::from([("linux".to_string(), "7.2.14".to_string()), ("pam".to_string(), "1.7.3".to_string())]);
        let only: HashSet<String> = ["linux".to_string(), "pam".to_string()].into();
        let v = vec![avg("AVG-1594", "linux", "5.15.8", None), avg("AVG-2901", "pam", "1.7.0", None)];
        let o = obsolete_packages(&v, &inst, &only, &naive);
        assert_eq!(o.len(), 2);
        assert_eq!(o["linux"][0].affected, "5.15.8");
    }

    #[test]
    fn meme_version_ou_plus_ancienne_reste_concernee() {
        let inst = HashMap::from([("openssl".to_string(), "3.5.0".to_string())]);
        let only: HashSet<String> = ["openssl".to_string()].into();
        let v = vec![avg("AVG-1", "openssl", "3.5.0", None)];
        assert!(obsolete_packages(&v, &inst, &only, &naive).is_empty());
    }

    #[test]
    fn une_seule_entree_reelle_suffit_a_garder_le_paquet() {
        let inst = HashMap::from([("perl".to_string(), "5.44.0".to_string())]);
        let only: HashSet<String> = ["perl".to_string()].into();
        let v = vec![avg("AVG-A", "perl", "5.34.0", None), avg("AVG-B", "perl", "5.44.0", None)];
        assert!(obsolete_packages(&v, &inst, &only, &naive).is_empty(), "une entrée encore valable : le paquet reste signalé");
    }

    #[test]
    fn entree_avec_correctif_ignoree() {
        let inst = HashMap::from([("x".to_string(), "2.0".to_string())]);
        let only: HashSet<String> = ["x".to_string()].into();
        let v = vec![avg("AVG-1", "x", "1.0", Some("1.5"))];
        assert!(obsolete_packages(&v, &inst, &only, &naive).is_empty(), "déjà traitée par arch-audit");
    }

    #[test]
    fn vercmp_reel_de_pacman() {
        assert_eq!(vercmp("7.2.14.arch1-1", "5.15.8.arch1-1"), 1);
        assert_eq!(vercmp("1:3.7.9-1.1", "1:2.4.1-4"), 1);
        assert_eq!(vercmp("1.7.0-2", "1.7.3-1.1"), -1);
        assert_eq!(vercmp("-x", "1"), 0, "une valeur suspecte n'est jamais passée à vercmp");
    }
}

// ───────────────────── delta réel : version installée / version corrigée ─────────────────────

/// Comparaison de versions d'Arch (algorithme de libalpm, « rpmvercmp »), sans lancer de processus.
fn rpmvercmp(a: &str, b: &str) -> i32 {
    if a == b {
        return 0;
    }
    let (a, b) = (a.as_bytes(), b.as_bytes());
    let (mut i, mut j) = (0usize, 0usize);
    while i < a.len() && j < b.len() {
        while i < a.len() && !a[i].is_ascii_alphanumeric() {
            i += 1;
        }
        while j < b.len() && !b[j].is_ascii_alphanumeric() {
            j += 1;
        }
        if i >= a.len() || j >= b.len() {
            break;
        }
        let (si, sj) = (i, j);
        let numeric = a[i].is_ascii_digit();
        if numeric {
            while i < a.len() && a[i].is_ascii_digit() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_digit() {
                j += 1;
            }
        } else {
            while i < a.len() && a[i].is_ascii_alphabetic() {
                i += 1;
            }
            while j < b.len() && b[j].is_ascii_alphabetic() {
                j += 1;
            }
        }
        let (mut x, mut y) = (&a[si..i], &b[sj..j]);
        if y.is_empty() {
            return if numeric { 1 } else { -1 }; // segments de nature différente : le numérique l'emporte
        }
        if numeric {
            while x.first() == Some(&b'0') {
                x = &x[1..];
            }
            while y.first() == Some(&b'0') {
                y = &y[1..];
            }
            if x.len() != y.len() {
                return if x.len() > y.len() { 1 } else { -1 };
            }
        }
        match x.cmp(y) {
            std::cmp::Ordering::Greater => return 1,
            std::cmp::Ordering::Less => return -1,
            _ => {}
        }
    }
    if i >= a.len() && j >= b.len() {
        return 0;
    }
    let (one_end, two_alpha, one_alpha) = (i >= a.len(), b.get(j).is_some_and(u8::is_ascii_alphabetic), a.get(i).is_some_and(u8::is_ascii_alphabetic));
    if (one_end && !two_alpha) || one_alpha { -1 } else { 1 }
}

/// « époque:version-release » : 1 si `a` est plus récente que `b`, -1 si plus ancienne, 0 si égales.
pub fn vercmp_native(a: &str, b: &str) -> i32 {
    let split = |v: &str| -> (i64, String, Option<String>) {
        let (epoch, rest) = match v.split_once(':') {
            Some((e, r)) if e.chars().all(|c| c.is_ascii_digit()) && !e.is_empty() => (e.parse().unwrap_or(0), r),
            _ => (0, v),
        };
        match rest.rsplit_once('-') {
            Some((ver, rel)) => (epoch, ver.to_string(), Some(rel.to_string())),
            None => (epoch, rest.to_string(), None),
        }
    };
    let ((ea, va, ra), (eb, vb, rb)) = (split(a), split(b));
    if ea != eb {
        return if ea > eb { 1 } else { -1 };
    }
    let c = rpmvercmp(&va, &vb);
    if c != 0 {
        return c;
    }
    match (ra, rb) {
        (Some(x), Some(y)) => rpmvercmp(&x, &y),
        _ => 0,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// La version installée contient le correctif (ou n'est pas concernée).
    Fixed,
    /// La version installée est concernée et aucun correctif n'est installé.
    Vulnerable,
    /// Le tracker ne dit rien de ce paquet pour cette CVE.
    Unknown,
}

/// Index CVE -> entrées du tracker d'Arch.
#[derive(Default)]
pub struct CveIndex {
    avgs: Vec<Avg>,
    by_cve: HashMap<String, Vec<usize>>,
}

impl CveIndex {
    pub fn new(avgs: Vec<Avg>) -> CveIndex {
        let mut by_cve: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, a) in avgs.iter().enumerate() {
            for c in &a.issues {
                by_cve.entry(c.clone()).or_default().push(i);
            }
        }
        CveIndex { avgs, by_cve }
    }

    /// Verdict pour une CVE et un paquet installé, d'après le tracker : le DELTA entre la version installée et la version corrigée.
    pub fn verdict(&self, cve: &str, pkg: &str, installed: &str) -> Verdict {
        let Some(ids) = self.by_cve.get(cve) else { return Verdict::Unknown };
        let (mut seen, mut vulnerable) = (false, false);
        for a in ids.iter().map(|i| &self.avgs[*i]).filter(|a| a.packages.iter().any(|p| p == pkg)) {
            seen = true;
            let fixed = a.fixed.as_deref().unwrap_or("");
            let open = match a.status.as_str() {
                "Not affected" => false,
                _ if !fixed.is_empty() => vercmp_native(installed, fixed) < 0, // installée plus ancienne que la version corrigée
                "Fixed" => false,
                _ => vercmp_native(installed, &a.affected) <= 0, // sans correctif noté : concernée si pas plus récente que la version affectée
            };
            vulnerable |= open;
        }
        match (seen, vulnerable) {
            (false, _) => Verdict::Unknown,
            (true, true) => Verdict::Vulnerable,
            (true, false) => Verdict::Fixed,
        }
    }
}

#[cfg(test)]
mod delta_tests {
    use super::*;

    #[test]
    fn comparaison_de_versions() {
        for (a, b, r) in [("1.0", "1.0", 0), ("1.0.1", "1.0", 1), ("1.0a", "1.0", -1), ("1.0", "1.0a", 1), ("2.0-1", "2.0-2", -1), ("1:1.0", "2.0", 1), ("9.0.1224-1", "9.0.1225-1", -1), ("156.0.8078.79-1", "156.0.8078.79-1", 0), ("1.10", "1.9", 1), ("1.0rc1", "1.0", -1), ("1.0.0", "1.0", 1)] {
            assert_eq!(vercmp_native(a, b), r, "{a} vs {b}");
            assert_eq!(vercmp_native(b, a), -r, "{b} vs {a}");
        }
    }

    #[test]
    fn identique_a_vercmp_du_systeme() {
        if !std::path::Path::new("/usr/bin/vercmp").exists() {
            return;
        }
        for (a, b) in [("1.2.1-1.1", "1.2.1-1"), ("7.3.3-1", "7.3.0-5"), ("1.0.0", "1.0"), ("2.0rc1-1", "2.0-1"), ("1:0.9-1", "5.0-1"), ("3.13.5-1", "3.13.10-1"), ("20260101-1", "2026.01.01-1"), ("1.0_beta", "1.0")] {
            assert_eq!(vercmp_native(a, b), vercmp(a, b), "{a} vs {b}");
        }
    }

    #[test]
    fn verdict_installee_contre_corrigee() {
        let avgs = parse(r#"[{"name":"AVG-1","packages":["chromium"],"status":"Fixed","affected":"155.0-1","fixed":"156.0-1","issues":["CVE-2026-1"]},{"name":"AVG-2","packages":["foo"],"status":"Vulnerable","affected":"1.0-1","fixed":null,"issues":["CVE-2026-2"]}]"#);
        let ix = CveIndex::new(avgs);
        assert_eq!(ix.verdict("CVE-2026-1", "chromium", "156.0-1"), Verdict::Fixed);
        assert_eq!(ix.verdict("CVE-2026-1", "chromium", "155.0-1"), Verdict::Vulnerable);
        assert_eq!(ix.verdict("CVE-2026-2", "foo", "1.0-1"), Verdict::Vulnerable);
        assert_eq!(ix.verdict("CVE-2026-2", "foo", "1.1-1"), Verdict::Fixed);
        assert_eq!(ix.verdict("CVE-2026-9", "foo", "1.0-1"), Verdict::Unknown);
        assert_eq!(ix.verdict("CVE-2026-1", "autre", "1.0-1"), Verdict::Unknown);
    }
}
