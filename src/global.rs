//! Failles de TOUS les systèmes et éditeurs (pas seulement Linux), depuis des sources officielles :
//!  - CISA KEV : catalogue des failles activement exploitées (Windows, Apple, Cisco, Linux…)
//!  - NVD (NIST) : catalogue mondial de référence des CVE
//! Les URL sont construites ici uniquement, à partir d'entrées validées ; téléchargement en HTTPS uniquement.

use crate::runner::private_tmpdir;
use crate::tools::Plan;
use crate::util::abs_prog;
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::sync::LazyLock;

pub const KEV_URL: &str = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const NVD_BASE: &str = "https://services.nvd.nist.gov/rest/json/cves/2.0";

// ───────────────────────────── téléchargement ──────────────────────────────

/// Commande curl durcie : HTTPS uniquement (y compris après redirection), TLS ≥ 1.2, taille et durée plafonnées.
/// La réponse est écrite dans un fichier privé géré par le runner (option « -o »).
pub fn fetch_plan(url: &str) -> Result<Plan, String> {
    if !url.starts_with("https://www.cisa.gov/") && !url.starts_with("https://services.nvd.nist.gov/") && !url.starts_with("https://security.archlinux.org/") {
        return Err("source non autorisée".into());
    }
    let curl = abs_prog("curl").ok_or("curl est introuvable")?;
    let mut argv: Vec<String> = [
        "--proto", "=https", "--proto-redir", "=https", "--tlsv1.2", "--fail", "--silent", "--show-error", "--location", "--max-redirs", "3", "--max-time", "180", "--max-filesize", "64000000",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    argv.insert(0, curl.to_string_lossy().into_owned());
    let out_pos = argv.len();
    argv.push(url.to_string());
    Ok(Plan { argv, elevated: false, out_flag: Some("-o"), out_pos })
}

#[allow(dead_code)]
pub fn scratch() -> std::io::Result<std::path::PathBuf> {
    private_tmpdir()
}

// ───────────────────────────────── CISA KEV ────────────────────────────────

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct KevVuln {
    #[serde(rename = "cveID")]
    pub cve: String,
    #[serde(rename = "vendorProject")]
    pub vendor: String,
    pub product: String,
    #[serde(rename = "vulnerabilityName")]
    pub name: String,
    #[serde(rename = "dateAdded")]
    pub added: String,
    #[serde(rename = "dueDate")]
    pub due: String,
    #[serde(rename = "knownRansomwareCampaignUse")]
    pub ransomware: String,
    /// Description officielle de la faille (CISA).
    #[serde(rename = "shortDescription")]
    pub description: String,
    /// Mesure demandée par la CISA (texte officiel, en anglais).
    #[serde(rename = "requiredAction")]
    pub action: String,
}

#[derive(Deserialize, Default, Clone, Debug)]
#[serde(default)]
pub struct Kev {
    #[serde(rename = "catalogVersion")]
    pub version: String,
    #[serde(rename = "dateReleased")]
    pub released: String,
    pub count: u64,
    pub vulnerabilities: Vec<KevVuln>,
}

static RE_CVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^CVE-\d{4}-\d{4,7}$").unwrap());

pub fn is_cve(s: &str) -> bool {
    RE_CVE.is_match(s)
}

/// Contrôle d'intégrité : un catalogue vide ou incohérent est refusé (il ne remplace pas le précédent).
pub fn parse_kev(json: &str) -> Result<Kev, String> {
    let k: Kev = serde_json::from_str(json).map_err(|e| format!("catalogue illisible : {e}"))?;
    if k.vulnerabilities.is_empty() {
        return Err("catalogue vide".into());
    }
    if k.count as usize != k.vulnerabilities.len() {
        return Err(format!("catalogue incohérent ({} annoncées, {} reçues)", k.count, k.vulnerabilities.len()));
    }
    if k.vulnerabilities.iter().any(|v| !is_cve(&v.cve)) {
        return Err("identifiant CVE invalide dans le catalogue".into());
    }
    Ok(k)
}

// ───────────────────────── inventaire des logiciels ────────────────────────

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pkg {
    pub name: String,
    pub version: String,
}

pub fn parse_pacman_q(out: &str) -> Vec<Pkg> {
    out.lines()
        .filter_map(|l| {
            let mut p = l.split_whitespace();
            Some(Pkg { name: p.next()?.to_string(), version: p.next()?.to_string() })
        })
        .collect()
}

pub fn parse_flatpak(out: &str) -> Vec<Pkg> {
    out.lines()
        .filter_map(|l| {
            let mut p = l.split('\t');
            let app = p.next()?.trim();
            let ver = p.next().unwrap_or("").trim();
            let short = app.rsplit('.').next().unwrap_or(app).to_lowercase();
            (!short.is_empty()).then(|| Pkg { name: short, version: ver.to_string() })
        })
        .collect()
}

pub fn inventory() -> Vec<Pkg> {
    let run = |prog: &str, args: &[&str]| -> String {
        abs_prog(prog).and_then(|p| std::process::Command::new(p).args(args).env("LC_ALL", "C").output().ok()).map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
    };
    let mut v = parse_pacman_q(&run("pacman", &["-Q"]));
    v.extend(parse_flatpak(&run("flatpak", &["list", "--columns=application,version"])));
    v
}

// ───────────────────── correspondance avec votre machine ───────────────────

#[derive(Clone, Debug)]
pub struct Matched {
    pub kev: KevVuln,
    pub pkg: Pkg,
}

const STOP: &[&str] = &[
    "windows", "server", "enterprise", "manager", "software", "system", "platform", "service", "services", "control", "data", "center", "application", "applications", "plugin", "plugins",
    "express", "library", "framework", "firmware", "cloud", "mobile", "access", "remote", "client", "desktop", "professional", "edition", "security", "network", "device", "devices", "management",
    "gateway", "portal", "appliance", "office", "exchange", "sharepoint", "internet", "explorer", "protect", "email", "mail", "player", "reader", "studio", "console", "agent", "tools", "suite",
    "file", "files", "code", "android", "core", "kernel", "open", "help", "media", "http", "pulse", "graphics", "processing", "unit", "interface", "engine", "identity", "infrastructure", "management", "center", "support", "archive", "runtime", "environment", "provider", "camera", "wiki", "markup", "firewall", "connect", "secure",
];

fn tokens(s: &str) -> Vec<String> {
    s.to_lowercase().split(|c: char| !c.is_ascii_alphanumeric()).filter(|t| !t.is_empty()).map(String::from).collect()
}

fn squash(s: &str) -> String {
    s.to_lowercase().chars().filter(|c| c.is_ascii_alphanumeric()).collect()
}

/// Correspondance PAR NOM (la version n'est pas comparée) : résultat à vérifier, pas une preuve de vulnérabilité.
/// Chaque faille est rattachée au MEILLEUR paquet candidat (nom exact > premier terme > alias) pour limiter les faux positifs.
pub fn matches(kev: &Kev, inv: &[Pkg]) -> Vec<Matched> {
    let info: Vec<(Vec<String>, String)> = inv.iter().map(|p| (tokens(&p.name), squash(&p.name))).collect();
    let mut out = Vec::new();
    for v in &kev.vulnerabilities {
        let (vendor, product) = (v.vendor.to_lowercase(), v.product.to_lowercase());
        let ptoks = tokens(&v.product);
        let sig: Vec<&String> = ptoks.iter().filter(|t| t.len() >= 4 && !STOP.contains(&t.as_str())).collect();
        let prod_squash = squash(&v.product);
        let is_kernel = product.contains("kernel");
        let is_android = product.contains("android");
        let mut best: Option<(u8, usize)> = None; // (score, index)
        for (i, p) in inv.iter().enumerate() {
            let (pt, ps) = &info[i];
            let mut score = 0u8;
            if vendor == "linux" && is_kernel {
                let excluded = ["firmware", "headers", "api", "docs", "tools", "nvidia", "zfs", "manager", "doc"].iter().any(|x| p.name.contains(x));
                if (p.name == "linux" || p.name.starts_with("linux-")) && !excluded {
                    score = 3;
                }
            } else if !is_kernel {
                let chromium = (product.contains("chromium") || product.contains("chrome")) && !is_android && (p.name.contains("chrome") || p.name.contains("chromium"));
                if prod_squash.len() >= 3 && *ps == prod_squash {
                    score = 4; // nom exact
                } else if chromium {
                    score = 2;
                } else if pt.len() == 1 && sig.iter().any(|t| **t == pt[0]) {
                    score = 3; // paquet à un seul terme, présent dans le nom du produit
                } else if sig.len() == 1 && pt.first().is_some_and(|f| *f == *sig[0]) && pt.len() <= 3 {
                    score = 1; // premier terme du paquet = unique terme significatif du produit
                }
            }
            if score > 0 && best.is_none_or(|(s, bi)| score > s || (score == s && p.name.len() < inv[bi].name.len())) {
                best = Some((score, i));
            }
        }
        if let Some((_, i)) = best {
            out.push(Matched { kev: v.clone(), pkg: inv[i].clone() });
        }
    }
    out
}


// ───────────────────────────────── NVD ─────────────────────────────────────

fn pct(s: &str) -> String {
    s.bytes().map(|b| if b.is_ascii_alphanumeric() || b"-._~".contains(&b) { (b as char).to_string() } else { format!("%{b:02X}") }).collect()
}

static RE_KEYWORD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9 ._:/+-]{2,80}$").unwrap());

/// Recherche par identifiant CVE ou par mot-clé (produit, éditeur…).
pub fn nvd_search_url(query: &str, limit: u32) -> Result<String, String> {
    let q = query.trim();
    let limit = limit.clamp(1, 100);
    if is_cve(&q.to_uppercase()) {
        return Ok(format!("{NVD_BASE}?cveId={}", q.to_uppercase()));
    }
    if !RE_KEYWORD.is_match(q) || q.starts_with('-') {
        return Err("Saisissez un identifiant CVE (CVE-2021-44228) ou un mot-clé simple (2 à 80 caractères : lettres, chiffres, espace, . _ : / + -).".into());
    }
    Ok(format!("{NVD_BASE}?keywordSearch={}&resultsPerPage={limit}", pct(q)))
}

/// Failles critiques publiées depuis `since_unix` (NVD limite la plage à 120 jours).
pub fn nvd_recent_url(now: i64, days: i64) -> String {
    let days = days.clamp(1, 120);
    format!("{NVD_BASE}?cvssV3Severity=CRITICAL&pubStartDate={}&pubEndDate={}&resultsPerPage=100", pct(&iso_utc(now - days * 86_400)), pct(&iso_utc(now)))
}

pub fn nvd_total_url() -> String {
    format!("{NVD_BASE}?resultsPerPage=1")
}

/// Date UTC au format attendu par NVD (algorithme « civil from days » de H. Hinnant).
pub fn iso_utc(unix: i64) -> String {
    let (days, secs) = (unix.div_euclid(86_400), unix.rem_euclid(86_400));
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.000+00:00", secs / 3600, secs % 3600 / 60, secs % 60)
}

#[derive(Clone, Debug, Default)]
pub struct NvdRow {
    pub id: String,
    pub published: String,
    pub score: String,
    pub severity: String,
    pub description: String,
}

#[derive(Clone, Debug, Default)]
pub struct NvdPage {
    pub total: u64,
    pub rows: Vec<NvdRow>,
}

pub fn parse_nvd(json: &str) -> Result<NvdPage, String> {
    let v: Value = serde_json::from_str(json).map_err(|e| format!("réponse NVD illisible : {e}"))?;
    let total = v.get("totalResults").and_then(Value::as_u64).unwrap_or(0);
    let mut rows = Vec::new();
    for item in v.get("vulnerabilities").and_then(Value::as_array).into_iter().flatten() {
        let Some(cve) = item.get("cve") else { continue };
        let id = cve.get("id").and_then(Value::as_str).unwrap_or("");
        if !is_cve(id) {
            continue;
        }
        let mut score = String::new();
        let mut sev = "unknown".to_string();
        for k in ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"] {
            if let Some(d) = cve.get("metrics").and_then(|m| m.get(k)).and_then(|a| a.get(0)).and_then(|m| m.get("cvssData")) {
                if let Some(s) = d.get("baseScore").and_then(Value::as_f64) {
                    score = format!("{s:.1}");
                    sev = d.get("baseSeverity").and_then(Value::as_str).unwrap_or("unknown").to_lowercase();
                    break;
                }
            }
        }
        let desc = cve.get("descriptions").and_then(Value::as_array).into_iter().flatten().find(|d| d.get("lang").and_then(Value::as_str) == Some("en")).and_then(|d| d.get("value")).and_then(Value::as_str).unwrap_or("");
        rows.push(NvdRow {
            id: id.into(),
            published: cve.get("published").and_then(Value::as_str).unwrap_or("").chars().take(10).collect(),
            score,
            severity: sev,
            description: desc.chars().take(400).collect(),
        });
    }
    Ok(NvdPage { total, rows })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn kev(items: &[(&str, &str, &str)]) -> Kev {
        Kev {
            version: "t".into(),
            released: "t".into(),
            count: items.len() as u64,
            vulnerabilities: items.iter().map(|(c, v, p)| KevVuln { cve: (*c).into(), vendor: (*v).into(), product: (*p).into(), ..Default::default() }).collect(),
        }
    }

    #[test]
    fn kev_incoherent_refuse() {
        let ok = r#"{"catalogVersion":"1","dateReleased":"x","count":1,"vulnerabilities":[{"cveID":"CVE-2026-19868","vendorProject":"SonicWall","product":"SonicOS SSLVPN"}]}"#;
        assert!(parse_kev(ok).is_ok());
        assert!(parse_kev(&ok.replace("\"count\":1", "\"count\":5")).is_err());
        assert!(parse_kev(&ok.replace("CVE-2026-19868", "../etc")).is_err());
        assert!(parse_kev(r#"{"count":0,"vulnerabilities":[]}"#).is_err());
        assert!(parse_kev("pas du json").is_err());
    }

    #[test]
    fn correspondance_par_nom() {
        let k = kev(&[("CVE-2025-1000", "Linux", "Kernel"), ("CVE-2025-1001", "Google", "Chromium V8"), ("CVE-2025-1002", "Microsoft", "Windows"), ("CVE-2025-1003", "Sudo", "Sudo"), ("CVE-2025-1004", "Cisco", "IOS XE")]);
        let inv = parse_pacman_q("linux-zen 7.3.0-5\nlinux-firmware 2026-1\ngoogle-chrome 157.0\nsudo 1.9.17\nttf-google-fonts 1\nbash 5.3\n");
        let m: Vec<String> = matches(&k, &inv).iter().map(|x| format!("{}={}", x.kev.cve, x.pkg.name)).collect();
        assert!(m.contains(&"CVE-2025-1000=linux-zen".to_string()), "{m:?}");
        assert!(m.contains(&"CVE-2025-1001=google-chrome".to_string()), "{m:?}");
        assert!(m.contains(&"CVE-2025-1003=sudo".to_string()), "{m:?}");
        assert!(!m.iter().any(|x| x.starts_with("CVE-2025-1002")), "Windows ne doit pas correspondre");
        assert!(!m.iter().any(|x| x.contains("ttf-google-fonts")), "l'éditeur seul ne suffit pas");
    }

    #[test]
    fn urls_nvd_validees() {
        assert!(nvd_search_url("CVE-2021-44228", 10).unwrap().ends_with("cveId=CVE-2021-44228"));
        assert!(nvd_search_url("chrome", 10).unwrap().contains("keywordSearch=chrome"));
        assert!(nvd_search_url("a b&x=1", 10).is_err());
        assert!(nvd_search_url("-rf", 10).is_err());
        assert!(nvd_search_url("x", 10).is_err());
        assert!(nvd_search_url("apache log4j", 10).unwrap().contains("apache%20log4j"));
    }

    #[test]
    fn dates_iso() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00.000+00:00");
        assert_eq!(iso_utc(1_794_130_000), "2026-11-08T09:26:40.000+00:00");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00.000+00:00", "année bissextile");
        assert!(nvd_recent_url(1_794_130_000, 7).contains("pubStartDate=2026-11-01T09%3A26%3A40.000%2B00%3A00"));
    }

    #[test]
    fn nvd_json() {
        let j = r#"{"totalResults":421096,"vulnerabilities":[{"cve":{"id":"CVE-2021-44228","published":"2021-12-10T10:15:09.143","descriptions":[{"lang":"en","value":"Apache Log4j2"}],"metrics":{"cvssMetricV31":[{"cvssData":{"baseScore":10.0,"baseSeverity":"CRITICAL"}}]}}},{"cve":{"id":"pas-un-cve"}}]}"#;
        let p = parse_nvd(j).unwrap();
        assert_eq!(p.total, 421_096);
        assert_eq!(p.rows.len(), 1, "un identifiant invalide est ignoré");
        assert_eq!(p.rows[0].score, "10.0");
        assert_eq!(p.rows[0].severity, "critical");
    }

    #[test]
    fn telechargement_https_et_hotes_autorises() {
        assert!(fetch_plan("http://www.cisa.gov/x").is_err());
        assert!(fetch_plan("https://evil.example/x").is_err());
        assert!(fetch_plan(KEV_URL).is_ok());
    }
}

#[cfg(test)]
mod diagnostic {
    use super::*;
    use std::collections::BTreeMap;

    /// Diagnostic manuel : `cargo test diagnostic -- --ignored --nocapture`
    #[test]
    #[ignore]
    fn correspondances_reelles() {
        let kev = parse_kev(&crate::util::load_private("kev.json", 16 << 20).expect("kev.json")).unwrap();
        let inv = inventory();
        let m = matches(&kev, &inv);
        let mut by_pkg: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for x in &m {
            by_pkg.entry(format!("{} ({})", x.pkg.name, x.kev.product)).or_default().push(x.kev.cve.clone());
        }
        println!("{} correspondances, {} logiciels", m.len(), by_pkg.len());
        let mut v: Vec<_> = by_pkg.iter().collect();
        v.sort_by_key(|(_, c)| std::cmp::Reverse(c.len()));
        for (k, c) in v.iter().take(40) {
            println!("{:4}  {k}", c.len());
        }
    }
}

// ───────────── date de construction des paquets installés (pour estimer si une faille est déjà corrigée) ─────────────

/// Jours depuis le 1er janvier 1970 (calendrier grégorien).
fn days_from_civil(y: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// « Fri Oct 30 09:52:40 2026 » (sortie de pacman -Qi en langue C) -> secondes Unix.
pub fn parse_pacman_date(s: &str) -> Option<i64> {
    let p: Vec<&str> = s.split_whitespace().collect();
    if p.len() < 5 {
        return None;
    }
    let m = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"].iter().position(|x| *x == p[1])? as i64 + 1;
    let d: i64 = p[2].parse().ok()?;
    let y: i64 = p[4].parse().ok()?;
    let t: Vec<i64> = p[3].split(':').filter_map(|x| x.parse().ok()).collect();
    if t.len() != 3 || !(1..=31).contains(&d) || !(1970..=2200).contains(&y) {
        return None;
    }
    Some(days_from_civil(y, m, d) * 86_400 + t[0] * 3600 + t[1] * 60 + t[2])
}

/// « 2026-09-09 » -> secondes Unix (minuit UTC).
pub fn parse_iso_day(s: &str) -> Option<i64> {
    let p: Vec<i64> = s.get(..10)?.split('-').filter_map(|x| x.parse().ok()).collect();
    if p.len() != 3 || !(1..=12).contains(&p[1]) || !(1..=31).contains(&p[2]) {
        return None;
    }
    Some(days_from_civil(p[0], p[1], p[2]) * 86_400)
}

/// nom du paquet -> date de construction (pacman -Qi).
pub fn parse_build_dates(out: &str) -> std::collections::HashMap<String, i64> {
    let mut map = std::collections::HashMap::new();
    for block in out.split("\n\n") {
        let (mut name, mut date) = (None, None);
        for l in block.lines() {
            if let Some((k, v)) = l.split_once(':') {
                match k.trim() {
                    "Name" => name = Some(v.trim().to_string()),
                    "Build Date" => date = parse_pacman_date(v.trim()),
                    _ => {}
                }
            }
        }
        if let (Some(n), Some(d)) = (name, date) {
            map.insert(n, d);
        }
    }
    map
}

pub fn build_dates() -> std::collections::HashMap<String, i64> {
    let out = abs_prog("pacman").and_then(|p| std::process::Command::new(p).args(["-Qi"]).env("LC_ALL", "C").output().ok()).map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default();
    parse_build_dates(&out)
}

#[cfg(test)]
mod build_tests {
    use super::*;

    #[test]
    fn dates_de_paquets() {
        assert_eq!(parse_pacman_date("Fri Jan  1 00:00:00 1960"), None, "année hors plage refusée");
        assert_eq!(parse_pacman_date("Fri Oct 30 09:52:40 2026"), Some(1_793_353_960));
        assert_eq!(parse_iso_day("2026-09-09"), Some(1_788_912_000));
        assert!(parse_pacman_date("n'importe quoi").is_none());
        let m = parse_build_dates("Name            : chromium\nVersion         : 1\nBuild Date      : Fri Oct 30 09:52:40 2026\n\nName            : bash\nBuild Date      : Wed Oct 21 16:29:38 2026\n");
        assert!(m["chromium"] > m["bash"]);
    }
}
