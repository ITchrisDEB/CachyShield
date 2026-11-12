//! Définition des cinq outils : options, construction des commandes, analyse des résultats.
//! Aucune interface graphique ici : tout est testable (`cargo test`).

use crate::model::{Level, Outcome, ScanResult, level_from_counts};
use crate::util::{Pat, abs_prog, now_unix, validate};
use regex::Regex;
use serde::Deserialize;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::Path;
use std::sync::LazyLock;

// ─────────────────────────────── options ───────────────────────────────────

pub type Choices = &'static [(&'static str, &'static str)];

#[derive(Clone, Copy)]
pub enum Kind {
    Section,
    Check,
    Text(Pat),
    Path,
    Combo(Choices),
    Int(u32, u32),
    Multi(Choices),
}

#[derive(Clone, Copy)]
pub enum Def {
    None,
    B(bool),
    S(&'static str),
    L(&'static [&'static str]),
    Dyn(fn() -> String),
}

#[derive(Clone, Copy)]
pub struct OptDef {
    pub key: &'static str,
    pub kind: Kind,
    pub label: &'static str,
    pub flag: Option<&'static str>,
    pub tip: &'static str,
    pub def: Def,
}

#[derive(Clone, Debug)]
pub enum Val {
    B(bool),
    S(String),
    I(u32),
    L(Vec<String>),
}

#[derive(Clone, Debug, Default)]
pub struct Values(pub HashMap<String, Val>);

impl Values {
    pub fn b(&self, k: &str) -> bool {
        matches!(self.0.get(k), Some(Val::B(true)))
    }
    pub fn s(&self, k: &str) -> &str {
        match self.0.get(k) {
            Some(Val::S(s)) => s.trim(),
            _ => "",
        }
    }
    pub fn i(&self, k: &str) -> u32 {
        match self.0.get(k) {
            Some(Val::I(i)) => *i,
            _ => 0,
        }
    }
    pub fn l(&self, k: &str) -> &[String] {
        match self.0.get(k) {
            Some(Val::L(l)) => l,
            _ => &[],
        }
    }
}

fn sec(label: &'static str) -> OptDef {
    OptDef { key: "", kind: Kind::Section, label, flag: None, tip: "", def: Def::None }
}
fn chk(key: &'static str, label: &'static str, flag: &'static str, tip: &'static str, on: bool) -> OptDef {
    OptDef { key, kind: Kind::Check, label, flag: Some(flag), tip, def: Def::B(on) }
}
fn chk_nf(key: &'static str, label: &'static str, tip: &'static str, on: bool) -> OptDef {
    OptDef { key, kind: Kind::Check, label, flag: None, tip, def: Def::B(on) }
}
fn txt(key: &'static str, label: &'static str, flag: Option<&'static str>, tip: &'static str, pat: Pat, def: Def) -> OptDef {
    OptDef { key, kind: Kind::Text(pat), label, flag, tip, def }
}
fn path(key: &'static str, label: &'static str, flag: Option<&'static str>, tip: &'static str, def: Def) -> OptDef {
    OptDef { key, kind: Kind::Path, label, flag, tip, def }
}
fn combo(key: &'static str, label: &'static str, flag: Option<&'static str>, tip: &'static str, ch: Choices, def: &'static str) -> OptDef {
    OptDef { key, kind: Kind::Combo(ch), label, flag, tip, def: Def::S(def) }
}
fn int(key: &'static str, label: &'static str, flag: &'static str, tip: &'static str, max: u32) -> OptDef {
    OptDef { key, kind: Kind::Int(0, max), label, flag: Some(flag), tip, def: Def::None }
}
fn multi(key: &'static str, label: &'static str, flag: &'static str, tip: &'static str, ch: Choices, def: &'static [&'static str]) -> OptDef {
    OptDef { key, kind: Kind::Multi(ch), label, flag: Some(flag), tip, def: Def::L(def) }
}

/// Transforme les valeurs saisies en arguments, en validant chacune.
pub fn flags(defs: &[OptDef], v: &Values) -> Result<Vec<String>, String> {
    let mut out = Vec::new();
    for o in defs {
        let Some(flag) = o.flag else { continue };
        match o.kind {
            Kind::Section => {}
            Kind::Check => {
                if v.b(o.key) {
                    out.push(flag.to_string());
                }
            }
            Kind::Text(pat) => {
                let s = v.s(o.key);
                if !s.is_empty() {
                    validate(o.label, s, pat)?;
                    out.extend([flag.to_string(), s.to_string()]);
                }
            }
            Kind::Path => {
                let s = v.s(o.key);
                if !s.is_empty() {
                    validate(o.label, s, Pat::AbsPath)?;
                    out.extend([flag.to_string(), s.to_string()]);
                }
            }
            Kind::Combo(choices) => {
                let s = v.s(o.key);
                if !s.is_empty() {
                    if !choices.iter().any(|(_, val)| *val == s) {
                        return Err(format!("{} : choix inconnu", o.label));
                    }
                    out.extend([flag.to_string(), s.to_string()]);
                }
            }
            Kind::Int(_, _) => {
                if v.i(o.key) > 0 {
                    out.extend([flag.to_string(), v.i(o.key).to_string()]);
                }
            }
            Kind::Multi(choices) => {
                let l = v.l(o.key);
                if l.iter().any(|x| !choices.iter().any(|(_, val)| val == x)) {
                    return Err(format!("{} : choix inconnu", o.label));
                }
                if !l.is_empty() {
                    out.extend([flag.to_string(), l.join(",")]);
                }
            }
        }
    }
    Ok(out)
}

// ─────────────────────────────── outils ────────────────────────────────────

pub struct Plan {
    pub argv: Vec<String>,
    pub elevated: bool,
    /// Option qui désigne le fichier de résultat ; position d'insertion en mode non privilégié.
    pub out_flag: Option<&'static str>,
    pub out_pos: usize,
}

pub struct Tool {
    pub key: &'static str,
    pub title: &'static str,
    pub desc: &'static str,
    pub columns: &'static [&'static str],
    pub widths: &'static [i32],
    pub sev_col: Option<usize>,
    pub link: Option<(usize, fn(&str) -> Option<String>)>,
    pub options: fn() -> Vec<OptDef>,
    pub build: fn(&Values) -> Result<Plan, String>,
    /// (valeurs, sortie standard filtrée, contenu du fichier de résultat)
    pub parse: fn(&Values, &str, Option<&str>) -> Outcome,
    pub noise: &'static [&'static str],
    pub notice: fn() -> Option<String>,
}

pub fn all() -> Vec<Tool> {
    vec![arch_audit::tool(), lynis::tool(), rkhunter::tool(), trivy::tool(), osv::tool()]
}

fn prog(name: &str) -> Result<String, String> {
    abs_prog(name)
        .map(|p| p.to_string_lossy().into_owned())
        .ok_or_else(|| format!("{name} est introuvable : installez-le avec pacman"))
}


fn no_notice() -> Option<String> {
    None
}

fn counts_of(rows: &[Vec<String>], col: usize) -> BTreeMap<String, u64> {
    let mut m = BTreeMap::new();
    for r in rows {
        *m.entry(r[col].clone()).or_insert(0) += 1;
    }
    m
}

fn finish(rows: Vec<Vec<String>>, headline: String, level: Level, counts: BTreeMap<String, u64>, score: Option<u32>) -> Outcome {
    Outcome { rows, result: ScanResult { headline, level, score, time: now_unix(), counts } }
}

// ───────────────────────────── arch-audit ──────────────────────────────────

pub mod arch_audit {
    use super::*;

    const SEP: char = '\u{1f}';

    pub fn tool() -> Tool {
        Tool {
            key: "arch-audit",
            title: "arch-audit — failles connues dans vos paquets",
            desc: "Compare les paquets installés au tracker de sécurité d'Arch Linux (security.archlinux.org). Les paquets AUR ne sont pas couverts.",
            columns: &["Paquet", "Gravité", "Type", "Correctif", "Nb CVE", "CVE", "Requis par"],
            widths: &[150, 90, 190, 110, 60, 320, 300],
            sev_col: Some(1),
            link: Some((5, |cell| {
                let id = cell.split(',').next()?.trim();
                crate::util::is_advisory_id(id).then(|| format!("https://security.archlinux.org/{id}"))
            })),
            options,
            build,
            parse,
            noise: &[],
            notice: no_notice,
        }
    }

    pub fn options() -> Vec<OptDef> {
        vec![
            sec("Filtres"),
            chk("upg", "Seulement les paquets déjà corrigés (-u)", "-u", "Affiche uniquement les paquets pour lesquels un correctif existe déjà : ce sont ceux à mettre à jour.", false),
            chk("testing", "Inclure les dépôts [testing] (-t)", "-t", "Montre aussi les paquets présents dans les dépôts de test.", false),
            chk("rec", "Paquets dépendants (-r)", "-r", "Ajoute la colonne « Requis par » : paquets qui dépendent d'un paquet vulnérable.", false),
            sec("Tri"),
            combo("sort", "Ordre de tri (--sort)", Some("--sort"), "Critère de tri de la sortie.",
                &[("Gravité puis nom", "severity,pkgname"), ("Nom du paquet", "pkgname"), ("Corrigés d'abord", "upgradable"), ("Inverser", "reverse")],
                "severity,pkgname"),
            sec("Source et réseau"),
            txt("source", "Source des données (--source)", Some("--source"), "URL https ou fichier JSON du tracker de sécurité.", Pat::UrlOrPath, Def::S("")),
            path("dbpath", "Base pacman (--dbpath)", Some("--dbpath"), "Emplacement alternatif de la base pacman.", Def::S("")),
            txt("proxy", "Proxy (--proxy)", Some("--proxy"), "Passer les requêtes par ce proxy (http, https, socks5).", Pat::Url, Def::S("")),
            chk("noproxy", "Ne pas utiliser de proxy (--no-proxy)", "--no-proxy", "Ignore le proxy configuré dans l'environnement.", false),
        ]
    }

    pub fn build(v: &Values) -> Result<Plan, String> {
        let fmt = ["%n", "%s", "%t", "%v", "%c", "%r"].join(&SEP.to_string());
        let mut argv = vec![prog("arch-audit")?, "-f".into(), fmt, "--color".into(), "never".into()];
        argv.extend(flags(&options(), v)?);
        Ok(Plan { argv, elevated: false, out_flag: None, out_pos: 0 })
    }

    fn severity(s: &str) -> &'static str {
        match s.to_lowercase().split_whitespace().next().unwrap_or("") {
            "critical" => "critical",
            "high" => "high",
            "medium" => "medium",
            "low" => "low",
            _ => "unknown",
        }
    }

    pub fn parse(_v: &Values, out: &str, _file: Option<&str>) -> Outcome {
        let mut rows: Vec<Vec<String>> = Vec::new();
        for line in out.lines() {
            let p: Vec<&str> = line.split(SEP).collect();
            if p.len() < 5 {
                continue;
            }
            let cves: Vec<&str> = p[4].split(',').map(str::trim).filter(|c| !c.is_empty()).collect();
            let fixed = if p[3].trim().is_empty() { "aucun" } else { p[3].trim() };
            rows.push(vec![
                p[0].trim().into(),
                severity(p[1]).into(),
                p[2].trim().into(),
                fixed.into(),
                cves.len().to_string(),
                cves.join(", "),
                p.get(5).map(|s| s.trim()).unwrap_or("").into(),
            ]);
        }
        let counts = counts_of(&rows, 1);
        let fixable = rows.iter().filter(|r| r[3] != "aucun").count();
        let level = level_from_counts(&counts, !rows.is_empty());
        let headline = if rows.is_empty() {
            "Aucune faille connue".to_string()
        } else {
            format!("{} paquet(s) vulnérable(s) — {fixable} avec correctif", rows.len())
        };
        finish(rows, headline, level, counts, None)
    }
}

// ─────────────────────────────── Lynis ─────────────────────────────────────

pub mod lynis {
    use super::*;

    pub fn tool() -> Tool {
        Tool {
            key: "lynis",
            title: "Lynis — audit de configuration et de durcissement",
            desc: "Examine SSH, pare-feu, noyau, permissions, comptes, services… et calcule un score de durcissement. Il vérifie la configuration, pas les CVE des paquets. Demande les droits administrateur.",
            columns: &["Type", "Gravité", "Identifiant", "Description", "Détail"],
            widths: &[100, 100, 100, 480, 300],
            sev_col: Some(1),
            link: None,
            options,
            build,
            parse,
            noise: &[],
            notice: no_notice,
        }
    }

    pub fn options() -> Vec<OptDef> {
        vec![
            sec("Mode d'audit"),
            combo("mode", "Mode", None, "Audit complet, test d'intrusion non privilégié ou analyse forensique.",
                &[("Audit système complet", "audit"), ("Pentest non privilégié (--pentest)", "--pentest"), ("Forensique (--forensics)", "--forensics")], "audit"),
            chk("quick", "Mode rapide, sans pauses (--quick)", "--quick", "N'attend pas d'appui sur une touche entre les sections.", true),
            chk_nf("admin", "Exécuter en administrateur (pkexec)", "Nécessaire pour un audit complet. Sans root, de nombreux tests sont ignorés.", true),
            sec("Sélection des tests"),
            txt("tests", "Tests précis (--tests)", Some("--tests"), "Identifiants séparés par des espaces, ex. SSH-7440.", Pat::Ident, Def::S("")),
            txt("group", "Groupes de tests (--tests-from-group)", Some("--tests-from-group"), "Ex. : ssh, firewall, kernel…", Pat::Ident, Def::S("")),
            chk("skipplug", "Ignorer les plugins (--no-plugins)", "--no-plugins", "Ne charge pas les plugins.", false),
            sec("Affichage et journaux"),
            chk("verbose", "Sortie détaillée (--verbose)", "--verbose", "Affiche plus de détails à l'écran.", false),
            chk("debug", "Mode débogage (--debug)", "--debug", "Journalise les détails de débogage.", false),
            chk("nolog", "Pas de fichier journal (--no-log)", "--no-log", "N'écrit pas /var/log/lynis.log.", false),
            int("slow", "Seuil de test lent, secondes (--slow-warning)", "--slow-warning", "Signale les tests plus lents que ce seuil.", 600),
            sec("Avancé"),
            txt("profile", "Fichier de profil (--profile)", Some("--profile"), "Profil Lynis personnalisé (.prf), chemin absolu.", Pat::AbsPath, Def::S("")),
            txt("auditor", "Nom de l'auditeur (--auditor)", Some("--auditor"), "Nom inscrit dans le rapport.", Pat::Name, Def::S("")),
            path("plugindir", "Dossier de plugins (--plugindir)", Some("--plugindir"), "Dossier de plugins Lynis.", Def::S("")),
        ]
    }

    pub fn build(v: &Values) -> Result<Plan, String> {
        let mode = v.s("mode");
        let mut argv = vec![prog("lynis")?, "audit".into(), "system".into()];
        if mode == "--pentest" || mode == "--forensics" {
            argv.push(mode.into());
        }
        argv.push("--no-colors".into());
        argv.extend(flags(&options(), v)?);
        let out_pos = argv.len();
        Ok(Plan { argv, elevated: v.b("admin") && mode != "--pentest", out_flag: Some("--report-file"), out_pos })
    }

    pub fn parse(_v: &Values, out: &str, file: Option<&str>) -> Outcome {
        let mut kv: HashMap<&str, &str> = HashMap::new();
        let (mut warns, mut suggs) = (Vec::new(), Vec::new());
        for line in file.unwrap_or("").lines() {
            if line.starts_with('#') {
                continue;
            }
            let Some((k, val)) = line.split_once('=') else { continue };
            match k {
                "warning[]" => warns.push(val),
                "suggestion[]" => suggs.push(val),
                _ => {
                    kv.insert(k, val);
                }
            }
        }
        let mut rows = Vec::new();
        for (typ, sev, items) in [("Alerte", "warning", &warns), ("Suggestion", "suggestion", &suggs)] {
            for it in items {
                let mut p = it.split('|');
                let id = p.next().unwrap_or("");
                let text = p.next().unwrap_or("");
                let detail: Vec<&str> = p.take(2).filter(|x| !x.is_empty() && *x != "-").collect();
                rows.push(vec![typ.into(), sev.into(), id.into(), text.into(), detail.join(" ")]);
            }
        }
        static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Hardening index\s*:\s*(\d+)").unwrap());
        let score = kv
            .get("hardening_index")
            .and_then(|s| s.trim().parse::<u32>().ok())
            .or_else(|| RE.captures(out).and_then(|c| c[1].parse().ok()))
            .map(|s| s.min(100));
        let (level, headline) = match score {
            None => (Level::None, format!("{} alerte(s), {} suggestion(s)", warns.len(), suggs.len())),
            Some(s) => {
                let l = if s >= 80 && warns.is_empty() { Level::Ok } else if s >= 60 { Level::Warn } else { Level::Bad };
                (l, format!("Score {s}/100 — {} alerte(s), {} suggestion(s)", warns.len(), suggs.len()))
            }
        };
        let counts = BTreeMap::from([("warning".to_string(), warns.len() as u64), ("suggestion".to_string(), suggs.len() as u64)]);
        finish(rows, headline, level, counts, score)
    }
}

// ───────────────────────────── rkhunter ────────────────────────────────────

pub mod rkhunter {
    use super::*;

    pub fn tool() -> Tool {
        Tool {
            key: "rkhunter",
            title: "rkhunter — recherche de rootkits et de fichiers modifiés",
            desc: "Compare les fichiers système à une base de référence, cherche des rootkits connus, des processus ou fichiers cachés. Des alertes isolées sont souvent des faux positifs. Demande les droits administrateur.",
            columns: &["Gravité", "Alerte", "Commentaire"],
            widths: &[100, 380, 520],
            sev_col: Some(0),
            link: None,
            options,
            build,
            parse,
            noise: &["egrep: warning", "grep: warning", "grep: avertissement"],
            notice: || {
                (!Path::new("/var/lib/rkhunter/db/rkhunter.dat").exists()).then(|| {
                    "Base de référence absente : lancez d'abord « Mettre à jour les signatures » puis « Initialiser la base de référence », idéalement sur un système que vous savez sain.".to_string()
                })
            },
        }
    }

    pub fn options() -> Vec<OptDef> {
        vec![
            sec("Action"),
            combo("action", "Opération", None, "Choisissez ce que rkhunter doit faire.",
                &[("Analyse complète (--check)", "--check"), ("Mettre à jour les signatures (--update)", "--update"),
                  ("Initialiser la base de référence (--propupd)", "--propupd"), ("Vérifier la version (--versioncheck)", "--versioncheck"),
                  ("Lister les tests (--list)", "--list"), ("Vérifier la configuration (--config-check)", "--config-check")], "--check"),
            sec("Comportement"),
            chk("rwo", "Afficher uniquement les alertes (--report-warnings-only)", "--report-warnings-only", "Réduit la sortie aux avertissements.", false),
            chk("nomail", "Pas de courriel (--no-mail-on-warning)", "--no-mail-on-warning", "N'envoie pas de mail en cas d'alerte.", true),
            chk("syslog", "Écrire dans syslog (--syslog)", "--syslog", "Envoie aussi les alertes à syslog.", false),
            chk("nolog", "Pas de fichier journal (--nolog)", "--nolog", "N'écrit pas /var/log/rkhunter.log.", false),
            chk("append", "Ajouter au journal existant (--appendlog)", "--appendlog", "Conserve les anciens résultats dans le journal.", false),
            sec("Tests"),
            txt("enable", "Activer seulement ces tests (--enable)", Some("--enable"), "Liste séparée par des virgules, ex. : rootkits,hidden_procs", Pat::Ident, Def::S("")),
            txt("disable", "Désactiver ces tests (--disable)", Some("--disable"), "Liste séparée par des virgules, ex. : apps,hidden_ports", Pat::Ident, Def::S("")),
            combo("pkgmgr", "Gestionnaire de paquets (--pkgmgr)", Some("--pkgmgr"),
                "rkhunter ne gère pas pacman : sur Arch, laissez « Aucun » (il utilise sa propre base d'empreintes).",
                &[("Aucun (recommandé sur Arch)", "NONE"), ("Automatique", ""), ("RPM", "RPM"), ("DPKG", "DPKG"), ("BSD", "BSD"), ("Solaris", "SOLARIS")], "NONE"),
            txt("lang", "Langue des messages (--lang)", Some("--lang"), "Code langue, ex. en.", Pat::Lang, Def::S("en")),
            sec("Fichiers"),
            path("cfg", "Fichier de configuration (--configfile)", Some("--configfile"), "Alternative à /etc/rkhunter.conf.", Def::S("")),
            path("logfile", "Fichier journal (--logfile)", Some("--logfile"), "Emplacement du journal.", Def::S("")),
        ]
    }

    pub fn build(v: &Values) -> Result<Plan, String> {
        let action = v.s("action");
        let mut argv = vec![prog("rkhunter")?, action.to_string()];
        if action == "--list" {
            argv.push("tests".into());
        }
        argv.extend(["--skip-keypress".into(), "--nocolors".into()]);
        argv.extend(flags(&options(), v)?);
        // sans chemin de journal choisi par l'utilisateur : le journal est récupéré (détail des fichiers signalés)
        let out_flag = if v.s("logfile").is_empty() && !v.b("nolog") { Some("--logfile") } else { None };
        let out_pos = argv.len();
        Ok(Plan { argv, elevated: true, out_flag, out_pos })
    }

    static NOTES: LazyLock<Vec<(Regex, &'static str)>> = LazyLock::new(|| {
        [
            (r"Hidden file found", "Fichier caché signalé : l'application le compare à la base des paquets pour savoir s'il est normal."),
            (r"Suspicious file in /dev", "Fichier inhabituel dans /dev : l'application vérifie à qui il appartient."),
            (r"/(egrep|fgrep|ldd)\b", "Ce sont des scripts shell et non des binaires : très souvent un faux positif sur Arch."),
            (r"prerequisites", "Un outil requis par rkhunter est un script ou manque : en général sans gravité."),
            (r"passwd file changes|group file changes", "Aucune base de référence : lancez « Initialiser la base de référence » sur un système sain, puis relancez."),
            (r"SSH root access", "PermitRootLogin n'est pas défini explicitement dans sshd_config. Définissez-le à « no » pour faire disparaître l'alerte."),
            (r"SSH protocol v1", "Faux positif fréquent : OpenSSH moderne ne gère plus le protocole 1."),
            (r"/dev for suspicious", "À vérifier : fichiers inhabituels dans /dev (souvent des périphériques virtuels)."),
            (r"hidden files", "À vérifier : fichiers cachés hors des emplacements habituels (souvent des fichiers d'applications)."),
        ]
        .into_iter()
        .map(|(p, n)| (Regex::new(p).unwrap(), n))
        .collect()
    });

    /// Détail des fichiers signalés, lu dans le journal de rkhunter (la sortie écran ne donne que le titre de la vérification).
    pub fn log_details(log: &str) -> Vec<String> {
        static TS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^\[\d{2}:\d{2}:\d{2}\]\s?").unwrap());
        let (mut out, mut in_dev) = (Vec::new(), false);
        for raw in log.lines() {
            let l = TS.replace(raw, "").to_string();
            let t = l.trim();
            if let Some(rest) = t.strip_prefix("Warning: Hidden file found: ") {
                out.push(format!("Hidden file found: {}", rest.split(": ").next().unwrap_or(rest)));
                in_dev = false;
            } else if t.starts_with("Warning: Suspicious file types found in /dev") {
                in_dev = true;
            } else if in_dev && l.starts_with(' ') && t.starts_with('/') {
                out.push(format!("Suspicious file in /dev: {}", t.split(": ").next().unwrap_or(t)));
            } else {
                in_dev = false;
            }
        }
        out
    }

    pub fn parse(v: &Values, out: &str, file: Option<&str>) -> Outcome {
        if v.s("action") != "--check" {
            return Outcome::simple("Opération terminée", Level::None);
        }
        if !out.contains("System checks summary") {
            let err = out.lines().map(str::trim).find(|l| {
                let low = l.to_lowercase();
                ["invalid", "error", "cannot", "unable"].iter().any(|w| low.contains(w))
            });
            let head = match err {
                Some(e) => format!("Analyse non terminée : {e}"),
                None => "Analyse non terminée".into(),
            };
            return Outcome::simple(head, Level::Bad);
        }
        static WARN: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\[\s*(Warning|Vulnerable)\s*\]").unwrap());
        static SPACES: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\s{2,}").unwrap());
        static ROOTKITS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Possible rootkits:\s*(\d+)").unwrap());
        let mut seen = HashSet::new();
        let mut rows = Vec::new();
        for line in out.lines().map(str::trim) {
            // « [ Found ] » est une vérification normale ; seules les lignes Warning comptent.
            let text = if let Some(rest) = line.strip_prefix("Warning:") {
                rest.trim().to_string()
            } else if WARN.is_match(line) {
                SPACES.replace_all(line, "  ").into_owned()
            } else {
                continue;
            };
            if seen.insert(text.clone()) {
                let note = NOTES.iter().find(|(re, _)| re.is_match(&text)).map(|(_, n)| *n).unwrap_or("À examiner.");
                rows.push(vec!["warning".into(), text, note.into()]);
            }
        }
        // le journal donne les fichiers précis : ils remplacent les lignes génériques « hidden files » et « /dev »
        let details = file.map(log_details).unwrap_or_default();
        if !details.is_empty() {
            rows.retain(|r| !(r[1].contains("hidden files and directories") || r[1].contains("/dev for suspicious")));
            for d in details {
                if seen.insert(d.clone()) {
                    let note = NOTES.iter().find(|(re, _)| re.is_match(&d)).map(|(_, n)| *n).unwrap_or("À examiner.");
                    rows.push(vec!["warning".into(), d, note.into()]);
                }
            }
        }
        let rk: u64 = ROOTKITS.captures(out).and_then(|c| c[1].parse().ok()).unwrap_or(0);
        let level = if rk > 0 { Level::Bad } else if rows.is_empty() { Level::Ok } else { Level::Warn };
        let mut head = String::new();
        if rk > 0 {
            head += &format!("{rk} rootkit(s) possible(s), ");
        }
        head += &if rows.is_empty() { "Aucune alerte".to_string() } else { format!("{} alerte(s)", rows.len()) };
        let counts = BTreeMap::from([("warning".to_string(), rows.len() as u64), ("rootkits".to_string(), rk)]);
        finish(rows, head, level, counts, None)
    }
}

// ───────────────────────────────── Trivy ───────────────────────────────────

pub mod trivy {
    use super::*;

    pub fn tool() -> Tool {
        Tool {
            key: "trivy",
            title: "Trivy — bibliothèques, secrets et configurations",
            desc: "Analyse un dossier ou tout le système : dépendances vulnérables (Python, Node, Go, Rust…), secrets exposés, configurations à risque. Trivy ne gère pas les paquets pacman (voir arch-audit). La première analyse télécharge sa base de vulnérabilités.",
            columns: &["Type", "Gravité", "Paquet / règle", "Version", "Correctif", "Identifiant", "Cible", "Description", "Emplacement"],
            widths: &[110, 90, 170, 100, 110, 150, 260, 380, 300],
            sev_col: Some(1),
            link: Some((5, |id| {
                let id = id.trim();
                (id.starts_with("CVE-") || id.starts_with("GHSA-"))
                    .then(|| crate::util::is_advisory_id(id).then(|| format!("https://avd.aquasec.com/nvd/{}", id.to_lowercase())))
                    .flatten()
            })),
            options,
            build,
            parse,
            noise: &[],
            notice: no_notice,
        }
    }

    pub fn options() -> Vec<OptDef> {
        vec![
            sec("Cible"),
            path("target", "Dossier à analyser", None, "Chemin analysé. « / » = tout le système.", Def::S("/")),
            combo("mode", "Type d'analyse", None, "rootfs : système de fichiers complet ; fs : projet de code.",
                &[("Système de fichiers (rootfs)", "rootfs"), ("Projet de code (fs)", "fs")], "rootfs"),
            chk_nf("admin", "Exécuter en administrateur (pkexec)", "Permet de lire les fichiers réservés à root.", false),
            sec("Ce qu'il faut chercher"),
            multi("scanners", "Analyseurs (--scanners)", "--scanners", "Types de problèmes à rechercher.",
                &[("Vulnérabilités (vuln)", "vuln"), ("Secrets (secret)", "secret"), ("Configurations (misconfig)", "misconfig"), ("Licences (license)", "license")], &["vuln"]),
            multi("severity", "Gravités (--severity)", "--severity", "Niveaux de gravité à afficher.",
                &[("Inconnue", "UNKNOWN"), ("Faible", "LOW"), ("Moyenne", "MEDIUM"), ("Élevée", "HIGH"), ("Critique", "CRITICAL")], &["MEDIUM", "HIGH", "CRITICAL"]),
            multi("pkgtypes", "Types de paquets (--pkg-types)", "--pkg-types", "Système ou bibliothèques.",
                &[("Système (os)", "os"), ("Bibliothèques (library)", "library")], &["library"]),
            chk("unfixed", "Ignorer les failles sans correctif (--ignore-unfixed)", "--ignore-unfixed", "Masque les vulnérabilités qu'aucune mise à jour ne corrige encore.", false),
            chk("dev", "Inclure les dépendances de dev (--include-dev-deps) — projets de code seulement", "--include-dev-deps", "Analyse aussi les dépendances de développement. Ignorée en mode « Système de fichiers » (Trivy ne la connaît que pour les projets).", false),
            sec("Exclusions"),
            txt("skipdirs", "Dossiers ignorés (--skip-dirs)", Some("--skip-dirs"), "Séparés par des virgules. Votre dossier personnel est exclu par défaut : vos projets sont analysés à part (bouton « Dossiers… »).", Pat::Any, Def::Dyn(default_skipdirs)),
            txt("skipfiles", "Fichiers ignorés (--skip-files)", Some("--skip-files"), "Séparés par des virgules.", Pat::Any, Def::S("")),
            sec("Base de données et réseau"),
            chk("skipdb", "Ne pas mettre à jour la base (--skip-db-update)", "--skip-db-update", "Utilise la base téléchargée précédemment.", false),
            chk("offline", "Mode hors ligne (--offline-scan)", "--offline-scan", "N'envoie aucune requête externe.", false),
            txt("dbrepo", "Dépôt de la base (--db-repository)", Some("--db-repository"), "Registre OCI alternatif.", Pat::Any, Def::S("")),
            sec("Performance"),
            txt("timeout", "Délai maximum (--timeout)", Some("--timeout"), "Ex. : 10m, 1h.", Pat::Duration, Def::S("30m")),
            int("parallel", "Tâches parallèles (--parallel)", "--parallel", "Nombre de workers.", 64),
            combo("prio", "Priorité de détection (--detection-priority)", Some("--detection-priority"),
                "precise : moins de faux positifs ; comprehensive : plus de résultats.",
                &[("Par défaut", ""), ("Précise", "precise"), ("Exhaustive", "comprehensive")], ""),
        ]
    }

    /// Dossiers ignorés par défaut : pseudo-systèmes, supports amovibles, et le dossier personnel de l'utilisateur courant.
    pub fn default_skipdirs() -> String {
        let mut s = String::from("/proc,/sys,/dev,/run,/tmp,/mnt,/media,/var/lib/libvirt");
        if let Some(h) = crate::util::home_dir().filter(|h| h.as_os_str().len() > 1) {
            let h = h.to_string_lossy().into_owned();
            if !h.contains(',') {
                s.push(',');
                s.push_str(&h);
            }
        }
        s
    }

    pub fn build(v: &Values) -> Result<Plan, String> {
        let target = if v.s("target").is_empty() { "/" } else { v.s("target") };
        validate("Dossier à analyser", target, Pat::AbsPath)?;
        let mode = match v.s("mode") {
            "fs" => "fs",
            _ => "rootfs",
        };
        let mut argv = vec![prog("trivy")?, mode.into(), "--no-progress".into(), "--format".into(), "json".into()];
        argv.extend(flags(&options(), v)?);
        // --include-dev-deps n'existe que pour les projets de code (fs) : en mode système, Trivy échoue avec « unknown flag »
        if mode == "rootfs" {
            argv.retain(|a| a != "--include-dev-deps");
        }
        let out_pos = argv.len();
        argv.push(target.into());
        Ok(Plan { argv, elevated: v.b("admin"), out_flag: Some("--output"), out_pos })
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Report {
        #[serde(rename = "Results")]
        results: Vec<Res>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Res {
        #[serde(rename = "Target")]
        target: String,
        #[serde(rename = "Vulnerabilities")]
        vulns: Vec<Vuln>,
        #[serde(rename = "Secrets")]
        secrets: Vec<Secret>,
        #[serde(rename = "Misconfigurations")]
        misconf: Vec<Misconf>,
        #[serde(rename = "Licenses")]
        licenses: Vec<Lic>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Vuln {
        #[serde(rename = "PkgName")]
        pkg: String,
        #[serde(rename = "InstalledVersion")]
        installed: String,
        #[serde(rename = "FixedVersion")]
        fixed: String,
        #[serde(rename = "Severity")]
        sev: String,
        #[serde(rename = "VulnerabilityID")]
        id: String,
        #[serde(rename = "Title")]
        title: String,
        #[serde(rename = "PkgPath")]
        path: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Secret {
        #[serde(rename = "RuleID")]
        rule: String,
        #[serde(rename = "Severity")]
        sev: String,
        #[serde(rename = "StartLine")]
        line: u64,
        #[serde(rename = "Category")]
        cat: String,
        #[serde(rename = "Title")]
        title: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Misconf {
        #[serde(rename = "ID")]
        id: String,
        #[serde(rename = "AVDID")]
        avd: String,
        #[serde(rename = "Severity")]
        sev: String,
        #[serde(rename = "Title")]
        title: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Lic {
        #[serde(rename = "PkgName")]
        pkg: String,
        #[serde(rename = "Name")]
        name: String,
        #[serde(rename = "Severity")]
        sev: String,
        #[serde(rename = "Category")]
        cat: String,
    }

    fn sev(s: &str) -> String {
        match s.to_lowercase().as_str() {
            k @ ("critical" | "high" | "medium" | "low") => k.into(),
            _ => "unknown".into(),
        }
    }

    pub fn parse(_v: &Values, _out: &str, file: Option<&str>) -> Outcome {
        let Some(text) = file.filter(|t| !t.trim().is_empty()) else {
            return Outcome::simple("Aucun résultat (voir la sortie brute)", Level::None);
        };
        let Ok(rep) = serde_json::from_str::<Report>(text) else {
            return Outcome::simple("Résultat illisible (voir la sortie brute)", Level::Bad);
        };
        let mut rows: Vec<Vec<String>> = Vec::new();
        for r in &rep.results {
            for v in &r.vulns {
                let fixed = if v.fixed.is_empty() { "aucun" } else { &v.fixed };
                rows.push(vec!["Vulnérabilité".into(), sev(&v.sev), v.pkg.clone(), v.installed.clone(), fixed.into(), v.id.clone(), r.target.clone(), v.title.clone(), if v.path.is_empty() { String::new() } else { format!("/{}", v.path.trim_start_matches('/')) }]);
            }
            for s in &r.secrets {
                rows.push(vec!["Secret".into(), sev(&s.sev), s.rule.clone(), format!("ligne {}", s.line), "—".into(), s.cat.clone(), r.target.clone(), s.title.clone(), String::new()]);
            }
            for m in &r.misconf {
                rows.push(vec!["Configuration".into(), sev(&m.sev), m.id.clone(), "—".into(), "—".into(), m.avd.clone(), r.target.clone(), m.title.clone(), String::new()]);
            }
            for l in &r.licenses {
                rows.push(vec!["Licence".into(), sev(&l.sev), l.pkg.clone(), "—".into(), "—".into(), l.name.clone(), r.target.clone(), l.cat.clone(), String::new()]);
            }
        }
        let counts = counts_of(&rows, 1);
        let level = level_from_counts(&counts, !rows.is_empty());
        let head = if rows.is_empty() { "Rien à signaler".to_string() } else { format!("{} problème(s) détecté(s)", rows.len()) };
        finish(rows, head, level, counts, None)
    }
}

// ────────────────────────────── OSV-Scanner ────────────────────────────────

pub mod osv {
    use super::*;

    pub fn tool() -> Tool {
        Tool {
            key: "osv-scanner",
            title: "OSV-Scanner — dépendances de vos projets (base OSV)",
            desc: "Lit les fichiers de dépendances de vos projets (requirements.txt, package-lock.json, go.mod, Cargo.lock…) et les compare à la base OSV (GitHub, PyPI, Go, npm…). Complète Trivy. Ne regarde pas les paquets pacman.",
            columns: &["Écosystème", "Gravité", "Paquet", "Version", "Correctif", "Identifiant", "Fichier", "Résumé"],
            widths: &[100, 90, 170, 90, 120, 170, 300, 380],
            sev_col: Some(1),
            link: Some((5, |id| {
                let id = id.trim();
                crate::util::is_advisory_id(id).then(|| format!("https://osv.dev/vulnerability/{id}"))
            })),
            options,
            build,
            parse,
            noise: &[],
            notice: no_notice,
        }
    }

    pub fn options() -> Vec<OptDef> {
        vec![
            sec("Cible"),
            path("target", "Dossiers à analyser", None, "Vos dossiers de projets, séparés par « ; ». Utilisez le bouton « Dossiers… » de la page Failles pour les gérer.", Def::S("")),
            txt("lockfile", "Un fichier de dépendances précis (--lockfile)", Some("--lockfile"), "Analyse seulement ce fichier (chemin absolu) au lieu d'un dossier.", Pat::AbsPath, Def::S("")),
            chk("recursive", "Inclure les sous-dossiers (--recursive)", "--recursive", "Cherche les fichiers de dépendances dans tous les sous-dossiers.", true),
            sec("Fichiers pris en compte"),
            chk("noignore", "Ignorer .gitignore (--no-ignore)", "--no-ignore", "Analyse aussi les fichiers normalement exclus par .gitignore.", false),
            chk("gitroot", "Inclure la racine git (--include-git-root)", "--include-git-root", "Analyse aussi les dépôts git non-sous-modules.", false),
            txt("exclude", "Dossiers exclus (--x-exclude)", None, "Séparés par des virgules. Préfixes : g:glob, r:regex, ou nom exact.", Pat::Any, Def::S("node_modules,.venv,venv")),
            chk("allownolock", "Ne pas échouer sans fichier de dépendances (--allow-no-lockfiles)", "--allow-no-lockfiles", "Considère l'absence de fichiers comme normale.", true),
            sec("Résolution des dépendances"),
            chk("noresolve", "Pas de dépendances transitives (--no-resolve)", "--no-resolve", "N'essaie pas de résoudre les dépendances indirectes des manifestes.", false),
            combo("datasource", "Source des paquets (--data-source)", Some("--data-source"), "deps.dev (par défaut) ou résolution native.", &[("deps.dev (défaut)", ""), ("native", "native")], ""),
            txt("maven", "Registre Maven (--maven-registry)", Some("--maven-registry"), "URL du registre Maven.", Pat::Url, Def::S("")),
            sec("Résultats"),
            chk("allvulns", "Toutes les vulnérabilités (--all-vulns)", "--all-vulns", "Inclut aussi les failles jugées peu importantes ou non appelées.", false),
            chk("allpkgs", "Tous les paquets (--all-packages)", "--all-packages", "Liste aussi les paquets sans faille dans le JSON.", false),
            chk("deprecated", "Signaler les versions obsolètes (--x-flag-deprecated-packages)", "--x-flag-deprecated-packages", "Repère les versions de paquets déclarées obsolètes.", false),
            combo("callan", "Analyse d'appel (--call-analysis)", Some("--call-analysis"), "Go uniquement : ne signale que les failles réellement appelées. (Rust lance des scripts de build : non proposé.)", &[("Désactivée", ""), ("Go", "go")], ""),
            sec("Réseau et base locale"),
            chk("offline", "Mode hors ligne (--offline)", "--offline", "Désactive tout accès réseau.", false),
            chk("offvuln", "Base locale (--offline-vulnerabilities)", "--offline-vulnerabilities", "Utilise les bases déjà téléchargées.", false),
            chk("dl", "Télécharger les bases (--download-offline-databases)", "--download-offline-databases", "Télécharge les bases pour un usage hors ligne.", false),
            sec("Avancé"),
            path("config", "Fichier de configuration (--config)", Some("--config"), "Remplace osv-scanner.toml.", Def::S("")),
            combo("verbosity", "Niveau de détail (--verbosity)", Some("--verbosity"), "Quantité d'informations affichées.", &[("Info", "info"), ("Avertissements", "warn"), ("Erreurs", "error")], "info"),
        ]
    }

    pub fn build(v: &Values) -> Result<Plan, String> {
        // les modes hors ligne exigent des bases déjà téléchargées (~/.cache/osv-scalibr), sinon OSV-Scanner échoue
        offline_precondition(v, crate::util::home_dir().as_deref())?;
        let mut argv = vec![prog("osv-scanner")?, "scan".into(), "source".into(), "--format".into(), "json".into()];
        argv.extend(flags(&options(), v)?);
        for ex in v.s("exclude").split(',').map(str::trim).filter(|s| !s.is_empty()) {
            validate("Dossiers exclus", ex, Pat::Any)?;
            argv.extend(["--x-exclude".into(), ex.into()]);
        }
        let out_pos = argv.len();
        if v.s("lockfile").is_empty() {
            let dirs: Vec<&str> = v.s("target").split(';').map(str::trim).filter(|s| !s.is_empty()).collect();
            if dirs.is_empty() {
                return Err("Aucun dossier de projets à analyser : ajoutez-en avec « Dossiers… » (page Failles, tuile « Vos projets »).".into());
            }
            for t in dirs {
                validate("Dossier à analyser", t, Pat::AbsPath)?;
                argv.push(t.into());
            }
        }
        // la sortie JSON est écrite dans un fichier privé (voir runner) : l'insertion se fait avant la cible
        Ok(Plan { argv, elevated: false, out_flag: Some("--output-file"), out_pos })
    }

    /// Les modes hors ligne exigent des bases déjà téléchargées (~/.cache/osv-scalibr), sinon OSV-Scanner échoue.
    pub fn offline_precondition(v: &Values, home: Option<&Path>) -> Result<(), String> {
        if (v.b("offline") || v.b("offvuln")) && !v.b("dl") && !home.is_some_and(|h| h.join(".cache/osv-scalibr").is_dir()) {
            return Err("Mode hors ligne : cochez d'abord « Télécharger les bases » — aucune base locale n'est présente, l'analyse échouerait.".into());
        }
        Ok(())
    }

    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Report {
        results: Vec<Res>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Res {
        source: Source,
        packages: Vec<Pkg>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Source {
        path: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Pkg {
        package: PkgInfo,
        groups: Vec<Group>,
        vulnerabilities: Vec<Vuln>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct PkgInfo {
        name: String,
        version: String,
        ecosystem: String,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Group {
        ids: Vec<String>,
        aliases: Vec<String>,
        max_severity: Value,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Vuln {
        id: String,
        summary: String,
        database_specific: Option<DbSpecific>,
        affected: Vec<Affected>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct DbSpecific {
        severity: Option<String>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Affected {
        ranges: Vec<Range>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Range {
        events: Vec<Event>,
    }
    #[derive(Deserialize, Default)]
    #[serde(default)]
    struct Event {
        fixed: Option<String>,
    }

    fn level(score: f64, fallback: Option<&str>) -> &'static str {
        if score >= 9.0 {
            "critical"
        } else if score >= 7.0 {
            "high"
        } else if score >= 4.0 {
            "medium"
        } else if score > 0.0 {
            "low"
        } else {
            match fallback {
                Some("CRITICAL") => "critical",
                Some("HIGH") => "high",
                Some("MODERATE") => "medium",
                Some("LOW") => "low",
                _ => "unknown",
            }
        }
    }

    pub fn parse(_v: &Values, out: &str, file: Option<&str>) -> Outcome {
        let Some(text) = file.filter(|t| !t.trim().is_empty()) else {
            let msg = if out.contains("No package sources found") { "Aucun fichier de dépendances trouvé" } else { "Aucun résultat (voir la sortie brute)" };
            return Outcome::simple(msg, Level::None);
        };
        let Ok(rep) = serde_json::from_str::<Report>(text) else {
            return Outcome::simple("Résultat illisible (voir la sortie brute)", Level::Bad);
        };
        let mut rows: Vec<Vec<String>> = Vec::new();
        let mut pkgs: HashSet<(String, String)> = HashSet::new();
        let mut uniq: HashSet<(String, String, String)> = HashSet::new();
        for res in &rep.results {
            for pk in &res.packages {
                let vulns: HashMap<&str, &Vuln> = pk.vulnerabilities.iter().map(|v| (v.id.as_str(), v)).collect();
                for g in &pk.groups {
                    let ident = g.aliases.iter().find(|a| a.starts_with("CVE-")).or(g.ids.first()).cloned().unwrap_or_default();
                    let score = match &g.max_severity {
                        Value::String(s) => s.parse::<f64>().unwrap_or(0.0),
                        Value::Number(n) => n.as_f64().unwrap_or(0.0),
                        _ => 0.0,
                    };
                    let fb = g.ids.iter().filter_map(|i| vulns.get(i.as_str())).find_map(|v| v.database_specific.as_ref()?.severity.as_deref());
                    let installed_v = pk.package.version.clone();
                    let mut fixed: Vec<&str> = g
                        .ids
                        .iter()
                        .filter_map(|i| vulns.get(i.as_str()))
                        .flat_map(|v| v.affected.iter())
                        .flat_map(|a| a.ranges.iter())
                        .flat_map(|r| r.events.iter())
                        .filter_map(|e| e.fixed.as_deref())
                        .collect();
                    fixed.sort_unstable();
                    fixed.dedup();
                    // correctif réellement utile : la plus petite version corrective plus récente que celle installée (jamais un identifiant de commit)
                    let fx = crate::depfix::pick_fixed(&installed_v, &fixed).unwrap_or_else(|| "aucun".to_string());
                    let summary = g.ids.iter().filter_map(|i| vulns.get(i.as_str())).map(|v| v.summary.as_str()).find(|s| !s.is_empty()).unwrap_or("");
                    pkgs.insert((pk.package.name.clone(), pk.package.version.clone()));
                    uniq.insert((pk.package.name.clone(), pk.package.version.clone(), ident.clone()));
                    rows.push(vec![pk.package.ecosystem.clone(), level(score, fb).into(), pk.package.name.clone(), pk.package.version.clone(), fx, ident, res.source.path.clone(), summary.into()]);
                }
            }
        }
        let counts = counts_of(&rows, 1);
        let lvl = level_from_counts(&counts, !rows.is_empty());
        let head = if rows.is_empty() { "Aucune faille connue".to_string() } else { format!("{} faille(s) dans {} dépendance(s)", uniq.len(), pkgs.len()) };
        finish(rows, head, lvl, counts, None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vals(pairs: &[(&str, Val)]) -> Values {
        Values(pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect())
    }

    #[test]
    fn arch_audit_gravite_et_correctif() {
        let line = "grub\u{1f}High risk\u{1f}multiple issues\u{1f}\u{1f}CVE-2022-28737, CVE-2022-28736\u{1f}grub-btrfs, grub-hook";
        let o = arch_audit::parse(&Values::default(), &format!("{line}\n"), None);
        assert_eq!(o.rows.len(), 1);
        assert_eq!(o.rows[0][1], "high");
        assert_eq!(o.rows[0][3], "aucun");
        assert_eq!(o.rows[0][4], "2");
        assert_eq!(o.result.level, Level::Bad);
    }

    #[test]
    fn lynis_score_et_alertes() {
        let rep = "hardening_index=66\nwarning[]=PKGS-7392|Found one or more vulnerable packages|-|-|\nsuggestion[]=SSH-7440|Consider hardening SSH|detail|-|\n";
        let o = lynis::parse(&Values::default(), "", Some(rep));
        assert_eq!(o.result.score, Some(66));
        assert_eq!(o.rows.len(), 2);
        assert_eq!(o.rows[0][1], "warning");
        assert_eq!(o.result.level, Level::Warn);
    }

    #[test]
    fn rkhunter_ignore_found_et_annote() {
        let out = "Checking for local host name   [ Found ]\n /usr/bin/egrep  [ Warning ]\nChecking if SSH root access is allowed  [ Warning ]\nSystem checks summary\nPossible rootkits: 0\n";
        let v = vals(&[("action", Val::S("--check".into()))]);
        let o = rkhunter::parse(&v, out, None);
        assert_eq!(o.rows.len(), 2, "« Found » ne doit pas être une alerte");
        assert!(o.rows[0][2].contains("faux positif"));
        assert_eq!(o.result.level, Level::Warn);
    }

    #[test]
    fn rkhunter_detail_du_journal() {
        let log = "[11:12:32]   Checking /dev for suspicious file types         [ Warning ]\n[11:12:32] Warning: Suspicious file types found in /dev:\n[11:12:32]          /dev/shm/PostgreSQL.2594536624: data\n[11:12:32]          /dev/shm/PostgreSQL.3310637662: data\n[11:12:32]   Checking for hidden files and directories       [ Warning ]\n[11:12:32] Warning: Hidden file found: /etc/.updated: ASCII text\n[11:12:32] Warning: Hidden file found: /usr/share/man/man5/.k5login.5.gz: gzip compressed data\n[11:12:32]   Checking for missing log files                  [ Skipped ]\n";
        let d = rkhunter::log_details(log);
        assert_eq!(d, vec!["Suspicious file in /dev: /dev/shm/PostgreSQL.2594536624", "Suspicious file in /dev: /dev/shm/PostgreSQL.3310637662", "Hidden file found: /etc/.updated", "Hidden file found: /usr/share/man/man5/.k5login.5.gz"]);
        let out = "Checking /dev for suspicious file types  [ Warning ]\nChecking for hidden files and directories  [ Warning ]\nSystem checks summary\nPossible rootkits: 0\n";
        let v = vals(&[("action", Val::S("--check".into()))]);
        let o = rkhunter::parse(&v, out, Some(log));
        assert_eq!(o.rows.len(), 4, "les lignes génériques sont remplacées par les fichiers précis");
    }

    #[test]
    fn rkhunter_echec_n_est_pas_un_succes() {
        let v = vals(&[("action", Val::S("--check".into()))]);
        let o = rkhunter::parse(&v, "Invalid package manager given: PACMAN\n", None);
        assert_eq!(o.result.level, Level::Bad);
        assert!(o.result.headline.contains("Invalid"));
    }

    #[test]
    fn rkhunter_pacman_refuse() {
        let v = vals(&[("action", Val::S("--check".into())), ("pkgmgr", Val::S("PACMAN".into()))]);
        assert!(flags(&rkhunter::options(), &v).is_err(), "PACMAN n'est pas un choix valide");
    }

    #[test]
    fn trivy_json() {
        let j = r#"{"Results":[{"Target":"app","Vulnerabilities":[{"PkgName":"stdlib","InstalledVersion":"v1.23.12","FixedVersion":"1.24.13","Severity":"CRITICAL","VulnerabilityID":"CVE-2025-68121","Title":"t"}]}]}"#;
        let o = trivy::parse(&Values::default(), "", Some(j));
        assert_eq!(o.rows[0][1], "critical");
        assert_eq!(o.result.level, Level::Bad);
    }

    #[test]
    fn osv_json() {
        let j = r#"{"results":[{"source":{"path":"/p/req.txt"},"packages":[{"package":{"name":"aiohttp","version":"3.9.5","ecosystem":"PyPI"},
        "groups":[{"ids":["PYSEC-1","GHSA-x"],"aliases":["CVE-2025-1"],"max_severity":"7.5"}],
        "vulnerabilities":[{"id":"PYSEC-1","summary":"s","affected":[{"ranges":[{"events":[{"introduced":"0"},{"fixed":"3.10.0"}]}]}]}]}]}]}"#;
        let o = osv::parse(&Values::default(), "", Some(j));
        assert_eq!(o.rows.len(), 1);
        assert_eq!(o.rows[0][1], "high");
        assert_eq!(o.rows[0][4], "3.10.0");
        assert_eq!(o.rows[0][5], "CVE-2025-1");
    }

    #[test]
    fn trivy_systeme_n_envoie_pas_include_dev_deps() {
        let v = vals(&[("target", Val::S("/".into())), ("mode", Val::S("rootfs".into())), ("dev", Val::B(true))]);
        assert!(!trivy::build(&v).unwrap().argv.contains(&"--include-dev-deps".to_string()), "sinon Trivy échoue : unknown flag");
        let v = vals(&[("target", Val::S("/home".into())), ("mode", Val::S("fs".into())), ("dev", Val::B(true))]);
        assert!(trivy::build(&v).unwrap().argv.contains(&"--include-dev-deps".to_string()), "en mode projet l'option est valide");
    }

    #[test]
    fn osv_hors_ligne_sans_base_est_refuse_clairement() {
        let vide = std::env::temp_dir().join("cs-test-home-vide");
        std::fs::create_dir_all(&vide).unwrap();
        let off = vals(&[("offline", Val::B(true))]);
        assert!(osv::offline_precondition(&off, Some(&vide)).is_err(), "pas de base locale : message clair avant de lancer");
        std::fs::create_dir_all(vide.join(".cache/osv-scalibr")).unwrap();
        assert!(osv::offline_precondition(&off, Some(&vide)).is_ok(), "base présente : autorisé");
        let avec_dl = vals(&[("offline", Val::B(true)), ("dl", Val::B(true))]);
        assert!(osv::offline_precondition(&avec_dl, None).is_ok(), "avec « télécharger les bases » : autorisé");
        let _ = std::fs::remove_dir_all(&vide);
    }

    #[test]
    fn options_invalides_refusees() {
        let v = vals(&[("tests", Val::S("-x; rm -rf /".into()))]);
        assert!(flags(&lynis::options(), &v).is_err());
        let v = vals(&[("timeout", Val::S("30m; id".into()))]);
        assert!(flags(&trivy::options(), &v).is_err());
        let v = vals(&[("scanners", Val::L(vec!["vuln".into(), "../../x".into()]))]);
        assert!(flags(&trivy::options(), &v).is_err());
    }
}

#[cfg(test)]
mod diag_flags {
    /// Diagnostic (lecture seule) : liste les options à drapeau de chaque outil, pour les comparer à l'aide de l'outil installé.
    #[test]
    #[ignore]
    fn dump_flags() {
        for t in super::all() {
            for o in (t.options)() {
                if let Some(f) = o.flag {
                    println!("FLAG {} {}", t.key, f);
                }
            }
        }
    }
}
