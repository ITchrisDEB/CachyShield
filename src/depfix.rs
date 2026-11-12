//! Correction des dépendances de VOS projets (jamais sans accord : l'interface montre le plan et demande confirmation).
//!
//! Écosystèmes pris en charge :
//! * npm : `npm install nom@version --ignore-scripts` dans le dossier du projet ;
//! * Python : réécriture de la ligne épinglée `nom==x` dans un fichier `requirements*.txt` ;
//! * Rust : `cargo update -p nom@x --precise y` (ne touche que Cargo.lock).
//!
//! Garde-fous : chemins absolus, jamais de lien symbolique, sauvegarde `.cs-backup-…` à côté du fichier,
//! restauration automatique en cas d'échec, aucun script d'installation exécuté, aucun droit administrateur.

use regex::Regex;
use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

const MAX_FILE: u64 = 16 << 20;

static RE_NAME: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9@][A-Za-z0-9@/._+-]{0,99}$").unwrap());
static RE_VER: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^v?[0-9][0-9A-Za-z.+_-]{0,60}$").unwrap());
static RE_HASH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[0-9a-fA-F]{12,64}$").unwrap());
static RE_REQ: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^(?P<pre>\s*)(?P<n>[A-Za-z0-9][A-Za-z0-9._-]*)(?P<ex>\s*\[[^\]]*\])?(?P<eq>\s*==\s*)(?P<v>[^\s;#,]+)(?P<rest>.*)$").unwrap());

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kind {
    Npm,
    /// `npm update nom` dans un projet (dépendance indirecte) : npm respecte les limites de versions du projet.
    NpmUpdate,
    Pip,
    Cargo,
    /// Rien d'automatique : la raison et la commande à copier.
    Manual,
}

#[derive(Clone, Debug)]
pub struct Item {
    pub name: String,
    pub version: String,
    pub fixed: String,
    /// Plus petite version qui corrige AU MOINS une faille (≤ `fixed`) : sert aux corrections partielles quand le projet interdit d'aller jusqu'à `fixed`.
    pub min_fix: String,
    /// Fichier de dépendances signalé par l'analyse (chemin absolu).
    pub file: String,
    pub kind: Kind,
    /// Saut de version majeure : risque de casser le projet (décoché par défaut).
    pub major: bool,
    pub grave: bool,
    /// Pour `Manual` : pourquoi ; sinon vide.
    pub note: String,
    pub command: String,
    /// Libellé d'emplacement pour l'affichage (ex. nom du venv) ; vide = dossier du fichier.
    pub place: String,
    /// Paquet pacman propriétaire du fichier (vide si aucun).
    pub pkg: String,
}

impl Item {
    pub fn dir(&self) -> PathBuf {
        Path::new(&self.file).parent().map(Path::to_path_buf).unwrap_or_default()
    }
    pub fn project(&self) -> String {
        if !self.place.is_empty() {
            return self.place.clone();
        }
        self.dir().file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default()
    }
}

// ───────────────────────────── versions ─────────────────────────────

fn tokens(v: &str) -> Vec<(bool, String)> {
    let v = v.trim().trim_start_matches(['v', 'V']);
    let mut out: Vec<(bool, String)> = Vec::new();
    let mut fresh = true;
    for c in v.chars() {
        if !c.is_ascii_alphanumeric() {
            fresh = true;
            continue;
        }
        let was_fresh = std::mem::replace(&mut fresh, false);
        if c.is_ascii_digit() {
            match out.last_mut() {
                Some((true, s)) if !was_fresh => s.push(c),
                _ => out.push((true, c.to_string())),
            }
        } else if c.is_ascii_alphabetic() {
            match out.last_mut() {
                Some((false, s)) if !was_fresh => s.push(c.to_ascii_lowercase()),
                _ => out.push((false, c.to_ascii_lowercase().to_string())),
            }
        }
    }
    out
}

/// Comparaison de versions (numérique par segment ; un suffixe alphabétique — rc, dev, beta — est plus ancien que la version nue).
pub fn cmp(a: &str, b: &str) -> Ordering {
    let (ta, tb) = (tokens(a), tokens(b));
    for i in 0..ta.len().max(tb.len()) {
        match (ta.get(i), tb.get(i)) {
            (Some((true, x)), Some((true, y))) => {
                let (x, y) = (x.trim_start_matches('0'), y.trim_start_matches('0'));
                let o = x.len().cmp(&y.len()).then_with(|| x.cmp(y));
                if o != Ordering::Equal {
                    return o;
                }
            }
            (Some((false, x)), Some((false, y))) => {
                let o = x.cmp(y);
                if o != Ordering::Equal {
                    return o;
                }
            }
            (Some((true, _)), Some((false, _))) => return Ordering::Greater,
            (Some((false, _)), Some((true, _))) => return Ordering::Less,
            (Some((true, x)), None) => {
                if !x.trim_start_matches('0').is_empty() {
                    return Ordering::Greater;
                }
            }
            (None, Some((true, y))) => {
                if !y.trim_start_matches('0').is_empty() {
                    return Ordering::Less;
                }
            }
            (Some((false, _)), None) => return Ordering::Less,
            (None, Some((false, _))) => return Ordering::Greater,
            (None, None) => {}
        }
    }
    Ordering::Equal
}

fn major(v: &str) -> Option<u64> {
    let t = tokens(v);
    match t.first() {
        Some((true, s)) => s.parse().ok(),
        _ => None,
    }
}

/// Plus petite version corrective strictement supérieure à la version installée (les identifiants de commit sont ignorés).
/// `None` si OSV ne connaît aucune version corrective utilisable.
pub fn pick_fixed(installed: &str, fixed: &[&str]) -> Option<String> {
    fixed
        .iter()
        .copied()
        .filter(|f| RE_VER.is_match(f) && !(RE_HASH.is_match(f) && !f.contains('.')))
        .filter(|f| cmp(f, installed) == Ordering::Greater)
        .min_by(|a, b| cmp(a, b))
        .map(String::from)
}

// ───────────────────────────── plan ─────────────────────────────

fn lock_kind(eco: &str, file: &str) -> Option<Kind> {
    let p = Path::new(file);
    let base = p.file_name()?.to_str()?;
    match eco {
        "npm" if matches!(base, "package-lock.json" | "package.json" | "npm-shrinkwrap.json") => Some(Kind::Npm),
        "PyPI" if base.starts_with("requirements") && base.ends_with(".txt") => Some(Kind::Pip),
        "crates.io" if base == "Cargo.lock" => Some(Kind::Cargo),
        _ => None,
    }
}

fn regular_file(p: &Path) -> bool {
    std::fs::symlink_metadata(p).map(|m| m.is_file() && !m.file_type().is_symlink() && m.len() <= MAX_FILE).unwrap_or(false)
}

fn real_dir(p: &Path) -> bool {
    std::fs::symlink_metadata(p).map(|m| m.is_dir() && !m.file_type().is_symlink()).unwrap_or(false)
}

fn manual_command(eco: &str, name: &str, fixed: &str) -> String {
    crate::advice::dependency_commands(eco, name, fixed).into_iter().next().unwrap_or_default()
}

/// Construit la liste des corrections possibles à partir des lignes OSV
/// (colonnes : écosystème, gravité, paquet, version, correctif, identifiant, fichier, résumé).
/// `only` : limite à certains noms de paquets (liste « attaques réelles »).
pub fn plan(rows: &[Vec<String>], only: Option<&HashSet<String>>) -> Vec<Item> {
    // (écosystème, nom, version, fichier) → (correctif le plus élevé, grave)
    let mut by: BTreeMap<(String, String, String, String), (String, bool)> = BTreeMap::new();
    for r in rows {
        if r.len() < 7 || r[4] == "aucun" || r[4].is_empty() {
            continue;
        }
        if only.is_some_and(|o| !o.contains(&r[2])) {
            continue;
        }
        let e = by.entry((r[0].clone(), r[2].clone(), r[3].clone(), r[6].clone())).or_insert((String::new(), false));
        let fixed = r[4].split(',').next().unwrap_or("").trim().to_string();
        if e.0.is_empty() || cmp(&fixed, &e.0) == Ordering::Greater {
            e.0 = fixed;
        }
        e.1 |= matches!(r[1].as_str(), "critical" | "high");
    }
    let mut out = Vec::new();
    for ((eco, name, version, file), (fixed, grave)) in by {
        if !RE_NAME.is_match(&name) || !RE_VER.is_match(&version) || !RE_VER.is_match(&fixed) || !Path::new(&file).is_absolute() {
            continue;
        }
        let jump = match (major(&version), major(&fixed)) {
            (Some(a), Some(b)) => b > a,
            _ => true,
        };
        let mut it = Item { name: name.clone(), version, fixed: fixed.clone(), min_fix: fixed.clone(), file: file.clone(), kind: Kind::Manual, major: jump, grave, note: String::new(), command: manual_command(&eco, &name, &fixed), place: String::new(), pkg: String::new() };
        if eco == "PyPI" {
            let f = Path::new(&file);
            // Les venv ne sont JAMAIS modifiés : seule la ligne épinglée (==) du fichier requirements peut l'être, avec sauvegarde.
            let venv = find_venv(f);
            let pin = lock_kind(&eco, &file) == Some(Kind::Pip) && regular_file(f) && std::fs::read_to_string(f).map(|t| pin_rewrite(&t, &it.name, &it.version, &it.fixed).1 > 0).unwrap_or(false);
            if pin {
                it.kind = Kind::Pip;
            } else {
                it.note = "Cette bibliothèque n'est pas épinglée (==) dans ce fichier : changez la contrainte à la main. L'application ne modifie jamais vos venv.".into();
                if let Some(v) = venv.as_ref().filter(|v| installed_version(v, &name).is_some()) {
                    it.command = venv_command(v, &it.name, &it.fixed);
                }
            }
            out.push(it);
            continue;
        }
        match lock_kind(&eco, &file) {
            Some(Kind::Npm) => {
                let d = Path::new(&file).parent().unwrap_or(Path::new("/"));
                if real_dir(d) && regular_file(&d.join("package.json")) && d.parent().is_some() {
                    it.kind = Kind::Npm;
                } else {
                    it.note = "Le dossier du projet npm est introuvable.".into();
                }
            }
            Some(Kind::Pip) => {
                let ok = regular_file(Path::new(&file)) && std::fs::read_to_string(&file).map(|t| pin_rewrite(&t, &it.name, &it.version, &it.fixed).1 > 0).unwrap_or(false);
                if ok {
                    it.kind = Kind::Pip;
                } else {
                    it.note = "Cette bibliothèque n'est pas épinglée (==) dans ce fichier : changez la contrainte à la main.".into();
                }
            }
            Some(Kind::Cargo) => {
                let d = Path::new(&file).parent().unwrap_or(Path::new("/"));
                if real_dir(d) && regular_file(&d.join("Cargo.toml")) && regular_file(Path::new(&file)) {
                    it.kind = Kind::Cargo;
                } else {
                    it.note = "Cargo.toml introuvable à côté de Cargo.lock.".into();
                }
            }
            _ => {
                let base = Path::new(&file).file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
                it.note = format!("Le fichier « {base} » n'est pas modifié automatiquement : mettez la dépendance à jour avec l'outil de ce projet.");
            }
        }
        out.push(it);
    }
    // les corrections automatiques d'abord, puis les graves, puis les sauts majeurs en dernier
    out.sort_by(|a, b| (a.kind == Kind::Manual).cmp(&(b.kind == Kind::Manual)).then(a.major.cmp(&b.major)).then(b.grave.cmp(&a.grave)).then(a.name.cmp(&b.name)));
    out
}

// ───────────────────────────── exécution ─────────────────────────────

/// Réécrit `nom==ancienne` en `nom==nouvelle` (nom normalisé : majuscules, `-`, `_`, `.` équivalents). Renvoie (texte, nombre de lignes modifiées).
pub fn pin_rewrite(text: &str, name: &str, old: &str, new: &str) -> (String, usize) {
    let norm = |s: &str| s.to_lowercase().replace(['_', '.'], "-");
    let target = norm(name);
    let mut n = 0;
    let mut out = String::with_capacity(text.len());
    for line in text.split_inclusive('\n') {
        let (body, eol) = if let Some(b) = line.strip_suffix("\r\n") { (b, "\r\n") } else if let Some(b) = line.strip_suffix('\n') { (b, "\n") } else { (line, "") };
        match RE_REQ.captures(body) {
            Some(c) if norm(&c["n"]) == target && &c["v"] == old => {
                n += 1;
                out.push_str(&format!("{}{}{}{}{}{}", &c["pre"], &c["n"], c.name("ex").map_or("", |m| m.as_str()), &c["eq"], new, &c["rest"]));
            }
            _ => out.push_str(body),
        }
        out.push_str(eol);
    }
    (out, n)
}

fn stamp() -> String {
    let t = crate::util::now_unix();
    format!("{t}")
}

fn backup(file: &Path, ts: &str, done: &mut HashSet<PathBuf>) -> Result<(), String> {
    if !file.exists() || !done.insert(file.to_path_buf()) {
        return Ok(());
    }
    let name = file.file_name().ok_or("nom de fichier invalide")?.to_string_lossy().into_owned();
    let dest = file.with_file_name(format!("{name}.cs-backup-{ts}"));
    if dest.exists() {
        return Ok(());
    }
    std::fs::copy(file, &dest).map(|_| ()).map_err(|e| format!("sauvegarde impossible ({e})"))
}

fn snapshot(files: &[PathBuf]) -> Vec<(PathBuf, Option<Vec<u8>>)> {
    files.iter().map(|f| (f.clone(), if regular_file(f) { std::fs::read(f).ok() } else { None })).collect()
}

fn restore(snap: &[(PathBuf, Option<Vec<u8>>)]) {
    for (f, data) in snap {
        match data {
            Some(d) => {
                let _ = std::fs::write(f, d);
            }
            None => {
                // fichier créé pendant l'opération (ex. package-lock.json absent avant) : on le retire
                if std::fs::symlink_metadata(f).map(|m| m.is_file()).unwrap_or(false) {
                    let _ = std::fs::remove_file(f);
                }
            }
        }
    }
}

fn clean_text(s: &str) -> String {
    let t: String = s.chars().map(|c| if c.is_control() && c != '\n' { ' ' } else { c }).collect();
    let lines: Vec<&str> = t.lines().filter(|l| !l.trim().is_empty()).collect();
    let keep = lines.len().saturating_sub(12);
    lines[keep..].join("\n")
}

/// Lance une commande avec limite de temps ; renvoie (succès, sortie, erreurs).
fn run_split(mut cmd: Command, dir: &Path, secs: u64) -> (bool, String, String) {
    cmd.current_dir(dir).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => return (false, String::new(), format!("lancement impossible : {e}")),
    };
    let grab = |r: Option<Box<dyn Read + Send>>| std::thread::spawn(move || {
        let mut s = String::new();
        if let Some(mut r) = r {
            let mut buf = Vec::new();
            let _ = r.by_ref().take(1 << 20).read_to_end(&mut buf);
            s = String::from_utf8_lossy(&buf).into_owned();
        }
        s
    });
    let (o, e) = (grab(child.stdout.take().map(|x| Box::new(x) as Box<dyn Read + Send>)), grab(child.stderr.take().map(|x| Box::new(x) as Box<dyn Read + Send>)));
    let start = Instant::now();
    let ok = loop {
        match child.try_wait() {
            Ok(Some(st)) => break st.success(),
            Ok(None) if start.elapsed() > Duration::from_secs(secs) => {
                let _ = child.kill();
                let _ = child.wait();
                break false;
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(100)),
            Err(_) => break false,
        }
    };
    (ok, o.join().unwrap_or_default(), e.join().unwrap_or_default())
}

/// Lance une commande avec limite de temps ; renvoie (succès, sortie et erreurs nettoyées).
fn run_limited(cmd: Command, dir: &Path, secs: u64) -> (bool, String) {
    let (ok, o, e) = run_split(cmd, dir, secs);
    (ok, clean_text(&format!("{o}\n{e}")))
}

/// Toutes les versions de `name` installées dans le projet, d'après `npm ls name --all --json` (arbre complet, y compris les sous-dépendances).
pub fn npm_installed_versions(json: &str, name: &str) -> Vec<String> {
    fn walk(v: &serde_json::Value, name: &str, out: &mut Vec<String>) {
        let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) else { return };
        for (k, d) in deps {
            if k == name {
                if let Some(ver) = d.get("version").and_then(|x| x.as_str()) {
                    out.push(ver.to_string());
                }
            }
            walk(d, name, out);
        }
    }
    let mut out = Vec::new();
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(json) {
        walk(&v, name, &mut out);
    }
    out
}

/// Dépendances DIRECTES du projet par lesquelles `name@version` est présent dans l'arbre (d'après `npm ls name --all --json`).
/// Une sous-dépendance ne peut monter que si son parent monte : on essaie donc aussi de mettre à jour ces parents.
pub fn npm_top_level_parents(json: &str, name: &str, version: &str) -> Vec<String> {
    fn has(v: &serde_json::Value, name: &str, version: &str) -> bool {
        let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) else { return false };
        deps.iter().any(|(k, d)| (k == name && d.get("version").and_then(|x| x.as_str()) == Some(version)) || has(d, name, version))
    }
    let Ok(root) = serde_json::from_str::<serde_json::Value>(json) else { return vec![] };
    let Some(top) = root.get("dependencies").and_then(|d| d.as_object()) else { return vec![] };
    top.iter().filter(|(k, d)| k.as_str() != name && has(d, name, version)).map(|(k, _)| k.clone()).collect()
}

/// Meilleur choix entre plusieurs simulations (candidat, version atteinte) : la plus haute version qui corrige au moins une faille
/// (≥ `min_fix`) et dépasse la version installée. Le premier candidat gagne à égalité (on préfère la mise à jour directe).
pub fn best_target(installed: &str, min_fix: &str, tries: &[(String, Option<String>)]) -> Option<(String, String)> {
    let mut best: Option<(String, String)> = None;
    for (cand, t) in tries {
        let Some(t) = t else { continue };
        if cmp(t, installed) != Ordering::Greater || cmp(t, min_fix) == Ordering::Less {
            continue;
        }
        if best.as_ref().is_none_or(|(_, b)| cmp(t, b) == Ordering::Greater) {
            best = Some((cand.clone(), t.clone()));
        }
    }
    best
}

/// Plus haute version que `npm update --dry-run --json` installerait
/// pour `name` (None si rien ne change).
pub fn npm_dry_target(json: &str, name: &str) -> Option<String> {
    let v: serde_json::Value = serde_json::from_str(json).ok()?;
    // npm 7+ : "change" (from/to) et "add" ; anciens formats : "updated" avec un "to" simple
    let mut found: Vec<String> = Vec::new();
    for key in ["change", "add", "updated"] {
        let Some(arr) = v.get(key).and_then(|a| a.as_array()) else { continue };
        for e in arr {
            let to = e.get("to").unwrap_or(e);
            let (n, ver) = (to.get("name").and_then(|x| x.as_str()).or_else(|| e.get("name").and_then(|x| x.as_str())), to.get("version").and_then(|x| x.as_str()).or_else(|| to.as_str()));
            if let (Some(n), Some(ver)) = (n, ver) {
                if n == name {
                    found.push(ver.to_string());
                }
            }
        }
    }
    found.into_iter().max_by(|a, b| cmp(a, b))
}

// ───────────────────── Python : environnement virtuel du projet ─────────────────────

fn norm_py(s: &str) -> String {
    s.to_lowercase().replace(['-', '.'], "_")
}

/// Venv du projet : `.venv`, `venv` ou `env` dans le dossier du fichier ou l'un de ses deux parents
/// (doit contenir `pyvenv.cfg` et `bin/python` ; jamais un lien symbolique).
pub fn find_venv(file: &Path) -> Option<PathBuf> {
    file.parent()?.ancestors().take(3).find_map(|d| {
        [".venv", "venv", "env"].iter().map(|n| d.join(n)).find(|p| real_dir(p) && regular_file(&p.join("pyvenv.cfg")) && p.join("bin/python").exists())
    })
}

/// Version réellement installée dans le venv (lue dans les dossiers `*.dist-info`, sans rien exécuter).
pub fn installed_version(venv: &Path, name: &str) -> Option<String> {
    let want = norm_py(name);
    for lib in ["lib", "lib64"] {
        let Ok(pys) = std::fs::read_dir(venv.join(lib)) else { continue };
        for py in pys.flatten().filter(|e| e.file_name().to_string_lossy().starts_with("python")) {
            let Ok(pk) = std::fs::read_dir(py.path().join("site-packages")) else { continue };
            for e in pk.flatten() {
                let f = e.file_name().to_string_lossy().into_owned();
                if let Some(stem) = f.strip_suffix(".dist-info") {
                    if let Some((n, v)) = stem.split_once('-') {
                        if norm_py(n) == want {
                            return Some(v.to_string());
                        }
                    }
                }
            }
        }
    }
    None
}

/// Commande que VOUS pouvez lancer vous-même pour mettre à jour la bibliothèque dans ce venv (affichée, jamais exécutée par l'application).
fn venv_command(venv: &Path, name: &str, fixed: &str) -> String {
    format!("{} -m pip install --only-binary :all: {name}=={fixed}", crate::runner::shell_quote(&venv.join("bin/python").to_string_lossy()))
}

/// Réécrit la ligne épinglée du fichier requirements (sauvegarde avant). Erreur si le fichier n'a pas cette ligne.
fn rewrite_requirements(it: &Item, f: &Path, ts: &str, done: &mut HashSet<PathBuf>) -> Result<usize, String> {
    if !regular_file(f) {
        return Err("fichier introuvable ou lien symbolique".into());
    }
    let base = f.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
    if !(base.starts_with("requirements") && base.ends_with(".txt")) {
        return Err("ce fichier n'est pas un requirements.txt".into());
    }
    let text = std::fs::read_to_string(f).map_err(|e| format!("lecture impossible ({e})"))?;
    let (new, n) = pin_rewrite(&text, &it.name, &it.version, &it.fixed);
    if n == 0 {
        return Err(format!("« {}=={} » introuvable dans le fichier (déjà modifié ?)", it.name, it.version));
    }
    backup(f, ts, done)?;
    let tmp = f.with_file_name(format!(".cs-tmp-{}", std::process::id()));
    std::fs::write(&tmp, new).map_err(|e| format!("écriture impossible ({e})"))?;
    if let Ok(m) = std::fs::metadata(f) {
        let _ = std::fs::set_permissions(&tmp, m.permissions());
    }
    std::fs::rename(&tmp, f).map_err(|e| {
        let _ = std::fs::remove_file(&tmp);
        format!("remplacement impossible ({e})")
    })?;
    Ok(n)
}

/// Applique UNE correction ; en cas d'échec, les fichiers sont remis dans leur état d'origine.
fn apply_one(it: &Item, ts: &str, done: &mut HashSet<PathBuf>, log: &mut dyn FnMut(String)) -> Result<(), String> {
    let dir = it.dir();
    if !dir.is_absolute() || !real_dir(&dir) {
        return Err("dossier du projet introuvable".into());
    }
    if !RE_NAME.is_match(&it.name) || !RE_VER.is_match(&it.fixed) || !RE_VER.is_match(&it.version) {
        return Err("nom ou version invalide".into());
    }
    match it.kind {
        Kind::Manual => Err("correction manuelle uniquement".into()),
        Kind::Pip => {
            let f = PathBuf::from(&it.file);
            let n = rewrite_requirements(it, &f, ts, done)?;
            log(format!("{n} ligne(s) modifiée(s) dans {}", f.file_name().map(|x| x.to_string_lossy().into_owned()).unwrap_or_default()));
            Ok(())
        }
        Kind::NpmUpdate => {
            let exe = crate::util::abs_prog("npm").ok_or("« npm » n'est pas installé")?;
            let files = vec![dir.join("package.json"), dir.join("package-lock.json")];
            // 0) déjà corrigé ? (une mise à jour précédente de la série a pu monter cette sous-dépendance)
            let mut ls = Command::new(&exe);
            ls.args(["ls", it.name.as_str(), "--all", "--json", "--ignore-scripts"]);
            let (_, ls_out, _) = run_split(ls, &dir, 300);
            let installed = npm_installed_versions(&ls_out, &it.name);
            if !installed.is_empty() && !installed.iter().any(|v| cmp(v, &it.version) == Ordering::Equal) {
                log(format!("déjà corrigé : la version {} n'est plus installée (maintenant : {})", it.version, installed.join(", ")));
                return Ok(());
            }
            // 1) simulations : mettre à jour le paquet lui-même, puis chacun de ses parents directs (une sous-dépendance
            //    ne monte que si son parent monte), toujours dans les limites de versions du projet
            let mut cands: Vec<String> = vec![it.name.clone()];
            cands.extend(npm_top_level_parents(&ls_out, &it.name, &it.version).into_iter().filter(|c| RE_NAME.is_match(c)));
            let mut tries: Vec<(String, Option<String>)> = Vec::new();
            for c in &cands {
                let mut dry = Command::new(&exe);
                dry.args(["update", c.as_str(), "--dry-run", "--json", "--ignore-scripts", "--no-audit", "--no-fund"]);
                let (ok, out, err) = run_split(dry, &dir, 300);
                if !ok {
                    if c == &it.name {
                        return Err(format!("simulation impossible :\n{}", clean_text(&err)));
                    }
                    continue;
                }
                tries.push((c.clone(), npm_dry_target(&out, &it.name)));
            }
            let Some((cand, target)) = best_target(&it.version, &it.min_fix, &tries) else {
                let parents = cands.iter().skip(1).cloned().collect::<Vec<_>>();
                let who = if parents.is_empty() { String::new() } else { format!(" Elle est apportée par : {}.", parents.join(", ")) };
                return Err(format!("impossible dans les limites de versions du projet : aucune mise à jour autorisée ne fait monter {} jusqu'à une version corrigée (il faut au moins {}).{who} Il faudrait une mise à jour MAJEURE d'un de ces paquets, ou un « overrides » dans package.json : rien n'est fait automatiquement. Rien n'a été modifié.", it.name, it.min_fix));
            };
            let full = cmp(&target, &it.fixed) != Ordering::Less;
            let via = if cand == it.name { String::new() } else { format!(" en mettant à jour « {cand} » (dans les limites du projet)") };
            if full {
                log(format!("npm peut monter {} jusqu'à {target}{via}", it.name));
            } else {
                log(format!("⚠ correction PARTIELLE : npm peut monter {} jusqu'à {target}{via} ; la version {} corrigerait toutes les failles mais dépasse les limites du projet", it.name, it.fixed));
            }
            // 2) mise à jour réelle, avec sauvegarde et restauration des fichiers de verrouillage
            let snap = snapshot(&files);
            for f in &files {
                backup(f, ts, done)?;
            }
            let mut cmd = Command::new(&exe);
            cmd.args(["update", cand.as_str(), "--ignore-scripts", "--no-audit", "--no-fund"]);
            let (ok, text) = run_limited(cmd, &dir, 600);
            if !ok {
                restore(&snap);
                return Err(format!("{text}\nFichiers de verrouillage d'origine restaurés."));
            }
            // 3) contrôle : l'ancienne version ne doit plus être installée
            let mut ls2 = Command::new(&exe);
            ls2.args(["ls", it.name.as_str(), "--all", "--json", "--ignore-scripts"]);
            let (_, ls2_out, _) = run_split(ls2, &dir, 300);
            let after = npm_installed_versions(&ls2_out, &it.name);
            if after.iter().any(|v| cmp(v, &it.version) == Ordering::Equal) {
                restore(&snap);
                return Err(format!("la mise à jour n'a pas fait monter {} (toujours en {}). Fichiers de verrouillage d'origine restaurés.", it.name, it.version));
            }
            log(format!("{} est maintenant en : {}", it.name, after.join(", ")));
            Ok(())
        }
        Kind::Npm | Kind::Cargo => {
            let (prog, args, files): (&str, Vec<String>, Vec<PathBuf>) = if it.kind == Kind::Npm {
                ("npm", vec!["install".into(), format!("{}@{}", it.name, it.fixed), "--ignore-scripts".into(), "--no-audit".into(), "--no-fund".into()], vec![dir.join("package.json"), dir.join("package-lock.json")])
            } else {
                ("cargo", vec!["update".into(), "-p".into(), format!("{}@{}", it.name, it.version), "--precise".into(), it.fixed.clone()], vec![dir.join("Cargo.lock")])
            };
            let exe = crate::util::abs_prog(prog).ok_or_else(|| format!("« {prog} » n'est pas installé"))?;
            let snap = snapshot(&files);
            for f in &files {
                backup(f, ts, done)?;
            }
            let mut cmd = Command::new(exe);
            cmd.args(&args);
            let (ok, text) = run_limited(cmd, &dir, 600);
            if ok {
                if !text.is_empty() {
                    log(text);
                }
                Ok(())
            } else {
                restore(&snap);
                Err(format!("{}\nFichiers d'origine restaurés.", text))
            }
        }
    }
}

/// Applique les corrections choisies l'une après l'autre. `log` reçoit une ligne d'avancement à la fois.
/// Renvoie (réussies, échouées).
pub fn apply(items: &[Item], log: &mut dyn FnMut(String)) -> (usize, usize) {
    let ts = stamp();
    let mut done = HashSet::new();
    let (mut ok, mut ko) = (0, 0);
    for (i, it) in items.iter().enumerate() {
        log(format!("[{}/{}] {} {} → {} ({})", i + 1, items.len(), it.name, it.version, it.fixed, it.project()));
        match apply_one(it, &ts, &mut done, log) {
            Ok(()) => {
                ok += 1;
                log("✔ fait".into());
            }
            Err(e) => {
                ko += 1;
                log(format!("✘ échec : {e}"));
            }
        }
    }
    (ok, ko)
}

// ───────────────────── bibliothèques des programmes installés (hors dossier personnel) ─────────────────────

/// Propriétaires pacman des fichiers donnés (un seul appel à `pacman -Qo`). Les fichiers sans propriétaire sont absents du résultat.
pub fn pacman_owners(paths: &[String]) -> std::collections::HashMap<String, String> {
    let mut out = std::collections::HashMap::new();
    let Some(pm) = crate::util::abs_prog("pacman") else { return out };
    let list: Vec<&String> = paths.iter().filter(|p| p.starts_with('/') && !p.contains('\n')).take(400).collect();
    if list.is_empty() {
        return out;
    }
    let Ok(o) = Command::new(pm).env("LC_ALL", "C").arg("-Qo").arg("--").args(&list).stdin(Stdio::null()).output() else { return out };
    let re = Regex::new(r"^(.+) is owned by (\S+) \S+$").unwrap();
    for l in String::from_utf8_lossy(&o.stdout).lines() {
        if let Some(c) = re.captures(l) {
            out.insert(c[1].to_string(), c[2].to_string());
        }
    }
    out
}

fn owned_by_me(p: &Path) -> bool {
    use std::os::unix::fs::MetadataExt;
    match (std::fs::metadata(p), std::fs::metadata("/proc/self")) {
        (Ok(a), Ok(b)) => a.uid() == b.uid(),
        _ => false,
    }
}

/// Emplacement d'une ligne Trivy : colonne « Emplacement » (bibliothèques Python, Node…) ou, pour un programme compilé (Go, Rust…),
/// le chemin du binaire qui sert de « Cible ». Chaîne vide si inconnu.
pub fn row_path(r: &[String]) -> String {
    match r.get(8).map(String::as_str).filter(|p| !p.is_empty()) {
        Some(p) => p.to_string(),
        None => match r.get(6) {
            Some(t) if t.contains('/') => format!("/{}", t.trim_start_matches('/')),
            _ => String::new(),
        },
    }
}

/// Programme auquel appartient une bibliothèque, d'après son emplacement (sans nom d'utilisateur ni chemin propre à une machine) :
/// `opt/<programme>/…`, `usr/(local/)bin/<programme>`, `usr/(local/)lib|share|libexec/<programme>/…`, le dossier d'un projet Node (avant `node_modules`),
/// le venv Python (avant `lib/python…`), le projet d'un dossier personnel. Emplacement inconnu : le nom de la bibliothèque elle-même.
pub fn program_of(path: &str, lib_name: &str) -> String {
    let p = path.trim_matches('/');
    let base = |s: &str| s.rsplit('/').next().unwrap_or(s).to_string();
    if p.is_empty() {
        return lib_name.to_string();
    }
    // noms de dossiers trop génériques pour identifier un programme (applications Electron : « …/resources/app/node_modules »)
    let generic = |s: &str| matches!(s, "app" | "apps" | "resources" | "dist" | "build" | "src" | "lib" | "lib64" | "bin" | "main" | "node" | "www" | "public" | "packages" | "usr" | "opt");
    for marker in ["/node_modules/", "/lib/python"] {
        if let Some((pre, _)) = p.split_once(marker) {
            let b = base(pre);
            if !generic(&b) {
                return b;
            }
        }
    }
    let segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    let pick = |i: usize| segs.get(i).map(|s| s.to_string());
    let out = match segs.first().copied() {
        Some("opt") => pick(1),
        Some("usr") => {
            let i = if segs.get(1) == Some(&"local") { 2 } else { 1 };
            match segs.get(i).copied() {
                Some("bin" | "sbin" | "lib" | "lib64" | "share" | "libexec") => pick(i + 1),
                _ => None,
            }
        }
        Some("home") => pick(2),
        _ => None,
    };
    out.filter(|s| !s.is_empty()).unwrap_or_else(|| lib_name.to_string())
}

/// Corrections possibles pour les bibliothèques des programmes installés
/// (lignes Trivy : type, gravité, nom, version, correctifs, id, cible, résumé, emplacement).
/// * venv Python qui vous appartient (ex. dans /opt) : correction automatique dans ce venv ;
/// * fichier d'un paquet pacman : se corrige par la mise à jour de ce paquet ;
/// * installation globale hors pacman, ou bibliothèque livrée avec une application : explication, rien de modifié.
pub fn plan_system(rows: &[Vec<String>], owners: &std::collections::HashMap<String, String>) -> Vec<Item> {
    let mut by: BTreeMap<(String, String, String, String), (String, bool, String)> = BTreeMap::new();
    for r in rows {
        if r.len() < 7 || r[0] != "Vulnérabilité" {
            continue;
        }
        let per: Vec<String> = r[4].split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect();
        let refs: Vec<&str> = per.iter().map(String::as_str).collect();
        let Some(f) = pick_fixed(&r[3], &refs) else { continue };
        let path = row_path(r);
        let kind = if r[6].contains('/') { "binaire".to_string() } else { r[6].clone() };
        let e = by.entry((kind, r[2].clone(), r[3].clone(), path)).or_insert((String::new(), false, String::new()));
        if e.2.is_empty() || cmp(&f, &e.2) == Ordering::Less {
            e.2 = f.clone();
        }
        if e.0.is_empty() || cmp(&f, &e.0) == Ordering::Greater {
            e.0 = f;
        }
        e.1 |= matches!(r[1].as_str(), "critical" | "high");
    }
    let mut out = Vec::new();
    for ((kind, name, version, path), (fixed, grave, min_fix)) in by {
        if !RE_NAME.is_match(&name) || !RE_VER.is_match(&version) || !RE_VER.is_match(&fixed) {
            continue;
        }
        let jump = match (major(&version), major(&fixed)) {
            (Some(a), Some(b)) => b > a,
            _ => true,
        };
        let mut it = Item { name: name.clone(), version: version.clone(), fixed, min_fix, file: path.clone(), kind: Kind::Manual, major: jump, grave, note: String::new(), command: String::new(), place: String::new(), pkg: String::new() };
        let p = Path::new(&path);
        let venv = (kind == "Python" && p.is_absolute()).then(|| p.ancestors().find(|a| regular_file(&a.join("pyvenv.cfg")) && a.join("bin/python").exists()).map(Path::to_path_buf)).flatten();
        it.place = venv.as_ref().and_then(|v| v.file_name()).map(|n| n.to_string_lossy().into_owned()).unwrap_or_else(|| path.trim_start_matches('/').split('/').take(3).collect::<Vec<_>>().join("/"));
        if path.is_empty() {
            it.note = "Emplacement inconnu : relancez « Analyser » pour le connaître.".into();
        } else if let Some(v) = &venv {
            it.note = "Installée dans un venv : l'application ne modifie jamais vos venv. Mettez-la à jour vous-même (commande ci-dessous), en vérifiant les limites de versions de votre projet.".into();
            it.command = venv_command(v, &name, &it.fixed);
        } else if let Some(proj) = (kind == "Node.js").then(|| path.split_once("/node_modules/").map(|(p, _)| PathBuf::from(p))).flatten().filter(|p| p.is_absolute() && real_dir(p) && regular_file(&p.join("package.json")) && owned_by_me(p) && !owners.contains_key(&path)) {
            // node_modules d'un projet qui vous appartient : `npm update` (limites de versions du projet respectées)
            it.kind = Kind::NpmUpdate;
            it.file = proj.join("package.json").to_string_lossy().into_owned();
            it.place = proj.file_name().map(|n| n.to_string_lossy().into_owned()).unwrap_or_default();
        } else if let Some(pk) = owners.get(&path) {
            it.pkg = pk.clone();
            it.note = format!("Fait partie du paquet « {pk} » : elle se corrige par la mise à jour de ce paquet (page « Mises à jour »). Aucune n'est en attente tant que les dépôts n'ont pas publié de correctif.");
        } else if kind == "Python" && path.starts_with("/usr/") {
            it.note = "Installée globalement hors pacman (pip en administrateur ?) : ne la modifiez pas avec pip sur Arch. Réinstallez-la dans un venv, ou installez le paquet pacman correspondant (python-…).".into();
        } else {
            it.note = "Livrée avec un logiciel ou un projet installé : elle se corrige en mettant ce logiciel à jour (ou en mettant à jour le projet).".into();
        }
        out.push(it);
    }
    out.sort_by(|a, b| (a.kind == Kind::Manual).cmp(&(b.kind == Kind::Manual)).then(a.major.cmp(&b.major)).then(b.grave.cmp(&a.grave)).then(a.name.cmp(&b.name)));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(eco: &str, sev: &str, name: &str, ver: &str, fixed: &str, file: &str) -> Vec<String> {
        vec![eco.into(), sev.into(), name.into(), ver.into(), fixed.into(), "CVE-1".into(), file.into(), String::new()]
    }

    #[test]
    fn comparaison_de_versions() {
        assert_eq!(cmp("1.10.0", "1.9.9"), Ordering::Greater);
        assert_eq!(cmp("3.1.43", "3.1.47"), Ordering::Less);
        assert_eq!(cmp("1.0", "1.0.0"), Ordering::Equal);
        assert_eq!(cmp("2.0.0rc1", "2.0.0"), Ordering::Less);
        assert_eq!(cmp("v2.0", "2.0"), Ordering::Equal);
    }

    #[test]
    fn choix_du_correctif() {
        assert_eq!(pick_fixed("11.3.0", &["10.0.1", "11.3.2", "12.0.0"]), Some("11.3.2".into()));
        assert_eq!(pick_fixed("0.0.0.dev0", &["1.13.1", "767f6aa49fe20a2766b9843d01e3b7f7793df6a3"]), Some("1.13.1".into()), "un identifiant de commit n'est pas une version");
        assert_eq!(pick_fixed("2.0", &["1.5"]), None);
    }

    #[test]
    fn epinglage_python() {
        let t = "# commentaire\nPillow==9.5.0 ; python_version>'3'\nrequests[security]==2.0.0\r\nautre==1.0\n";
        let (o, n) = pin_rewrite(t, "pillow", "9.5.0", "10.0.1");
        assert_eq!(n, 1);
        assert!(o.contains("Pillow==10.0.1 ; python_version>'3'\n"));
        let (o2, n2) = pin_rewrite(&o, "requests", "2.0.0", "2.32.0");
        assert_eq!(n2, 1);
        assert!(o2.contains("requests[security]==2.32.0\r\n"), "fin de ligne Windows conservée");
        assert_eq!(pin_rewrite(t, "pillow", "9.0.0", "10").1, 0, "mauvaise version : rien n'est modifié");
        assert_eq!(pin_rewrite("pil_low==1.0\n", "pil-low", "1.0", "1.1").1, 1, "noms normalisés");
    }

    #[test]
    fn plan_et_garde_fous() {
        let d = std::env::temp_dir().join(format!("cs-depfix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        let req = d.join("requirements.txt");
        std::fs::write(&req, "pillow==9.5.0\n").unwrap();
        std::fs::write(d.join("package.json"), "{}").unwrap();
        let lock = d.join("package-lock.json");
        std::fs::write(&lock, "{}").unwrap();
        let rows = vec![
            row("PyPI", "high", "pillow", "9.5.0", "10.0.1", req.to_str().unwrap()),
            row("PyPI", "low", "pillow", "9.5.0", "9.5.1", req.to_str().unwrap()),
            row("npm", "medium", "axios", "1.13.1", "1.13.2", lock.to_str().unwrap()),
            row("PyPI", "low", "absent", "1.0", "1.1", req.to_str().unwrap()),
            row("Go", "low", "x/y", "1.0.0", "1.0.1", "/tmp/go.mod"),
            row("npm", "low", "sans-fix", "1.0.0", "aucun", lock.to_str().unwrap()),
            row("npm", "low", "relatif", "1.0.0", "1.0.1", "package-lock.json"),
        ];
        let p = plan(&rows, None);
        let pil = p.iter().find(|i| i.name == "pillow").unwrap();
        assert_eq!((pil.kind.clone(), pil.fixed.as_str(), pil.major), (Kind::Pip, "10.0.1", true), "le correctif le plus élevé du groupe ; 9→10 = saut majeur");
        let ax = p.iter().find(|i| i.name == "axios").unwrap();
        assert_eq!((ax.kind.clone(), ax.major), (Kind::Npm, false));
        assert_eq!(p.iter().find(|i| i.name == "absent").unwrap().kind, Kind::Manual);
        assert_eq!(p.iter().find(|i| i.name == "x/y").unwrap().kind, Kind::Manual);
        assert!(plan(&[row("npm", "low", "-g", "1.0.0", "1.0.1", lock.to_str().unwrap())], None).is_empty(), "un nom commençant par « - » pourrait passer pour une option");
        assert!(p.iter().all(|i| i.name != "sans-fix" && i.name != "relatif"));
        let only: HashSet<String> = ["axios".to_string()].into();
        assert_eq!(plan(&rows, Some(&only)).len(), 1);
        // application Python : sauvegarde + réécriture
        let mut lines = vec![];
        let (ok, ko) = apply(std::slice::from_ref(pil), &mut |l| lines.push(l));
        assert_eq!((ok, ko), (1, 0), "{lines:?}");
        assert_eq!(std::fs::read_to_string(&req).unwrap(), "pillow==10.0.1\n");
        let backups: Vec<_> = std::fs::read_dir(&d).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().contains(".cs-backup-")).collect();
        assert_eq!(backups.len(), 1);
        assert_eq!(std::fs::read_to_string(backups[0].path()).unwrap(), "pillow==9.5.0\n", "la sauvegarde contient l'original");
        // un second passage échoue proprement (déjà modifié) sans rien casser
        let (ok2, ko2) = apply(std::slice::from_ref(pil), &mut |_| {});
        assert_eq!((ok2, ko2), (0, 1));
        assert_eq!(std::fs::read_to_string(&req).unwrap(), "pillow==10.0.1\n");
        // lien symbolique refusé
        let link = d.join("requirements-link.txt");
        std::os::unix::fs::symlink(&req, &link).unwrap();
        let rows2 = vec![row("PyPI", "high", "pillow", "10.0.1", "10.0.2", link.to_str().unwrap())];
        assert_eq!(plan(&rows2, None)[0].kind, Kind::Manual, "jamais de lien symbolique");
        let _ = std::fs::remove_dir_all(&d);
    }
    #[test]
    fn les_venv_ne_sont_jamais_modifies() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("cs-venv-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let v = d.join(".venv");
        std::fs::create_dir_all(v.join("bin")).unwrap();
        std::fs::create_dir_all(v.join("lib/python3.12/site-packages/Pillow-9.5.0.dist-info")).unwrap();
        std::fs::write(v.join("pyvenv.cfg"), "home = /usr/bin\n").unwrap();
        let log = d.join("calls.log");
        std::fs::write(v.join("bin/python"), format!("#!/bin/sh\necho \"$*\" >> {}\n", log.display())).unwrap();
        std::fs::set_permissions(v.join("bin/python"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let req = d.join("requirements.txt");
        std::fs::write(&req, "pillow>=9\n").unwrap();
        assert_eq!(find_venv(&req), Some(v.clone()));
        assert_eq!(installed_version(&v, "pillow"), Some("9.5.0".into()));
        let p = plan(&[row("PyPI", "high", "pillow", "9.5.0", "10.0.1", req.to_str().unwrap())], None);
        assert_eq!(p[0].kind, Kind::Manual, "non épinglé : rien d'automatique");
        assert!(p[0].command.contains("-m pip install"), "commande affichée pour que l'utilisateur la lance lui-même : {}", p[0].command);
        let (a, b) = apply(&p, &mut |_| {});
        assert_eq!((a, b), (0, 1));
        assert!(!log.exists(), "le python du venv n'a JAMAIS été lancé");
        assert_eq!(std::fs::read_to_string(&req).unwrap(), "pillow>=9\n");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn bibliotheques_du_systeme_classees_par_emplacement() {
        use std::os::unix::fs::PermissionsExt;
        let d = std::env::temp_dir().join(format!("cs-sys-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let v = d.join("venv-x");
        std::fs::create_dir_all(v.join("bin")).unwrap();
        std::fs::create_dir_all(v.join("lib/python3.14/site-packages/pillow-12.2.0.dist-info")).unwrap();
        std::fs::write(v.join("pyvenv.cfg"), "home = /usr/bin\n").unwrap();
        std::fs::write(v.join("bin/python"), "#!/bin/sh\nexit 0\n").unwrap();
        std::fs::set_permissions(v.join("bin/python"), std::fs::Permissions::from_mode(0o755)).unwrap();
        let meta = v.join("lib/python3.14/site-packages/pillow-12.2.0.dist-info/METADATA");
        let trivy = |kind: &str, name: &str, ver: &str, fix: &str, path: &str| -> Vec<String> {
            vec!["Vulnérabilité".into(), "high".into(), name.into(), ver.into(), fix.into(), "CVE-1".into(), kind.into(), String::new(), path.into()]
        };
        let rows = vec![
            trivy("Python", "pillow", "12.2.0", "12.2.1, 13.0.0", meta.to_str().unwrap()),
            trivy("Python", "gitpython", "3.1.45", "3.2.1", "/usr/lib/python3.13/site-packages/gitpython-3.1.45.dist-info/METADATA"),
            trivy("Python", "owned", "1.0", "1.1", "/usr/lib/python3.13/site-packages/owned-1.0.dist-info/METADATA"),
            trivy("GoBinary", "stdlib", "1.18.10", "1.26.10", "/opt/app/bin/tool"),
            trivy("Python", "sans-fix", "1.0", "", "/opt/x"),
        ];
        let owners: std::collections::HashMap<String, String> = [("/usr/lib/python3.13/site-packages/owned-1.0.dist-info/METADATA".to_string(), "python-owned".to_string())].into();
        let p = plan_system(&rows, &owners);
        let find = |n: &str| p.iter().find(|i| i.name == n).unwrap();
        assert_eq!((find("pillow").kind.clone(), find("pillow").fixed.as_str()), (Kind::Manual, "12.2.1"), "un venv n'est jamais corrigé automatiquement");
        assert!(find("pillow").note.contains("ne modifie jamais vos venv"), "{}", find("pillow").note);
        assert!(find("pillow").command.contains("venv-x") && find("pillow").command.contains("pillow==12.2.1"), "{}", find("pillow").command);
        assert_eq!(find("pillow").place, "venv-x");
        assert!(find("gitpython").note.contains("hors pacman"), "{}", find("gitpython").note);
        assert!(find("owned").note.contains("python-owned"));
        assert!(find("stdlib").note.contains("Livrée avec"));
        assert!(p.iter().all(|i| i.name != "sans-fix"), "sans version corrective : rien à proposer");
        assert!(p.iter().filter(|i| i.name != "pillow").all(|i| i.command.is_empty()), "jamais de commande pip globale suggérée");
        let _ = std::fs::remove_dir_all(&d);
    }
    #[test]
    fn dependances_node_d_un_projet_a_moi_sont_corrigeables_dans_ses_limites() {
        let d = std::env::temp_dir().join(format!("cs-node-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let proj = d.join("front");
        std::fs::create_dir_all(proj.join("node_modules/flatted")).unwrap();
        std::fs::write(proj.join("package.json"), "{}").unwrap();
        let path = proj.join("node_modules/flatted/package.json");
        let mk = |p: &str| -> Vec<String> { vec!["Vulnérabilité".into(), "high".into(), "flatted".into(), "3.3.3".into(), "3.4.2".into(), "CVE-1".into(), "Node.js".into(), String::new(), p.into()] };
        let p = plan_system(&[mk(path.to_str().unwrap())], &Default::default());
        assert_eq!((p[0].kind.clone(), p[0].fixed.as_str(), p[0].place.as_str()), (Kind::NpmUpdate, "3.4.2", "front"));
        assert_eq!(p[0].dir(), proj, "npm tourne dans le dossier du projet");
        let owned: std::collections::HashMap<String, String> = [(path.to_string_lossy().into_owned(), "un-paquet".to_string())].into();
        assert_eq!(plan_system(&[mk(path.to_str().unwrap())], &owned)[0].kind, Kind::Manual, "fichier d'un paquet pacman : jamais modifié à la main");
        assert_eq!(plan_system(&[mk("/opt/inexistant/node_modules/x/package.json")], &Default::default())[0].kind, Kind::Manual);
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn versions_installees_dans_tout_l_arbre() {
        let j = r#"{"name":"p","dependencies":{"eslint":{"version":"9.39.0","dependencies":{"minimatch":{"version":"3.1.5","dependencies":{"brace-expansion":{"version":"1.1.21"}}}}},"ts":{"version":"8","dependencies":{"brace-expansion":{"version":"2.1.7"}}}}}"#;
        let mut v = npm_installed_versions(j, "brace-expansion");
        v.sort();
        assert_eq!(v, ["1.1.21", "2.1.7"], "les deux versions, même en sous-dépendance");
        assert!(npm_installed_versions(j, "absent").is_empty());
        assert!(npm_installed_versions("pas du json", "x").is_empty());
    }

    #[test]
    fn simulation_npm_lue_correctement() {
        // sortie réelle de npm 12 (`npm update vite --dry-run --json`)
        let real = r#"{"add":[],"added":0,"change":[{"from":{"name":"vite","version":"6.4.1","path":"/p/node_modules/vite"},"to":{"name":"vite","version":"6.4.5","path":"/p/node_modules/vite"}}],"changed":1,"remove":[]}"#;
        assert_eq!(npm_dry_target(real, "vite"), Some("6.4.5".into()), "format actuel de npm");
        assert_eq!(npm_dry_target(real, "autre"), None);
        let j = r#"{"added":[],"updated":[{"name":"flatted","from":"3.3.3","to":"3.4.2"},{"name":"autre","from":"1.0.0","to":"9.0.0"},{"name":"flatted","from":"3.0.0","to":"3.3.0"}]}"#;
        assert_eq!(npm_dry_target(j, "flatted"), Some("3.4.2".into()));
        assert_eq!(npm_dry_target(j, "absent"), None);
        assert_eq!(npm_dry_target("pas du json", "x"), None);
        assert_eq!(npm_dry_target(r#"{"updated":[]}"#, "x"), None);
    }
    /// Essai réel (réseau + npm) dans un projet jetable ; lancé à la main : `cargo test reel_npm -- --ignored`.
    #[test]
    #[ignore]
    fn reel_npm_update_dans_un_projet_jetable() {
        let d = std::env::temp_dir().join(format!("cs-real-npm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        let proj = d.join("front");
        std::fs::create_dir_all(&proj).unwrap();
        std::fs::write(proj.join("package.json"), r#"{"name":"t","version":"1.0.0","dependencies":{"flatted":"^3.3.0"}}"#).unwrap();
        let npm = crate::util::abs_prog("npm").expect("npm");
        let ok = Command::new(&npm).args(["install", "flatted@3.3.3", "--ignore-scripts", "--no-audit", "--no-fund", "--save-exact=false"]).current_dir(&proj).status().unwrap().success();
        assert!(ok);
        let ver = |p: &Path| std::fs::read_to_string(p.join("node_modules/flatted/package.json")).unwrap().lines().find(|l| l.contains("\"version\"")).unwrap().to_string();
        assert!(ver(&proj).contains("3.3.3"));
        let path = proj.join("node_modules/flatted/package.json");
        let row = |fixed: &str| -> Vec<String> { vec!["Vulnérabilité".into(), "high".into(), "flatted".into(), "3.3.3".into(), fixed.into(), "CVE-1".into(), "Node.js".into(), String::new(), path.to_string_lossy().into_owned()] };
        // version hors des limites du projet (^3.3.0) : refus, rien de modifié
        let hors = plan_system(&[row("99.0.0")], &Default::default());
        let mut log = vec![];
        let (a, b) = apply(&hors, &mut |l| log.push(l));
        assert_eq!((a, b), (0, 1), "{log:?}");
        assert!(ver(&proj).contains("3.3.3"), "rien n'a bougé");
        // version atteignable : la mise à jour est faite
        let ok = plan_system(&[row("3.3.4")], &Default::default());
        let mut log = vec![];
        let (a, b) = apply(&ok, &mut |l| log.push(l));
        assert_eq!((a, b), (1, 0), "{log:?}");
        assert!(!ver(&proj).contains("3.3.3"), "version mise à jour : {}", ver(&proj));
        let sauv: Vec<_> = std::fs::read_dir(&proj).unwrap().filter_map(|e| e.ok()).filter(|e| e.file_name().to_string_lossy().contains(".cs-backup-")).collect();
        assert_eq!(sauv.len(), 2, "package.json et package-lock.json sauvegardés");
        let _ = std::fs::remove_dir_all(&d);
    }
    #[test]
    fn bibliotheque_go_avec_version_prefixee_et_paquet_proprietaire() {
        let path = "/opt/app/bin/outil";
        let row: Vec<String> = vec!["Vulnérabilité".into(), "high".into(), "stdlib".into(), "v1.18.10".into(), "1.26.10".into(), "CVE-1".into(), "opt/app/bin/outil".into(), String::new(), String::new()];
        let owners: std::collections::HashMap<String, String> = [(path.to_string(), "app-bin".to_string())].into();
        let p = plan_system(&[row], &owners);
        assert_eq!(p.len(), 1, "la version « v1.18.10 » est acceptée");
        assert_eq!((p[0].kind.clone(), p[0].pkg.as_str(), p[0].version.as_str()), (Kind::Manual, "app-bin", "v1.18.10"));
    }
}

#[cfg(test)]
mod tests_programme {
    use super::*;

    #[test]
    fn programme_d_apres_l_emplacement() {
        assert_eq!(program_of("/opt/some-app/resources/app/bin/tool", "stdlib"), "some-app");
        assert_eq!(program_of("opt/some-app/x/y", "stdlib"), "some-app");
        assert_eq!(program_of("/opt/group/front/node_modules/@scope/pkg/bin/x", "esbuild"), "front", "projet Node : le dossier avant node_modules");
        assert_eq!(program_of("/usr/bin/duf", "stdlib"), "duf");
        assert_eq!(program_of("/usr/local/bin/mytool", "stdlib"), "mytool");
        assert_eq!(program_of("/usr/lib/code/node_modules/x/y.js", "x"), "code");
        assert_eq!(program_of("/usr/share/editor/plugins/p.jar", "log4j"), "editor");
        assert_eq!(program_of("/opt/venv-demo/lib/python3.12/site-packages/pkg", "pkg"), "venv-demo", "venv Python");
        assert_eq!(program_of("/home/someone/projet/node_modules/x/index.js", "x"), "projet");
        assert_eq!(program_of("/home/someone/outil/bin/run", "lib"), "outil", "jamais le nom d'utilisateur");
        assert_eq!(program_of("/opt/editor/resources/app/node_modules/x/y.js", "x"), "editor", "dossier trop générique (app) : on retombe sur le programme");
        assert_eq!(program_of("", "stdlib"), "stdlib", "emplacement inconnu : la bibliothèque elle-même");
        assert_eq!(program_of("/srv/x/y", "zlib"), "zlib");
    }
}

#[cfg(test)]
mod tests_partiel {

    use super::*;

    fn t(c: &str, v: Option<&str>) -> (String, Option<String>) {
        (c.to_string(), v.map(String::from))
    }

    #[test]
    fn parents_directs_d_une_sous_dependance() {
        let ls = r#"{"name":"proj","dependencies":{"react-router-dom":{"version":"7.9.5","dependencies":{"react-router":{"version":"7.9.5"}}},"tailwindcss":{"version":"3","dependencies":{"sucrase":{"version":"3.35.0","dependencies":{"glob":{"version":"10.4.5"}}}}},"other":{"version":"1"}}}"#;
        assert_eq!(npm_top_level_parents(ls, "react-router", "7.9.5"), ["react-router-dom"]);
        assert_eq!(npm_top_level_parents(ls, "glob", "10.4.5"), ["tailwindcss"]);
        assert!(npm_top_level_parents(ls, "glob", "9.0.0").is_empty(), "version absente : aucun parent");
        assert!(npm_top_level_parents("pas du json", "x", "1").is_empty());
    }

    #[test]
    fn choix_du_meilleur_candidat() {
        // le paquet lui-même ne peut pas monter, son parent oui
        assert_eq!(best_target("7.9.5", "7.18.0", &[t("react-router", None), t("react-router-dom", Some("7.18.5"))]), Some(("react-router-dom".into(), "7.18.5".into())));
        // correction partielle : 10.5.0 corrige au moins une faille (min 10.5.0) même si 14.0.2 serait nécessaire pour toutes
        assert_eq!(best_target("10.4.5", "10.5.0", &[t("glob", Some("10.5.0"))]), Some(("glob".into(), "10.5.0".into())));
        // trop bas pour corriger quoi que ce soit : refusé
        assert_eq!(best_target("9.0.9", "10.2.0", &[t("minimatch", Some("9.0.10"))]), None);
        // la version installée elle-même n'est pas une amélioration
        assert_eq!(best_target("1.0.0", "1.0.1", &[t("a", Some("1.0.0"))]), None);
        // à égalité, la mise à jour directe passe avant celle du parent
        assert_eq!(best_target("1.0.0", "1.1.0", &[t("a", Some("1.2.0")), t("parent", Some("1.2.0"))]), Some(("a".into(), "1.2.0".into())));
        // la plus haute version gagne
        assert_eq!(best_target("1.0.0", "1.1.0", &[t("a", Some("1.2.0")), t("parent", Some("1.9.0"))]), Some(("parent".into(), "1.9.0".into())));
    }

    #[test]
    fn plan_systeme_garde_le_minimum_et_le_maximum() {
        let r = |fixed: &str| vec!["Vulnérabilité".into(), "high".into(), "glob".into(), "10.4.5".into(), fixed.into(), "CVE-X".into(), "Node.js".into(), String::new(), "/p/node_modules/glob/package.json".into()];
        let rows = vec![r("10.5.0, 11.1.0"), r("14.0.2")];
        let items = plan_system(&rows, &std::collections::HashMap::new());
        let g = items.iter().find(|i| i.name == "glob").expect("glob");
        assert_eq!((g.min_fix.as_str(), g.fixed.as_str()), ("10.5.0", "14.0.2"));
    }
}
