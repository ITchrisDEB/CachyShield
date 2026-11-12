//! Nettoyage : fichiers temporaires, caches, corbeille, et données des navigateurs (cache, cookies, historique).
//!
//! Sécurité : la liste des cibles est FIXE (aucun chemin ne vient d'une saisie ou d'un fichier externe) ; tout reste sous le
//! dossier personnel ; les liens symboliques ne sont jamais suivis ; les navigateurs doivent être fermés ; rien n'est supprimé
//! sans confirmation de l'utilisateur (voir l'interface).

use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Group {
    Systeme,
    Navigateur,
    Administrateur,
}

/// Ce qu'on supprime à un emplacement.
#[derive(Clone, Debug)]
pub enum Target {
    /// Le CONTENU du dossier (le dossier lui-même est conservé).
    Contents(String),
    /// Des fichiers précis (« * » permis comme composant entier : profils de navigateurs).
    Files(String),
}

#[derive(Clone, Debug)]
pub struct Item {
    pub id: String,
    pub group: Group,
    pub title: String,
    pub desc: &'static str,
    pub targets: Vec<Target>,
    /// Nom du processus du navigateur : il doit être fermé.
    pub browser_proc: Option<&'static str>,
    /// Tâche administrateur (script constant lancé via pkexec) au lieu de suppression directe.
    pub admin_script: Option<&'static str>,
}

pub const PACCACHE_SCRIPT: &str = "/usr/bin/paccache -r -k 3; /usr/bin/paccache -r -u -k 0; echo 'Cache de pacman nettoyé (3 dernières versions gardées).'";
pub const JOURNAL_SCRIPT: &str = "/usr/bin/journalctl --vacuum-time=14d; echo 'Anciens journaux supprimés (14 derniers jours gardés).'";

/// Les deux tâches administrateur en un seul script : un seul mot de passe demandé.
pub const ADMIN_BOTH: &str = "/usr/bin/paccache -r -k 3; /usr/bin/paccache -r -u -k 0; /usr/bin/journalctl --vacuum-time=14d; echo 'Cache de pacman et anciens journaux nettoyés.'";

fn item(id: &str, group: Group, title: &str, desc: &'static str, targets: Vec<Target>) -> Item {
    Item { id: id.into(), group, title: title.into(), desc, targets, browser_proc: None, admin_script: None }
}

/// (id, nom affiché, processus, dossier de configuration, dossier de cache, motif des profils)
const CHROMIUM_LIKE: &[(&str, &str, &str, &str, &str)] = &[
    ("chrome", "Google Chrome", "chrome", ".config/google-chrome", ".cache/google-chrome"),
    ("chromium", "Chromium", "chromium", ".config/chromium", ".cache/chromium"),
    ("brave", "Brave", "brave", ".config/BraveSoftware/Brave-Browser", ".cache/BraveSoftware/Brave-Browser"),
    ("vivaldi", "Vivaldi", "vivaldi-bin", ".config/vivaldi", ".cache/vivaldi"),
    ("edge", "Microsoft Edge", "msedge", ".config/microsoft-edge", ".cache/microsoft-edge"),
    ("opera", "Opera", "opera", ".config/opera", ".cache/opera"),
];

/// Liste des éléments nettoyables sur CETTE machine (les navigateurs absents ne sont pas listés).
pub fn items(home: &Path) -> Vec<Item> {
    let mut v = vec![
        item("trash", Group::Systeme, "Corbeille", "Fichiers déjà jetés à la corbeille : ils sont supprimés définitivement.", vec![Target::Contents(".local/share/Trash/files".into()), Target::Contents(".local/share/Trash/info".into())]),
        item("thumbs", Group::Systeme, "Miniatures d'images", "Aperçus générés par le bureau ; ils se recréent tout seuls.", vec![Target::Contents(".cache/thumbnails".into())]),
        item("pkgcache", Group::Systeme, "Caches des outils de développement", "Téléchargements gardés par pip, npm, yay et paru ; ils se retéléchargent au besoin.", vec![Target::Contents(".cache/pip".into()), Target::Contents(".npm/_cacache".into()), Target::Contents(".cache/yay".into()), Target::Contents(".cache/paru".into())]),
        item("gpucache", Group::Systeme, "Caches graphiques", "Shaders compilés (Mesa, NVIDIA) ; ils se recréent au prochain lancement d'un jeu ou d'une application 3D.", vec![Target::Contents(".cache/mesa_shader_cache".into()), Target::Contents(".nv/GLCache".into()), Target::Contents(".cache/nvidia".into())]),
    ];
    for (id, name, proc_name, cfg, cache) in CHROMIUM_LIKE {
        if !home.join(cfg).is_dir() && !home.join(cache).is_dir() {
            continue;
        }
        let mut c = item(&format!("{id}-cache"), Group::Navigateur, &format!("{name} : cache"), "Pages et images mémorisées : le navigateur les retélécharge (le premier chargement est un peu plus lent).", vec![Target::Contents((*cache).into())]);
        c.browser_proc = Some(proc_name);
        let mut k = item(&format!("{id}-cookies"), Group::Navigateur, &format!("{name} : cookies"), "Vous serez déconnecté de la plupart des sites (comptes, paniers…). Utile pour la vie privée.", vec![Target::Files(format!("{cfg}/*/Cookies")), Target::Files(format!("{cfg}/*/Cookies-journal")), Target::Files(format!("{cfg}/*/Network/Cookies")), Target::Files(format!("{cfg}/*/Network/Cookies-journal"))]);
        k.browser_proc = Some(proc_name);
        let mut h = item(&format!("{id}-history"), Group::Navigateur, &format!("{name} : historique de navigation"), "La liste des pages visitées. Les favoris et les mots de passe ne sont PAS touchés.", vec![Target::Files(format!("{cfg}/*/History")), Target::Files(format!("{cfg}/*/History-journal"))]);
        h.browser_proc = Some(proc_name);
        v.extend([c, k, h]);
    }
    if home.join(".mozilla/firefox").is_dir() || home.join(".cache/mozilla/firefox").is_dir() {
        let mut c = item("firefox-cache", Group::Navigateur, "Firefox : cache", "Pages et images mémorisées : le navigateur les retélécharge.", vec![Target::Contents(".cache/mozilla/firefox/*/cache2".into())]);
        c.browser_proc = Some("firefox");
        let mut k = item("firefox-cookies", Group::Navigateur, "Firefox : cookies", "Vous serez déconnecté de la plupart des sites. Utile pour la vie privée.", vec![Target::Files(".mozilla/firefox/*/cookies.sqlite".into()), Target::Files(".mozilla/firefox/*/cookies.sqlite-wal".into()), Target::Files(".mozilla/firefox/*/cookies.sqlite-shm".into())]);
        k.browser_proc = Some("firefox");
        v.extend([c, k]);
    }
    let mut p = item("pacman", Group::Administrateur, "Cache de pacman", "Anciennes versions des paquets téléchargés (les 3 dernières sont gardées) : libère souvent plusieurs Go. Demande votre mot de passe.", vec![]);
    p.admin_script = Some(PACCACHE_SCRIPT);
    let mut j = item("journal", Group::Administrateur, "Anciens journaux système", "Journaux de plus de 14 jours. Demande votre mot de passe.", vec![]);
    j.admin_script = Some(JOURNAL_SCRIPT);
    v.extend([p, j]);
    v
}

/// Développe un chemin relatif à `home` ; un composant « * » représente n'importe quel sous-dossier direct (jamais « .. »).
pub fn expand(home: &Path, rel: &str) -> Vec<PathBuf> {
    if rel.is_empty() || rel.starts_with('/') || rel.split('/').any(|c| c == ".." || c.is_empty() || c == ".") {
        return vec![];
    }
    let mut out = vec![home.to_path_buf()];
    for comp in rel.split('/') {
        let mut next = Vec::new();
        for base in &out {
            if comp == "*" {
                if let Ok(rd) = std::fs::read_dir(base) {
                    for e in rd.flatten() {
                        if e.file_type().is_ok_and(|t| t.is_dir()) {
                            next.push(e.path());
                        }
                    }
                }
            } else if comp.contains('*') {
                return vec![]; // seul « * » entier est permis
            } else {
                next.push(base.join(comp));
            }
        }
        out = next;
    }
    out.into_iter().filter(|p| std::fs::symlink_metadata(p).is_ok()).collect()
}

/// Taille et nombre de fichiers d'un chemin, SANS suivre les liens symboliques.
fn measure(p: &Path) -> (u64, u64) {
    let Ok(md) = std::fs::symlink_metadata(p) else { return (0, 0) };
    if md.file_type().is_symlink() || md.is_file() {
        return (md.len(), 1);
    }
    let (mut bytes, mut files) = (0u64, 0u64);
    if let Ok(rd) = std::fs::read_dir(p) {
        for e in rd.flatten() {
            let (b, f) = measure(&e.path());
            bytes += b;
            files += f;
        }
    }
    (bytes, files)
}

/// Éléments concrets (chemins existants) d'une cible.
fn paths_of(home: &Path, it: &Item) -> Vec<PathBuf> {
    let mut v = Vec::new();
    for t in &it.targets {
        match t {
            Target::Contents(rel) => {
                for d in expand(home, rel) {
                    if std::fs::symlink_metadata(&d).is_ok_and(|m| m.is_dir() && !m.file_type().is_symlink()) {
                        if let Ok(rd) = std::fs::read_dir(&d) {
                            v.extend(rd.flatten().map(|e| e.path()));
                        }
                    }
                }
            }
            Target::Files(rel) => v.extend(expand(home, rel)),
        }
    }
    v
}

/// (octets, fichiers) qui seraient supprimés. Lecture seule.
pub fn size_of(home: &Path, it: &Item) -> (u64, u64) {
    paths_of(home, it).iter().fold((0, 0), |a, p| {
        let (b, f) = measure(p);
        (a.0 + b, a.1 + f)
    })
}

/// Supprime réellement ; renvoie (octets libérés, erreurs). Tout chemin hors du dossier personnel est refusé.
pub fn delete(home: &Path, it: &Item) -> (u64, Vec<String>) {
    let (mut freed, mut errors) = (0u64, Vec::new());
    for p in paths_of(home, it) {
        if !p.starts_with(home) || p == home {
            errors.push(format!("{} : chemin refusé", p.display()));
            continue;
        }
        let (b, _) = measure(&p);
        let md = std::fs::symlink_metadata(&p);
        let res = match md {
            Ok(m) if m.is_dir() && !m.file_type().is_symlink() => std::fs::remove_dir_all(&p),
            Ok(_) => std::fs::remove_file(&p), // fichier ou lien symbolique : on retire le lien, jamais sa cible
            Err(e) => Err(e),
        };
        match res {
            Ok(()) => freed += b,
            Err(e) => errors.push(format!("{} : {e}", p.display())),
        }
    }
    (freed, errors)
}

/// Un processus de ce nom tourne-t-il ? (lecture de /proc/*/comm)
pub fn process_running(name: &str) -> bool {
    std::fs::read_dir("/proc").map(|rd| rd.flatten().any(|e| std::fs::read_to_string(e.path().join("comm")).is_ok_and(|c| c.trim() == name))).unwrap_or(false)
}

pub fn human(bytes: u64) -> String {
    human_in(bytes, crate::i18n::lang() == "fr")
}

fn human_in(bytes: u64, french: bool) -> String {
    // le français compte en octets (Ko, Mo…) ; les autres langues en bytes (KB, MB…)
    const FR: [&str; 5] = ["o", "Ko", "Mo", "Go", "To"];
    const INTL: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let units = if french { FR } else { INTL };
    let (mut v, mut i) = (bytes as f64, 0);
    while v >= 1024.0 && i < 4 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 { format!("{bytes} {}", units[0]) } else { format!("{v:.1} {}", units[i]) }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("cs-clean-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn chemins_dangereux_refuses() {
        let h = tmp("exp");
        assert!(expand(&h, "../etc").is_empty());
        assert!(expand(&h, "/etc/passwd").is_empty());
        assert!(expand(&h, "a/../b").is_empty());
        assert!(expand(&h, "a*b/c").is_empty(), "« * » doit être un composant entier");
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn supprime_le_contenu_et_garde_le_dossier() {
        let h = tmp("del");
        let cache = h.join(".cache/thumbnails");
        std::fs::create_dir_all(cache.join("sous")).unwrap();
        std::fs::write(cache.join("a.png"), vec![0u8; 100]).unwrap();
        std::fs::write(cache.join("sous/b.png"), vec![0u8; 50]).unwrap();
        let it = items(&h).into_iter().find(|i| i.id == "thumbs").unwrap();
        assert_eq!(size_of(&h, &it), (150, 2));
        let (freed, errs) = delete(&h, &it);
        assert_eq!((freed, errs.len()), (150, 0));
        assert!(cache.is_dir() && std::fs::read_dir(&cache).unwrap().count() == 0, "le dossier est conservé, vide");
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn ne_suit_jamais_un_lien_symbolique() {
        let h = tmp("lnk");
        let precieux = h.join("precieux");
        std::fs::create_dir_all(&precieux).unwrap();
        std::fs::write(precieux.join("important.txt"), "x").unwrap();
        let cache = h.join(".cache/thumbnails");
        std::fs::create_dir_all(&cache).unwrap();
        std::os::unix::fs::symlink(&precieux, cache.join("lien")).unwrap();
        let it = items(&h).into_iter().find(|i| i.id == "thumbs").unwrap();
        let (_, errs) = delete(&h, &it);
        assert!(errs.is_empty());
        assert!(precieux.join("important.txt").exists(), "la cible du lien ne doit JAMAIS être supprimée");
        assert!(std::fs::symlink_metadata(cache.join("lien")).is_err(), "seul le lien est retiré");
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn cookies_des_profils_chromium_et_firefox() {
        let h = tmp("ck");
        for p in ["Default", "Profile 1"] {
            std::fs::create_dir_all(h.join(".config/google-chrome").join(p).join("Network")).unwrap();
            std::fs::write(h.join(".config/google-chrome").join(p).join("Network/Cookies"), "c").unwrap();
            std::fs::write(h.join(".config/google-chrome").join(p).join("Bookmarks"), "b").unwrap();
        }
        let it = items(&h).into_iter().find(|i| i.id == "chrome-cookies").unwrap();
        assert_eq!(size_of(&h, &it).1, 2);
        let _ = delete(&h, &it);
        assert!(h.join(".config/google-chrome/Default/Bookmarks").exists(), "les favoris ne sont pas touchés");
        assert!(!h.join(".config/google-chrome/Default/Network/Cookies").exists());
        assert!(items(&h).iter().all(|i| i.id != "brave-cookies"), "navigateur absent : non listé");
        let _ = std::fs::remove_dir_all(&h);
    }

    #[test]
    fn tailles_lisibles() {
        assert_eq!(human_in(512, true), "512 o");
        assert_eq!(human_in(1536, true), "1.5 Ko");
        assert_eq!(human_in(5 * 1024 * 1024 * 1024, true), "5.0 Go");
        assert_eq!(human_in(1536, false), "1.5 KB");
        assert_eq!(human_in(2 * 1024 * 1024, false), "2.0 MB");
    }
}

#[cfg(test)]
mod diag {
    use super::*;

    /// Diagnostic en LECTURE SEULE sur le vrai dossier personnel : `cargo test diag -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn tailles_reelles() {
        let home = PathBuf::from(std::env::var("HOME").unwrap());
        for it in items(&home) {
            if it.admin_script.is_some() {
                continue;
            }
            let ps = paths_of(&home, &it);
            println!("{:<34} {:>12} octets {:>8} fichiers ({} chemins)", it.id, size_of(&home, &it).0, size_of(&home, &it).1, ps.len());
        }
    }
}
