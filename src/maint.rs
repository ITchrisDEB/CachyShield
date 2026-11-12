//! Entretien après mise à jour, calqué sur `arch-update` (CachyOS) : paquets orphelins, Flatpak (mises à jour et éléments inutilisés), cache de pacman,
//! redémarrage du noyau et services à relancer. La détection est en LECTURE SEULE ; les actions passent par des scripts constants.
//! (`arch-update` propose aussi les fichiers .pacnew mais cette étape est désactivée dans sa version actuelle : non reprise ici.)

use crate::util::abs_prog;
use std::process::Command;

/// Versions anciennes gardées dans le cache (valeur par défaut d'`arch-update`).
pub const KEEP_OLD: &str = "3";

/// Supprime des paquets orphelins. Arguments = noms de paquets, revalidés ici : forme du nom, puis « toujours orphelin ».
pub const ORPHAN_SCRIPT: &str = r#"[ "$#" -ge 1 ] || { echo "Aucun paquet indiqué."; exit 2; }
for p in "$@"; do
  case "$p" in ''|-*|*[!A-Za-z0-9@._+-]*) echo "Nom de paquet invalide : refusé."; exit 2;; esac
done
cur=$(/usr/bin/pacman -Qtdq 2>/dev/null)
for p in "$@"; do
  case "
$cur
" in *"
$p
"*) ;; *) echo "« $p » n'est plus un paquet orphelin : abandon, rien n'a été supprimé."; exit 3;; esac
done
echo "Suppression des paquets orphelins (et de leurs dépendances devenues inutiles)…"
/usr/bin/pacman -Rns --noconfirm -- "$@"
"#;

/// Services (hors gestionnaire de session) dont un fichier a changé : à relancer après la mise à jour. Même appel qu'arch-update.
pub const SERVICES_LIST_SCRIPT: &str = r#"[ -x /usr/bin/checkservices ] || exit 0
/usr/bin/checkservices -F -P -R -i gdm.service -i plasmalogin.service -i sddm.service -i lightdm.service -i lxdm.service -i slim.service -i xdm.service -i greetd.service -i nodm.service -i ly.service -i lemurs.service 2>/dev/null | /usr/bin/grep '\.service' | /usr/bin/cut -f2 -d "'"
exit 0
"#;

/// Relance des services choisis : seuls ceux que `checkservices` désigne à cet instant sont acceptés.
pub const SERVICES_RESTART_SCRIPT: &str = r#"[ "$#" -ge 1 ] || { echo "Aucun service indiqué."; exit 2; }
[ -x /usr/bin/checkservices ] || { echo "checkservices est introuvable."; exit 2; }
for s in "$@"; do
  case "$s" in ''|-*|*[!A-Za-z0-9@:._-]*) echo "Nom de service invalide : refusé."; exit 2;; esac
  case "$s" in *.service) ;; *) echo "Nom de service invalide : refusé."; exit 2;; esac
done
cur=$(/usr/bin/checkservices -F -P -R -i gdm.service -i plasmalogin.service -i sddm.service -i lightdm.service -i lxdm.service -i slim.service -i xdm.service -i greetd.service -i nodm.service -i ly.service -i lemurs.service 2>/dev/null | /usr/bin/grep '\.service' | /usr/bin/cut -f2 -d "'")
for s in "$@"; do
  case "
$cur
" in *"
$s
"*) ;; *) echo "« $s » n'a plus besoin d'être relancé : abandon."; exit 3;; esac
done
rc=0
for s in "$@"; do
  echo "Relance de $s…"
  /usr/bin/systemctl restart -- "$s" || { echo "Échec pour $s."; rc=4; }
done
exit $rc
"#;

fn run(prog: &str, args: &[&str]) -> Option<(i32, String)> {
    let p = abs_prog(prog)?;
    let o = Command::new(p).args(args).env("LC_ALL", "C").output().ok()?;
    Some((o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned()))
}

/// Nom de paquet acceptable (mêmes règles que le script).
pub fn valid_pkg(n: &str) -> bool {
    !n.is_empty() && !n.starts_with('-') && n.chars().all(|c| c.is_ascii_alphanumeric() || "@._+-".contains(c))
}

/// Nom de service acceptable (mêmes règles que le script).
pub fn valid_service(n: &str) -> bool {
    n.ends_with(".service") && !n.starts_with('-') && n.chars().all(|c| c.is_ascii_alphanumeric() || "@:._-".contains(c))
}

/// Paquets installés comme dépendances et dont plus rien ne dépend (`pacman -Qtdq`).
pub fn orphans() -> Vec<String> {
    let Some((_, out)) = run("pacman", &["-Qtdq"]) else { return vec![] };
    let mut v: Vec<String> = out.lines().map(str::trim).filter(|l| valid_pkg(l)).map(String::from).collect();
    v.sort();
    v
}

/// Ce que `pacman -Rns` supprimerait réellement (orphelins + dépendances devenues inutiles), sans rien toucher.
pub fn removal_preview(pkgs: &[String]) -> Vec<String> {
    if pkgs.is_empty() || !pkgs.iter().all(|p| valid_pkg(p)) {
        return vec![];
    }
    let Some(pm) = abs_prog("pacman") else { return vec![] };
    let o = Command::new(pm).args(["-Rnsp", "--print-format", "%n", "--"]).args(pkgs).env("LC_ALL", "C").output();
    match o {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout).lines().map(str::trim).filter(|l| valid_pkg(l)).map(String::from).collect(),
        _ => vec![],
    }
}

/// « ==> finished: 7 candidates (disk space saved: 1.2 GiB) » → 7
pub fn parse_candidates(out: &str) -> usize {
    out.lines().find_map(|l| l.split(": ").nth(1).and_then(|r| r.split(" candidate").next()).filter(|_| l.contains("candidate")).and_then(|n| n.trim().parse().ok())).unwrap_or(0)
}

/// Archives anciennes ou de paquets désinstallés du cache de pacman (mêmes réglages qu'arch-update : 3 versions gardées).
pub fn cache_candidates() -> usize {
    if abs_prog("paccache").is_none() {
        return 0;
    }
    let old = run("paccache", &["-dk", KEEP_OLD]).map(|(_, o)| parse_candidates(&o)).unwrap_or(0);
    let gone = run("paccache", &["-duk0"]).map(|(_, o)| parse_candidates(&o)).unwrap_or(0);
    old + gone
}

/// Applications Flatpak ayant une mise à jour (`flatpak remote-ls --updates`) : un identifiant par ligne.
pub fn parse_flatpak_ids(out: &str) -> Vec<String> {
    let mut v: Vec<String> = out.lines().map(str::trim).filter(|l| l.contains('.') && !l.contains(' ') && l.chars().all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c))).map(String::from).collect();
    v.sort();
    v.dedup();
    v
}

pub fn flatpak_updates() -> Vec<String> {
    let Some((0, out)) = run("flatpak", &["remote-ls", "--updates", "--columns=application"]) else { return vec![] };
    parse_flatpak_ids(&out)
}

/// Éléments Flatpak devenus inutiles : lignes « 1.  org.example.Runtime  … » de `flatpak uninstall --unused`.
pub fn parse_flatpak_unused(out: &str) -> Vec<String> {
    out.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            let n = it.next()?;
            let id = it.next()?;
            (n.strip_suffix('.').is_some_and(|d| !d.is_empty() && d.chars().all(|c| c.is_ascii_digit())) && id.contains('.') && id.chars().all(|c| c.is_ascii_alphanumeric() || "._-/".contains(c))).then(|| id.to_string())
        })
        .collect()
}

pub fn flatpak_unused() -> Vec<String> {
    let Some(fp) = abs_prog("flatpak") else { return vec![] };
    // lecture seule : la question finale reçoit une entrée vide, rien n'est supprimé
    let o = Command::new(fp).args(["uninstall", "--unused"]).env("LC_ALL", "C").stdin(std::process::Stdio::null()).output();
    match o {
        Ok(o) => parse_flatpak_unused(&String::from_utf8_lossy(&o.stdout)),
        Err(_) => vec![],
    }
}

/// Le noyau en cours n'existe plus sur le disque : une mise à jour attend un redémarrage.
/// Comme arch-update : sans objet avec kernel-modules-hook / mkmm, ni dans un conteneur.
pub fn reboot_pending() -> bool {
    let Ok(rel) = std::fs::read_to_string("/proc/sys/kernel/osrelease") else { return false };
    let rel = rel.trim();
    if rel.is_empty() || rel.contains('/') || !std::path::Path::new("/usr/lib/modules").is_dir() {
        return false;
    }
    if std::path::Path::new("/usr/lib/modules").join(rel).join("vmlinuz").exists() {
        return false;
    }
    let installed = |p: &str| run("pacman", &["-Q", p]).is_some_and(|(c, _)| c == 0);
    if installed("kernel-modules-hook") || installed("mkmm") {
        return false;
    }
    !run("systemd-detect-virt", &["--container", "--quiet"]).is_some_and(|(c, _)| c == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn candidats_du_cache() {
        assert_eq!(parse_candidates("==> finished: 7 candidates (disk space saved: 1.20 GiB)"), 7);
        assert_eq!(parse_candidates("==> finished: 1 candidate (disk space saved: 3 MiB)"), 1);
        assert_eq!(parse_candidates("==> no candidate packages found for pruning"), 0);
        assert_eq!(parse_candidates(""), 0);
    }

    #[test]
    fn noms_de_paquets_et_de_services() {
        assert!(valid_pkg("haskell-generically"));
        assert!(valid_pkg("lib32-gcc-libs"));
        assert!(!valid_pkg("-Rdd"));
        assert!(!valid_pkg("a b"));
        assert!(!valid_pkg("a;rm"));
        assert!(valid_service("dbus-broker.service"));
        assert!(valid_service("user@1000.service"));
        assert!(!valid_service("sshd"));
        assert!(!valid_service("-x.service"));
        assert!(!valid_service("a;b.service"));
    }

    #[test]
    fn flatpak_listes() {
        let out = "Looking for unused…\n\n        ID                           Branch   Op\n 1.     org.freedesktop.Platform.GL.default   23.08   r\n 2.     org.gnome.Platform   45   r\n\nProceed with these changes to the system installation? [Y/n]: n\n";
        assert_eq!(parse_flatpak_unused(out), vec!["org.freedesktop.Platform.GL.default", "org.gnome.Platform"]);
        assert!(parse_flatpak_unused("Nothing unused to uninstall\n").is_empty());
        assert_eq!(parse_flatpak_ids("org.mozilla.firefox\norg.gimp.GIMP\norg.mozilla.firefox\n"), vec!["org.gimp.GIMP", "org.mozilla.firefox"]);
        assert!(parse_flatpak_ids("Nothing to do.\n").is_empty());
    }

    #[test]
    fn les_scripts_valident_leurs_arguments() {
        assert!(ORPHAN_SCRIPT.contains("-Rns --noconfirm -- \"$@\""));
        assert!(ORPHAN_SCRIPT.contains("pacman -Qtdq"));
        assert!(SERVICES_RESTART_SCRIPT.contains("Nom de service invalide"));
        assert!(SERVICES_RESTART_SCRIPT.contains("systemctl restart --"));
    }
}
