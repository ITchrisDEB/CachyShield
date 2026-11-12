//! Pour chaque problème : ce que l'application peut faire DIRECTEMENT, et ce qui relève d'une
//! RECOMMANDATION de la source (CVE, éditeur, outil). Rien n'est promis qui ne soit pas réellement possible.

use crate::global::KevVuln;
use crate::risk::Update;
use regex::Regex;
use std::sync::LazyLock;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Direct {
    /// Installer les mises à jour du système (pacman -Syu) ; contient ces paquets.
    SystemUpdate { packages: Vec<String> },
    /// Interdire la connexion root par SSH (réversible).
    SshFix,
    /// Annuler la correction SSH.
    SshRevert,
    /// Ne plus signaler cette alerte (aucune modification du système).
    IgnoreAlert,
    /// Marquer un service ouvert au réseau comme autorisé.
    MarkWanted,
    /// Aperçu des correctifs de dépendances (npm / Maven), sur une copie.
    OsvFixPreview,
    /// Commande à copier (jamais exécutée par l'application).
    CopyCommand { command: String },
    /// Arrêter ce programme (demande d'arrêt propre, SIGTERM).
    StopProcess { name: String, pids: Vec<u32> },
    /// Bloquer l'accès à un port DEPUIS LE RÉSEAU (l'accès local reste possible).
    BlockPort { proto: String, port: u16 },
    UnblockPort { proto: String, port: u16 },
    /// Bloquer les connexions sortantes vers ces serveurs publics.
    BlockHosts { ips: Vec<String> },
    /// Mettre à jour une dépendance npm DANS le projet (sauvegarde automatique de package.json et package-lock.json).
    NpmFix { dir: String, name: String, fixed: String },
    /// Corriger une bibliothèque d'un projet (npm update…) via la fenêtre de correction.
    LibFix { name: String, fixed: String, place: String },
    /// Mettre à jour des paquets AUR (ou tout l'AUR si la liste est vide) dans un terminal : relecture du PKGBUILD et mot de passe dans ce terminal.
    /// `terminal` : false = dans l'application (relecture du PKGBUILD dans une fenêtre), true = dans le terminal de l'utilisateur.
    AurUpdate { helper: String, packages: Vec<String>, terminal: bool },
    /// Redémarrer l'ordinateur (après confirmation) : applique les mises à jour du noyau et des pilotes.
    Reboot,
}

#[derive(Clone, Debug, Default)]
pub struct Advice {
    pub direct: Vec<Direct>,
    /// Si rien n'est faisable directement : pourquoi.
    pub no_direct: Option<String>,
    /// Ce que recommande la source.
    pub recommendation: Vec<String>,
    pub source: String,
    pub links: Vec<(String, String)>,
}

static RE_SAFE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9@/._+-]{1,100}$").unwrap());
static RE_LYNIS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Z]{3,5}-\d{4}$").unwrap());
static RE_CVE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^CVE-\d{4}-\d{4,7}$").unwrap());

fn first_cve(cves: &str) -> Option<String> {
    cves.split(',').map(str::trim).find(|c| RE_CVE.is_match(c)).map(String::from)
}

/// Paquet du système (Arch Security Tracker) : correctif publié ? présent dans les mises à jour en attente ?
pub fn for_system_package(name: &str, fixed: &str, cves: &str, pending: &[Update]) -> Advice {
    let mut a = Advice { source: "Arch Security Tracker (équipe sécurité d'Arch Linux)".into(), ..Default::default() };
    if let Some(c) = first_cve(cves) {
        a.links.push((format!("Ouvrir la fiche {c}"), format!("https://security.archlinux.org/{c}")));
    }
    let has_fix = !fixed.is_empty() && fixed != "aucun";
    let in_pending = pending.iter().find(|u| u.name == name);
    match (has_fix, in_pending) {
        (true, Some(u)) => {
            a.direct.push(Direct::SystemUpdate { packages: vec![name.into()] });
            a.recommendation.push(format!("Un correctif existe (version {fixed}). Le paquet {name} fait partie des mises à jour en attente : {} → {}.", u.old, u.new));
            a.recommendation.push("Sur Arch Linux seule la mise à jour COMPLÈTE du système est supportée (jamais un paquet isolé), car les paquets dépendent les uns des autres.".into());
        }
        (true, None) => {
            a.no_direct = Some(format!("Le correctif {fixed} est publié mais n'est pas encore dans vos dépôts synchronisés : il n'y a rien à installer maintenant."));
            a.recommendation.push("Relancez la recherche de mises à jour plus tard : le correctif arrivera avec une prochaine mise à jour du système.".into());
        }
        (false, _) => {
            a.no_direct = Some("Aucun correctif n'est publié pour le moment : il n'y a rien à installer.".into());
            a.recommendation.push("L'équipe sécurité d'Arch suit cette faille. Dès qu'un correctif sort, il apparaîtra dans « Mises à jour ».".into());
            a.recommendation.push("En attendant, limitez l'exposition : n'utilisez pas ce logiciel avec des fichiers ou des serveurs non fiables.".into());
        }
    }
    a
}

/// Logiciel ciblé par des attaques réelles (catalogue CISA KEV).
pub fn for_kev(software: &str, entries: &[KevVuln], pending: &[Update]) -> Advice {
    let mut a = Advice { source: "CISA — catalogue des failles exploitées (KEV)".into(), ..Default::default() };
    if let Some(e) = entries.first() {
        if !e.action.is_empty() {
            a.recommendation.push(format!("Action demandée par la CISA : « {} »", e.action));
            a.recommendation.push("En clair : appliquez les correctifs ou mesures de l'éditeur ; s'il n'y en a pas, cessez d'utiliser le produit.".into());
        }
        if !e.description.is_empty() {
            a.recommendation.push(format!("{} ({}, ajoutée le {}, échéance CISA {}{})", e.name, e.cve, e.added, e.due, if e.ransomware == "Known" { " — utilisée par des rançongiciels" } else { "" }));
        }
        if RE_CVE.is_match(&e.cve) {
            a.links.push((format!("Fiche officielle {}", e.cve), format!("https://nvd.nist.gov/vuln/detail/{}", e.cve)));
        }
    }
    a.links.push(("Catalogue CISA".into(), "https://www.cisa.gov/known-exploited-vulnerabilities-catalog".into()));
    if let Some(u) = pending.iter().find(|u| u.name == software) {
        a.direct.push(Direct::SystemUpdate { packages: vec![software.into()] });
        a.recommendation.push(format!("{software} a une mise à jour en attente ({} → {}) : l'installer applique les correctifs de l'éditeur.", u.old, u.new));
    } else {
        a.no_direct = Some(format!("« {software} » n'a pas de mise à jour en attente chez vous. La liste CISA ne précise pas quelles versions sont touchées : si le logiciel est à jour, la faille est probablement déjà corrigée."));
    }
    a
}

/// Commande de mise à jour d'une dépendance, par écosystème. Aucune commande n'est produite si un nom contient un caractère inhabituel.
pub fn dependency_commands(eco: &str, name: &str, fixed: &str) -> Vec<String> {
    if !RE_SAFE.is_match(name) || !RE_SAFE.is_match(fixed) {
        return vec![];
    }
    match eco {
        "PyPI" => vec![format!("pip install --upgrade \"{name}>={fixed}\"")],
        "npm" => vec![format!("npm install {name}@{fixed}")],
        "crates.io" => vec![format!("cargo update -p {name}")],
        "Go" => vec![format!("go get {name}@v{fixed}")],
        "RubyGems" => vec![format!("bundle update {name}")],
        "NuGet" => vec![format!("dotnet add package {name} --version {fixed}")],
        _ => vec![],
    }
}

/// Dépendance d'un de vos projets (OSV).
pub fn for_dependency(eco: &str, name: &str, version: &str, fixed: &str, files: &[String]) -> Advice {
    let mut a = Advice { source: "OSV (osv.dev) — GitHub Advisory, PyPI, npm, Go, crates.io…".into(), ..Default::default() };
    let has_fix = !fixed.is_empty() && fixed != "aucun";
    if !files.is_empty() {
        a.recommendation.push(format!("Fichier(s) concerné(s) : {}", files.join(", ")));
    }
    if has_fix {
        a.recommendation.push(format!("Mettez {name} de la version {version} à la version {fixed} (ou plus récente) dans votre projet."));
        for c in dependency_commands(eco, name, fixed) {
            a.direct.push(Direct::CopyCommand { command: c });
        }
        if eco == "npm" {
            if let Some(dir) = npm_project_dir(files) {
                if RE_SAFE.is_match(name) && RE_SAFE.is_match(fixed) {
                    a.direct.push(Direct::NpmFix { dir, name: name.to_string(), fixed: fixed.to_string() });
                }
            }
        }
        if eco == "npm" || eco == "Maven" {
            a.direct.push(Direct::OsvFixPreview);
        }
        if a.direct.is_empty() {
            a.no_direct = Some(format!("Pour l'écosystème « {eco} » l'application ne modifie pas vos projets : modifiez la version dans le fichier de dépendances indiqué."));
        } else {
            a.recommendation.push(if a.direct.iter().any(|d| matches!(d, Direct::NpmFix { .. })) { "Mise à jour dans le projet : package.json et package-lock.json sont sauvegardés avant, et restaurés automatiquement en cas d'échec. Testez votre projet après la mise à jour." } else { "L'application ne modifie pas vos projets sans votre accord : elle copie la commande ou montre un aperçu sur une copie. Testez votre projet après la mise à jour." }.into());
        }
    } else {
        a.no_direct = Some("OSV ne connaît pas de version corrigée : il n'y a rien à mettre à jour.".into());
        a.recommendation.push("Remplacez la bibliothèque par une alternative maintenue, ou limitez son usage aux données de confiance.".into());
    }
    if RE_SAFE.is_match(name) {
        a.links.push(("Chercher sur osv.dev".into(), format!("https://osv.dev/list?q={name}")));
    }
    a
}

/// Dossier du projet npm : celui du package-lock.json / package.json signalé (chemin absolu, dossier existant, package.json présent).
pub fn npm_project_dir(files: &[String]) -> Option<String> {
    files.iter().find_map(|f| {
        let p = std::path::Path::new(f);
        let name = p.file_name()?.to_str()?;
        if !matches!(name, "package-lock.json" | "package.json" | "npm-shrinkwrap.json") || !p.is_absolute() {
            return None;
        }
        let dir = p.parent()?;
        (dir.join("package.json").is_file() && dir.parent().is_some()).then(|| dir.to_string_lossy().into_owned())
    })
}

/// Mise à jour du système en attente.
pub fn for_update(u: &Update, risk: Option<&str>) -> Advice {
    let mut a = Advice { source: crate::i18n::tr("Dépôts {distro}").replace("{distro}", &crate::util::distro_name()), ..Default::default() };
    a.direct.push(Direct::SystemUpdate { packages: vec![u.name.clone()] });
    a.recommendation.push(format!("{} : {} → {}", u.name, u.old, u.new));
    if let Some(r) = risk {
        a.recommendation.push(format!("⚠ {r}"));
        a.recommendation.push("Un instantané de secours (snapper) est créé avant l'installation : vous pourrez revenir en arrière.".into());
    }
    a
}

/// Conseil de Lynis : jamais appliqué automatiquement.
pub fn for_lynis(id: &str, text: &str, detail: &str) -> Advice {
    let mut a = Advice { source: "Lynis (CISOfy)".into(), ..Default::default() };
    a.no_direct = Some("Lynis ne modifie jamais le système, et ce réglage dépend de votre usage : l'appliquer automatiquement pourrait casser un programme que vous utilisez. C'est une recommandation à appliquer à la main.".into());
    a.recommendation.push(text.to_string());
    if id == "KRNL-5830" {
        a.no_direct = None;
        a.direct.push(Direct::Reboot);
        a.recommendation.push("Le noyau en cours d'exécution n'est plus celui qui est installé : un redémarrage applique les mises à jour du noyau et des pilotes (et permet au pare-feu de charger ses composants). Enregistrez vos travaux avant.".into());
    }
    if !detail.is_empty() {
        a.recommendation.push(detail.to_string());
    }
    if RE_LYNIS.is_match(id) {
        a.links.push((format!("Explication du contrôle {id}"), format!("https://cisofy.com/lynis/controls/{id}/")));
    }
    a
}

/// Programme qui accepte des connexions venant du réseau : le bloquer (réversible) ou l'arrêter, avec garde-fous.
pub fn for_service(name: &str, ports: &[(String, u16)], procs: &[crate::procctl::ProcInfo], blocked: &[(String, u16)], wanted: bool) -> Advice {
    use crate::procctl::{self, Kill};
    let mut a = Advice { source: "Analyse locale de cet ordinateur (ss et /proc)".into(), ..Default::default() };
    let list = ports.iter().map(|(p, n)| format!("{n}/{p}")).collect::<Vec<_>>().join(", ");
    a.recommendation.push(format!("« {name} » accepte des connexions venant d'autres appareils sur : {list}."));
    if let Some(p) = procs.first() {
        if !p.cmdline.is_empty() {
            a.recommendation.push(format!("Commande : {}", p.cmdline));
        }
        a.recommendation.push(format!("Processus n°{} (compte n°{}).", procs.iter().map(|p| p.pid.to_string()).collect::<Vec<_>>().join(", "), p.uid));
    }
    if !wanted {
        a.direct.push(Direct::MarkWanted);
    }
    for (proto, port) in ports.iter().filter(|(p, _)| procctl::valid_proto(p)).take(2) {
        if blocked.iter().any(|(bp, bn)| bp == proto && bn == port) {
            a.direct.push(Direct::UnblockPort { proto: proto.clone(), port: *port });
        } else {
            a.direct.push(Direct::BlockPort { proto: proto.clone(), port: *port });
        }
    }
    let (me, own) = (procctl::current_uid(), std::process::id());
    let refusal = procs.iter().find_map(|p| if let Kill::Refused(r) = procctl::can_kill(p, me, own) { Some(r) } else { None });
    match refusal {
        None if !procs.is_empty() => a.direct.push(Direct::StopProcess { name: name.into(), pids: procctl::pids_valid(&procs.iter().map(|p| p.pid).collect::<Vec<_>>()) }),
        Some(r) => a.recommendation.push(format!("Arrêt impossible depuis l'application : {r}")),
        None => {}
    }
    a.recommendation.push("Bloquer l'accès réseau : le programme continue de fonctionner et reste utilisable depuis cet ordinateur, mais plus depuis les autres appareils. Le blocage disparaît au redémarrage (ou avec « Tout débloquer »).".into());
    a.recommendation.push("Arrêter le programme : il reçoit une demande d'arrêt propre ; les données non enregistrées peuvent être perdues, et il ne repart pas tout seul sauf s'il est géré par un service.".into());
    if a.direct.is_empty() {
        a.no_direct = Some("Aucune action directe n'est sûre pour ce programme (voir la recommandation).".into());
    }
    a
}

/// Programme avec des connexions vers Internet : l'arrêter ou bloquer ses serveurs (publics seulement).
pub fn for_connections(name: &str, procs: &[crate::procctl::ProcInfo], remotes: &[String]) -> Advice {
    use crate::procctl::{self, Kill};
    let mut a = Advice { source: "Analyse locale de cet ordinateur (ss et /proc)".into(), ..Default::default() };
    a.recommendation.push(format!("« {name} » a des connexions ouvertes vers {} serveur(s) : {}{}.", remotes.len(), remotes.iter().take(8).cloned().collect::<Vec<_>>().join(", "), if remotes.len() > 8 { "…" } else { "" }));
    if let Some(p) = procs.first().filter(|p| !p.cmdline.is_empty()) {
        a.recommendation.push(format!("Commande : {}", p.cmdline));
    }
    let (me, own) = (procctl::current_uid(), std::process::id());
    match procs.iter().find_map(|p| if let Kill::Refused(r) = procctl::can_kill(p, me, own) { Some(r) } else { None }) {
        None if !procs.is_empty() => a.direct.push(Direct::StopProcess { name: name.into(), pids: procctl::pids_valid(&procs.iter().map(|p| p.pid).collect::<Vec<_>>()) }),
        Some(r) => a.recommendation.push(format!("Arrêt impossible depuis l'application : {r}")),
        None => {}
    }
    let ips: Vec<String> = remotes.iter().filter_map(|r| procctl::blockable_host(r)).take(10).collect();
    if !ips.is_empty() {
        a.direct.push(Direct::BlockHosts { ips });
        a.recommendation.push("Bloquer ces serveurs coupe les connexions vers ces adresses sans arrêter le programme. Attention : un site peut utiliser plusieurs adresses, et bloquer une adresse partagée peut en gêner d'autres. Réversible avec « Tout débloquer ».".into());
    }
    if a.direct.is_empty() {
        a.no_direct = Some("Aucune action directe n'est sûre pour ce programme (voir la recommandation).".into());
    }
    a
}

pub fn direct_label(d: &Direct) -> String {
    match d {
        Direct::SystemUpdate { packages } => format!("Installer la mise à jour du système (inclut {})", packages.join(", ")),
        Direct::SshFix => "Interdire la connexion « root » par SSH (réversible, avec instantané de secours)".into(),
        Direct::SshRevert => "Annuler la correction SSH".into(),
        Direct::IgnoreAlert => "Ne plus signaler cette alerte (aucune modification du système)".into(),
        Direct::MarkWanted => "Marquer ce service comme autorisé (aucune modification du système)".into(),
        Direct::OsvFixPreview => "Voir un aperçu des correctifs de dépendances (sur une copie, vos fichiers ne sont pas modifiés)".into(),
        Direct::CopyCommand { command } => format!("Copier la commande : {command}"),
        Direct::StopProcess { name, pids } => format!("Arrêter « {name} » (arrêt propre, PID {})", pids.iter().map(u32::to_string).collect::<Vec<_>>().join(", ")),
        Direct::BlockPort { proto, port } => format!("Bloquer le port {port}/{proto} depuis le réseau (l'accès local reste possible, jusqu'au redémarrage)"),
        Direct::UnblockPort { proto, port } => format!("Débloquer le port {port}/{proto}"),
        Direct::BlockHosts { ips } => format!("Bloquer les connexions vers {} serveur(s) : {}", ips.len(), ips.join(", ")),
        Direct::NpmFix { name, fixed, .. } => format!("Mettre à jour {name} vers {fixed} dans le projet (sauvegarde automatique avant)"),
        Direct::LibFix { name, fixed, place } => format!("Mettre à jour {name} vers {fixed} dans « {place} » (sauvegarde automatique avant, limites de versions du projet respectées)"),
        Direct::AurUpdate { terminal: false, packages, .. } => format!("Mettre à jour {} depuis l'AUR dans l'application (vous relisez le PKGBUILD avant l'installation)", packages.join(", ")),
        Direct::AurUpdate { helper, packages, .. } => if packages.is_empty() { format!("Mettre à jour tout l'AUR avec {helper} dans un terminal (relecture des PKGBUILD, mot de passe saisi dans le terminal)") } else { format!("Mettre à jour {} avec {helper} dans un terminal (relecture du PKGBUILD)", packages.join(", ")) },
        Direct::Reboot => "Redémarrer l'ordinateur maintenant (après confirmation)".into(),
    }
}

/// Texte affiché dans la fenêtre de détail : deux parties bien séparées.
pub fn render(a: &Advice) -> String {
    let mut s = String::from("CE QUE L'APPLICATION PEUT FAIRE DIRECTEMENT\n");
    if a.direct.is_empty() {
        s += &format!("✘ Rien d'automatique. {}\n", a.no_direct.clone().unwrap_or_else(|| "Aucune action directe n'est possible pour ce point.".into()));
    } else {
        for d in &a.direct {
            s += &format!("✔ {}\n", direct_label(d));
        }
    }
    if !a.recommendation.is_empty() {
        s += &format!("\nRECOMMANDATION DE LA SOURCE — {}\n", a.source);
        for r in &a.recommendation {
            s += &format!("• {r}\n");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upd(n: &str) -> Update {
        Update { name: n.into(), old: "1.0-1".into(), new: "1.1-1".into() }
    }

    #[test]
    fn correctif_dans_les_mises_a_jour_en_attente() {
        let a = for_system_package("openssl", "3.5.1", "CVE-2025-1000, CVE-2025-1001", &[upd("openssl")]);
        assert!(a.direct.contains(&Direct::SystemUpdate { packages: vec!["openssl".into()] }));
        assert!(a.no_direct.is_none());
        assert!(a.links[0].1.ends_with("/CVE-2025-1000"));
        assert!(render(&a).contains("COMPLÈTE"));
    }

    #[test]
    fn correctif_publie_mais_pas_encore_disponible_ne_promet_rien() {
        let a = for_system_package("pam", "1.7.2", "CVE-2025-6020", &[]);
        assert!(a.direct.is_empty(), "rien d'installable : on ne promet pas d'action");
        assert!(a.no_direct.unwrap().contains("pas encore"));
    }

    #[test]
    fn sans_correctif_aucune_action_directe() {
        let a = for_system_package("grub", "aucun", "CVE-2022-28737", &[upd("grub")]);
        assert!(a.direct.is_empty());
        assert!(a.no_direct.unwrap().contains("Aucun correctif"));
    }

    #[test]
    fn kev_reprend_l_action_officielle_de_la_cisa() {
        let e = KevVuln { cve: "CVE-2025-9999".into(), name: "Chromium V8 Out of Bounds".into(), added: "2026-09-09".into(), due: "2026-09-23".into(), action: "Apply mitigations per vendor instructions.".into(), description: "d".into(), ..Default::default() };
        let a = for_kev("chromium", &[e.clone()], &[upd("chromium")]);
        assert!(render(&a).contains("Apply mitigations per vendor instructions."));
        assert!(a.direct.contains(&Direct::SystemUpdate { packages: vec!["chromium".into()] }));
        let b = for_kev("chromium", &[e], &[]);
        assert!(b.direct.is_empty() && b.no_direct.is_some());
    }

    #[test]
    fn commandes_de_dependances_par_ecosysteme_et_securisees() {
        assert_eq!(dependency_commands("PyPI", "pillow", "10.0.1"), vec!["pip install --upgrade \"pillow>=10.0.1\""]);
        assert_eq!(dependency_commands("npm", "vite", "5.0.1"), vec!["npm install vite@5.0.1"]);
        assert!(dependency_commands("PyPI", "x; rm -rf ~", "1.0").is_empty(), "un nom suspect ne produit jamais de commande");
        assert!(dependency_commands("Maven", "a", "1").is_empty());
    }

    #[test]
    fn dependance_npm_propose_apercu_pypi_seulement_commande() {
        let n = for_dependency("npm", "vite", "4.5.0", "5.0.1", &["/p/package.json".into()]);
        assert!(n.direct.contains(&Direct::OsvFixPreview));
        let p = for_dependency("PyPI", "pillow", "9.5.0", "10.0.1", &[]);
        assert!(!p.direct.contains(&Direct::OsvFixPreview));
        assert!(matches!(p.direct[0], Direct::CopyCommand { .. }));
        let s = for_dependency("PyPI", "x", "1", "aucun", &[]);
        assert!(s.direct.is_empty() && s.no_direct.is_some());
    }

    #[test]
    fn lynis_jamais_automatique() {
        let a = for_lynis("SSH-7440", "Consider hardening SSH", "PermitRootLogin");
        assert!(a.direct.is_empty());
        assert!(a.links[0].1.contains("SSH-7440"));
        assert!(for_lynis("x; id", "t", "").links.is_empty());
    }
}

#[cfg(test)]
mod tests_reseau {
    use super::*;
    use crate::procctl::ProcInfo;

    fn proc(pid: u32, uid: u32, name: &str) -> ProcInfo {
        ProcInfo { pid, uid, name: name.into(), cmdline: format!("/usr/bin/{name} --x") }
    }

    #[test]
    fn service_utilisateur_peut_etre_bloque_ou_arrete() {
        let me = crate::procctl::current_uid();
        let a = for_service("python3", &[("tcp".into(), 8090)], &[proc(4000, me, "python3")], &[], false);
        assert!(a.direct.contains(&Direct::MarkWanted));
        assert!(a.direct.contains(&Direct::BlockPort { proto: "tcp".into(), port: 8090 }));
        assert!(a.direct.iter().any(|d| matches!(d, Direct::StopProcess { .. })));
    }

    #[test]
    fn service_systeme_ou_session_jamais_arrete_mais_bloquable() {
        let a = for_service("sshd", &[("tcp".into(), 22)], &[proc(900, 0, "sshd")], &[], true);
        assert!(!a.direct.iter().any(|d| matches!(d, Direct::StopProcess { .. })), "root : pas d'arrêt");
        assert!(a.direct.contains(&Direct::BlockPort { proto: "tcp".into(), port: 22 }));
        assert!(render(&a).contains("Arrêt impossible"));
    }

    #[test]
    fn port_deja_bloque_propose_le_deblocage() {
        let a = for_service("x", &[("tcp".into(), 80)], &[], &[("tcp".into(), 80)], true);
        assert!(a.direct.contains(&Direct::UnblockPort { proto: "tcp".into(), port: 80 }));
        assert!(!a.direct.contains(&Direct::BlockPort { proto: "tcp".into(), port: 80 }));
    }

    #[test]
    fn connexions_ne_bloquent_que_des_serveurs_publics() {
        let me = crate::procctl::current_uid();
        let a = for_connections("chrome", &[proc(5000, me, "chrome")], &["142.251.173.95".into(), "192.168.1.30".into(), "127.0.0.1".into()]);
        let ips = a.direct.iter().find_map(|d| if let Direct::BlockHosts { ips } = d { Some(ips.clone()) } else { None }).unwrap();
        assert_eq!(ips, vec!["142.251.173.95"], "jamais le réseau local ni la boucle locale");
    }
}

#[cfg(test)]
mod npm_tests {
    use super::*;

    #[test]
    fn dossier_npm() {
        assert_eq!(npm_project_dir(&["relatif/package.json".into()]), None, "chemin relatif refusé");
        assert_eq!(npm_project_dir(&["/etc/passwd".into()]), None);
        let d = std::env::temp_dir().join("cs-npm-test");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("package.json"), "{}").unwrap();
        assert_eq!(npm_project_dir(&[d.join("package-lock.json").to_string_lossy().into_owned()]), Some(d.to_string_lossy().into_owned()));
        let _ = std::fs::remove_dir_all(&d);
    }
}
