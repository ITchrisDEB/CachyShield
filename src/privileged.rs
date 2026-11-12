//! Autorisation administrateur UNE SEULE FOIS : au démarrage, `pkexec` lance une seconde instance de ce programme en mode
//! « assistant » (`--root-helper`). Le programme principal lui envoie ensuite ses demandes par un tube (stdin/stdout).
//!
//! Sécurité :
//! * l'assistant n'exécute que des scripts CONSTANTS connus (comparés au texte exact) et une courte liste de programmes
//!   d'audit par chemin absolu ; toute autre demande est refusée (le programme principal retombe alors sur une demande
//!   `pkexec` ordinaire, avec mot de passe) ;
//! * les valeurs variables (ports, adresses…) restent des ARGUMENTS validés par les scripts eux-mêmes, comme avec `pkexec` ;
//! * le canal est un tube anonyme : seul le programme qui a lancé l'assistant peut lui parler ;
//! * l'assistant s'arrête dès que le programme principal se ferme, et refuse de tourner sans être root ;
//! * il n'est lancé que si l'exécutable appartient à root et n'est modifiable par personne d'autre (installation système) :
//!   sinon un programme du même utilisateur pourrait remplacer le fichier avant que vous entriez votre mot de passe.
//! Les actions qui modifient le système demandent toujours une confirmation dans l'interface avant d'être envoyées.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, Sender, channel};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use crate::util::{HELPER_SCRIPT, PKEXEC, SH, abs_prog};

pub const HELPER_FLAG: &str = "--root-helper";

#[derive(Serialize, Deserialize, Debug)]
#[serde(default)]
struct Req {
    id: u64,
    argv: Vec<String>,
    cancel: bool,
}
impl Default for Req {
    fn default() -> Self {
        Req { id: 0, argv: vec![], cancel: false }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
#[serde(default)]
struct Frame {
    id: u64,
    ready: bool,
    /// ligne de sortie standard
    o: Option<String>,
    /// ligne d'erreur
    e: Option<String>,
    /// code de sortie
    x: Option<i32>,
}

// ───────────────────────────── liste blanche ─────────────────────────────

/// Tous les scripts constants que le programme peut faire exécuter en root.
pub fn known_scripts() -> Vec<&'static str> {
    use crate::procctl as p;
    vec![
        HELPER_SCRIPT,
        crate::live::AUTH_SCRIPT,
        crate::harden::APPLY_SCRIPT,
        crate::harden::REVERT_SCRIPT,
        crate::ui::smart::ADMIN_BUNDLE_SCRIPT,
        crate::clean::PACCACHE_SCRIPT,
        crate::maint::ORPHAN_SCRIPT,
        crate::maint::SERVICES_LIST_SCRIPT,
        crate::maint::SERVICES_RESTART_SCRIPT,
        crate::clean::JOURNAL_SCRIPT,
        crate::clean::ADMIN_BOTH,
        crate::sshcfg::APPLY_SCRIPT,
        p::BLOCK_PORT_SCRIPT,
        p::UNBLOCK_PORT_SCRIPT,
        p::BLOCK_HOSTS_SCRIPT,
        p::UNBLOCK_ALL_SCRIPT,
        p::FIREWALL_ON_SCRIPT,
        p::FIREWALL_OFF_SCRIPT,
        p::UFW_ON_SCRIPT,
        p::UFW_OFF_SCRIPT,
        crate::fwd::EDIT_SCRIPT,
        crate::ufwrules::RULE_SCRIPT,
        crate::ufwrules::READ_SCRIPT,
        crate::ufwrules::DEFAULT_SCRIPT,
        p::FIREWALLD_ON_SCRIPT,
        p::FIREWALLD_OFF_SCRIPT,
    ]
}

/// Programmes d'audit autorisés (chemin absolu obligatoire).
const AUDIT_PROGRAMS: &[&str] = &["lynis", "rkhunter", "trivy"];
/// Options qui feraient charger du code ou une configuration choisie par l'utilisateur en root : toujours refusées.
const FORBIDDEN_FLAGS: &[&str] = &["--configfile", "--plugindir", "--plugin-dir", "--config", "--profile", "--cronjob-conf", "--wrapper"];
/// Options de fichier de sortie acceptées avec le script d'encadrement.
const OUT_FLAGS: &[&str] = &["--report-file", "--logfile", "--output"];

fn prog_ok(path: &str, allowed: &[&str]) -> bool {
    Path::new(path).file_name().and_then(|n| n.to_str()).is_some_and(|n| allowed.contains(&n) && abs_prog(n).is_some_and(|p| p == Path::new(path)))
}

/// Une demande est-elle autorisée à passer par l'assistant ? (`argv` : la commande SANS `pkexec`.)
pub fn authorize(argv: &[String]) -> Result<(), String> {
    let bad = |m: &str| Err(m.to_string());
    if argv.is_empty() || argv.iter().any(|a| a.contains('\0')) {
        return bad("commande vide ou invalide");
    }
    if argv[0] == SH {
        if argv.len() < 3 || argv[1] != "-c" {
            return bad("forme de commande refusée");
        }
        if !known_scripts().contains(&argv[2].as_str()) {
            return bad("script inconnu");
        }
        if argv[2] == HELPER_SCRIPT {
            // sh -c SCRIPT sh --flag /usr/bin/programme args…
            if argv.len() < 6 || argv[3] != "sh" || !OUT_FLAGS.contains(&argv[4].as_str()) || !prog_ok(&argv[5], AUDIT_PROGRAMS) {
                return bad("programme d'audit non autorisé");
            }
            return check_flags(&argv[6..]);
        }
        if argv.len() > 3 && argv[3] != "sh" {
            return bad("forme de commande refusée");
        }
        return Ok(());
    }
    // programmes lancés directement
    if prog_ok(&argv[0], &["pacman"]) {
        return if argv[1..] == ["-Syu", "--noconfirm"] { Ok(()) } else { bad("options pacman non autorisées") };
    }
    if prog_ok(&argv[0], &["rkhunter"]) {
        return check_flags(&argv[1..]);
    }
    bad("programme non autorisé")
}

fn check_flags(args: &[String]) -> Result<(), String> {
    for a in args {
        let name = a.split('=').next().unwrap_or("");
        if FORBIDDEN_FLAGS.contains(&name) {
            return Err(format!("option refusée : {name}"));
        }
    }
    Ok(())
}

// ───────────────────────────── côté root ─────────────────────────────

fn running_as_root() -> bool {
    std::fs::metadata("/proc/self").map(|m| m.uid() == 0).unwrap_or(false)
}

type Out = Mutex<Box<dyn Write + Send>>;

fn send(out: &Out, f: &Frame) {
    if let Ok(mut o) = out.lock() {
        let _ = writeln!(o, "{}", serde_json::to_string(f).unwrap_or_default());
        let _ = o.flush();
    }
}

/// Boucle de l'assistant (processus root). Ne retourne qu'à la fermeture du tube.
pub fn helper_main() -> i32 {
    if !running_as_root() {
        eprintln!("l'assistant doit être lancé par pkexec (root)");
        return 1;
    }
    serve(BufReader::new(std::io::stdin()), Arc::new(Mutex::new(Box::new(std::io::stdout()))))
}

/// Boucle de service : une demande JSON par ligne, des trames JSON en réponse. Retourne à la fin de l'entrée.
fn serve<R: BufRead>(input: R, out: Arc<Out>) -> i32 {
    send(&out, &Frame { ready: true, ..Default::default() });
    let cancels: Arc<Mutex<HashMap<u64, Arc<AtomicBool>>>> = Arc::new(Mutex::new(HashMap::new()));
    let mut workers = Vec::new();
    for line in input.lines() {
        let Ok(line) = line else { break };
        let Ok(req) = serde_json::from_str::<Req>(&line) else { continue };
        if req.cancel {
            if let Some(c) = cancels.lock().unwrap().get(&req.id) {
                c.store(true, Ordering::Relaxed);
            }
            continue;
        }
        if let Err(e) = authorize(&req.argv) {
            send(&out, &Frame { id: req.id, e: Some(format!("refusé par l'assistant : {e}")), ..Default::default() });
            send(&out, &Frame { id: req.id, x: Some(126), ..Default::default() });
            continue;
        }
        let flag = Arc::new(AtomicBool::new(false));
        cancels.lock().unwrap().insert(req.id, flag.clone());
        let (out2, cancels2) = (out.clone(), cancels.clone());
        workers.retain(|w: &std::thread::JoinHandle<()>| !w.is_finished());
        workers.push(std::thread::spawn(move || {
            let code = run_child(req.id, &req.argv, &out2, &flag);
            cancels2.lock().unwrap().remove(&req.id);
            send(&out2, &Frame { id: req.id, x: Some(code), ..Default::default() });
        }));
    }
    // le programme principal est parti : tout ce qui tourne encore est arrêté
    for c in cancels.lock().unwrap().values() {
        c.store(true, Ordering::Relaxed);
    }
    for w in workers {
        let _ = w.join();
    }
    0
}

fn stop_group(pid: u32, sig: &str) {
    if let Some(k) = abs_prog("kill") {
        let _ = Command::new(k).args([sig, "--", &format!("-{pid}")]).stdout(Stdio::null()).stderr(Stdio::null()).status();
    }
}

fn run_child(id: u64, argv: &[String], out: &Arc<Out>, cancel: &AtomicBool) -> i32 {
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).env("LC_ALL", "C").env("TERM", "dumb").process_group(0);
    let mut child: Child = match cmd.spawn() {
        Ok(c) => c,
        Err(e) => {
            send(out, &Frame { id, e: Some(format!("lancement impossible : {e}")), ..Default::default() });
            return 127;
        }
    };
    let pid = child.id();
    let pump = |stream: Box<dyn Read + Send>, is_out: bool| {
        let out = out.clone();
        std::thread::spawn(move || {
            for raw in BufReader::new(stream).split(b'\n') {
                let Ok(raw) = raw else { break };
                let l = String::from_utf8_lossy(&raw).into_owned();
                let f = if is_out { Frame { id, o: Some(l), ..Default::default() } } else { Frame { id, e: Some(l), ..Default::default() } };
                send(&out, &f);
            }
        })
    };
    let readers = [child.stdout.take().map(|s| pump(Box::new(s), true)), child.stderr.take().map(|s| pump(Box::new(s), false))];
    let mut asked = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break s.code().unwrap_or(-1),
            Ok(None) => {
                if cancel.load(Ordering::Relaxed) && !asked {
                    asked = true;
                    stop_group(pid, "-TERM");
                } else if asked {
                    std::thread::sleep(Duration::from_millis(1500));
                    stop_group(pid, "-KILL");
                }
                std::thread::sleep(Duration::from_millis(100));
            }
            Err(_) => break -1,
        }
    };
    for r in readers.into_iter().flatten() {
        let _ = r.join();
    }
    status
}

// ───────────────────────────── côté programme principal ─────────────────────────────

#[derive(Debug)]
pub enum Event {
    Out(String),
    Err(String),
    Exit(i32),
}

pub struct Session {
    stdin: Mutex<Box<dyn Write + Send>>,
    subs: Mutex<HashMap<u64, Sender<Event>>>,
    next: AtomicU64,
    alive: AtomicBool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Status {
    /// Pas encore demandé : le mot de passe sera demandé à la première action qui en a besoin.
    Idle,
    /// Fenêtre de mot de passe affichée.
    Asking,
    Active,
    /// Mot de passe refusé ou fenêtre fermée.
    Declined,
    /// Programme non installé dans un dossier protégé : chaque action demande le mot de passe.
    Unavailable,
    /// Réglage désactivé par l'utilisateur.
    Off,
}

struct Global {
    status: Status,
    session: Option<Arc<Session>>,
}

fn global() -> &'static Mutex<Global> {
    static G: OnceLock<Mutex<Global>> = OnceLock::new();
    G.get_or_init(|| Mutex::new(Global { status: Status::Idle, session: None }))
}

pub fn status() -> Status {
    global().lock().map(|g| g.status.clone()).unwrap_or(Status::Idle)
}

/// Session active (l'assistant tourne et répond), sinon None.
pub fn session() -> Option<Arc<Session>> {
    let g = global().lock().ok()?;
    g.session.clone().filter(|s| s.alive.load(Ordering::Relaxed))
}

/// L'exécutable appartient-il à root et n'est-il modifiable que par root (lui et ses dossiers parents) ?
pub fn exe_is_protected(exe: &Path) -> bool {
    let secure = |p: &Path| std::fs::metadata(p).map(|m| m.uid() == 0 && m.permissions().mode() & 0o022 == 0).unwrap_or(false);
    let mut p: Option<&Path> = Some(exe);
    while let Some(x) = p {
        if !secure(x) {
            return false;
        }
        p = x.parent().filter(|d| d.as_os_str().len() > 0);
    }
    true
}

fn exe_path() -> Option<PathBuf> {
    std::env::current_exe().ok().and_then(|p| std::fs::canonicalize(p).ok())
}

/// Prépare l'autorisation administrateur SANS rien demander : le mot de passe n'est demandé qu'au premier besoin (`ensure`).
pub fn init(enabled: bool) {
    let set = |s: Status| {
        if let Ok(mut g) = global().lock() {
            g.status = s;
        }
    };
    if !enabled {
        return set(Status::Off);
    }
    if exe_path().filter(|e| exe_is_protected(e)).is_none() || !Path::new(PKEXEC).exists() {
        return set(Status::Unavailable);
    }
    set(Status::Idle);
}

/// Session administrateur : la renvoie si elle existe ; sinon, à la PREMIÈRE demande seulement, affiche la fenêtre de mot de passe
/// et démarre l'assistant. BLOQUANT (jamais depuis le fil de l'interface). Refusé ou impossible : None, et chaque action
/// repasse alors par un `pkexec` ordinaire.
pub fn ensure() -> Option<Arc<Session>> {
    if let Some(s) = session() {
        return Some(s);
    }
    static ASKING: Mutex<()> = Mutex::new(());
    // une seule fenêtre de mot de passe à la fois : les autres demandes attendent ici puis réutilisent la session
    let _guard = ASKING.lock().ok()?;
    if let Some(s) = session() {
        return Some(s);
    }
    if status() != Status::Idle {
        return None;
    }
    let exe = exe_path().filter(|e| exe_is_protected(e))?;
    let set = |s: Status| {
        if let Ok(mut g) = global().lock() {
            g.status = s;
        }
    };
    set(Status::Asking);
    let Ok(mut child) = Command::new(PKEXEC).arg(&exe).arg(HELPER_FLAG).stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::null()).spawn() else {
        set(Status::Declined);
        return None;
    };
    let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        set(Status::Declined);
        return None;
    };
    let mut rd = BufReader::new(stdout);
    let mut first = String::new();
    let ready = rd.read_line(&mut first).is_ok() && serde_json::from_str::<Frame>(first.trim()).map(|f| f.ready).unwrap_or(false);
    if !ready {
        let _ = child.wait();
        set(Status::Declined);
        return None;
    }
    Some(attach(Box::new(stdin), Box::new(rd), move || {
        let _ = child.wait();
        set(Status::Declined);
    }))
}

/// Relie une session à un assistant (déjà prêt) : le fil de lecture distribue les trames aux demandes en cours.
/// `on_end` est appelé quand l'assistant s'arrête.
fn attach(w: Box<dyn Write + Send>, r: Box<dyn BufRead + Send>, on_end: impl FnOnce() + Send + 'static) -> Arc<Session> {
    let s = Arc::new(Session { stdin: Mutex::new(w), subs: Mutex::new(HashMap::new()), next: AtomicU64::new(1), alive: AtomicBool::new(true) });
    if let Ok(mut g) = global().lock() {
        g.status = Status::Active;
        g.session = Some(s.clone());
    }
    let s2 = s.clone();
    std::thread::spawn(move || {
        let s = s2;
        for line in r.lines() {
            let Ok(line) = line else { break };
            let Ok(f) = serde_json::from_str::<Frame>(&line) else { continue };
            let ev = match (f.o, f.e, f.x) {
                (Some(o), _, _) => Event::Out(o),
                (_, Some(e), _) => Event::Err(e),
                (_, _, Some(x)) => Event::Exit(x),
                _ => continue,
            };
            let last = matches!(ev, Event::Exit(_));
            let tx = s.subs.lock().ok().and_then(|m| m.get(&f.id).cloned());
            if let Some(tx) = tx {
                let _ = tx.send(ev);
            }
            if last {
                if let Ok(mut m) = s.subs.lock() {
                    m.remove(&f.id);
                }
            }
        }
        // l'assistant s'est arrêté : les demandes en cours se terminent en erreur, la suite repasse par pkexec
        s.alive.store(false, Ordering::Relaxed);
        if let Ok(mut m) = s.subs.lock() {
            for (_, tx) in m.drain() {
                let _ = tx.send(Event::Exit(-1));
            }
        }
        on_end();
    });
    s
}

impl Session {
    /// Envoie une commande (sans `pkexec`) ; renvoie son numéro et le flux d'événements.
    pub fn run(&self, argv: &[String]) -> Result<(u64, Receiver<Event>), String> {
        authorize(argv)?;
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = channel();
        self.subs.lock().map_err(|_| "verrou".to_string())?.insert(id, tx);
        let line = serde_json::to_string(&Req { id, argv: argv.to_vec(), cancel: false }).map_err(|e| e.to_string())?;
        let mut w = self.stdin.lock().map_err(|_| "verrou".to_string())?;
        if writeln!(w, "{line}").and_then(|_| w.flush()).is_err() {
            self.alive.store(false, Ordering::Relaxed);
            return Err("l'assistant ne répond plus".into());
        }
        Ok((id, rx))
    }

    pub fn cancel(&self, id: u64) {
        if let (Ok(line), Ok(mut w)) = (serde_json::to_string(&Req { id, argv: vec![], cancel: true }), self.stdin.lock()) {
            let _ = writeln!(w, "{line}").and_then(|_| w.flush());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sh(script: &str, args: &[&str]) -> Vec<String> {
        let mut v = vec![SH.to_string(), "-c".into(), script.to_string()];
        if !args.is_empty() {
            v.push("sh".into());
            v.extend(args.iter().map(|s| s.to_string()));
        }
        v
    }

    #[test]
    fn scripts_connus_acceptes_inconnus_refuses() {
        for s in known_scripts() {
            if s != HELPER_SCRIPT {
                assert!(authorize(&sh(s, &["tcp", "22"])).is_ok(), "script connu refusé : {}", &s[..30.min(s.len())]);
            }
        }
        assert!(authorize(&sh("rm -rf /", &[])).is_err(), "script inconnu refusé");
        assert!(authorize(&sh("echo ok", &[])).is_err());
        let mut v = sh(crate::procctl::FIREWALLD_OFF_SCRIPT, &[]);
        v[2].push(' ');
        assert!(authorize(&v).is_err(), "un seul caractère de différence suffit à refuser");
        assert!(authorize(&[]).is_err());
        assert!(authorize(&[SH.into(), "-s".into()]).is_err(), "pas de shell interactif");
    }

    #[test]
    fn scripts_distincts() {
        let k = known_scripts();
        let set: std::collections::HashSet<_> = k.iter().collect();
        assert_eq!(set.len(), k.len(), "aucun doublon dans la liste blanche");
        assert!(k.iter().all(|s| !s.trim().is_empty()));
    }

    #[test]
    fn programmes_d_audit_par_chemin_absolu() {
        let lynis = abs_prog("lynis").map(|p| p.to_string_lossy().into_owned());
        if let Some(l) = lynis {
            let mut v = vec![SH.to_string(), "-c".into(), HELPER_SCRIPT.into(), "sh".into(), "--report-file".into(), l.clone(), "audit".into(), "system".into()];
            assert!(authorize(&v).is_ok());
            v.push("--plugindir=/home/x".into());
            assert!(authorize(&v).is_err(), "répertoire de modules choisi par l'utilisateur refusé");
        }
        let bad = vec![SH.to_string(), "-c".into(), HELPER_SCRIPT.into(), "sh".into(), "--report-file".into(), "/tmp/evil".into()];
        assert!(authorize(&bad).is_err(), "programme hors liste refusé");
        let rel = vec![SH.to_string(), "-c".into(), HELPER_SCRIPT.into(), "sh".into(), "--output".into(), "lynis".into()];
        assert!(authorize(&rel).is_err(), "chemin relatif refusé");
        let other = vec![SH.to_string(), "-c".into(), HELPER_SCRIPT.into(), "sh".into(), "--bidule".into(), "/usr/bin/lynis".into()];
        assert!(authorize(&other).is_err());
    }

    #[test]
    fn pacman_seulement_pour_la_mise_a_jour() {
        if let Some(p) = abs_prog("pacman") {
            let p = p.to_string_lossy().into_owned();
            assert!(authorize(&[p.clone(), "-Syu".into(), "--noconfirm".into()]).is_ok());
            assert!(authorize(&[p.clone(), "-S".into(), "evil".into()]).is_err());
            assert!(authorize(&[p, "-U".into(), "/tmp/x.pkg.tar.zst".into()]).is_err());
        }
        assert!(authorize(&["/usr/bin/id".into()]).is_err());
        assert!(authorize(&["/tmp/pacman".into(), "-Syu".into(), "--noconfirm".into()]).is_err());
    }

    #[test]
    fn executable_protege() {
        assert!(exe_is_protected(Path::new("/usr/bin/true")) || !Path::new("/usr/bin/true").exists());
        let d = std::env::temp_dir().join(format!("cs-priv-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        let f = d.join("x");
        std::fs::write(&f, "").unwrap();
        assert!(!exe_is_protected(&f), "un fichier de l'utilisateur n'est jamais « protégé »");
        let _ = std::fs::remove_dir_all(&d);
    }

    #[test]
    fn protocole_json() {
        let r: Req = serde_json::from_str(r#"{"id":3,"argv":["/bin/sh","-c","x"]}"#).unwrap();
        assert_eq!((r.id, r.argv.len(), r.cancel), (3, 3, false));
        let f: Frame = serde_json::from_str(r#"{"id":3,"o":"ligne"}"#).unwrap();
        assert_eq!(f.o.as_deref(), Some("ligne"));
    }
    /// Sortie partagée pour les tests de l'assistant.
    #[derive(Clone, Default)]
    struct Buf(Arc<Mutex<Vec<u8>>>);
    impl Write for Buf {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(b);
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn frames(b: &Buf) -> Vec<Frame> {
        String::from_utf8_lossy(&b.0.lock().unwrap()).lines().filter_map(|l| serde_json::from_str(l).ok()).collect()
    }

    #[test]
    fn assistant_refuse_et_execute_via_le_tube() {
        let buf = Buf::default();
        let evil = serde_json::to_string(&Req { id: 1, argv: vec![SH.into(), "-c".into(), "touch /tmp/cs-pwned".into()], cancel: false }).unwrap();
        let mut input = format!("{evil}\nnon-json\n");
        if let Some(rk) = abs_prog("lynis") {
            let ok = Req { id: 2, argv: vec![SH.into(), "-c".into(), HELPER_SCRIPT.into(), "sh".into(), "--report-file".into(), rk.to_string_lossy().into_owned(), "show".into(), "version".into()], cancel: false };
            input.push_str(&format!("{}\n", serde_json::to_string(&ok).unwrap()));
        }
        // le tube reste ouvert tant que les commandes tournent (sa fermeture arrête l'assistant, comme à la fermeture du programme)
        let (rd, mut wr) = std::io::pipe().unwrap();
        let out: Arc<Out> = Arc::new(Mutex::new(Box::new(buf.clone())));
        let th = std::thread::spawn(move || serve(BufReader::new(rd), out));
        wr.write_all(input.as_bytes()).unwrap();
        let want = if abs_prog("lynis").is_some() { 2 } else { 1 };
        for _ in 0..150 {
            let f = frames(&buf);
            if f.iter().filter(|x| x.x.is_some()).count() >= want {
                break;
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        drop(wr);
        assert_eq!(th.join().unwrap(), 0, "la boucle se termine à la fermeture du tube");
        let f = frames(&buf);
        assert!(f[0].ready);
        assert!(f.iter().any(|x| x.id == 1 && x.x == Some(126)), "script inconnu : refusé avec le code 126");
        assert!(f.iter().any(|x| x.id == 1 && x.e.as_deref().is_some_and(|e| e.contains("refusé"))));
        assert!(!Path::new("/tmp/cs-pwned").exists(), "rien n'a été exécuté");
        if abs_prog("lynis").is_some() {
            assert!(f.iter().any(|x| x.id == 2 && x.o.as_deref().is_some_and(|o| o.contains("@@CS-OUTPUT-BEGIN@@"))), "sortie encadrée relayée : {f:?}");
            assert!(f.iter().any(|x| x.id == 2 && x.x.is_some()), "code de sortie renvoyé");
        }
    }
    /// Bout en bout, sans root : lanceur de commandes → session → assistant (dans ce processus) → programme autorisé.
    #[test]
    fn le_lanceur_utilise_la_session_sans_pkexec() {
        let Some(lynis) = abs_prog("lynis") else { return };
        let (req_r, req_w) = std::io::pipe().unwrap();
        let (resp_r, resp_w) = std::io::pipe().unwrap();
        let out: Arc<Out> = Arc::new(Mutex::new(Box::new(resp_w)));
        std::thread::spawn(move || serve(BufReader::new(req_r), out));
        let mut rd = BufReader::new(resp_r);
        let mut first = String::new();
        rd.read_line(&mut first).unwrap();
        assert!(serde_json::from_str::<Frame>(first.trim()).unwrap().ready);
        let s = attach(Box::new(req_w), Box::new(rd), || {});
        assert!(session().is_some());
        let plan = crate::tools::Plan { argv: vec![lynis.to_string_lossy().into_owned(), "show".into(), "version".into()], elevated: true, out_flag: Some("--report-file"), out_pos: 3 };
        let run = crate::runner::spawn(&plan, &[], None).unwrap();
        let (mut lines, mut done) = (vec![], None);
        while let Ok(m) = run.rx.recv_blocking() {
            match m {
                crate::runner::Msg::Line(l) => lines.push(l),
                crate::runner::Msg::Done { code, blob, text, .. } => {
                    done = Some((code, blob, text));
                    break;
                }
            }
        }
        let (code, blob, text) = done.expect("résultat reçu");
        assert_eq!(code, 0, "{lines:?} {text}");
        assert!(text.contains("3."), "la sortie du programme a traversé l'assistant : {text:?}");
        assert!(blob.is_some(), "résultat encadré lu comme avec pkexec");
        // une commande hors liste n'est jamais envoyée : le lanceur retombe sur pkexec
        assert!(s.run(&[SH.to_string(), "-c".into(), "id".into()]).is_err());
    }
}
