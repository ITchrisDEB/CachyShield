//! Exécution de commandes : jamais de shell construit dynamiquement, programmes par chemin absolu,
//! dossier temporaire privé (0700) créé sans suivre de lien symbolique, sorties plafonnées.

use crate::tools::Plan;
use crate::util::{HELPER_SCRIPT, OUT_END, PKEXEC, SH, strip_ansi};
use std::collections::HashMap;
use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::os::unix::fs::DirBuilderExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

const MAX_BLOB: u64 = 256 * 1024 * 1024;
const MAX_TEXT: usize = 8 * 1024 * 1024;
const MAX_LINE: usize = 4000;
const MAX_LINES: usize = 50_000;

pub enum Msg {
    Line(String),
    /// `blob` : résultat anonyme ; `blobs` : résultats nommés (une seule autorisation peut produire plusieurs résultats).
    Done { code: i32, blob: Option<String>, blobs: HashMap<String, String>, text: String },
}

pub struct Running {
    pub rx: async_channel::Receiver<Msg>,
    pub cancel: Arc<AtomicBool>,
}

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Dossier privé de l'utilisateur : $XDG_RUNTIME_DIR (0700, en mémoire) sinon /tmp.
/// `DirBuilder::create` échoue si le nom existe déjà (même un lien symbolique) : pas de détournement possible.
pub fn private_tmpdir() -> std::io::Result<PathBuf> {
    let base = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from).filter(|p| p.is_absolute() && p.is_dir()).unwrap_or_else(|| PathBuf::from("/tmp"));
    let nanos = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.subsec_nanos()).unwrap_or(0);
    let name = format!("cachy-shield-{}-{}-{}", std::process::id(), nanos, COUNTER.fetch_add(1, Ordering::Relaxed));
    let dir = base.join(name);
    fs::DirBuilder::new().mode(0o700).create(&dir)?;
    Ok(dir)
}

/// Commande finale : aucune interpolation, tout passe en arguments.
pub fn final_argv(plan: &Plan, out_file: &Path) -> Vec<String> {
    match (plan.out_flag, plan.elevated) {
        (Some(flag), true) => {
            let mut v = vec![PKEXEC.into(), SH.into(), "-c".into(), HELPER_SCRIPT.into(), "sh".into(), flag.into()];
            v.extend(plan.argv.iter().cloned());
            v
        }
        (Some(flag), false) => {
            let mut v = plan.argv.clone();
            let pos = plan.out_pos.min(v.len());
            v.splice(pos..pos, [flag.to_string(), out_file.to_string_lossy().into_owned()]);
            v
        }
        (None, true) => {
            let mut v = vec![PKEXEC.to_string()];
            v.extend(plan.argv.iter().cloned());
            v
        }
        (None, false) => plan.argv.clone(),
    }
}

/// Texte de la commande tel qu'il sera exécuté (pour l'aperçu).
pub fn preview(plan: &Plan) -> String {
    let shown = Plan { argv: plan.argv.clone(), elevated: false, out_flag: plan.out_flag, out_pos: plan.out_pos };
    let mut v = final_argv(&shown, Path::new("<fichier temporaire privé>"));
    if plan.elevated {
        v.insert(0, "pkexec".into());
    }
    v.iter().map(|a| shell_quote(a)).collect::<Vec<_>>().join(" ")
}

pub fn shell_quote(s: &str) -> String {
    if !s.is_empty() && s.chars().all(|c| c.is_ascii_alphanumeric() || "-_./=:,@%+".contains(c)) {
        s.to_string()
    } else {
        format!("'{}'", s.replace('\'', r"'\''"))
    }
}

pub fn spawn(plan: &Plan, noise: &'static [&'static str], cwd: Option<PathBuf>) -> Result<Running, String> {
    let tmp = private_tmpdir().map_err(|e| format!("dossier temporaire impossible : {e}"))?;
    let out_file = tmp.join("out");
    let argv = final_argv(plan, &out_file);
    let elevated_blob = plan.elevated && plan.out_flag.is_some();
    // une exécution administrateur peut renvoyer des résultats encadrés par des marqueurs (un ou plusieurs)
    let parse_markers = plan.elevated;
    let file_mode = !plan.elevated && plan.out_flag.is_some();
    let (tx, rx) = async_channel::unbounded::<Msg>();
    let cancel = Arc::new(AtomicBool::new(false));
    let cancel2 = cancel.clone();
    let want_remote = plan.elevated;

    std::thread::spawn(move || {
        // autorisation administrateur : le mot de passe est demandé UNE fois, à la première action qui en a besoin ; ensuite la
        // demande passe par l'assistant (sans nouveau mot de passe). Ce fil peut attendre la fenêtre : l'interface reste libre.
        let remote = if want_remote { crate::privileged::ensure().and_then(|s| s.run(&argv[1..]).ok().map(|(id, rx)| (s, id, rx))) } else { None };
        let done = |code: i32, blob: Option<String>, blobs: HashMap<String, String>, text: String| {
            let _ = tx.send_blocking(Msg::Done { code, blob, blobs, text });
            let _ = fs::remove_dir_all(&tmp);
        };
        let mut child: Option<std::process::Child> = None;
        let mut remote_exit: Option<std::sync::mpsc::Receiver<i32>> = None;
        let (stream_out, stream_err): (Option<Box<dyn Read + Send>>, Option<Box<dyn Read + Send>>) = if let Some((sess, id, erx)) = remote {
            let (Ok((out_r, out_w)), Ok((err_r, err_w))) = (std::io::pipe(), std::io::pipe()) else { return done(127, None, HashMap::new(), "tube interne impossible".into()) };
            let (xtx, xrx) = std::sync::mpsc::channel();
            let cancel3 = cancel2.clone();
            std::thread::spawn(move || {
                use crate::privileged::Event;
                use std::io::Write;
                let (mut ow, mut ew) = (out_w, err_w);
                let mut asked = false;
                let code = loop {
                    match erx.recv_timeout(Duration::from_millis(100)) {
                        Ok(Event::Out(l)) => {
                            let _ = writeln!(ow, "{l}");
                        }
                        Ok(Event::Err(l)) => {
                            let _ = writeln!(ew, "{l}");
                        }
                        Ok(Event::Exit(c)) => break c,
                        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                            if cancel3.load(Ordering::Relaxed) && !asked {
                                asked = true;
                                sess.cancel(id);
                            }
                        }
                        Err(_) => break -1,
                    }
                };
                drop(ow);
                drop(ew);
                let _ = xtx.send(code);
            });
            remote_exit = Some(xrx);
            (Some(Box::new(out_r)), Some(Box::new(err_r)))
        } else {
            let mut cmd = Command::new(&argv[0]);
            cmd.args(&argv[1..]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).env("LC_ALL", "C").env("TERM", "dumb");
            if let Some(d) = &cwd {
                cmd.current_dir(d);
            }
            let mut c = match cmd.spawn() {
                Ok(c) => c,
                Err(e) => return done(127, None, HashMap::new(), format!("lancement impossible : {e}")),
            };
            let so = c.stdout.take().map(|x| Box::new(x) as Box<dyn Read + Send>);
            let se = c.stderr.take().map(|x| Box::new(x) as Box<dyn Read + Send>);
            child = Some(c);
            (so, se)
        };
        let blobs: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
        let text = Arc::new(Mutex::new(String::new()));
        let lines = Arc::new(AtomicU64::new(0));

        let mut readers = Vec::new();
        let mut spawn_reader = |stream: Box<dyn Read + Send>, is_stdout: bool| {
            let (tx, blobs, text, lines) = (tx.clone(), blobs.clone(), text.clone(), lines.clone());
            readers.push(std::thread::spawn(move || {
                let mut in_block: Option<String> = None;
                for raw in BufReader::new(stream).split(b'\n') {
                    let Ok(raw) = raw else { break };
                    let line = strip_ansi(&String::from_utf8_lossy(&raw));
                    if is_stdout && parse_markers {
                        if let Some(name) = begin_name(&line) {
                            in_block = Some(name);
                            continue;
                        }
                        if in_block.is_some() && line.trim() == OUT_END {
                            in_block = None;
                            continue;
                        }
                        if let Some(name) = &in_block {
                            let mut b = blobs.lock().unwrap();
                            let e = b.entry(name.clone()).or_default();
                            if (e.len() as u64) < MAX_BLOB {
                                e.push_str(&line);
                                e.push('\n');
                            }
                            continue;
                        }
                    }
                    if noise.iter().any(|n| line.contains(n)) {
                        continue;
                    }
                    {
                        let mut t = text.lock().unwrap();
                        if t.len() < MAX_TEXT {
                            t.push_str(&line);
                            t.push('\n');
                        }
                    }
                    let n = lines.fetch_add(1, Ordering::Relaxed);
                    if n < MAX_LINES as u64 {
                        let mut shown = line;
                        if shown.len() > MAX_LINE {
                            shown.truncate(shown.floor_char_boundary(MAX_LINE));
                        }
                        let _ = tx.send_blocking(Msg::Line(shown));
                    } else if n == MAX_LINES as u64 {
                        let _ = tx.send_blocking(Msg::Line("[… sortie tronquée : trop de lignes …]".into()));
                    }
                }
            }));
        };
        if let Some(o) = stream_out {
            spawn_reader(o, true);
        }
        if let Some(e) = stream_err {
            spawn_reader(e, false);
        }

        let code = if let Some(x) = remote_exit {
            x.recv().unwrap_or(-1)
        } else if let Some(mut child) = child {
            let status = loop {
                match child.try_wait() {
                    Ok(Some(s)) => break Ok(s),
                    Ok(None) => {
                        if cancel2.load(Ordering::Relaxed) {
                            let _ = child.kill();
                            break child.wait();
                        }
                        std::thread::sleep(Duration::from_millis(100));
                    }
                    Err(e) => break Err(e),
                }
            };
            status.ok().and_then(|s| s.code()).unwrap_or(-1)
        } else {
            -1
        };
        for r in readers {
            let _ = r.join();
        }
        let mut named = std::mem::take(&mut *blobs.lock().unwrap());
        let blob_out = if elevated_blob {
            Some(named.remove("").unwrap_or_default())
        } else if file_mode {
            match fs::metadata(&out_file) {
                Ok(m) if m.is_file() && m.len() <= MAX_BLOB => fs::read_to_string(&out_file).ok(),
                _ => None,
            }
        } else {
            None
        };
        let t = std::mem::take(&mut *text.lock().unwrap());
        done(code, blob_out, named, t);
    });
    Ok(Running { rx, cancel })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan(elevated: bool, out: Option<&'static str>) -> Plan {
        Plan { argv: vec!["/usr/bin/trivy".into(), "rootfs".into(), "/".into()], elevated, out_flag: out, out_pos: 2 }
    }

    #[test]
    fn elevation_passe_par_script_constant() {
        let v = final_argv(&plan(true, Some("--output")), Path::new("/x"));
        assert_eq!(&v[..3], [PKEXEC, SH, "-c"]);
        assert_eq!(v[3], HELPER_SCRIPT, "le script ne doit jamais être modifié");
        assert_eq!(&v[4..6], ["sh", "--output"]);
        assert_eq!(&v[6..], ["/usr/bin/trivy", "rootfs", "/"]);
    }

    #[test]
    fn sortie_inseree_avant_la_cible() {
        let v = final_argv(&plan(false, Some("--output")), Path::new("/run/x/out"));
        assert_eq!(v, ["/usr/bin/trivy", "rootfs", "--output", "/run/x/out", "/"]);
    }

    #[test]
    fn valeur_hostile_reste_un_seul_argument() {
        let mut p = plan(true, None);
        p.argv.push("a; rm -rf / #".into());
        let v = final_argv(&p, Path::new("/x"));
        assert_eq!(v.last().unwrap(), "a; rm -rf / #");
        assert_eq!(v[0], PKEXEC);
    }

    #[test]
    fn dossier_prive_0700_et_refus_de_reutilisation() {
        let d = private_tmpdir().unwrap();
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(fs::metadata(&d).unwrap().permissions().mode() & 0o777, 0o700);
        assert!(fs::DirBuilder::new().mode(0o700).create(&d).is_err());
        fs::remove_dir_all(&d).unwrap();
    }
}

/// Début d'un résultat encadré : « @@CS-OUTPUT-BEGIN@@ » (anonyme) ou « @@CS-OUTPUT-BEGIN:nom@@ » (nommé, [a-z0-9_-]{1,32}).
pub fn begin_name(line: &str) -> Option<String> {
    let rest = line.trim().strip_prefix("@@CS-OUTPUT-BEGIN")?;
    if rest == "@@" {
        return Some(String::new());
    }
    let name = rest.strip_prefix(':')?.strip_suffix("@@")?;
    (!name.is_empty() && name.len() <= 32 && name.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_' || c == '-')).then(|| name.to_string())
}

#[cfg(test)]
mod tests_markers {
    use super::*;

    #[test]
    fn marqueurs_anonymes_et_nommes() {
        assert_eq!(begin_name("@@CS-OUTPUT-BEGIN@@"), Some(String::new()));
        assert_eq!(begin_name("@@CS-OUTPUT-BEGIN:lynis@@"), Some("lynis".into()));
        assert_eq!(begin_name("  @@CS-OUTPUT-BEGIN:rkhunter@@  "), Some("rkhunter".into()));
        assert_eq!(begin_name("@@CS-OUTPUT-BEGIN:../x@@"), None, "un nom suspect est refusé");
        assert_eq!(begin_name("@@CS-OUTPUT-BEGIN:@@"), None);
        assert_eq!(begin_name("texte normal"), None);
    }
}
