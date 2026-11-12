//! Règles RÉELLES d'ufw : lecture et modification même quand le pare-feu est désactivé.
//! ufw enregistre ses règles dans /etc/ufw même éteint (« ufw show added » les liste, « ufw allow … » les ajoute, « ufw delete … » les retire)
//! sans jamais activer le pare-feu. Les scripts ci-dessous sont CONSTANTS : aucune commande « enable », « reset » ou « disable » n'y existe ;
//! chaque argument est validé caractère par caractère avant d'atteindre ufw (aucun shell construit à partir de données externes).

use std::net::{Ipv4Addr, Ipv6Addr};

/// Lecture seule (administrateur : les fichiers de règles d'ufw ne sont lisibles que par root).
pub const READ_SCRIPT: &str = r#"echo "@@ADDED"
/usr/bin/ufw show added 2>&1
echo "@@STATUS"
/usr/bin/ufw status verbose 2>&1
"#;

/// « add » ou « del », puis la règle (action, direction, interface, protocole, adresses, port). N'active JAMAIS le pare-feu.
pub const RULE_SCRIPT: &str = r#"mode="$1"; shift
case "$mode" in add|del) ;; *) echo "Mode refusé."; exit 2;; esac
case "$1" in allow|deny|reject|limit) ;; *) echo "Action refusée."; exit 2;; esac
[ "$#" -le 24 ] || { echo "Règle trop longue."; exit 2; }
for a in "$@"; do
  case "$a" in ''|-*|*[!A-Za-z0-9./:,_-]*) echo "Argument refusé : $a"; exit 2;; esac
done
if [ "$mode" = add ]; then /usr/bin/ufw "$@"; else /usr/bin/ufw delete "$@"; fi
"#;

/// Politiques par défaut et niveau de journal. N'active JAMAIS le pare-feu.
pub const DEFAULT_SCRIPT: &str = r#"case "$1" in
  default)
    case "$2" in allow|deny|reject) ;; *) echo "Politique refusée."; exit 2;; esac
    case "$3" in incoming|outgoing|routed) ;; *) echo "Sens refusé."; exit 2;; esac
    /usr/bin/ufw default "$2" "$3";;
  logging)
    case "$2" in off|low|medium|high|full) ;; *) echo "Niveau refusé."; exit 2;; esac
    /usr/bin/ufw logging "$2";;
  *) echo "Commande refusée."; exit 2;;
esac
"#;

pub const ACTIONS: [&str; 4] = ["allow", "deny", "reject", "limit"];
pub const PROTOS: [&str; 9] = ["any", "tcp", "udp", "icmp", "esp", "ah", "gre", "ipv6", "igmp"];

/// Règle lue dans « ufw show added ».
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SysRule {
    /// Arguments après « ufw », sans commentaire (utilisés tels quels pour « ufw delete »).
    pub tokens: Vec<String>,
    /// Peut être supprimée depuis l'application (pas les règles « route », ni celles dont les arguments sortent de la liste sûre).
    pub deletable: bool,
}

pub fn token_ok(t: &str) -> bool {
    !t.is_empty() && t.len() <= 64 && !t.starts_with('-') && t.chars().all(|c| c.is_ascii_alphanumeric() || "./:,_-".contains(c))
}

/// Règles ajoutées par l'utilisateur, d'après la sortie de « ufw show added ».
pub fn parse_added(out: &str) -> Vec<SysRule> {
    let mut v = Vec::new();
    for line in out.lines() {
        let Some(rest) = line.trim().strip_prefix("ufw ") else { continue };
        // le commentaire (entre apostrophes) ne sert pas à la suppression : on le retire
        let rest = rest.split(" comment ").next().unwrap_or(rest);
        let tokens: Vec<String> = rest.split_whitespace().map(|s| s.to_string()).collect();
        if tokens.is_empty() {
            continue;
        }
        let deletable = ACTIONS.contains(&tokens[0].as_str()) && tokens.len() <= 24 && tokens.iter().all(|t| token_ok(t));
        v.push(SysRule { tokens, deletable });
    }
    v
}

/// État d'ufw lu SANS droits administrateur (/etc/default/ufw et /etc/ufw/ufw.conf sont lisibles par tous).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Defaults {
    pub enabled: bool,
    pub incoming: String,
    pub outgoing: String,
    pub routed: String,
    pub log: String,
}

pub fn parse_defaults(default_file: &str, conf: &str) -> Defaults {
    let get = |text: &str, key: &str| -> String {
        text.lines().find_map(|l| l.trim().strip_prefix(key).and_then(|r| r.strip_prefix('=')).map(|v| v.trim().trim_matches('"').to_string())).unwrap_or_default()
    };
    let pol = |v: String| match v.as_str() {
        "DROP" => "deny",
        "REJECT" => "reject",
        "ACCEPT" => "allow",
        _ => "?",
    }
    .to_string();
    Defaults {
        enabled: get(conf, "ENABLED").eq_ignore_ascii_case("yes"),
        incoming: pol(get(default_file, "DEFAULT_INPUT_POLICY")),
        outgoing: pol(get(default_file, "DEFAULT_OUTPUT_POLICY")),
        routed: pol(get(default_file, "DEFAULT_FORWARD_POLICY")),
        log: get(conf, "LOGLEVEL"),
    }
}

pub fn read_defaults() -> Defaults {
    let rd = |p: &str| std::fs::read_to_string(p).unwrap_or_default();
    parse_defaults(&rd("/etc/default/ufw"), &rd("/etc/ufw/ufw.conf"))
}

/// Règle à créer (champs du formulaire).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct NewRule {
    pub action: String,
    /// "in" ou "out"
    pub dir: String,
    pub proto: String,
    /// adresse ou réseau source (vide = n'importe où)
    pub from: String,
    /// adresse ou réseau destination (vide = n'importe où)
    pub to: String,
    /// port, plage « 8000:8100 » ou liste « 80,443 » (destination)
    pub port: String,
    pub iface: String,
    pub log: bool,
}

fn addr_ok(a: &str) -> bool {
    let (ip, prefix) = a.split_once('/').map_or((a, None), |(i, p)| (i, Some(p)));
    if let Ok(_) = ip.parse::<Ipv4Addr>() {
        return prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|n| n <= 32));
    }
    ip.parse::<Ipv6Addr>().is_ok() && prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|n| n <= 128))
}

fn port_ok(p: &str) -> bool {
    let one = |s: &str| s.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n));
    if let Some((a, b)) = p.split_once(':') {
        return one(a) && one(b) && a.parse::<u32>().unwrap_or(0) < b.parse::<u32>().unwrap_or(0);
    }
    let parts: Vec<&str> = p.split(',').collect();
    parts.len() <= 15 && parts.iter().all(|s| one(s))
}

/// Arguments « ufw » correspondant au formulaire, ou la raison du refus.
pub fn build_tokens(r: &NewRule) -> Result<Vec<String>, String> {
    if !ACTIONS.contains(&r.action.as_str()) {
        return Err("action invalide".into());
    }
    if r.dir != "in" && r.dir != "out" {
        return Err("sens invalide".into());
    }
    if !PROTOS.contains(&r.proto.as_str()) {
        return Err("protocole invalide".into());
    }
    for (name, a) in [("source", &r.from), ("destination", &r.to)] {
        if !a.is_empty() && !addr_ok(a) {
            return Err(format!("adresse {name} invalide (IPv4 ou IPv6, éventuellement avec /réseau)"));
        }
    }
    if !r.iface.is_empty() && !(r.iface.len() <= 15 && r.iface.chars().all(|c| c.is_ascii_alphanumeric() || "_.:-".contains(c)) && !r.iface.starts_with('-')) {
        return Err("interface invalide".into());
    }
    if !r.port.is_empty() {
        if !port_ok(&r.port) {
            return Err("port invalide (1 à 65535, plage 8000:8100 ou liste 80,443)".into());
        }
        if r.proto != "tcp" && r.proto != "udp" {
            return Err("un port demande le protocole TCP ou UDP".into());
        }
    }
    if r.port.is_empty() && r.from.is_empty() && r.to.is_empty() && r.proto == "any" && r.iface.is_empty() {
        return Err("règle vide : précisez au moins un port, une adresse, un protocole ou une interface".into());
    }
    let mut t: Vec<String> = vec![r.action.clone(), r.dir.clone()];
    if !r.iface.is_empty() {
        t.extend(["on".into(), r.iface.clone()]);
    }
    if r.log {
        t.push("log".into());
    }
    if r.proto != "any" {
        t.extend(["proto".into(), r.proto.clone()]);
    }
    if !r.from.is_empty() {
        t.extend(["from".into(), r.from.clone()]);
    }
    if !r.to.is_empty() || !r.port.is_empty() {
        t.extend(["to".into(), if r.to.is_empty() { "any".into() } else { r.to.clone() }]);
    }
    if !r.port.is_empty() {
        t.extend(["port".into(), r.port.clone()]);
    }
    if !t.iter().all(|x| token_ok(x)) {
        return Err("caractère non autorisé".into());
    }
    Ok(t)
}

/// Texte lisible d'une règle (le verbe est traduit par l'appelant).
pub fn summary(tokens: &[String]) -> (String, String) {
    let verb = tokens.first().cloned().unwrap_or_default();
    (verb, tokens.iter().skip(1).cloned().collect::<Vec<_>>().join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn r(f: impl FnOnce(&mut NewRule)) -> NewRule {
        let mut x = NewRule { action: "allow".into(), dir: "in".into(), proto: "tcp".into(), port: "22".into(), ..Default::default() };
        f(&mut x);
        x
    }

    #[test]
    fn lecture_des_regles_ajoutees() {
        let out = "Added user rules (see 'ufw status' for running firewall):\nufw allow 22/tcp\nufw allow from 192.168.0.0/24 to any port 22 proto tcp\nufw allow in on eth0 to any port 80 proto tcp comment 'web'\nufw route allow in on a out on b\nufw deny from 1.2.3.4; rm -rf /\n\nRules updated";
        let v = parse_added(out);
        assert_eq!(v.len(), 5);
        assert_eq!(v[0].tokens, ["allow", "22/tcp"]);
        assert!(v[0].deletable && v[1].deletable);
        assert_eq!(v[2].tokens.last().unwrap(), "tcp", "le commentaire est retiré");
        assert!(!v[3].deletable, "les règles route restent en lecture seule");
        assert!(!v[4].deletable, "arguments hors liste sûre : jamais transmis à ufw");
    }

    #[test]
    fn etat_lu_sans_droits() {
        let d = parse_defaults("DEFAULT_INPUT_POLICY=\"DROP\"\nDEFAULT_OUTPUT_POLICY=\"ACCEPT\"\nDEFAULT_FORWARD_POLICY=\"REJECT\"\n", "# x\nENABLED=no\n\nLOGLEVEL=low\n");
        assert_eq!(d, Defaults { enabled: false, incoming: "deny".into(), outgoing: "allow".into(), routed: "reject".into(), log: "low".into() });
        assert!(parse_defaults("", "ENABLED=yes").enabled);
    }

    #[test]
    fn formulaire_vers_arguments() {
        assert_eq!(build_tokens(&r(|_| {})).unwrap(), ["allow", "in", "proto", "tcp", "to", "any", "port", "22"]);
        let t = build_tokens(&r(|x| {
            x.from = "192.168.0.0/24".into();
            x.iface = "eth0".into();
            x.action = "limit".into();
            x.log = true;
        }))
        .unwrap();
        assert_eq!(t, ["limit", "in", "on", "eth0", "log", "proto", "tcp", "from", "192.168.0.0/24", "to", "any", "port", "22"]);
        assert!(build_tokens(&r(|x| x.from = "2001:db8::/32".into())).is_ok(), "IPv6 accepté");
        assert!(build_tokens(&r(|x| x.port = "8000:8100".into())).is_ok());
        assert!(build_tokens(&r(|x| x.port = "80,443".into())).is_ok());
        assert!(build_tokens(&r(|x| {
            x.proto = "icmp".into();
            x.port = String::new();
        }))
        .is_ok());
    }

    #[test]
    fn formulaire_refuse_le_dangereux() {
        for bad in [
            r(|x| x.action = "enable".into()),
            r(|x| x.action = "allow; reboot".into()),
            r(|x| x.dir = "route".into()),
            r(|x| x.port = "0".into()),
            r(|x| x.port = "70000".into()),
            r(|x| x.port = "9000:8000".into()),
            r(|x| x.port = "22;ls".into()),
            r(|x| x.from = "1.2.3.4; rm -rf /".into()),
            r(|x| x.from = "1.2.3.4/33".into()),
            r(|x| x.iface = "-x".into()),
            r(|x| x.iface = "a b".into()),
            r(|x| x.proto = "any".into()),
            r(|x| {
                x.proto = "any".into();
                x.port = String::new();
            }),
        ] {
            assert!(build_tokens(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn scripts_sans_commande_d_activation() {
        for s in [READ_SCRIPT, RULE_SCRIPT, DEFAULT_SCRIPT] {
            for banned in ["enable", "disable", "reset", "--force"] {
                assert!(!s.contains(banned), "{banned} ne doit jamais apparaître dans {s}");
            }
        }
    }

    /// Exécute RULE_SCRIPT avec un faux « ufw » qui affiche ses arguments : valide la barrière du script sans toucher au système.
    fn run_script(script: &str, args: &[&str]) -> (i32, String) {
        let dir = std::env::temp_dir().join(format!("cs-ufw-{}-{}", std::process::id(), args.join("_").len()));
        std::fs::create_dir_all(&dir).unwrap();
        let fake = dir.join("ufw");
        std::fs::write(&fake, "#!/bin/sh\necho \"UFW:$*\"\n").unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&fake, std::fs::Permissions::from_mode(0o755)).unwrap();
        let patched = script.replace("/usr/bin/ufw", &fake.to_string_lossy());
        let o = std::process::Command::new("/bin/sh").arg("-c").arg(patched).arg("sh").args(args).output().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).into_owned())
    }

    #[test]
    fn le_script_filtre_les_arguments() {
        assert_eq!(run_script(RULE_SCRIPT, &["add", "allow", "in", "proto", "tcp", "to", "any", "port", "22"]), (0, "UFW:allow in proto tcp to any port 22\n".into()));
        assert_eq!(run_script(RULE_SCRIPT, &["del", "allow", "22/tcp"]), (0, "UFW:delete allow 22/tcp\n".into()));
        for bad in [
            vec!["add", "enable"],
            vec!["add", "--force", "enable"],
            vec!["add", "allow", "22;reboot"],
            vec!["add", "allow", "$(id)"],
            vec!["add", "allow", "-x"],
            vec!["add", "allow", "a b"],
            vec!["reset"],
            vec!["add", "reset"],
            vec!["del", "enable"],
        ] {
            let (code, out) = run_script(RULE_SCRIPT, &bad);
            assert_eq!(code, 2, "{bad:?} doit être refusé");
            assert!(!out.contains("UFW:"), "ufw ne doit pas être appelé pour {bad:?}");
        }
        assert_eq!(run_script(DEFAULT_SCRIPT, &["default", "deny", "incoming"]).1, "UFW:default deny incoming\n");
        assert_eq!(run_script(DEFAULT_SCRIPT, &["logging", "medium"]).1, "UFW:logging medium\n");
        for bad in [vec!["default", "deny"], vec!["default", "evil", "incoming"], vec!["logging", "x"], vec!["enable"], vec!["default", "allow", "incoming; reboot"]] {
            assert_eq!(run_script(DEFAULT_SCRIPT, &bad).0, 2, "{bad:?}");
        }
    }
}
