//! firewalld : lecture et modification des règles RÉELLES, même quand le pare-feu est désactivé.
//!
//! • Lecture : directement dans les fichiers de configuration (/etc/firewalld et /usr/lib/firewalld, lisibles par tous) : aucun droit
//!   administrateur, aucun démarrage du service.
//! • Écriture : un script CONSTANT (EDIT_SCRIPT) lancé avec les droits administrateur. Si firewalld tourne, il utilise
//!   « firewall-cmd --permanent » (rien n'est appliqué avant un rechargement explicite) ; s'il est arrêté, « firewall-offline-cmd »
//!   modifie la configuration sans démarrer le service. Aucune commande d'activation, de mode panique ou de verrouillage n'existe dans ce script.
//! • Chaque valeur est validée ici (Rust) puis une seconde fois dans le script, caractère par caractère ; aucun shell n'est construit à partir de données externes.

use regex::Regex;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};

pub const ETC: &str = "/etc/firewalld";
pub const LIB: &str = "/usr/lib/firewalld";

/// Écriture de la configuration. Arguments : opération, zone, valeur. Voir les validations ci-dessous.
pub const EDIT_SCRIPT: &str = r#"op="$1"; z="$2"; v="$3"
if /usr/bin/systemctl is-active --quiet firewalld; then live=1; run="/usr/bin/firewall-cmd --permanent"; else live=0; run="/usr/bin/firewall-offline-cmd"; fi
chk_zone() { case "$z" in ''|*[!A-Za-z0-9_-]*) echo "Zone refusée."; exit 2;; esac; }
chk_name() { case "$v" in ''|-*|*[!a-z0-9-]*) echo "Nom refusé."; exit 2;; esac; }
chk_port() {
  case "$v" in ''|*[!0-9a-z/-]*) echo "Port refusé."; exit 2;; esac
  case "${v##*/}" in tcp|udp|sctp|dccp) ;; *) echo "Protocole refusé."; exit 2;; esac
  case "${v%%/*}" in ''|*[!0-9-]*) echo "Port refusé."; exit 2;; esac
}
chk_addr() { case "$v" in ''|*[!0-9A-Fa-f.:/]*) echo "Adresse refusée."; exit 2;; esac; }
chk_rich() {
  case "$v" in 'rule '*) ;; *) echo "Règle refusée."; exit 2;; esac
  case "$v" in *[!A-Za-z0-9\ =\"./:_%-]*) echo "Règle refusée."; exit 2;; esac
}
case "$op" in
  add-service)    chk_zone; chk_name; $run --zone="$z" --add-service="$v";;
  remove-service) chk_zone; chk_name; $run --zone="$z" --remove-service="$v";;
  add-port)       chk_zone; chk_port; $run --zone="$z" --add-port="$v";;
  remove-port)    chk_zone; chk_port; $run --zone="$z" --remove-port="$v";;
  add-source)     chk_zone; chk_addr; $run --zone="$z" --add-source="$v";;
  remove-source)  chk_zone; chk_addr; $run --zone="$z" --remove-source="$v";;
  add-rich)       chk_zone; chk_rich; $run --zone="$z" --add-rich-rule="$v";;
  remove-rich)    chk_zone; chk_rich; $run --zone="$z" --remove-rich-rule="$v";;
  add-icmp-block)    chk_zone; chk_name; $run --zone="$z" --add-icmp-block="$v";;
  remove-icmp-block) chk_zone; chk_name; $run --zone="$z" --remove-icmp-block="$v";;
  add-masquerade)    chk_zone; $run --zone="$z" --add-masquerade;;
  remove-masquerade) chk_zone; $run --zone="$z" --remove-masquerade;;
  set-target)
    chk_zone
    case "$v" in ACCEPT|DROP|'%%REJECT%%'|default) ;; *) echo "Cible refusée."; exit 2;; esac
    $run --zone="$z" --set-target="$v";;
  set-default-zone)
    chk_zone
    if [ "$live" = 1 ]; then /usr/bin/firewall-cmd --set-default-zone="$z"; else /usr/bin/firewall-offline-cmd --set-default-zone="$z"; fi;;
  set-log-denied)
    case "$v" in off|all|unicast|broadcast|multicast) ;; *) echo "Valeur refusée."; exit 2;; esac
    if [ "$live" = 1 ]; then /usr/bin/firewall-cmd --set-log-denied="$v"; else /usr/bin/sed -i "s/^LogDenied=.*/LogDenied=$v/" /etc/firewalld/firewalld.conf; fi;;
  reload)
    if [ "$live" = 1 ]; then /usr/bin/firewall-cmd --reload; else echo "firewalld est arrêté : les règles seront appliquées à son activation."; fi;;
  *) echo "Opération refusée."; exit 2;;
esac
rc=$?
[ "$rc" = 0 ] && [ "$live" = 1 ] && [ "$op" != reload ] && [ "$op" != set-default-zone ] && [ "$op" != set-log-denied ] && echo "Enregistré dans la configuration permanente : pas encore appliqué (rechargement nécessaire)."
exit $rc
"#;

// ─────────────────────────────────── lecture ───────────────────────────────────

pub fn installed() -> bool {
    crate::util::abs_prog("firewall-cmd").is_some() || crate::util::abs_prog("firewall-offline-cmd").is_some()
}

/// Le service tourne-t-il ? (sans droits administrateur)
pub fn running() -> bool {
    crate::util::abs_prog("systemctl").is_some_and(|p| std::process::Command::new(p).args(["is-active", "firewalld"]).output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active").unwrap_or(false))
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Conf {
    pub default_zone: String,
    pub log_denied: String,
    pub backend: String,
}

pub fn parse_conf(text: &str) -> Conf {
    let get = |k: &str| text.lines().find_map(|l| l.trim().strip_prefix(k).and_then(|r| r.strip_prefix('=')).map(|v| v.trim().to_string())).unwrap_or_default();
    Conf { default_zone: get("DefaultZone"), log_denied: get("LogDenied"), backend: get("FirewallBackend") }
}

pub fn read_conf() -> Conf {
    parse_conf(&std::fs::read_to_string(Path::new(ETC).join("firewalld.conf")).unwrap_or_default())
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RichRule {
    /// Texte lisible (affichage).
    pub text: String,
    /// Forme canonique pour « --remove-rich-rule » ; None si la règle utilise des éléments que l'application ne sait pas réécrire.
    pub canonical: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Zone {
    pub name: String,
    pub short: String,
    /// « default », « ACCEPT », « DROP » ou « %%REJECT%% »
    pub target: String,
    pub services: Vec<String>,
    /// (port ou plage, protocole)
    pub ports: Vec<(String, String)>,
    pub sources: Vec<String>,
    pub interfaces: Vec<String>,
    pub icmp_blocks: Vec<String>,
    pub masquerade: bool,
    pub rich: Vec<RichRule>,
}

fn attr(tag: &str, name: &str) -> Option<String> {
    let re = Regex::new(&format!(r#"\b{name}\s*=\s*"([^"]*)""#)).ok()?;
    re.captures(tag).map(|c| unescape(&c[1]))
}

fn unescape(s: &str) -> String {
    s.replace("&quot;", "\"").replace("&apos;", "'").replace("&lt;", "<").replace("&gt;", ">").replace("&amp;", "&")
}

fn rich_from_xml(xml: &str) -> RichRule {
    let tags: Vec<String> = Regex::new(r"<[^>]+>").unwrap().find_iter(xml).map(|m| m.as_str().to_string()).collect();
    let open = tags.first().cloned().unwrap_or_default();
    let mut parts: Vec<String> = vec!["rule".into()];
    if let Some(f) = attr(&open, "family") {
        parts.push(format!("family=\"{f}\""));
    }
    let (mut text, mut ok) = (Vec::new(), true);
    let mut action = String::new();
    for t in tags.iter().skip(1) {
        let name = t.trim_start_matches('<').trim_start_matches('/').split(|c: char| c.is_whitespace() || c == '/' || c == '>').next().unwrap_or("");
        if t.starts_with("</") {
            continue;
        }
        match name {
            "source" | "destination" => {
                let inv = attr(t, "invert").is_some_and(|v| v.eq_ignore_ascii_case("true"));
                if let Some(a) = attr(t, "address") {
                    parts.push(format!("{name} {}address=\"{a}\"", if inv { "NOT " } else { "" }));
                    text.push(format!("{name} {}{a}", if inv { "NOT " } else { "" }));
                } else {
                    ok = false;
                }
            }
            "service" => match attr(t, "name") {
                Some(n) => {
                    parts.push(format!("service name=\"{n}\""));
                    text.push(format!("service {n}"));
                }
                None => ok = false,
            },
            "port" => match (attr(t, "port"), attr(t, "protocol")) {
                (Some(p), Some(pr)) => {
                    parts.push(format!("port port=\"{p}\" protocol=\"{pr}\""));
                    text.push(format!("{p}/{pr}"));
                }
                _ => ok = false,
            },
            "accept" | "drop" => {
                action = name.to_string();
                if let Some(l) = attr(t, "value") {
                    let _ = l;
                }
            }
            "reject" => {
                action = "reject".into();
                if attr(t, "type").is_some() {
                    ok = false;
                }
            }
            "limit" => {
                if let Some(v) = attr(t, "value") {
                    // la limite se place après l'action (forme « accept limit value="10/m" »)
                    parts.push(format!("\u{1}limit value=\"{v}\""));
                    text.push(format!("limit {v}"));
                }
            }
            "log" | "audit" => {
                ok = false;
                text.push(name.to_string());
            }
            _ => {
                ok = false;
                text.push(name.to_string());
            }
        }
    }
    // « accept » (ou reject/drop) puis la limite éventuelle
    let (limit, rest): (Vec<String>, Vec<String>) = parts.into_iter().partition(|p| p.starts_with('\u{1}'));
    let mut canon = rest;
    if action.is_empty() {
        ok = false;
    } else {
        canon.push(action.clone());
    }
    canon.extend(limit.into_iter().map(|l| l.trim_start_matches('\u{1}').to_string()));
    let family = attr(&open, "family").unwrap_or_default();
    let verb = match action.as_str() {
        "accept" => "Autoriser",
        "reject" => "Rejeter",
        "drop" => "Bloquer en silence",
        _ => "?",
    };
    let text = format!("{verb} · {}{}", text.join(" · "), if family.is_empty() { String::new() } else { format!(" · {family}") });
    RichRule { text, canonical: ok.then(|| canon.join(" ")) }
}

/// Lit un fichier de zone firewalld (XML) : services, ports, sources, interfaces, blocs ICMP, masquerade et règles riches.
pub fn parse_zone(name: &str, xml: &str) -> Zone {
    let rule_re = Regex::new(r"(?s)<rule\b.*?</rule>").unwrap();
    let rich: Vec<RichRule> = rule_re.find_iter(xml).map(|m| rich_from_xml(m.as_str())).collect();
    let rest = rule_re.replace_all(xml, "");
    let tag_re = Regex::new(r"<([A-Za-z-]+)\b([^>]*)>").unwrap();
    let mut z = Zone { name: name.into(), target: "default".into(), rich, ..Default::default() };
    for c in tag_re.captures_iter(&rest) {
        let (tag, body) = (&c[1], &c[0]);
        match tag {
            "zone" => {
                if let Some(t) = attr(body, "target") {
                    z.target = t;
                }
            }
            "service" => z.services.extend(attr(body, "name")),
            "port" => {
                if let (Some(p), Some(pr)) = (attr(body, "port"), attr(body, "protocol")) {
                    z.ports.push((p, pr));
                }
            }
            "source" => z.sources.extend(attr(body, "address")),
            "interface" => z.interfaces.extend(attr(body, "name")),
            "icmp-block" => z.icmp_blocks.extend(attr(body, "name")),
            "masquerade" => z.masquerade = true,
            _ => {}
        }
    }
    if let Some(s) = Regex::new(r"(?s)<short>(.*?)</short>").unwrap().captures(&rest) {
        z.short = unescape(s[1].trim());
    }
    z
}

fn zone_dirs() -> [PathBuf; 2] {
    [Path::new(ETC).join("zones"), Path::new(LIB).join("zones")]
}

fn name_ok(n: &str) -> bool {
    !n.is_empty() && n.len() <= 40 && n.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Zones disponibles : celles de l'administrateur (/etc) priment sur celles fournies par le paquet.
pub fn zone_names() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for d in zone_dirs() {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let f = e.file_name().to_string_lossy().into_owned();
                if let Some(n) = f.strip_suffix(".xml") {
                    if name_ok(n) && !v.iter().any(|x| x == n) {
                        v.push(n.to_string());
                    }
                }
            }
        }
    }
    v.sort();
    v
}

pub fn load_zone(name: &str) -> Option<Zone> {
    if !name_ok(name) {
        return None;
    }
    zone_dirs().iter().find_map(|d| std::fs::read_to_string(d.join(format!("{name}.xml"))).ok()).map(|x| parse_zone(name, &x))
}

/// Services prédéfinis de firewalld (ssh, http, samba…), d'après les fichiers installés.
pub fn services_available() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for d in [Path::new(ETC).join("services"), Path::new(LIB).join("services")] {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let f = e.file_name().to_string_lossy().into_owned();
                if let Some(n) = f.strip_suffix(".xml") {
                    if name_ok(n) && !v.iter().any(|x| x == n) {
                        v.push(n.to_string());
                    }
                }
            }
        }
    }
    v.sort();
    v
}

/// Types ICMP connus (pour bloquer par exemple le ping : « echo-request »).
pub fn icmp_types() -> Vec<String> {
    let mut v: Vec<String> = Vec::new();
    for d in [Path::new(ETC).join("icmptypes"), Path::new(LIB).join("icmptypes")] {
        if let Ok(rd) = std::fs::read_dir(d) {
            for e in rd.flatten() {
                let f = e.file_name().to_string_lossy().into_owned();
                if let Some(n) = f.strip_suffix(".xml") {
                    if name_ok(n) && !v.iter().any(|x| x == n) {
                        v.push(n.to_string());
                    }
                }
            }
        }
    }
    v.sort();
    v
}

// ───────────────────────────────── validations ─────────────────────────────────

pub fn addr_ok(a: &str, family: Option<&str>) -> bool {
    let (ip, prefix) = a.split_once('/').map_or((a, None), |(i, p)| (i, Some(p)));
    let v4 = ip.parse::<Ipv4Addr>().is_ok() && prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|n| n <= 32));
    let v6 = ip.parse::<Ipv6Addr>().is_ok() && prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|n| n <= 128));
    match family {
        Some("ipv4") => v4,
        Some("ipv6") => v6,
        _ => v4 || v6,
    }
}

pub fn port_ok(p: &str) -> bool {
    let one = |s: &str| s.parse::<u32>().is_ok_and(|n| (1..=65535).contains(&n));
    match p.split_once('-') {
        Some((a, b)) => one(a) && one(b) && a.parse::<u32>().unwrap_or(0) < b.parse::<u32>().unwrap_or(0),
        None => one(p),
    }
}

pub fn proto_ok(p: &str) -> bool {
    matches!(p, "tcp" | "udp" | "sctp" | "dccp")
}

/// « 8080/tcp » à partir de deux champs, ou la raison du refus.
pub fn port_spec(port: &str, proto: &str) -> Result<String, String> {
    if !port_ok(port) {
        return Err("port invalide (1 à 65535, ou une plage 8000-8100)".into());
    }
    if !proto_ok(proto) {
        return Err("protocole invalide".into());
    }
    Ok(format!("{port}/{proto}"))
}

#[derive(Clone, Debug, Default)]
pub struct NewRich {
    /// accept, reject ou drop
    pub action: String,
    /// ipv4 ou ipv6
    pub family: String,
    pub source: String,
    pub service: String,
    pub port: String,
    pub proto: String,
    /// ex. « 10/m » (facultatif)
    pub limit: String,
}

/// Règle riche au format firewalld, ou la raison du refus. Forme : rule family=… source address=… service|port … action [limit …]
pub fn build_rich(r: &NewRich) -> Result<String, String> {
    if !matches!(r.action.as_str(), "accept" | "reject" | "drop") {
        return Err("action invalide".into());
    }
    if r.family != "ipv4" && r.family != "ipv6" {
        return Err("famille invalide (ipv4 ou ipv6)".into());
    }
    if !r.source.is_empty() && !addr_ok(&r.source, Some(&r.family)) {
        return Err(format!("adresse source invalide pour {}", r.family));
    }
    let has_service = !r.service.is_empty();
    let has_port = !r.port.is_empty();
    if has_service && has_port {
        return Err("choisissez un service OU un port, pas les deux".into());
    }
    if has_service && !(r.service.len() <= 40 && !r.service.starts_with('-') && r.service.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')) {
        return Err("nom de service invalide".into());
    }
    if has_port {
        port_spec(&r.port, &r.proto)?;
    }
    if !has_service && !has_port && r.source.is_empty() {
        return Err("règle vide : précisez une source, un service ou un port".into());
    }
    if !r.limit.is_empty() && !Regex::new(r"^[1-9][0-9]{0,3}/[smhd]$").unwrap().is_match(&r.limit) {
        return Err("limite invalide (exemple : 10/m)".into());
    }
    if !r.limit.is_empty() && r.action == "drop" {
        return Err("une limite ne s'applique pas à « drop »".into());
    }
    let mut s = format!("rule family=\"{}\"", r.family);
    if !r.source.is_empty() {
        s += &format!(" source address=\"{}\"", r.source);
    }
    if has_service {
        s += &format!(" service name=\"{}\"", r.service);
    } else if has_port {
        s += &format!(" port port=\"{}\" protocol=\"{}\"", r.port, r.proto);
    }
    s += &format!(" {}", r.action);
    if !r.limit.is_empty() {
        s += &format!(" limit value=\"{}\"", r.limit);
    }
    Ok(s)
}

pub const TARGETS: [(&str, &str); 4] = [("default", "Refuser avec message (défaut)"), ("%%REJECT%%", "Refuser avec message"), ("DROP", "Ignorer en silence"), ("ACCEPT", "Tout autoriser")];

// ─────────────────────────────────────── tests ───────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const PUBLIC: &str = r#"<?xml version="1.0" encoding="utf-8"?>
<zone target="%%REJECT%%">
  <short>Public</short>
  <description>Pour une utilisation en réseau public.</description>
  <service name="ssh"/>
  <service name="dhcpv6-client"/>
  <port port="8080" protocol="tcp"/>
  <port port="6000-6010" protocol="udp"/>
  <source address="192.168.1.0/24"/>
  <interface name="enp5s0"/>
  <icmp-block name="echo-request"/>
  <masquerade/>
  <rule family="ipv4">
    <source address="203.0.113.7"/>
    <port port="22" protocol="tcp"/>
    <reject/>
  </rule>
  <rule family="ipv4">
    <source address="10.0.0.0/8"/>
    <service name="http"/>
    <accept/>
    <limit value="10/m"/>
  </rule>
  <rule family="ipv6">
    <service name="ssh"/>
    <log prefix="x"/>
    <accept/>
  </rule>
</zone>
"#;

    #[test]
    fn lecture_d_une_zone() {
        let z = parse_zone("public", PUBLIC);
        assert_eq!(z.target, "%%REJECT%%");
        assert_eq!(z.short, "Public");
        assert_eq!(z.services, ["ssh", "dhcpv6-client"]);
        assert_eq!(z.ports, [("8080".to_string(), "tcp".to_string()), ("6000-6010".to_string(), "udp".to_string())]);
        assert_eq!(z.sources, ["192.168.1.0/24"]);
        assert_eq!(z.interfaces, ["enp5s0"]);
        assert_eq!(z.icmp_blocks, ["echo-request"]);
        assert!(z.masquerade);
        assert_eq!(z.rich.len(), 3, "les éléments des règles riches ne sont pas comptés comme des services ou ports de la zone");
        assert_eq!(z.rich[0].canonical.as_deref(), Some(r#"rule family="ipv4" source address="203.0.113.7" port port="22" protocol="tcp" reject"#));
        assert_eq!(z.rich[1].canonical.as_deref(), Some(r#"rule family="ipv4" source address="10.0.0.0/8" service name="http" accept limit value="10/m""#));
        assert!(z.rich[2].canonical.is_none(), "règle avec journalisation : affichée, mais pas réécrite par l'application");
        assert!(z.rich[0].text.starts_with("Rejeter") && z.rich[1].text.starts_with("Autoriser"));
    }

    #[test]
    fn zone_sans_cible_est_par_defaut() {
        let z = parse_zone("home", "<zone><short>Home</short><service name=\"samba-client\"/></zone>");
        assert_eq!(z.target, "default");
        assert!(!z.masquerade && z.rich.is_empty());
    }

    #[test]
    fn lecture_de_la_configuration() {
        let c = parse_conf("# x\nDefaultZone=public\nLogDenied=off\nFirewallBackend=nftables\n");
        assert_eq!(c, Conf { default_zone: "public".into(), log_denied: "off".into(), backend: "nftables".into() });
    }

    #[test]
    fn regle_riche_depuis_le_formulaire() {
        let base = NewRich { action: "accept".into(), family: "ipv4".into(), source: "192.168.0.0/24".into(), service: "ssh".into(), ..Default::default() };
        assert_eq!(build_rich(&base).unwrap(), r#"rule family="ipv4" source address="192.168.0.0/24" service name="ssh" accept"#);
        let p = NewRich { action: "reject".into(), family: "ipv4".into(), port: "22".into(), proto: "tcp".into(), limit: "5/m".into(), ..Default::default() };
        assert_eq!(build_rich(&p).unwrap(), r#"rule family="ipv4" port port="22" protocol="tcp" reject limit value="5/m""#);
        // la règle construite relue par parse_zone redonne exactement la même forme (aller-retour)
        let xml = r#"<zone><rule family="ipv4"><source address="192.168.0.0/24"/><service name="ssh"/><accept/></rule></zone>"#;
        assert_eq!(parse_zone("z", xml).rich[0].canonical.clone().unwrap(), build_rich(&base).unwrap());
        let v6 = NewRich { action: "drop".into(), family: "ipv6".into(), source: "2001:db8::/32".into(), ..Default::default() };
        assert!(build_rich(&v6).is_ok());
    }

    #[test]
    fn formulaire_refuse_le_dangereux() {
        let ok = NewRich { action: "accept".into(), family: "ipv4".into(), service: "ssh".into(), ..Default::default() };
        for bad in [
            NewRich { action: "accept\" ; reboot".into(), ..ok.clone() },
            NewRich { action: "mark".into(), ..ok.clone() },
            NewRich { family: "ipx".into(), ..ok.clone() },
            NewRich { source: "1.2.3.4\" accept".into(), ..ok.clone() },
            NewRich { source: "2001:db8::1".into(), ..ok.clone() },
            NewRich { service: "ssh\" reject".into(), ..ok.clone() },
            NewRich { service: "SSH".into(), ..ok.clone() },
            NewRich { port: "22".into(), proto: "tcp".into(), ..ok.clone() },
            NewRich { service: String::new(), port: "0".into(), proto: "tcp".into(), ..ok.clone() },
            NewRich { service: String::new(), port: "22".into(), proto: "icmp".into(), ..ok.clone() },
            NewRich { service: String::new(), ..ok.clone() },
            NewRich { limit: "10/year".into(), ..ok.clone() },
            NewRich { action: "drop".into(), limit: "10/m".into(), ..ok.clone() },
        ] {
            assert!(build_rich(&bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn ports_et_adresses() {
        for ok in ["1", "65535", "8000-8100"] {
            assert!(port_ok(ok), "{ok}");
        }
        for bad in ["0", "65536", "9000-8000", "a", "80,443", "80-", "-80", ""] {
            assert!(!port_ok(bad), "{bad}");
        }
        assert_eq!(port_spec("22", "tcp").unwrap(), "22/tcp");
        assert!(addr_ok("10.0.0.1", None) && addr_ok("fe80::1/64", None) && !addr_ok("10.0.0.1/33", None) && !addr_ok("x", None));
    }

    #[test]
    fn script_sans_commande_dangereuse() {
        for banned in ["--panic", "panic-on", "lockdown", "--runtime-to-permanent", "systemctl enable", "systemctl start", "--complete-reload", "--reset"] {
            assert!(!EDIT_SCRIPT.contains(banned), "{banned} ne doit jamais apparaître");
        }
    }

    /// Exécute le script avec de faux programmes qui affichent leurs arguments : valide la barrière sans toucher au système.
    fn run(live: bool, args: &[&str]) -> (i32, String) {
        let dir = std::env::temp_dir().join(format!("cs-fwd-{}-{}-{}", std::process::id(), live, args.join("_").len()));
        std::fs::create_dir_all(&dir).unwrap();
        use std::os::unix::fs::PermissionsExt;
        let mk = |name: &str, body: &str| {
            let p = dir.join(name);
            std::fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p
        };
        let sysctl = mk("systemctl", if live { "exit 0" } else { "exit 3" });
        let cmd = mk("firewall-cmd", "echo \"CMD:$*\"");
        let off = mk("firewall-offline-cmd", "echo \"OFF:$*\"");
        let sed = mk("sed", "echo \"SED:$*\"");
        let script = EDIT_SCRIPT.replace("/usr/bin/systemctl", &sysctl.to_string_lossy()).replace("/usr/bin/firewall-cmd", &cmd.to_string_lossy()).replace("/usr/bin/firewall-offline-cmd", &off.to_string_lossy()).replace("/usr/bin/sed", &sed.to_string_lossy());
        let o = std::process::Command::new("/bin/sh").arg("-c").arg(script).arg("sh").args(args).output().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
        (o.status.code().unwrap_or(-1), String::from_utf8_lossy(&o.stdout).replace(&dir.to_string_lossy().to_string(), "").replace('/', "/"))
    }

    #[test]
    fn script_choisit_le_bon_outil() {
        let (c, out) = run(false, &["add-service", "public", "http"]);
        assert_eq!(c, 0);
        assert!(out.contains("OFF:--zone=public --add-service=http") && !out.contains("CMD:"), "arrêté : modification hors ligne, sans démarrer firewalld : {out}");
        let (c, out) = run(true, &["add-port", "public", "8080/tcp"]);
        assert_eq!(c, 0);
        assert!(out.contains("CMD:--permanent --zone=public --add-port=8080/tcp") && out.contains("pas encore appliqué"), "actif : permanent seulement : {out}");
        assert!(run(true, &["set-default-zone", "home", ""]).1.contains("CMD:--set-default-zone=home"));
        assert!(run(false, &["set-default-zone", "home", ""]).1.contains("OFF:--set-default-zone=home"));
        assert!(run(false, &["set-log-denied", "", "all"]).1.contains("SED:-i s/^LogDenied=.*/LogDenied=all/"));
        assert!(run(true, &["set-log-denied", "", "all"]).1.contains("CMD:--set-log-denied=all"));
        assert!(run(false, &["reload", "", ""]).1.contains("arrêté"));
        assert!(run(true, &["reload", "", ""]).1.contains("CMD:--reload"));
        assert!(run(true, &["set-target", "public", "%%REJECT%%"]).1.contains("--set-target=%%REJECT%%"));
        assert!(run(false, &["add-rich", "public", r#"rule family="ipv4" service name="ssh" accept"#]).1.contains(r#"--add-rich-rule=rule family="ipv4" service name="ssh" accept"#));
        assert!(run(false, &["add-masquerade", "public", ""]).1.contains("--add-masquerade"));
    }

    #[test]
    fn script_refuse_tout_ce_qui_sort_du_cadre() {
        let rich_ok = r#"rule family="ipv4" accept"#;
        for (live, bad) in [
            (false, vec!["enable", "public", ""]),
            (false, vec!["panic-on", "", ""]),
            (false, vec!["add-service", "pub;lic", "http"]),
            (false, vec!["add-service", "", "http"]),
            (false, vec!["add-service", "public", "ht tp"]),
            (false, vec!["add-service", "public", "HTTP"]),
            (false, vec!["add-service", "public", "$(id)"]),
            (false, vec!["add-service", "public", "--panic-on"]),
            (false, vec!["add-port", "public", "80"]),
            (false, vec!["add-port", "public", "80/icmp"]),
            (false, vec!["add-port", "public", "a/tcp"]),
            (false, vec!["add-port", "public", "80;ls/tcp"]),
            (false, vec!["add-source", "public", "1.2.3.4;reboot"]),
            (false, vec!["add-source", "public", "$(id)"]),
            (false, vec!["add-rich", "public", "service name=\"ssh\" accept"]),
            (false, vec!["add-rich", "public", "rule family=\"ipv4\" accept; reboot"]),
            (false, vec!["add-rich", "public", "rule $(id)"]),
            (false, vec!["add-rich", "public", "rule `id`"]),
            (true, vec!["set-target", "public", "MARK"]),
            (true, vec!["set-log-denied", "", "all; reboot"]),
            (true, vec!["set-log-denied", "", "$(id)"]),
        ] {
            let (code, out) = run(live, &bad);
            assert_eq!(code, 2, "{bad:?} doit être refusé (sortie : {out})");
            assert!(!out.contains("CMD:") && !out.contains("OFF:") && !out.contains("SED:"), "aucun outil ne doit être appelé pour {bad:?}");
        }
        assert_eq!(run(false, &["add-rich", "public", rich_ok]).0, 0);
    }
}
