//! Surveillance en direct : ports en écoute, connexions, pare-feu, tentatives de connexion.

use regex::Regex;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::process::Command;
use std::sync::LazyLock;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Expo {
    All,
    Local,
    Net(String),
}

#[derive(Clone, Debug)]
pub struct Listener {
    pub proto: String,
    pub host: String,
    pub port: String,
    pub proc: String,
    pub pid: u32,
    pub expo: Expo,
}

#[derive(Clone, Debug)]
pub struct Conn {
    pub proc: String,
    pub pid: String,
    pub local: String,
    pub remote: String,
    pub port: String,
    pub public: bool,
}

#[derive(Clone, Debug, Default)]
pub struct Snapshot {
    pub listeners: Vec<Listener>,
    pub conns: Vec<Conn>,
    pub firewall: Option<String>,
}

fn run(prog: &str, args: &[&str]) -> String {
    Command::new(prog).args(args).env("LC_ALL", "C").output().map(|o| String::from_utf8_lossy(&o.stdout).into_owned()).unwrap_or_default()
}

fn split_addr(a: &str) -> (String, String) {
    match a.rsplit_once(':') {
        Some((h, p)) => (h.trim_matches(|c| c == '[' || c == ']').to_string(), p.to_string()),
        None => (a.to_string(), String::new()),
    }
}

fn proc_of(line: &str) -> (String, String) {
    static RE: LazyLock<Regex> = LazyLock::new(|| Regex::new(r#"users:\(\("([^"]+)",pid=(\d+)"#).unwrap());
    RE.captures(line).map(|c| (c[1].to_string(), c[2].to_string())).unwrap_or(("—".into(), String::new()))
}

pub fn is_private(host: &str) -> bool {
    match host.split('%').next().unwrap_or("").parse::<IpAddr>() {
        Ok(IpAddr::V4(a)) => a.is_private() || a.is_loopback() || a.is_link_local() || a.is_multicast() || a.is_unspecified(),
        Ok(IpAddr::V6(a)) => a.is_loopback() || a.is_unique_local() || a.is_unicast_link_local() || a.is_multicast() || a.is_unspecified(),
        Err(_) => true,
    }
}

pub fn parse_listen(out: &str) -> Vec<Listener> {
    out.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            if p.len() < 5 {
                return None;
            }
            let (host, port) = split_addr(p[4]);
            let expo = if matches!(host.as_str(), "0.0.0.0" | "*" | "::") {
                Expo::All
            } else if host.starts_with("127.") || host == "::1" {
                Expo::Local
            } else {
                Expo::Net(host.clone())
            };
            let (proc, pid) = proc_of(l);
            Some(Listener { proto: p[0].into(), host, port, proc, pid: pid.parse().unwrap_or(0), expo })
        })
        .collect()
}

pub fn parse_conns(out: &str) -> Vec<Conn> {
    out.lines()
        .filter_map(|l| {
            let p: Vec<&str> = l.split_whitespace().collect();
            if p.len() < 5 {
                return None;
            }
            let (lh, lp) = split_addr(p[3]);
            let (rh, rp) = split_addr(p[4]);
            let (proc, pid) = proc_of(l);
            Some(Conn { proc, pid, local: format!("{lh}:{lp}"), public: !is_private(&rh), remote: rh, port: rp })
        })
        .collect()
}

/// Clé d'autorisation : le nom du processus (stable même si le port change), sinon le port.
pub fn key_of(proc: &str, port: &str) -> String {
    if proc != "—" { proc.to_string() } else { format!("port:{port}") }
}

pub fn snapshot() -> Snapshot {
    let listeners = parse_listen(&run("/usr/bin/ss", &["-H", "-tulnp"]));
    let conns = parse_conns(&run("/usr/bin/ss", &["-H", "-tupn", "state", "established"]));
    let units = run("/usr/bin/systemctl", &["is-active", "ufw", "firewalld", "nftables"]);
    let firewall = ["ufw", "firewalld", "nftables"].iter().zip(units.lines()).find(|(_, s)| s.trim() == "active").map(|(n, _)| n.to_string());
    Snapshot { listeners, conns, firewall }
}

// ───────────────────────── tentatives de connexion ─────────────────────────

/// Script root CONSTANT : le nombre de jours arrive en argument positionnel ($1), validé côté interface.
pub const AUTH_SCRIPT: &str = "/usr/bin/journalctl -u sshd -u ssh --since \"$1 days ago\" --no-pager -q -o short-iso 2>/dev/null; echo '===LASTB==='; /usr/bin/lastb -i -n 500 2>/dev/null; true";

#[derive(Clone, Debug, Default)]
pub struct AuthReport {
    /// ip -> (échecs, dernière tentative, source)
    pub fails: BTreeMap<String, (u32, String, &'static str)>,
    pub accepted: u32,
}

pub fn parse_auth(text: &str) -> AuthReport {
    static IP: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b").unwrap());
    static FAIL: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"Failed password|Invalid user|authentication failure|Connection closed by .*preauth").unwrap());
    let mut rep = AuthReport::default();
    let mut lastb = false;
    for line in text.lines() {
        if line.starts_with("===LASTB===") {
            lastb = true;
            continue;
        }
        let ip = IP.captures(line).map(|c| c[1].to_string());
        if !lastb {
            if let (true, Some(ip)) = (FAIL.is_match(line), ip) {
                let e = rep.fails.entry(ip).or_insert((0, String::new(), "SSH"));
                e.0 += 1;
                e.1 = line.chars().take(19).collect();
            } else if line.contains("Accepted") {
                rep.accepted += 1;
            }
        } else if let (Some(ip), false) = (ip, line.starts_with("btmp")) {
            let e = rep.fails.entry(ip).or_insert((0, String::new(), "Système (lastb)"));
            e.0 += 1;
            if e.1.is_empty() {
                e.1 = line.split_whitespace().rev().take(6).collect::<Vec<_>>().into_iter().rev().take(4).collect::<Vec<_>>().join(" ");
            }
        }
    }
    rep
}

#[cfg(test)]
mod tests {
    use super::*;

    const SS: &str = "tcp   LISTEN 0 0 0.0.0.0:8080 0.0.0.0:* users:((\"demo-server\",pid=1495350,fd=18))\ntcp LISTEN 0 0 127.0.0.1:5432 0.0.0.0:*\ntcp LISTEN 0 0 192.168.1.20:59481 0.0.0.0:* users:((\"qbittorrent\",pid=1,fd=2))\n";

    #[test]
    fn ports_exposes_ou_locaux() {
        let l = parse_listen(SS);
        assert_eq!(l[0].expo, Expo::All);
        assert_eq!(l[0].proc, "demo-server");
        assert_eq!(l[1].expo, Expo::Local);
        assert_eq!(l[2].expo, Expo::Net("192.168.1.20".into()));
    }

    #[test]
    fn cle_stable_par_processus() {
        assert_eq!(key_of("demo-server", "8080"), "demo-server");
        assert_eq!(key_of("—", "5353"), "port:5353");
    }

    #[test]
    fn prive_ou_public() {
        assert!(is_private("192.168.1.40"));
        assert!(is_private("127.0.0.1"));
        assert!(!is_private("142.251.173.95"));
        assert!(is_private("fe80::1%eth0"));
        assert!(!is_private("2a00:1450:4007::"));
    }

    #[test]
    fn tentatives_ssh() {
        let t = "2026-11-08T09:00:01+0100 h sshd[1]: Failed password for root from 203.0.113.9 port 4000 ssh2\n2026-11-08T09:00:05+0100 h sshd[1]: Failed password for root from 203.0.113.9 port 4001 ssh2\n2026-11-08T09:10:00+0100 h sshd[2]: Accepted publickey for alice from 192.168.1.50\n===LASTB===\nbtmp begins Wed Nov 4\n";
        let r = parse_auth(t);
        assert_eq!(r.fails["203.0.113.9"].0, 2);
        assert_eq!(r.accepted, 1);
        assert!(!r.fails.contains_key("192.168.1.50"));
    }
}

/// (autorisés, à vérifier) : ports TCP écoutant sur toutes les interfaces, selon la liste « autorisés » de l'utilisateur.
pub fn exposure(snap: &Snapshot, allowed: &std::collections::HashSet<String>) -> (usize, usize) {
    let (mut wanted, mut to_check) = (0, 0);
    for l in snap.listeners.iter().filter(|l| l.proto == "tcp" && l.expo == Expo::All) {
        if allowed.contains(&key_of(&l.proc, &l.port)) {
            wanted += 1;
        } else {
            to_check += 1;
        }
    }
    (wanted, to_check)
}
