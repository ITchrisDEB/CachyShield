//! Couper ou bloquer un programme : informations sur le processus, garde-fous pour ne jamais casser la session,
//! et scripts administrateur CONSTANTS pour le pare-feu (table dédiée « cachy_shield », supprimée au redémarrage).

use std::net::IpAddr;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcInfo {
    pub pid: u32,
    pub uid: u32,
    pub name: String,
    pub cmdline: String,
}

fn field(status: &str, key: &str) -> Option<String> {
    status.lines().find_map(|l| l.strip_prefix(key)?.strip_prefix(':').map(|v| v.trim().to_string()))
}

/// Lit /proc/<pid> (lecture seule, sans droits particuliers).
pub fn read_proc(pid: u32) -> Option<ProcInfo> {
    read_proc_in(Path::new("/proc"), pid)
}

pub fn read_proc_in(root: &Path, pid: u32) -> Option<ProcInfo> {
    let status = std::fs::read_to_string(root.join(pid.to_string()).join("status")).ok()?;
    let uid = field(&status, "Uid")?.split_whitespace().next()?.parse().ok()?;
    let name = field(&status, "Name")?;
    let raw = std::fs::read(root.join(pid.to_string()).join("cmdline")).unwrap_or_default();
    let cmdline = String::from_utf8_lossy(&raw).split('\0').filter(|s| !s.is_empty()).collect::<Vec<_>>().join(" ");
    Some(ProcInfo { pid, uid, name, cmdline: cmdline.chars().take(300).collect() })
}

pub fn current_uid() -> u32 {
    std::fs::read_to_string("/proc/self/status").ok().and_then(|s| field(&s, "Uid")?.split_whitespace().next()?.parse().ok()).unwrap_or(u32::MAX)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kill {
    Allowed,
    Refused(String),
}

/// Programmes dont l'arrêt ferait tomber la session graphique, le réseau, le son ou l'authentification.
const PROTECTED: &[&str] = &[
    "systemd", "dbus", "kwin", "plasmashell", "plasma", "sddm", "xwayland", "xorg", "pipewire", "wireplumber", "pulseaudio", "polkit", "gdm", "networkmanager", "wpa_supplicant", "init", "kdeinit", "ksmserver",
    "kded", "kglobalacceld", "xdg-desktop-portal", "login", "agetty", "kscreenlocker", "krunner", "baloo", "akonadi", "kwalletd", "ssh-agent", "gnome-keyring", "at-spi", "gvfs", "udisks", "upower", "bluetoothd",
];

/// Un programme peut-il être arrêté sans risque ? Seuls les programmes de l'utilisateur courant, hors session et hors cette application.
pub fn can_kill(p: &ProcInfo, me_uid: u32, own_pid: u32) -> Kill {
    if p.pid <= 1 || p.pid == own_pid {
        return Kill::Refused("C'est ce programme lui-même (ou le processus système n°1) : l'arrêter fermerait l'application ou le système.".into());
    }
    if p.uid != me_uid {
        return Kill::Refused(if p.uid == 0 { "Ce programme appartient à root (service système) : l'arrêter peut déstabiliser le système. Préférez « Bloquer l'accès au réseau », qui n'arrête rien." } else { "Ce programme appartient à un autre utilisateur." }.into());
    }
    let low = p.name.to_lowercase();
    if PROTECTED.iter().any(|n| low.starts_with(n)) {
        return Kill::Refused(format!("« {} » fait partie de votre session (affichage, son, réseau ou authentification) : l'arrêter fermerait ou casserait votre session.", p.name));
    }
    Kill::Allowed
}

/// PID valides, sans doublon, triés (le processus 1 et les valeurs absurdes sont écartés).
pub fn pids_valid(pids: &[u32]) -> Vec<u32> {
    let mut v: Vec<u32> = pids.iter().copied().filter(|p| *p > 1 && *p < 4_194_304).collect();
    v.sort_unstable();
    v.dedup();
    v
}

pub fn alive(pid: u32) -> bool {
    Path::new("/proc").join(pid.to_string()).exists()
}

// ───────────────────────────── blocage réseau ──────────────────────────────

pub fn valid_proto(p: &str) -> bool {
    matches!(p, "tcp" | "udp")
}

/// Serveur distant bloquable : adresse IPv4 PUBLIQUE uniquement (jamais le réseau local, la boucle locale, la passerelle).
pub fn blockable_host(ip: &str) -> Option<String> {
    match ip.parse::<IpAddr>().ok()? {
        IpAddr::V4(a) if !(a.is_private() || a.is_loopback() || a.is_link_local() || a.is_multicast() || a.is_unspecified() || a.is_broadcast()) => Some(a.to_string()),
        _ => None,
    }
}

/// Bloque l'accès à un port DEPUIS LE RÉSEAU ; l'accès local (loopback) reste autorisé, donc rien ne casse sur cette machine.
pub const BLOCK_PORT_SCRIPT: &str = r#"case "$1" in tcp|udp) ;; *) echo "Protocole invalide."; exit 2;; esac
case "$2" in ''|*[!0-9]*) echo "Port invalide."; exit 2;; esac
[ "$2" -ge 1 ] && [ "$2" -le 65535 ] || { echo "Port invalide."; exit 2; }
echo "1/3 Préparation du pare-feu (table dédiée « cachy_shield », sans toucher aux autres règles)…"
/usr/bin/nft add table inet cachy_shield || exit 3
/usr/bin/nft 'add chain inet cachy_shield input { type filter hook input priority -10 ; policy accept ; }' || exit 3
if /usr/bin/nft -a list chain inet cachy_shield input | grep -q "cs_$1_$2\""; then echo "Ce port est déjà bloqué."; exit 0; fi
echo "2/3 Ajout de la règle (le trafic local reste autorisé)…"
/usr/bin/nft -f - <<EOF || exit 4
add rule inet cachy_shield input iifname != "lo" $1 dport $2 counter drop comment "cs_$1_$2"
EOF
echo "3/3 Terminé : le port $2/$1 n'est plus joignable depuis le réseau, jusqu'au prochain redémarrage."
"#;

pub const UNBLOCK_PORT_SCRIPT: &str = r#"case "$1" in tcp|udp) ;; *) echo "Protocole invalide."; exit 2;; esac
case "$2" in ''|*[!0-9]*) echo "Port invalide."; exit 2;; esac
h=$(/usr/bin/nft -a list chain inet cachy_shield input 2>/dev/null | sed -n "s/.*comment \"cs_$1_$2\" # handle \([0-9][0-9]*\)\$/\1/p" | head -1)
if [ -n "$h" ]; then /usr/bin/nft delete rule inet cachy_shield input handle "$h" && echo "Port $2/$1 débloqué."; else echo "Aucune règle trouvée (déjà retirée, par exemple après un redémarrage)."; fi
"#;

/// Bloque les connexions SORTANTES vers des serveurs distants publics (adresses IPv4 passées en arguments, revalidées ici).
pub const BLOCK_HOSTS_SCRIPT: &str = r#"/usr/bin/nft add table inet cachy_shield || exit 3
/usr/bin/nft 'add chain inet cachy_shield output { type filter hook output priority -10 ; policy accept ; }' || exit 3
n=0
for ip in "$@"; do
  case "$ip" in ''|*[!0-9.]*) echo "Adresse ignorée : $ip"; continue;; 10.*|127.*|192.168.*|169.254.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|0.*|22[4-9].*|2[3-5][0-9].*) echo "Adresse locale ou réservée ignorée : $ip"; continue;; esac
  if /usr/bin/nft -a list chain inet cachy_shield output | grep -q "cs_out_$ip\""; then echo "$ip est déjà bloqué."; continue; fi
  /usr/bin/nft -f - <<EOF && { echo "Serveur $ip bloqué."; n=$((n+1)); }
add rule inet cachy_shield output ip daddr $ip counter drop comment "cs_out_$ip"
EOF
done
echo "Terminé : $n serveur(s) bloqué(s) jusqu'au prochain redémarrage."
"#;

/// Retire TOUS les blocages de l'application (supprime sa table dédiée ; les autres règles ne sont pas touchées).
pub const UNBLOCK_ALL_SCRIPT: &str = r#"/usr/bin/nft delete table inet cachy_shield 2>/dev/null
echo "Tous les blocages de l'application sont levés."
"#;

/// Pare-feu simple : refuse tout ce qui arrive du réseau SAUF les réponses à vos connexions, le trafic local, le ping,
/// et les ports des services que vous avez marqués « autorisés » (arguments « tcp:22 », « udp:5353 »…, revalidés ici).
/// Table dédiée : les autres règles ne sont pas touchées ; elle disparaît au redémarrage.
pub const FIREWALL_ON_SCRIPT: &str = r#"mode="$1"; shift
[ -d "/lib/modules/$(uname -r)" ] || { echo "Les modules du noyau en cours d'exécution ne sont plus installés (mise à jour du noyau sans redémarrage) : redémarrez avant d'activer le pare-feu."; exit 9; }
case "$mode" in temp|perm) ;; *) echo "Mode invalide."; exit 2;; esac
d=$(mktemp -d) || exit 1
trap 'rm -rf "$d"' EXIT
: > "$d/deny"; : > "$d/allow"
lg=""
echo "1/3 Préparation des règles…"
for a in "$@"; do
  [ "$a" = "log:on" ] && { lg='log prefix "CS-REFUSE " limit rate 5/second'; continue; }
  IFS=: read -r act pr p from <<EOF4
$a
EOF4
  case "$act" in allow|deny|limit) ;; *) continue;; esac
  case "$pr" in tcp|udp) ;; *) continue;; esac
  case "$p" in ''|*[!0-9]*) continue;; esac
  [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || continue
  case "$from" in any) sm="";; ''|*[!0-9./]*) continue;; *) sm="ip saddr $from";; esac
  case "$act" in
    deny) echo "    $sm $pr dport $p drop" >> "$d/deny";;
    allow) echo "    $sm $pr dport $p accept" >> "$d/allow";;
    limit) echo "    $sm $pr dport $p ct state new limit rate 10/minute accept" >> "$d/allow";;
  esac
done
rd=$(cat "$d/deny"); ra=$(cat "$d/allow")
cat > "$d/fw.nft" <<EOF2
table inet cachy_shield_fw {
  chain input {
    type filter hook input priority 0 ; policy drop ;
    ct state established,related accept
    ct state invalid drop
    iifname "lo" accept
    meta l4proto { icmp, ipv6-icmp } accept
    udp sport 67 udp dport 68 accept
    udp dport 546 accept
$rd
$ra
    $lg
  }
}
EOF2
/usr/bin/nft -c -f "$d/fw.nft" || { echo "Règles invalides : rien n'a été modifié."; exit 3; }
if [ "$mode" = perm ]; then
  echo "2/3 Installation du service de démarrage (« cachy-shield-firewall », votre nftables.conf n'est pas touché)…"
  install -d -m 0755 /etc/cachy-shield || exit 4
  install -m 0644 "$d/fw.nft" /etc/cachy-shield/firewall.nft || exit 4
  cat > /etc/systemd/system/cachy-shield-firewall.service <<EOF3
[Unit]
Description=Pare-feu de Cachy Shield
Wants=network-pre.target
Before=network-pre.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/nft -f /etc/cachy-shield/firewall.nft
ExecStop=/usr/bin/nft delete table inet cachy_shield_fw

[Install]
WantedBy=multi-user.target
EOF3
  systemctl daemon-reload || exit 5
  systemctl enable cachy-shield-firewall.service || exit 5
fi
echo "3/3 Activation…"
/usr/bin/nft delete table inet cachy_shield_fw 2>/dev/null
/usr/bin/nft -f "$d/fw.nft" || exit 6
if [ "$mode" = perm ]; then echo "Pare-feu activé de façon PERMANENTE (il revient à chaque démarrage)."; else echo "Pare-feu activé jusqu'au prochain redémarrage."; fi
"#;

pub const FIREWALL_OFF_SCRIPT: &str = r#"systemctl disable cachy-shield-firewall.service 2>/dev/null
rm -f /etc/systemd/system/cachy-shield-firewall.service /etc/cachy-shield/firewall.nft
rmdir /etc/cachy-shield 2>/dev/null
systemctl daemon-reload 2>/dev/null
/usr/bin/nft delete table inet cachy_shield_fw 2>/dev/null
echo "Pare-feu de l'application désactivé (et retiré du démarrage)."
"#;

/// Une règle de l'utilisateur est-elle valide ? (action, protocole, port 1-65535, adresse IPv4 ou réseau CIDR, ou vide)
pub fn rule_valid(r: &crate::util::FwRule) -> bool {
    let from_ok = r.from.is_empty() || {
        let (ip, prefix) = r.from.split_once('/').map_or((r.from.as_str(), None), |(a, b)| (a, Some(b)));
        ip.parse::<std::net::Ipv4Addr>().is_ok() && prefix.is_none_or(|p| p.parse::<u8>().is_ok_and(|n| n <= 32))
    };
    matches!(r.action.as_str(), "allow" | "deny" | "limit") && valid_proto(&r.proto) && r.port > 0 && from_ok
}

/// Arguments des scripts d'activation : « action:proto:port:source ». Les services « autorisés » qui écoutent sur toutes
/// les interfaces sont autorisés ; les règles de l'utilisateur s'y ajoutent ; « log:on » active la journalisation.
pub fn firewall_args(listeners: &[(String, String, String)], allowed: &std::collections::HashSet<String>, rules: &[crate::util::FwRule], log: bool) -> Vec<String> {
    let mut v: Vec<String> = listeners
        .iter()
        .filter(|(proc, port, _)| allowed.contains(&crate::live::key_of(proc, port)))
        .filter(|(_, port, proto)| port.parse::<u16>().map(|p| p > 0).unwrap_or(false) && valid_proto(proto))
        .map(|(_, port, proto)| format!("allow:{proto}:{port}:any"))
        .collect();
    v.extend(rules.iter().filter(|r| rule_valid(r)).map(|r| format!("{}:{}:{}:{}", r.action, r.proto, r.port, if r.from.is_empty() { "any" } else { r.from.as_str() })));
    v.sort();
    v.dedup();
    if log {
        v.push("log:on".into());
    }
    v
}

// ─────────── pare-feu NATIF du système : ufw ou firewalld, selon ce qui est installé (persistants par nature) ───────────

/// Les modules du noyau en cours d'exécution sont-ils présents ? (sinon, après une mise à jour du noyau sans redémarrage, le pare-feu ne peut pas charger ses composants)
pub fn kernel_modules_present() -> bool {
    let rel = std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default();
    let rel = rel.trim();
    !rel.is_empty() && rel.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | '+')) && std::path::Path::new("/lib/modules").join(rel).is_dir()
}

/// Pare-feux que l'application sait piloter. « Own » : table nftables dédiée de l'application (si aucun pare-feu système n'est installé).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FwBackend {
    Ufw,
    Firewalld,
    Own,
}

impl FwBackend {
    /// Identifiant enregistré dans les réglages.
    pub fn id(self) -> &'static str {
        match self {
            FwBackend::Ufw => "ufw",
            FwBackend::Firewalld => "firewalld",
            FwBackend::Own => "nftables",
        }
    }
}

/// Préférence de l'utilisateur : « auto », « ufw », « firewalld » ou « nftables ».
static PREF: std::sync::Mutex<String> = std::sync::Mutex::new(String::new());

pub fn set_backend_pref(p: &str) {
    if let Ok(mut g) = PREF.lock() {
        *g = p.to_string();
    }
}

/// Pare-feux détectés sur la machine (toujours « nftables » en dernier : il est intégré à l'application).
pub fn available_backends() -> Vec<FwBackend> {
    let mut v = Vec::new();
    if crate::util::abs_prog("ufw").is_some() {
        v.push(FwBackend::Ufw);
    }
    if crate::fwd::installed() {
        v.push(FwBackend::Firewalld);
    }
    v.push(FwBackend::Own);
    v
}

/// Choix du pare-feu : la préférence de l'utilisateur si ce pare-feu est installé ; sinon, celui qui est déjà actif, sinon le premier détecté.
pub fn choose_backend(pref: &str, avail: &[FwBackend], active: Option<FwBackend>) -> FwBackend {
    if let Some(b) = avail.iter().find(|b| b.id() == pref) {
        return *b;
    }
    if let Some(a) = active.filter(|a| avail.contains(a)) {
        return a;
    }
    avail.first().copied().unwrap_or(FwBackend::Own)
}

/// Pare-feu système actuellement actif (sans droits administrateur).
pub fn active_backend() -> Option<FwBackend> {
    let sc = |u: &str| crate::util::abs_prog("systemctl").is_some_and(|p| std::process::Command::new(p).args(["is-active", u]).output().map(|o| String::from_utf8_lossy(&o.stdout).trim() == "active").unwrap_or(false));
    if sc("ufw") {
        Some(FwBackend::Ufw)
    } else if sc("firewalld") {
        Some(FwBackend::Firewalld)
    } else {
        None
    }
}

pub fn fw_backend() -> FwBackend {
    let pref = PREF.lock().map(|g| g.clone()).unwrap_or_default();
    choose_backend(&pref, &available_backends(), active_backend())
}

pub fn fw_backend_name(b: FwBackend) -> &'static str {
    b.id()
}

/// ufw : refuse l'entrant, autorise le sortant et les ports « autorisés », puis active (ufw garde ses règles au redémarrage).
pub const UFW_ON_SCRIPT: &str = r#"[ -d "/lib/modules/$(uname -r)" ] || { echo "Les modules du noyau en cours d'exécution ne sont plus installés (mise à jour du noyau sans redémarrage) : redémarrez avant d'activer le pare-feu."; exit 9; }
echo "1/4 Règles par défaut : refuser l'entrant, autoriser le sortant…"
/usr/bin/ufw default deny incoming || exit 3
/usr/bin/ufw default allow outgoing || exit 3
echo "2/4 Règles (services « autorisés » et règles personnalisées)…"
lg=low
for a in "$@"; do
  [ "$a" = "log:on" ] && { lg=low; continue; }
  IFS=: read -r act pr p from <<EOF4
$a
EOF4
  case "$act" in allow|deny|limit) ;; *) continue;; esac
  case "$pr" in tcp|udp) ;; *) continue;; esac
  case "$p" in ''|*[!0-9]*) continue;; esac
  [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || continue
  case "$from" in any) src=any;; ''|*[!0-9./]*) continue;; *) src=$from;; esac
  /usr/bin/ufw "$act" proto "$pr" from "$src" to any port "$p" || exit 4
done
case " $* " in *" log:on "*) ;; *) lg=off;; esac
echo "3/4 Journalisation : $lg"
/usr/bin/ufw logging "$lg" || true
echo "4/4 Activation…"
/usr/bin/ufw --force enable || exit 5
echo "ufw activé : il reste actif à chaque démarrage."
"#;

pub const UFW_OFF_SCRIPT: &str = r#"/usr/bin/ufw --force disable
echo "ufw désactivé."
"#;

/// firewalld : démarre le service, ouvre les ports « autorisés » de façon permanente, recharge.
pub const FIREWALLD_ON_SCRIPT: &str = r#"[ -d "/lib/modules/$(uname -r)" ] || { echo "Les modules du noyau en cours d'exécution ne sont plus installés (mise à jour du noyau sans redémarrage) : redémarrez avant d'activer le pare-feu."; exit 9; }
echo "1/4 Démarrage de firewalld…"
systemctl enable --now firewalld || exit 3
echo "2/4 Règles (services « autorisés » et règles personnalisées), permanentes…"
ld=off
for a in "$@"; do
  [ "$a" = "log:on" ] && { ld=unicast; continue; }
  IFS=: read -r act pr p from <<EOF4
$a
EOF4
  case "$act" in allow|deny|limit) ;; *) continue;; esac
  case "$pr" in tcp|udp) ;; *) continue;; esac
  case "$p" in ''|*[!0-9]*) continue;; esac
  [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || continue
  case "$from" in any) srcx="";; ''|*[!0-9./]*) continue;; *) srcx="source address=\"$from\"";; esac
  case "$act" in
    allow) if [ -z "$srcx" ]; then /usr/bin/firewall-cmd --permanent --add-port="$p/$pr" || exit 4
           else /usr/bin/firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" $srcx port port=\"$p\" protocol=\"$pr\" accept" || exit 4; fi;;
    deny) /usr/bin/firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" $srcx port port=\"$p\" protocol=\"$pr\" reject" || exit 4;;
    limit) /usr/bin/firewall-cmd --permanent --add-rich-rule="rule family=\"ipv4\" $srcx port port=\"$p\" protocol=\"$pr\" accept limit value=\"10/m\"" || exit 4;;
  esac
done
echo "3/4 Journalisation des paquets refusés : $ld"
/usr/bin/firewall-cmd --set-log-denied="$ld" >/dev/null || true
echo "4/4 Rechargement…"
/usr/bin/firewall-cmd --reload || exit 5
echo "firewalld activé : il reste actif à chaque démarrage."
"#;

pub const FIREWALLD_OFF_SCRIPT: &str = r#"systemctl disable --now firewalld
echo "firewalld désactivé."
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pid: u32, uid: u32, name: &str) -> ProcInfo {
        ProcInfo { pid, uid, name: name.into(), cmdline: String::new() }
    }

    #[test]
    fn ports_du_pare_feu() {
        let l = vec![("sshd".to_string(), "22".to_string(), "tcp".to_string()), ("x".to_string(), "99999".to_string(), "tcp".to_string()), ("y".to_string(), "80".to_string(), "tcp".to_string())];
        let allowed: std::collections::HashSet<String> = ["sshd", "x"].iter().map(|s| s.to_string()).collect();
        assert_eq!(firewall_args(&l, &allowed, &[], false), vec!["allow:tcp:22:any".to_string()], "seuls les ports autorisés et valides sont gardés");
        let r = crate::util::FwRule { action: "deny".into(), proto: "tcp".into(), port: 22, from: "203.0.113.0/24".into() };
        assert!(rule_valid(&r));
        assert!(!rule_valid(&crate::util::FwRule { from: "1.2.3.4; rm -rf /".into(), ..r.clone() }));
        assert!(!rule_valid(&crate::util::FwRule { port: 0, ..r.clone() }));
        assert_eq!(firewall_args(&l, &allowed, &[r], true).last().map(String::as_str), Some("log:on"));
        assert!(FIREWALL_ON_SCRIPT.contains("policy drop") && FIREWALL_ON_SCRIPT.contains("ct state established,related accept") && FIREWALL_ON_SCRIPT.contains("perm"));
    }

    #[test]
    fn garde_fous_de_l_arret() {
        assert_eq!(can_kill(&p(5000, 1000, "demo-app"), 1000, 1), Kill::Allowed);
        assert_eq!(can_kill(&p(5001, 1000, "python3"), 1000, 1), Kill::Allowed);
        assert!(matches!(can_kill(&p(1, 0, "systemd"), 1000, 9), Kill::Refused(_)), "PID 1 jamais");
        assert!(matches!(can_kill(&p(900, 0, "sshd"), 1000, 9), Kill::Refused(_)), "root jamais");
        assert!(matches!(can_kill(&p(901, 1000, "kwin_wayland"), 1000, 9), Kill::Refused(_)), "la session jamais");
        assert!(matches!(can_kill(&p(902, 1000, "plasmashell"), 1000, 9), Kill::Refused(_)));
        assert!(matches!(can_kill(&p(903, 1000, "pipewire"), 1000, 9), Kill::Refused(_)));
        assert!(matches!(can_kill(&p(77, 1000, "cachy-shield"), 1000, 77), Kill::Refused(_)), "pas soi-même");
        assert!(matches!(can_kill(&p(904, 1001, "x"), 1000, 9), Kill::Refused(_)), "autre utilisateur");
    }

    #[test]
    fn pids_filtres() {
        assert_eq!(pids_valid(&[0, 1, 500, 500, 99, 5_000_000]), vec![99, 500]);
    }

    #[test]
    fn serveurs_bloquables_publics_seulement() {
        assert_eq!(blockable_host("142.251.173.95").as_deref(), Some("142.251.173.95"));
        assert_eq!(blockable_host("192.168.1.30"), None, "jamais le réseau local");
        assert_eq!(blockable_host("127.0.0.1"), None);
        assert_eq!(blockable_host("169.254.1.1"), None);
        assert_eq!(blockable_host("1.2.3.4; rm -rf /"), None);
        assert_eq!(blockable_host("::1"), None);
    }

    #[test]
    fn lecture_de_proc() {
        let me = std::process::id();
        let i = read_proc(me).expect("lecture de son propre processus");
        assert_eq!(i.pid, me);
        assert_eq!(i.uid, current_uid());
        assert!(!i.name.is_empty());
        assert!(read_proc(4_000_000).is_none());
    }

    #[test]
    fn scripts_syntaxe_valide_et_sans_donnee_externe() {
        for (nom, s) in [("block_port", BLOCK_PORT_SCRIPT), ("unblock_port", UNBLOCK_PORT_SCRIPT), ("block_hosts", BLOCK_HOSTS_SCRIPT), ("unblock_all", UNBLOCK_ALL_SCRIPT)] {
            let f = std::env::temp_dir().join(format!("cs-test-{nom}.sh"));
            std::fs::write(&f, s).unwrap();
            let st = std::process::Command::new("/bin/sh").arg("-n").arg(&f).status().unwrap();
            let _ = std::fs::remove_file(&f);
            assert!(st.success(), "syntaxe invalide : {nom}");
        }
    }
}

/// Texte lisible des règles qui seraient appliquées (« Autoriser TCP 22 · Refuser TCP 23 depuis 203.0.113.0/24 · … »).
pub fn human_rules(args: &[String]) -> String {
    let mut out: Vec<String> = Vec::new();
    for a in args {
        if a == "log:on" {
            out.push("journalisation des connexions refusées".into());
            continue;
        }
        let p: Vec<&str> = a.split(':').collect();
        if p.len() != 4 {
            continue;
        }
        let verb = match p[0] {
            "allow" => "autoriser",
            "deny" => "refuser",
            "limit" => "limiter",
            _ => continue,
        };
        let from = if p[3] == "any" { String::new() } else { format!(" depuis {}", p[3]) };
        out.push(format!("{verb} {} {}{from}", p[1].to_uppercase(), p[2]));
    }
    out.join(" · ")
}

#[cfg(test)]
mod tests_backend {
    use super::*;

    #[test]
    fn choix_du_pare_feu() {
        use FwBackend::*;
        assert_eq!(choose_backend("auto", &[Ufw, Own], None), Ufw, "un seul pare-feu installé : celui-là");
        assert_eq!(choose_backend("auto", &[Firewalld, Own], None), Firewalld);
        assert_eq!(choose_backend("auto", &[Own], None), Own);
        assert_eq!(choose_backend("auto", &[Ufw, Firewalld, Own], Some(Firewalld)), Firewalld, "les deux installés : celui qui est actif");
        assert_eq!(choose_backend("auto", &[Ufw, Firewalld, Own], None), Ufw, "les deux installés, aucun actif : ufw (le plus courant)");
        assert_eq!(choose_backend("firewalld", &[Ufw, Firewalld, Own], Some(Ufw)), Firewalld, "le choix de l'utilisateur prime");
        assert_eq!(choose_backend("firewalld", &[Ufw, Own], None), Ufw, "choix d'un pare-feu absent : retour à la détection");
        assert_eq!(choose_backend("nftables", &[Ufw, Own], None), Own);
        assert_eq!(choose_backend("n'importe quoi", &[Firewalld, Own], None), Firewalld);
    }
}
