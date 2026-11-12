//! Durcissement du noyau et du réseau par le mécanisme natif de Linux : un fichier `/etc/sysctl.d/99-cachy-shield.conf`
//! (lu par systemd à chaque démarrage, appliqué tout de suite avec `sysctl -p`). Seuls des réglages SANS risque pour un poste
//! de bureau sont proposés ; chacun est comparé à la valeur ACTUELLE (lue dans /proc/sys) et les valeurs d'origine sont
//! gardées dans le fichier (« # was ») pour pouvoir tout annuler.

use std::path::Path;

pub struct Item {
    pub key: &'static str,
    pub want: &'static str,
    pub why: &'static str,
}

pub const ITEMS: &[Item] = &[
    Item { key: "kernel.dmesg_restrict", want: "1", why: "Empêche les programmes sans droits de lire les messages du noyau (qui révèlent des adresses utiles aux attaquants)." },
    Item { key: "kernel.kptr_restrict", want: "2", why: "Cache les adresses internes du noyau aux utilisateurs, ce qui complique l'exploitation de failles du noyau." },
    Item { key: "fs.suid_dumpable", want: "0", why: "Interdit les copies mémoire (core dumps) des programmes à privilèges, qui peuvent contenir des secrets." },
    Item { key: "net.ipv4.conf.all.accept_redirects", want: "0", why: "Refuse les « redirections » ICMP, qu'un attaquant du réseau peut utiliser pour détourner votre trafic." },
    Item { key: "net.ipv4.conf.default.accept_redirects", want: "0", why: "Idem pour les nouvelles interfaces réseau." },
    Item { key: "net.ipv6.conf.all.accept_redirects", want: "0", why: "Refuse les redirections en IPv6." },
    Item { key: "net.ipv4.conf.all.send_redirects", want: "0", why: "Cet ordinateur n'est pas un routeur : il n'a pas à envoyer de redirections." },
    Item { key: "net.ipv4.conf.all.accept_source_route", want: "0", why: "Refuse les paquets qui imposent leur propre chemin (technique de détournement)." },
    Item { key: "net.ipv4.conf.all.log_martians", want: "1", why: "Journalise les paquets aux adresses impossibles (signe d'usurpation) pour pouvoir les repérer." },
    Item { key: "net.ipv4.tcp_syncookies", want: "1", why: "Protège contre les inondations de connexions (SYN flood)." },
];

pub const CONF: &str = "/etc/sysctl.d/99-cachy-shield.conf";

fn proc_path(key: &str) -> String {
    format!("/proc/sys/{}", key.replace('.', "/"))
}

pub fn current(key: &str) -> Option<String> {
    std::fs::read_to_string(proc_path(key)).ok().map(|s| s.trim().to_string())
}

/// Réglages dont la valeur actuelle diffère de la valeur souhaitée (et qui existent sur ce noyau).
pub fn pending() -> Vec<(&'static Item, String)> {
    ITEMS.iter().filter_map(|i| current(i.key).filter(|c| c != i.want && c.chars().all(|ch| ch.is_ascii_digit())).map(|c| (i, c))).collect()
}

pub fn applied() -> bool {
    Path::new(CONF).exists()
}

/// Arguments du script : « clé=voulue=ancienne ».
pub fn args(p: &[(&Item, String)]) -> Vec<String> {
    p.iter().map(|(i, old)| format!("{}={}={}", i.key, i.want, old)).collect()
}

pub const APPLY_SCRIPT: &str = r#"f=/etc/sysctl.d/99-cachy-shield.conf
tmp=$(mktemp) || exit 1
trap 'rm -f "$tmp"' EXIT
printf '%s\n' '# Géré par Cachy Shield. Supprimez ce fichier pour annuler.' > "$tmp"
n=0
echo "1/3 Préparation des réglages…"
for a in "$@"; do
  k=${a%%=*}; r=${a#*=}; v=${r%%=*}; o=${r#*=}
  case "$k" in ''|*[!a-z0-9._]*) continue;; esac
  case "$v" in ''|*[!0-9]*) continue;; esac
  case "$o" in ''|*[!0-9]*) continue;; esac
  [ -e "/proc/sys/$(echo "$k" | tr . /)" ] || continue
  printf '%s = %s\n# was %s=%s\n' "$k" "$v" "$k" "$o" >> "$tmp"
  n=$((n+1))
done
[ "$n" -gt 0 ] || { echo "Aucun réglage valide : rien n'a été modifié."; exit 2; }
echo "2/3 Écriture de $f ($n réglage(s))…"
install -m 0644 "$tmp" "$f" || exit 3
echo "3/3 Application immédiate…"
if ! /usr/bin/sysctl -p "$f"; then rm -f "$f"; echo "Un réglage a été refusé : tout est annulé."; exit 4; fi
echo "Terminé : actif maintenant et à chaque démarrage."
"#;

pub const REVERT_SCRIPT: &str = r#"f=/etc/sysctl.d/99-cachy-shield.conf
[ -f "$f" ] || { echo "Rien à annuler."; exit 0; }
sed -n 's/^# was //p' "$f" | while IFS='=' read -r k o; do
  case "$k" in ''|*[!a-z0-9._]*) continue;; esac
  case "$o" in ''|*[!0-9]*) continue;; esac
  /usr/bin/sysctl -w "$k=$o" >/dev/null && echo "Rétabli : $k = $o"
done
rm -f "$f"
echo "Durcissement annulé : les valeurs d'origine sont rétablies."
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reglages_valides() {
        for i in ITEMS {
            assert!(i.key.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '_'), "{}", i.key);
            assert!(i.want.chars().all(|c| c.is_ascii_digit()));
        }
        let it = &ITEMS[0];
        assert_eq!(args(&[(it, "0".into())]), vec!["kernel.dmesg_restrict=1=0".to_string()]);
    }
}
