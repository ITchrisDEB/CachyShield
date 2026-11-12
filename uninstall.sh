#!/bin/sh
# Cachy Shield — uninstaller. After installation a copy lives in /usr/bin, so the cloned folder is not needed:
#
#   sudo cachy-shield-uninstall
#
# Removes the program, the launcher, the icon and the tray autostart. Your settings and results are kept.
# Changes made from inside the application (firewall, SSH, sysctl files in /etc) are NOT removed: revert them
# from the application first.
set -eu

BIN=cachy-shield
APP_ID=io.github.cachy_shield.CachyShield

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

if [ "$(id -u)" -eq 0 ]; then
    [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] || die "run this with sudo from your normal account: sudo cachy-shield-uninstall"
    ME="$SUDO_USER"
    HOME_DIR="$(getent passwd "$ME" | cut -d: -f6)"
    [ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || die "cannot find the home folder of $ME."
    as_user() { sudo -u "$ME" -H "$@"; }
    as_root() { "$@"; }
else
    HOME_DIR="$HOME"
    as_user() { "$@"; }
    as_root() { if command -v sudo >/dev/null 2>&1; then sudo "$@"; else pkexec "$@"; fi; }
fi

DATA="${XDG_DATA_HOME:-$HOME_DIR/.local/share}"
CONF="${XDG_CONFIG_HOME:-$HOME_DIR/.config}"

# stop the running program and its tray icon, if any
as_user pkill -x "$BIN" >/dev/null 2>&1 || true

as_user rm -f "$CONF/autostart/$BIN-tray.desktop" "$DATA/applications/$APP_ID.desktop" "$DATA/icons/hicolor/scalable/apps/$BIN.svg" "$DATA/icons/hicolor/scalable/apps/$BIN-attention.svg"
command -v update-desktop-database >/dev/null 2>&1 && as_user update-desktop-database "$DATA/applications" >/dev/null 2>&1 || true
command -v gtk-update-icon-cache >/dev/null 2>&1 && as_user gtk-update-icon-cache -q -t "$DATA/icons/hicolor" >/dev/null 2>&1 || true

say "Removing /usr/bin/$BIN …"
as_root /usr/bin/rm -f "/usr/bin/$BIN" "/usr/bin/$BIN-uninstall"
say "Uninstalled. Your settings and results in $DATA/$BIN were kept (delete that folder to remove them too)."
