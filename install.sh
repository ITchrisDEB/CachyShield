#!/bin/sh
# Cachy Shield — installer for Arch Linux and Arch-based distributions (CachyOS, EndeavourOS, Manjaro…).
#
#   sudo ./install.sh             the usual way: installs the program in /usr/bin (needs administrator rights)
#   ./install.sh                  also works: it then asks for your password when it needs it
#
# Two ways to get it: from a release archive (the program is already built: nothing to compile, no Rust needed) or from a
# clone of the repository (the program is built first). The script detects which one it is.
#
#
#   ./install.sh --yes            answer "yes" to every question
#   ./install.sh --no-deps        skip the dependency check
#   ./install.sh --no-autostart   do not start the tray icon at login
#   ./install.sh --uninstall      remove everything this script installed (your settings and results are kept)
#
# What it installs:
#   /usr/bin/cachy-shield                the program, in a folder only root can write to: that is what allows the
#   /usr/bin/cachy-shield-uninstall      the uninstaller: "sudo cachy-shield-uninstall" works even if you delete this folder
#                                        administrator password to be requested only ONCE at startup
#   ~/.local/share/{applications,icons}  launcher and icon (XDG_DATA_HOME is honoured)
#   ~/.config/autostart                  tray icon at login (XDG_CONFIG_HOME is honoured)
# Nothing is installed without asking first, and this script never reads your password.
set -eu

cd "$(dirname "$0")"

APP_ID=io.github.cachy_shield.CachyShield
BIN=cachy-shield

# Required to build and run.
RUNTIME_PKGS="gtk4 libadwaita polkit pacman-contrib iproute2 nftables curl"
BUILD_PKGS="gcc make pkgconf"
# The scanners are what the application is built on: offered by default. The helpers give Lynis and rkhunter more complete results.
SCANNER_PKGS="arch-audit lynis rkhunter trivy osv-scanner"
HELPER_PKGS="unhide net-tools"

# A release archive contains the ready-made program next to this script and no source code.
PREBUILT=0
if [ ! -f Cargo.toml ] && [ -x "./$BIN" ]; then PREBUILT=1; fi

ASSUME_YES=0
DO_DEPS=1
DO_AUTOSTART=1
UNINSTALL=0

say() { printf '%s\n' "$*"; }
die() { printf 'Error: %s\n' "$*" >&2; exit 1; }

usage() {
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
}

for arg in "$@"; do
    case "$arg" in
        --yes | -y) ASSUME_YES=1 ;;
        --no-deps) DO_DEPS=0 ;;
        --no-autostart) DO_AUTOSTART=0 ;;
        --uninstall) UNINSTALL=1 ;;
        --help | -h) usage; exit 0 ;;
        *) die "unknown option: $arg (try --help)" ;;
    esac
done

# ── who is installing? ──────────────────────────────────────────────────────────────────────────────
# Run normally: we are the user and only ask for the password for the steps that need it.
# Run with sudo: we are root, but everything personal (build, launcher, icon, tray) is done AS the user who typed sudo.
if [ "$(id -u)" -eq 0 ]; then
    [ -n "${SUDO_USER:-}" ] && [ "$SUDO_USER" != root ] || die "run this as your normal user (./install.sh) or with sudo from your normal account (sudo ./install.sh), not from a root login."
    ME="$SUDO_USER"
    HOME_DIR="$(getent passwd "$ME" | cut -d: -f6)"
    [ -n "$HOME_DIR" ] && [ -d "$HOME_DIR" ] || die "cannot find the home folder of $ME."
    as_user() { sudo -u "$ME" -H "$@"; }
    as_root() { "$@"; }
else
    ME="$(id -un)"
    HOME_DIR="$HOME"
    as_user() { "$@"; }
    as_root() {
        if command -v sudo >/dev/null 2>&1; then sudo "$@"; else pkexec "$@"; fi
    }
fi

DATA="${XDG_DATA_HOME:-$HOME_DIR/.local/share}"
CONF="${XDG_CONFIG_HOME:-$HOME_DIR/.config}"

refresh_caches() {
    if command -v update-desktop-database >/dev/null 2>&1; then as_user update-desktop-database "$DATA/applications" >/dev/null 2>&1 || true; fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1; then as_user gtk-update-icon-cache -q -t "$DATA/icons/hicolor" >/dev/null 2>&1 || true; fi
}

# ── uninstall ───────────────────────────────────────────────────────────────────────────────────────
if [ "$UNINSTALL" -eq 1 ]; then
    exec sh ./uninstall.sh
fi

# ── dependencies ────────────────────────────────────────────────────────────────────────────────────
ask() { # ask "question" default(y|n) → returns 0 for yes
    [ "$ASSUME_YES" -eq 1 ] && return 0
    [ -t 0 ] || { [ "$2" = y ]; return; }
    if [ "$2" = y ]; then hint="[Y/n]"; else hint="[y/N]"; fi
    printf '%s %s ' "$1" "$hint"
    read -r reply || reply=""
    case "$reply" in
        [Yy]*) return 0 ;;
        [Nn]*) return 1 ;;
        "") [ "$2" = y ] ;;
        *) return 1 ;;
    esac
}

missing_of() { # prints the packages (among the arguments) that are not installed
    # shellcheck disable=SC2068
    pacman -T $@ 2>/dev/null || true
}

available_of() { # keeps only the packages that exist in the configured repositories
    for p in "$@"; do
        if pacman -Ssq "^$p\$" 2>/dev/null | grep -qx "$p"; then printf '%s ' "$p"; fi
    done
}

install_pkgs() {
    say "→ pacman -S --needed $*"
    as_root pacman -S --needed "$@"
}

if [ "$DO_DEPS" -eq 1 ]; then
    command -v pacman >/dev/null 2>&1 || die "pacman not found: Cachy Shield is made for Arch Linux and Arch-based distributions."

    if [ "$PREBUILT" -eq 1 ]; then
        need="$(missing_of $RUNTIME_PKGS)"
    else
        need="$(missing_of $RUNTIME_PKGS $BUILD_PKGS)"
        if ! as_user sh -c 'command -v cargo' >/dev/null 2>&1; then need="$need rust"; fi
    fi
    need="$(printf '%s' "$need" | tr -s ' \n' ' ' | sed 's/^ //; s/ $//')"
    if [ -n "$need" ]; then
        say "Some programs Cachy Shield needs are missing: $need"
        if ask "Install them now? (your password will be asked)" y; then
            # shellcheck disable=SC2086
            install_pkgs $need
        else
            die "install them first with:  sudo pacman -S --needed $need"
        fi
    else
        say "Everything Cachy Shield needs is installed."
    fi

    # shellcheck disable=SC2086
    opt_missing="$(missing_of $(available_of $SCANNER_PKGS $HELPER_PKGS))"
    opt_missing="$(printf '%s' "$opt_missing" | tr -s ' \n' ' ' | sed 's/^ //; s/ $//')"
    if [ -n "$opt_missing" ]; then
        say "These security tools are not installed yet (Cachy Shield is built on them; without one, its checks are skipped): $opt_missing"
        if ask "Install them too?" y; then
            # shellcheck disable=SC2086
            install_pkgs $opt_missing
        fi
    fi
fi

if [ "$PREBUILT" -eq 1 ]; then
    PROGRAM="./$BIN"
    say "Using the ready-made program from this archive (nothing to compile)."
else
    as_user sh -c 'command -v cargo' >/dev/null 2>&1 || die "the Rust compiler was not found. Install it with:  sudo pacman -S rust   (if you use rustup, run ./install.sh without sudo)."
    say "Building Cachy Shield (a few minutes the first time)…"
    # no path of this machine ends up in the program
    as_user env RUSTFLAGS="${RUSTFLAGS:-} --remap-path-prefix=$PWD=. --remap-path-prefix=$HOME_DIR/.cargo=/cargo --remap-path-prefix=$HOME_DIR=~" cargo build --release --locked
    PROGRAM="target/release/$BIN"
fi

say "Installing /usr/bin/$BIN …"
as_root /usr/bin/install -Dm755 "$PROGRAM" "/usr/bin/$BIN"
as_root /usr/bin/install -Dm755 uninstall.sh "/usr/bin/$BIN-uninstall"

as_user install -Dm644 "packaging/$BIN.svg" "$DATA/icons/hicolor/scalable/apps/$BIN.svg"
as_user install -Dm644 "packaging/$BIN-attention.svg" "$DATA/icons/hicolor/scalable/apps/$BIN-attention.svg"
as_user install -Dm644 "packaging/$APP_ID.desktop" "$DATA/applications/$APP_ID.desktop"
if [ "$DO_AUTOSTART" -eq 1 ]; then
    as_user install -Dm644 "packaging/$BIN-tray.desktop" "$CONF/autostart/$BIN-tray.desktop"
else
    as_user rm -f "$CONF/autostart/$BIN-tray.desktop"
fi
refresh_caches

say ""
say "Done. Open \"Cachy Shield\" from your applications menu (or type: $BIN)."
if [ "$DO_AUTOSTART" -eq 1 ]; then
    say "The tray icon will appear at your next login. To turn it off: Cachy Shield settings, or ./install.sh --no-autostart"
fi
