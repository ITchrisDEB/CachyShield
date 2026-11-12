# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-12

### Changed
- The administrator password is asked at the first action that needs it, not at startup.
- Faster release build (`lto = false`, `codegen-units = 16`).

### Added
- First public version of **Cachy Shield**: Smart care, Protection, Vulnerabilities, Updates, Cleanup, Network,
  Configuration and Advanced pages on top of arch-audit, Lynis, rkhunter, Trivy and OSV-Scanner.
- Post-update maintenance in the Updates page "Fix" button: orphaned packages, pacman cache, Flatpak, services to restart
  and pending kernel reboot (each step confirmed, none required).
- Firewall editor for ufw and firewalld, SSH settings editor, kernel/network hardening with rollback.
- Tray icon (`--background` mode) with update notifications; autostart installed by `install.sh`.
- Interface in English, French, German, Spanish, Italian and Dutch.
- `install.sh`: dependency check, build, install in `/usr/bin`; `cachy-shield-uninstall` is installed alongside it.
- Release archive (`packaging/make-release.sh`, built by the GitHub `Release` workflow): ready-made program and complete installer, nothing to compile.
- Language selector at the bottom left of the window; tray icon turns into a shield with an orange badge when updates are pending, and refreshes after an update.
