# Security policy

Cachy Shield runs administrator actions on your behalf, so security reports are taken seriously.

## Reporting a vulnerability

**Please do not open a public issue.** Use GitHub's private reporting:
*Security → Report a vulnerability* on this repository. Include what you found, how to reproduce it, and the version.
You will get an answer as soon as possible; fixes are released with credit unless you prefer otherwise.

## Scope

Of particular interest: the root helper (`--root-helper`, `src/privileged.rs`), the constant root scripts and their argument
validation, the AUR flow, and anything that could make the program change the system without confirmation.

## How administrator rights work

At the first action that needs administrator rights, `pkexec` starts a small helper (`--root-helper`) of this same program, once, and the main program talks to it
over an anonymous pipe.

* The helper only runs *constant, built-in scripts* (compared byte for byte) and a short list of audit programs by absolute
  path. Anything else is refused and falls back to a regular `pkexec` prompt.
* Variable values (ports, package names…) are only ever script arguments, validated by the scripts themselves.
* The helper refuses to run unless it is root, exits when the main program closes, and only starts from an executable owned
  by root and not writable by anyone else — which is why the program is installed in `/usr/bin`.
* The AUR flow never uses `--noconfirm`; dependency fixes in projects keep a backup and restore it on failure.

## Supported versions

Only the latest release receives security fixes.
