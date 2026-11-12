# Contributing to Cachy Shield

Thanks for helping! Bug reports, translations, docs and code are all welcome.

## Ground rules

Cachy Shield is a **risk-management tool**, so some rules are not negotiable:

1. **No change to the system without an explicit confirmation** in the interface that says what will happen.
2. **Root actions are constant scripts.** Anything that runs as root must be a script constant listed in
   `privileged::known_scripts()`; variable values are *arguments* validated by the script itself, never interpolated.
3. **Never enable a firewall automatically**, never touch virtual environments, never install AUR packages silently.
4. **No personal data in the code or the docs**: no usernames, hardcoded home paths or machine-specific values — use the
   user's environment (`$HOME`, XDG variables). The release binary must not contain build paths (see below).
5. **`unsafe` is forbidden** (`unsafe_code = "forbid"`).
6. Everything shown to the user must be **translatable** (see "Translations").

## Build and test

```sh
cargo build --release --locked
cargo test --locked
```

Build exactly as the installer does, so that no path of your machine ends up in the binary:

```sh
RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=$HOME/.cargo=/cargo --remap-path-prefix=$HOME=~" cargo build --release --locked
strings target/release/cachy-shield | grep -c "$HOME"   # must print 0
```

Run `./install.sh --help` for the installer. Please run `sh -n install.sh` (and `shellcheck install.sh` if you have it) after editing it.

## Translations

The source language of the interface texts is **French**; `lang/en*.tsv` hold the English reference (`French<TAB>English`,
lines starting with `~` are regular expressions with `$1`… placeholders). `lang/<code>.tsv` (de, es, it, nl) contain
`id<TAB>translation` where `id` is the 0-based index of the entry in the concatenated English files.

* Keep placeholders (`$1`, `{n}`, `\n`) identical to the English reference.
* Plurals are written once and resolved from the preceding number: `{singular|plural}` (e.g. `$1 {file|files}`) or
  `word(s)` / `librar(y/ies)`. Never display both forms.
* Run `cargo test i18n` — it checks completeness, placeholders and leftover markers.
* To try a language without rebuilding, put `<code>.tsv` (`French text<TAB>translation`) in `~/.config/cachy-shield/lang/`.

## Pull requests

* Keep changes focused; describe *why*. Add or update tests when you change logic.
* New user-visible text needs its English entry and the four bundled translations (or open the PR and ask for help).
* Update `CHANGELOG.md` under **Unreleased**.
