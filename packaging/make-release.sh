#!/bin/sh
# Builds the release archive: the ready-made program + the complete installer, so that users do not need to compile.
#   sh packaging/make-release.sh        → dist/cachy-shield-<version>-x86_64.tar.gz and its .sha256
# The program is built for a generic x86-64 processor (no -C target-cpu=native), and no path of this machine ends up in it.
set -eu
cd "$(dirname "$0")/.."

BIN=cachy-shield
VERSION="$(sed -n 's/^version = "\(.*\)"/\1/p' Cargo.toml | head -n1)"
[ -n "$VERSION" ] || { echo "version not found in Cargo.toml" >&2; exit 1; }
NAME="$BIN-$VERSION-x86_64"

RUSTFLAGS="--remap-path-prefix=$PWD=. --remap-path-prefix=${CARGO_HOME:-$HOME/.cargo}=/cargo --remap-path-prefix=$HOME=~" cargo build --release --locked
if strings "target/release/$BIN" | grep -qF "$HOME"; then echo "a personal path is still in the program: aborting" >&2; exit 1; fi

rm -rf "dist/$NAME"
mkdir -p "dist/$NAME/packaging"
install -m755 "target/release/$BIN" "dist/$NAME/$BIN"
install -m755 install.sh uninstall.sh "dist/$NAME/"
install -m644 packaging/*.svg packaging/*.desktop "dist/$NAME/packaging/"
install -m644 LICENSE README.md "dist/$NAME/"

tar -C dist -czf "dist/$NAME.tar.gz" "$NAME"
(cd dist && sha256sum "$NAME.tar.gz" > "$NAME.tar.gz.sha256")
rm -rf "dist/$NAME"
echo "Done: dist/$NAME.tar.gz"
cat "dist/$NAME.tar.gz.sha256"
