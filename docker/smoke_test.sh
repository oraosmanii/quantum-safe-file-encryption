#!/bin/sh
# Smoke test for the pqc-bench image: print every tool's version, then do one
# encrypt/decrypt round trip per mode and compare SHA-256 hashes.
# Exits non-zero on the first failure. Uses throwaway keys in a temp dir only.
set -eu

echo "== versions"
age --version
age-keygen --version
gpg --version | head -n 3
gpgconf --list-dirs bindir
hyperfine --version
/usr/bin/time --version 2>&1 | head -n 1
python3 --version
sq version 2>&1
gopenpgp-cli version

tmp=$(mktemp -d)
trap 'gpgconf --homedir "$tmp/gpg-x" --kill all 2>/dev/null || true; gpgconf --homedir "$tmp/gpg-pq" --kill all 2>/dev/null || true; rm -rf "$tmp"' EXIT

head -c 102400 /dev/urandom > "$tmp/in.bin"
want=$(sha256sum "$tmp/in.bin" | cut -d' ' -f1)

check() {
    got=$(sha256sum "$tmp/out-$1.bin" | cut -d' ' -f1)
    if [ "$got" = "$want" ]; then
        echo "OK   $1 ($(wc -c < "$tmp/ct-$1") bytes ciphertext)"
    else
        echo "FAIL $1: hash mismatch" >&2
        exit 1
    fi
}

echo "== age round trips"
age-keygen -o "$tmp/age-x.txt" 2>/dev/null
age -r "$(age-keygen -y "$tmp/age-x.txt")" -o "$tmp/ct-age-x25519" "$tmp/in.bin"
age -d -i "$tmp/age-x.txt" -o "$tmp/out-age-x25519.bin" "$tmp/ct-age-x25519"
check age-x25519

age-keygen -pq -o "$tmp/age-pq.txt" 2>/dev/null
age -r "$(age-keygen -y "$tmp/age-pq.txt")" -o "$tmp/ct-age-pq" "$tmp/in.bin"
age -d -i "$tmp/age-pq.txt" -o "$tmp/out-age-pq.bin" "$tmp/ct-age-pq"
check age-pq

echo "== gpg round trips"
gpg_mode() {
    # gpg_mode <mode-id> <homedir-name> <primary-algo> [<encryption-subkey-algo>]
    # Without a subkey algo, the primary algo string creates the whole key (future-default).
    home="$tmp/$2"
    mkdir -m 700 "$home"
    gpg --homedir "$home" --batch --pinentry-mode loopback --passphrase '' \
        --quick-gen-key "smoke-$1 <smoke-$1@test>" "$3" default never 2>/dev/null
    if [ $# -ge 4 ]; then
        fpr=$(gpg --homedir "$home" --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
        gpg --homedir "$home" --batch --pinentry-mode loopback --passphrase '' \
            --quick-add-key "$fpr" "$4" encr never 2>/dev/null
    fi
    gpg --homedir "$home" --list-keys --with-colons | grep -E '^(pub|sub):' | cut -d: -f1,4,12,17
    gpg --homedir "$home" --batch --yes --trust-model always --compress-algo none \
        -r "smoke-$1@test" -o "$tmp/ct-$1" -e "$tmp/in.bin"
    gpg --homedir "$home" --batch --yes --pinentry-mode loopback \
        -o "$tmp/out-$1.bin" -d "$tmp/ct-$1" 2>/dev/null
    check "$1"
}
# Both modes use an Ed25519 primary key, so they differ only in the encryption subkey.
# gpg-pqc uses ky768_cv25519 (ML-KEM-768 + X25519) as the proposal defines it, not the
# "pqc" shortcut, which in 2.5.22 creates brainpoolP384r1 + ky768_bp256 (see NOTES.md).
gpg_mode gpg-cv25519 gpg-x future-default
gpg_mode gpg-pqc gpg-pq ed25519 ky768_cv25519

echo "== sq round trips (interop only)"
sq_mode() {
    # sq_mode <label> <profile> <cipher-suite>
    sq --home=none key generate --own-key --name "smoke-$1" --email "smoke-$1@test" \
        --without-password --profile "$2" --cipher-suite "$3" \
        --output "$tmp/$1.key" --rev-cert "$tmp/$1.rev" 2>/dev/null
    sq --home=none key delete --cert-file "$tmp/$1.key" --output "$tmp/$1.cert" 2>/dev/null
    sq --home=none encrypt --binary --without-signature --for-file "$tmp/$1.cert" \
        --output "$tmp/ct-$1" "$tmp/in.bin"
    sq --home=none decrypt --recipient-file "$tmp/$1.key" \
        --output "$tmp/out-$1.bin" "$tmp/ct-$1" 2>/dev/null
    check "$1"
}
sq_mode sq-classical rfc4880 cv25519
sq_mode sq-pqc rfc9580 mldsa65-ed25519

echo "== gopenpgp round trips (interop only)"
gopenpgp_mode() {
    # gopenpgp_mode <label> <--classical|--pqc>
    gopenpgp-cli keygen "$2" --uid "smoke-$1 <smoke-$1@test>" \
        --out-secret "$tmp/$1.sec" --out-public "$tmp/$1.pub"
    gopenpgp-cli encrypt --recipient "$tmp/$1.pub" --in "$tmp/in.bin" --out "$tmp/ct-$1"
    gopenpgp-cli decrypt --key "$tmp/$1.sec" --in "$tmp/ct-$1" --out "$tmp/out-$1.bin"
    check "$1"
}
gopenpgp_mode gopenpgp-classical --classical
gopenpgp_mode gopenpgp-pqc --pqc

echo "== smoke test passed"
