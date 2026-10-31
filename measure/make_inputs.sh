#!/bin/sh
# Generate the random input files data/in_<size_id>.bin
# and record their SHA-256 in results/inputs.sha256. Runs inside the pqc-bench image.
#
# usage: sh measure/make_inputs.sh [--force]
#
# Without --force the script is idempotent: if results/inputs.sha256 exists, it only
# checks the existing inputs against it and never creates new ones, because new random
# bytes would no longer match the committed hashes. --force regenerates all four files
# and rewrites the hash file, which changes the inputs of the experiment.
set -eu

cd "$(dirname "$0")/.."

force=0
case "${1:-}" in
    "") ;;
    --force) force=1 ;;
    *) echo "usage: sh measure/make_inputs.sh [--force]" >&2; exit 2 ;;
esac

# size_id and file_bytes, smallest first.
SIZES="1KB:1024 100KB:102400 10MB:10485760 1GB:1073741824"
HASHES=results/inputs.sha256

files=""
missing=0
for s in $SIZES; do
    f="data/in_${s%%:*}.bin"
    files="$files $f"
    [ -f "$f" ] || missing=1
done

if [ "$force" -eq 0 ] && [ -f "$HASHES" ]; then
    if [ "$missing" -eq 1 ]; then
        echo "error: $HASHES exists but some inputs in data/ are missing." >&2
        echo "New random inputs would not match the committed hashes. Copy the original" >&2
        echo "data/ files here, or run with --force to regenerate all inputs." >&2
        exit 1
    fi
    if sha256sum --check --quiet --strict "$HASHES"; then
        echo "inputs present and match $HASHES"
        exit 0
    fi
    echo "error: inputs in data/ do not match $HASHES (see above)." >&2
    exit 1
fi

mkdir -p data results
for s in $SIZES; do
    id=${s%%:*}
    bytes=${s#*:}
    f="data/in_$id.bin"
    if [ "$force" -eq 0 ] && [ -f "$f" ] && [ "$(stat -c %s "$f")" -eq "$bytes" ]; then
        echo "keep     $f"
        continue
    fi
    # Write to a temporary name first, so an interrupted run never leaves a short file.
    head -c "$bytes" /dev/urandom > "$f.tmp"
    got=$(stat -c %s "$f.tmp")
    if [ "$got" -ne "$bytes" ]; then
        echo "error: $f.tmp has $got bytes, expected $bytes" >&2
        rm -f "$f.tmp"
        exit 1
    fi
    mv "$f.tmp" "$f"
    echo "created  $f ($bytes bytes)"
done

# shellcheck disable=SC2086  # $files is a space-separated list of fixed paths
sha256sum $files > "$HASHES.tmp"
mv "$HASHES.tmp" "$HASHES"
echo "wrote    $HASHES"
cat "$HASHES"
