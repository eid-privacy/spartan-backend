#!/bin/bash -e
#
# Profile a Spartan proof with samply and open the flamegraph in the browser.
#
# Usage: ./scripts/samply.sh <circuit-match> [samply record args...]
#
#   <circuit-match>  Partial (substring) match of a circuit directory name under
#                    ./circuits, e.g. "06" -> circuits/c0006_sha256.
#
# Example:
#   ./scripts/samply.sh 06
#   ./scripts/samply.sh sha256 -r 2000     # extra args are passed to `samply record`
#
# The recorded profile is written to scripts/samply/<circuit>.json.gz and the
# Firefox Profiler UI (which includes the flamegraph view) is opened in the
# browser automatically.

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
ROOT="$(dirname "$DIR")"
CIRCUITS_DIR="$ROOT/circuits"
SPARTAN_DIR="$ROOT/spartan-backend"
OUT_DIR="$DIR/samply"

if [ -z "$1" ]; then
    echo "Usage: $0 <circuit-match> [samply record args...]" >&2
    echo "Example: $0 06" >&2
    exit 1
fi

MATCH="$1"
shift

# Resolve the circuit directory from the partial match.
# (Avoid `mapfile`, which macOS's bash 3.2 does not provide.)
MATCHES=()
while IFS= read -r line; do
    [ -n "$line" ] && MATCHES+=("$line")
done < <(cd "$CIRCUITS_DIR" && ls -d */ 2>/dev/null | sed 's#/$##' | grep -- "$MATCH" || true)

if [ "${#MATCHES[@]}" -eq 0 ]; then
    echo "No circuit under $CIRCUITS_DIR matches '$MATCH'." >&2
    echo "Available circuits:" >&2
    (cd "$CIRCUITS_DIR" && ls -d */ | sed 's#/$#  #' | tr -d '\n'; echo) >&2
    exit 1
elif [ "${#MATCHES[@]}" -gt 1 ]; then
    echo "'$MATCH' is ambiguous, it matches multiple circuits:" >&2
    printf '  %s\n' "${MATCHES[@]}" >&2
    exit 1
fi

CIRCUIT="${MATCHES[0]}"
CIRCUIT_DIR="$CIRCUITS_DIR/$CIRCUIT"
echo "Profiling circuit: $CIRCUIT ($CIRCUIT_DIR)"

if [ ! -f "$CIRCUIT_DIR/verifier_input.json" ] || [ -z "$(ls "$CIRCUIT_DIR"/target/*.gz 2>/dev/null)" ]; then
    echo "Circuit '$CIRCUIT' is not ready: it needs target/*.gz (witness) and verifier_input.json." >&2
    echo "Compile/execute it first, e.g.: (cd '$CIRCUIT_DIR' && nargo-t256 compile --force && nargo-t256 execute --force)" >&2
    exit 1
fi

# Build with the `profiling` profile: release optimizations + debug symbols.
echo "Building spartan-backend (profiling profile)..."
( cd "$SPARTAN_DIR" && cargo build --profile profiling )

BIN="$SPARTAN_DIR/target/profiling/spartan-backend"
if [ ! -x "$BIN" ]; then
    echo "Expected binary not found at $BIN" >&2
    exit 1
fi

mkdir -p "$OUT_DIR"
PROFILE="$OUT_DIR/$CIRCUIT.json.gz"

echo "Recording profile with samply -> $PROFILE"
# `samply record` records the run, saves the profile, then opens the Firefox
# Profiler UI in the browser (which provides the flamegraph / call-tree views).
samply record \
    --profile-name "$CIRCUIT" \
    -o "$PROFILE" \
    "$@" \
    -- "$BIN" -v "$CIRCUIT_DIR"
