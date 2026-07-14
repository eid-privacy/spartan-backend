#!/bin/bash -e
#
# Benchmark a single (non-parametric) circuit across a set of commits.
#
# Usage:
#   scripts/benchmark_commits.sh <circuit_code> [--barretenberg <bb_circuit_code>] [--commits <c1[,c2[,...]]>]
#   scripts/benchmark_commits.sh c0101_signature_pok_zkattest_style --barretenberg c0000_trivial --commits 8c257bb,16df669
#
# <circuit_code> (the sole positional argument) names BOTH the benchmarks/ output
# directory and the circuits/ directory holding the spartan circuit to benchmark.
#
# Barretenberg cannot process the t256-only spartan circuits, so it is benchmarked
# on a SEPARATE, standard-field circuit given via --barretenberg <bb_circuit_code>;
# the spartan proof/verify is benchmarked on <circuit_code>. Omit --barretenberg to
# skip the Barretenberg measurement entirely.
#
# For each commit it checks out a throwaway git worktree (in a mktemp dir, so the
# main working tree is never touched), builds spartan-backend there and times the
# proof/verification of <circuit_code> as committed at that commit. Barretenberg
# (write_vk/prove/verify) depends only on the circuit and not on the spartan-backend
# code, so it is run ONCE (on <bb_circuit_code>, from the CURRENT working tree — not
# any benchmarked commit).
#
# Results are written to benchmarks/<circuit_code>/, one CSV per run, named with a
# two-digit index so a plain lexical sort reflects git history (oldest first):
#   stats-00-barretenberg.csv   write_vk, prove, verify        (run once, bb circuit)
#   stats-01-<sha>.csv          spartan_proof, spartan_verify  (oldest commit)
#   stats-02-<sha>.csv          spartan_proof, spartan_verify
#   ...
# Each file has the schema: metric,min,max,mean,stddev

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
REPO_ROOT="$(git -C "$DIR" rev-parse --show-toplevel)"

N=5  # Number of times each benchmark is run; stats are computed over all N runs

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <circuit_code> [--barretenberg <bb_circuit_code>] [--commits <c1[,c2[,...]]>]" >&2
    exit 1
fi

CIRCUIT="$1"
shift

BB_CIRCUIT=""
COMMITS=()
while [ "$#" -gt 0 ]; do
    case "$1" in
        --barretenberg)
            [ -n "$2" ] || { echo "ERROR: --barretenberg requires a circuit name" >&2; exit 1; }
            BB_CIRCUIT="$2"
            shift 2
            ;;
        --commits)
            [ -n "$2" ] || { echo "ERROR: --commits requires a comma-separated commit list" >&2; exit 1; }
            IFS=',' read -r -a _commits <<< "$2"
            COMMITS+=("${_commits[@]}")
            shift 2
            ;;
        *)
            echo "ERROR: unknown argument '$1'" >&2
            echo "Usage: $0 <circuit_code> [--barretenberg <bb_circuit_code>] [--commits <c1[,c2[,...]]>]" >&2
            exit 1
            ;;
    esac
done
[ "${#COMMITS[@]}" -eq 0 ] && COMMITS=("HEAD")

OUT_DIR="$REPO_ROOT/benchmarks/$CIRCUIT"
mkdir -p "$OUT_DIR"

# Point cargo at a single shared target directory (the main working tree's
# spartan-backend/target) so each benchmarked commit reuses previously compiled
# dependencies instead of rebuilding from scratch in its throwaway worktree.
# Only the changed spartan-backend crate itself is recompiled per commit.
export CARGO_TARGET_DIR="$REPO_ROOT/spartan-backend/target"

if [ -n "$DEVBOX_PACKAGES_DIR" ]; then
    TIME_BIN="$DEVBOX_PACKAGES_DIR/bin/time"
else
    TIME_BIN="$(which time)"
fi

to_seconds() {
    local val="$1"
    local num=$(echo "$val" | sed 's/[a-zA-Z]*$//')
    local unit=$(echo "$val" | sed 's/^[0-9.]*//')
    case "$unit" in
        s)   awk "BEGIN {printf \"%.3f\n\", $num}" ;;
        ms)  awk "BEGIN {printf \"%.3f\n\", $num / 1000}" ;;
        us)  awk "BEGIN {printf \"%.3f\n\", $num / 1000000}" ;;
        ns)  awk "BEGIN {printf \"%.3f\n\", $num / 1000000000}" ;;
    esac
}

# Run a command N times; stdout is suppressed, stderr passes through.
# Prints space-separated elapsed times in seconds.
time_n() {
    local tmp results=()
    tmp=$(mktemp)
    for i in $(seq 1 "$N"); do
        $TIME_BIN -f '%e' -o "$tmp" "$@" > /dev/null
        results+=("$(cat "$tmp")")
    done
    rm -f "$tmp"
    echo "${results[@]}"
}

# Compute "min,max,mean,stddev" from space-separated float values.
# Stddev uses the population formula (n denominator).
stats_csv() {
    echo "$@" | tr ' ' '\n' | awk '
    NR==1 { min=$1; max=$1 }
    { sum+=$1; vals[NR]=$1; if($1<min) min=$1; if($1>max) max=$1 }
    END {
        n=NR; mean=sum/n; sq=0
        for(i=1;i<=n;i++) sq+=(vals[i]-mean)^2
        stddev=(n>1) ? sqrt(sq/n) : 0
        printf "%.3f,%.3f,%.3f,%.3f", min, max, mean, stddev
    }'
}

# --- worktree management ------------------------------------------------------
# All created worktrees are tracked and removed on exit so a failure mid-run never
# leaves a dangling worktree behind.
WORKTREES=()
BB_TMP=""  # temp dir for Barretenberg proof artifacts (see run_barretenberg)

cleanup() {
    for wt in "${WORKTREES[@]}"; do
        git -C "$REPO_ROOT" worktree remove --force "$wt" 2>/dev/null || true
        rm -rf "$(dirname "$wt")"
    done
    [ -n "$BB_TMP" ] && rm -rf "$BB_TMP" || true
}
trap cleanup EXIT

# Create a detached worktree for a commit in a fresh temp dir; echoes its path.
# NOTE: callers must add the returned path to WORKTREES themselves — this runs in
# a command-substitution subshell, so appending to WORKTREES here would not reach
# the parent shell and the worktree would never be cleaned up.
mk_worktree() {
    local commit="$1" tmp wt
    tmp=$(mktemp -d)
    wt="$tmp/wt"
    git -C "$REPO_ROOT" worktree add --detach "$wt" "$commit" >&2
    echo "$wt"
}

# --- order commits oldest -> newest by git history (topological) --------------
# Committer timestamps can be identical (e.g. after a rebase), so sort by ancestry
# instead: walk the requested commits + ancestors in reverse-topo (oldest-first)
# order and keep only the requested ones, preserving that order. Filenames use
# short shas. (Avoid `mapfile`; /bin/bash on macOS is 3.2 and lacks it.)
REQUESTED_FULL="$(for c in "${COMMITS[@]}"; do git -C "$REPO_ROOT" rev-parse "$c"; done)"
ORDERED=()
while IFS= read -r sha; do
    [ -n "$sha" ] && ORDERED+=("$(git -C "$REPO_ROOT" rev-parse --short "$sha")")
done < <(
    git -C "$REPO_ROOT" rev-list --topo-order --reverse "${COMMITS[@]}" \
        | grep -Fxf <(printf '%s\n' "$REQUESTED_FULL")
)

echo "Spartan circuit:      $CIRCUIT"
echo "Barretenberg circuit: ${BB_CIRCUIT:-<none>}"
echo "Commits (oldest first): ${ORDERED[*]}"
echo "Output:    $OUT_DIR"
echo

# --- Create the oldest commit's worktree (reused by the spartan loop below) ---
FIRST_WT="$(mk_worktree "${ORDERED[0]}")"
WORKTREES+=("$FIRST_WT")

if [ ! -d "$FIRST_WT/circuits/$CIRCUIT" ]; then
    echo "ERROR: circuits/$CIRCUIT not found at commit ${ORDERED[0]}" >&2
    exit 1
fi

# --- Barretenberg: run ONCE, on $BB_CIRCUIT from the CURRENT working tree ------
# Barretenberg only handles the standard field and cannot process the t256-only
# spartan circuits, so it runs on its own circuit ($BB_CIRCUIT). Its timings do not
# depend on the spartan-backend code, so it uses the current checked-out repo rather
# than any benchmarked commit. Still best-effort: run it inside a function invoked as
# an `if` condition, which disables `set -e` for its body, and skip gracefully on any
# failure (e.g. if $BB_CIRCUIT is also t256). The proof artifacts go to a temp dir so
# the working tree is not littered with a proof/ directory.
#
# `nargo execute --force` is needed to regenerate a valid witness from the circuit's
# Prover.toml — the committed target/*.gz is a placeholder that does not verify. We
# compile in place (in the working tree) so relative-path deps like `../eid` still
# resolve, then restore the tracked target/ afterward so the tree stays clean — but
# only if it was clean to begin with, so we never clobber uncommitted changes.
run_barretenberg() {
    local circuit_dir="$REPO_ROOT/circuits/$BB_CIRCUIT"
    local target="$circuit_dir/target"
    local bytecode="$target/$BB_CIRCUIT.json"
    local witness="$target/$BB_CIRCUIT.gz"
    BB_TMP="$(mktemp -d)"
    local proof="$BB_TMP/proof"

    local dirty_before wvk prove verify rc=0
    dirty_before="$(git -C "$REPO_ROOT" status --porcelain -- "circuits/$BB_CIRCUIT/target")"

    if ( cd "$circuit_dir" && nargo execute --force ); then
        echo "Writing verifier key ($N runs)"
        wvk=$(time_n bb write_vk -b "$bytecode" -o "$proof") || rc=1
        if [ "$rc" -eq 0 ]; then
            echo "Creating proof ($N runs)"
            prove=$(time_n bb prove -b "$bytecode" -w "$witness" -k "$proof/vk" -o "$proof") || rc=1
        fi
        if [ "$rc" -eq 0 ]; then
            echo "Verifying proof ($N runs)"
            verify=$(time_n bb verify -p "$proof/proof" -k "$proof/vk" -i "$proof/public_inputs") || rc=1
        fi
    else
        rc=1
    fi

    # Restore the working tree's target/ to its committed state if it started clean.
    if [ -z "$dirty_before" ]; then
        git -C "$REPO_ROOT" checkout -- "circuits/$BB_CIRCUIT/target" 2>/dev/null || true
        git -C "$REPO_ROOT" clean -fdq -- "circuits/$BB_CIRCUIT/target" 2>/dev/null || true
    else
        echo "NOTE: circuits/$BB_CIRCUIT/target had uncommitted changes; left as-is after recompile." >&2
    fi

    [ "$rc" -eq 0 ] || return 1

    local csv="$OUT_DIR/stats-00-barretenberg.csv"
    {
        echo "metric,min,max,mean,stddev"
        echo "write_vk,$(stats_csv "$wvk")"
        echo "prove,$(stats_csv "$prove")"
        echo "verify,$(stats_csv "$verify")"
    } > "$csv"
    echo "--- $csv ---"
    cat "$csv"
}

if [ -n "$BB_CIRCUIT" ]; then
    echo "=== Barretenberg on $BB_CIRCUIT (once, from current working tree) ==="
    if run_barretenberg; then
        :
    else
        echo "NOTE: skipping Barretenberg for '$BB_CIRCUIT' (not compatible with standard nargo / bb)." >&2
    fi
    echo
fi

# --- Spartan: per commit ------------------------------------------------------
NCOMMITS="${#ORDERED[@]}"
idx=0
for commit in "${ORDERED[@]}"; do
    idx=$(( idx + 1 ))
    SHA="$commit"

    # Reuse the worktree already created for Barretenberg for the oldest commit.
    if [ "$idx" -eq 1 ]; then
        WT="$FIRST_WT"
    else
        WT="$(mk_worktree "$commit")"
        WORKTREES+=("$WT")
    fi

    OUT_CSV="$OUT_DIR/stats-$(printf '%02d' "$idx")-${SHA}.csv"
    echo "=== commit $idx / $NCOMMITS: $SHA -> $(basename "$OUT_CSV") ==="

    if [ ! -d "$WT/circuits/$CIRCUIT" ]; then
        echo "WARNING: circuits/$CIRCUIT absent at $SHA, skipping" >&2
        continue
    fi

    CIRCUIT_DIR="$WT/circuits/$CIRCUIT"
    SPARTAN_DIR="$WT/spartan-backend"

    echo "[commit $idx / $NCOMMITS] stage: compilation"
    ( cd "$CIRCUIT_DIR" && nargo-t256 compile --force && nargo-t256 execute --force )

    echo "[commit $idx / $NCOMMITS] stage: compile (cargo build --release)"
    ( cd "$SPARTAN_DIR" && NO_COLOR=1 cargo build --release )

    echo "[commit $idx / $NCOMMITS] stage: run ($N runs)"
    SPARTAN_PROOF_TIMES=()
    SPARTAN_VERIFY_TIMES=()
    for i in $(seq 1 "$N"); do
        echo "[commit $idx / $NCOMMITS] run $i / $N"
        SPARTAN_OUTPUT=$(cd "$SPARTAN_DIR" && NO_COLOR=1 cargo run --release -- -v "$CIRCUIT_DIR" 2>&1) \
            || { echo "$SPARTAN_OUTPUT"; exit $?; }
        NORMALIZED=$(echo "$SPARTAN_OUTPUT" | sed 's/µs/us/g')
        PROOF_BUSY=$(echo "$NORMALIZED" | grep 'proof_creation: spartan_backend: close' | grep -oE 'time\.busy=[^ ]+' | sed 's/time\.busy=//')
        VERIFY_BUSY=$(echo "$NORMALIZED" | grep 'verification: spartan_backend: close' | grep -oE 'time\.busy=[^ ]+' | sed 's/time\.busy=//')
        SPARTAN_PROOF_TIMES+=("$(to_seconds "$PROOF_BUSY")")
        SPARTAN_VERIFY_TIMES+=("$(to_seconds "$VERIFY_BUSY")")
    done

    # Constraint count (-c) and proof size (-s) are spartan-only and deterministic,
    # so measure each once. They only exist on commits that added the flags
    # (count-constraints since 9b86d24, proof-size since 39456cb), so parse
    # best-effort and skip a metric when its flag is missing on an older commit.
    echo "Counting constraints"
    CONS_OUT=$(cd "$SPARTAN_DIR" && NO_COLOR=1 cargo run --release -- -c "$CIRCUIT_DIR" 2>&1) || CONS_OUT=""
    CONSTRAINTS=$(echo "$CONS_OUT" | grep -oE 'constraints=[0-9]+' | head -1 | sed 's/constraints=//')
    echo "Measuring proof size"
    SIZE_OUT=$(cd "$SPARTAN_DIR" && NO_COLOR=1 cargo run --release -- -s "$CIRCUIT_DIR" 2>&1) || SIZE_OUT=""
    PROOF_SIZE=$(echo "$SIZE_OUT" | grep -oE 'proof_size=[0-9]+' | head -1 | sed 's/proof_size=//')
    [ -z "$CONSTRAINTS" ] && echo "NOTE: no constraint count for $SHA (flag unsupported?)" >&2 || true
    [ -z "$PROOF_SIZE" ] && echo "NOTE: no proof size for $SHA (flag unsupported?)" >&2 || true

    {
        echo "metric,min,max,mean,stddev"
        echo "spartan_proof,$(stats_csv "${SPARTAN_PROOF_TIMES[@]}")"
        echo "spartan_verify,$(stats_csv "${SPARTAN_VERIFY_TIMES[@]}")"
        if [ -n "$CONSTRAINTS" ]; then echo "spartan_constraints,$(stats_csv "$CONSTRAINTS")"; fi
        if [ -n "$PROOF_SIZE" ]; then echo "spartan_proof_size,$(stats_csv "$PROOF_SIZE")"; fi
    } > "$OUT_CSV"
    echo "--- $OUT_CSV ---"
    cat "$OUT_CSV"
    echo
done

echo "Done. Results in $OUT_DIR"
