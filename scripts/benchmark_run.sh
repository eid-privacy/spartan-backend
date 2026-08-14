#!/bin/bash
#
# Measurement payload for scripts/benchmark_commits.sh. Runs *inside* `devbox run`,
# invoked once per commit with absolute paths, so it does not care about cwd.
# Writes one CSV per requested leg into --results; never deletes existing results.
#
# Usage:
#   benchmark_run.sh --checkout <dir> --results <dir> --legs <noir,spartan>
#       --noir-circuit <name> --spartan-circuit <name> --sha <short> --full-sha <full>
#       --noir-label <text> --spartan-label <text> --runs <n>
#
# Bash 3.2 safe: parallel indexed arrays only, no mapfile/declare -A/${var^^}.

CHECKOUT=""
RESULTS=""
LEGS=""
NOIR_CIRCUIT=""
SPARTAN_CIRCUIT=""
SHA=""
FULL_SHA=""
NOIR_LABEL=""
SPARTAN_LABEL=""
RUNS=5

while [ "$#" -gt 0 ]; do
    case "$1" in
        --checkout)        CHECKOUT="$2"; shift 2 ;;
        --results)         RESULTS="$2"; shift 2 ;;
        --legs)            LEGS="$2"; shift 2 ;;
        --noir-circuit)    NOIR_CIRCUIT="$2"; shift 2 ;;
        --spartan-circuit) SPARTAN_CIRCUIT="$2"; shift 2 ;;
        --sha)             SHA="$2"; shift 2 ;;
        --full-sha)        FULL_SHA="$2"; shift 2 ;;
        --noir-label)      NOIR_LABEL="$2"; shift 2 ;;
        --spartan-label)   SPARTAN_LABEL="$2"; shift 2 ;;
        --runs)            RUNS="$2"; shift 2 ;;
        *)
            echo "ERROR: unknown argument '$1'" >&2
            exit 1
            ;;
    esac
done

for req in CHECKOUT RESULTS LEGS SHA FULL_SHA RUNS; do
    eval "val=\"\$$req\""
    if [ -z "$val" ]; then
        echo "ERROR: --$(echo "$req" | tr 'A-Z_' 'a-z-') is required" >&2
        exit 1
    fi
done

RUN_NOIR=0
RUN_SPARTAN=0
IFS=',' read -r -a LEG_LIST <<< "$LEGS"
for leg in "${LEG_LIST[@]}"; do
    case "$leg" in
        noir)    RUN_NOIR=1 ;;
        spartan) RUN_SPARTAN=1 ;;
    esac
done

if [ "$RUN_NOIR" -eq 1 ] && [ -z "$NOIR_CIRCUIT" ]; then
    echo "ERROR: --noir-circuit is required when running the noir leg" >&2
    exit 1
fi
if [ "$RUN_SPARTAN" -eq 1 ] && [ -z "$SPARTAN_CIRCUIT" ]; then
    echo "ERROR: --spartan-circuit is required when running the spartan leg" >&2
    exit 1
fi

# --- helpers ------------------------------------------------------------------

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

# Run a command $RUNS times using the bash builtin `time` (GNU time is not
# available on all pinned toolchains). Echoes space-separated elapsed seconds,
# or returns non-zero if any run of the command itself fails. On failure, the
# command's own stdout/stderr (otherwise discarded) is dumped to stderr so the
# caller sees why it aborted, not just which step it aborted at.
time_n() {
    local i elapsed rc results=() cmdout
    cmdout=$(mktemp)
    for i in $(seq 1 "$RUNS"); do
        TIMEFORMAT='%3R'
        elapsed=$( { time "$@" >"$cmdout" 2>&1; } 2>&1 )
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "--- output of failed command (run $i/$RUNS): $* ---" >&2
            cat "$cmdout" >&2
            rm -f "$cmdout"
            return 1
        fi
        results+=("$elapsed")
    done
    rm -f "$cmdout"
    echo "${results[@]}"
}

# stats_row <metric> <v1> <v2> ... -> "metric,min,max,mean,stddev,v1;v2;..."
stats_row() {
    local metric="$1"
    shift
    printf '%s\n' "$@" | awk -v metric="$metric" '
    { vals[NR] = $1 }
    END {
        n = NR; min = vals[1]; max = vals[1]; sum = 0; raw = vals[1]
        for (i = 1; i <= n; i++) {
            v = vals[i]
            sum += v
            if (v < min) min = v
            if (v > max) max = v
            if (i > 1) raw = raw ";" v
        }
        mean = sum / n; sq = 0
        for (i = 1; i <= n; i++) sq += (vals[i] - mean) ^ 2
        stddev = (n > 1) ? sqrt(sq / n) : 0
        printf "%s,%.3f,%.3f,%.3f,%.3f,%s\n", metric, min, max, mean, stddev, raw
    }'
}

extract_pins() {
    local devbox_json="$1" noir_pin bb_pin t256_pin
    noir_pin=$(grep -oE 'noir-versions\.[A-Za-z0-9_.-]+' "$devbox_json" 2>/dev/null | head -1 | sed 's/^noir-versions\.//')
    bb_pin=$(grep -oE 'barretenberg-versions\.[A-Za-z0-9_.-]+' "$devbox_json" 2>/dev/null | head -1 | sed 's/^barretenberg-versions\.//')
    t256_pin=$(grep -oE 'nargo-t256-versions\.[A-Za-z0-9_.-]+' "$devbox_json" 2>/dev/null | head -1 | sed 's/^nargo-t256-versions\.//')
    echo "noir:${noir_pin:-unknown} bb:${bb_pin:-unknown} t256:${t256_pin:-unknown}"
}

write_csv_header() {
    local leg="$1" label="$2" circuit="$3"
    printf '# leg=%s commit=%s full=%s label=%s circuit=%s\n' "$leg" "$SHA" "$FULL_SHA" "$label" "$circuit"
    printf '# runs=%s date=%s host=%s os=%s\n' "$RUNS" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(uname -n)" "$(uname -sm)"
    printf '# pins=%s\n' "$(extract_pins "$CHECKOUT/devbox.json")"
    echo "metric,min,max,mean,stddev,samples"
}

# --- noir leg -------------------------------------------------------------

noir_leg() {
    local circuit_dir="$CHECKOUT/circuits/$NOIR_CIRCUIT"
    if [ ! -d "$circuit_dir" ]; then
        echo "WARNING: commit $SHA noir leg failed: circuits/$NOIR_CIRCUIT not found" >&2
        return 1
    fi

    local tmp
    tmp=$(mktemp -d)

    if ! ( cd "$circuit_dir" && nargo compile --force ); then
        echo "WARNING: commit $SHA noir leg failed at nargo compile" >&2
        rm -rf "$tmp"
        return 1
    fi
    if ! ( cd "$circuit_dir" && nargo execute --force ); then
        echo "WARNING: commit $SHA noir leg failed at nargo execute" >&2
        rm -rf "$tmp"
        return 1
    fi

    local bytecode="$circuit_dir/target/$NOIR_CIRCUIT.json"
    local witness="$circuit_dir/target/$NOIR_CIRCUIT.gz"
    local wvk prove verify

    wvk=$( cd "$circuit_dir" && time_n bb write_vk -b "$bytecode" -o "$tmp" )
    if [ $? -ne 0 ]; then
        echo "WARNING: commit $SHA noir leg failed at bb write_vk" >&2
        rm -rf "$tmp"
        return 1
    fi
    prove=$( cd "$circuit_dir" && time_n bb prove -b "$bytecode" -w "$witness" -k "$tmp/vk" -o "$tmp" )
    if [ $? -ne 0 ]; then
        echo "WARNING: commit $SHA noir leg failed at bb prove" >&2
        rm -rf "$tmp"
        return 1
    fi
    verify=$( cd "$circuit_dir" && time_n bb verify -p "$tmp/proof" -k "$tmp/vk" -i "$tmp/public_inputs" )
    if [ $? -ne 0 ]; then
        echo "WARNING: commit $SHA noir leg failed at bb verify" >&2
        rm -rf "$tmp"
        return 1
    fi

    local proof_size gates_out gates
    proof_size=$(wc -c < "$tmp/proof" | tr -d ' ')
    gates_out=$( ( cd "$circuit_dir" && bb gates -b "$bytecode" ) 2>/dev/null )
    gates=$(echo "$gates_out" | grep -oE 'circuit_size[^0-9]*[0-9]+' | head -1 | grep -oE '[0-9]+$')

    local out
    out=$(mktemp "$RESULTS/.tmp.XXXXXX")
    {
        write_csv_header "noir" "$NOIR_LABEL" "$NOIR_CIRCUIT"
        stats_row bb_write_vk $wvk
        stats_row bb_prove $prove
        stats_row bb_verify $verify
        stats_row bb_proof_size "$proof_size"
        if [ -n "$gates" ]; then
            stats_row bb_gates "$gates"
        else
            echo "NOTE: no bb_gates for $SHA (bb gates parse failed)" >&2
        fi
    } > "$out"
    mv "$out" "$RESULTS/noir-$SHA.csv"
    rm -rf "$tmp"
    return 0
}

# --- spartan leg ------------------------------------------------------------

spartan_leg() {
    local circuit_dir="$CHECKOUT/circuits/$SPARTAN_CIRCUIT"
    local spartan_dir="$CHECKOUT/spartan-backend"
    if [ ! -d "$circuit_dir" ]; then
        echo "WARNING: commit $SHA spartan leg failed: circuits/$SPARTAN_CIRCUIT not found" >&2
        return 1
    fi

    if ! ( cd "$circuit_dir" && nargo-t256 compile --force && nargo-t256 execute --force ); then
        echo "WARNING: commit $SHA spartan leg failed at nargo-t256 compile/execute" >&2
        return 1
    fi
    if ! ( cd "$spartan_dir" && NO_COLOR=1 cargo build --release ); then
        echo "WARNING: commit $SHA spartan leg failed at cargo build --release" >&2
        return 1
    fi

    local i output normalized proof_busy verify_busy rc
    local proof_times=() verify_times=()
    for i in $(seq 1 "$RUNS"); do
        output=$( cd "$spartan_dir" && NO_COLOR=1 cargo run --release -- -v "$circuit_dir" 2>&1 )
        rc=$?
        if [ "$rc" -ne 0 ]; then
            echo "WARNING: commit $SHA spartan leg failed at cargo run -v (run $i)" >&2
            echo "--- output of failed command ---" >&2
            echo "$output" >&2
            return 1
        fi
        normalized=$(echo "$output" | sed 's/µs/us/g')
        proof_busy=$(echo "$normalized" | grep 'proof_creation: spartan_backend: close' | grep -oE 'time\.busy=[^ ]+' | sed 's/time\.busy=//')
        verify_busy=$(echo "$normalized" | grep 'verification: spartan_backend: close' | grep -oE 'time\.busy=[^ ]+' | sed 's/time\.busy=//')
        if [ -z "$proof_busy" ] || [ -z "$verify_busy" ]; then
            echo "WARNING: commit $SHA spartan leg failed to parse timing output (run $i)" >&2
            echo "--- output of command ---" >&2
            echo "$output" >&2
            return 1
        fi
        proof_times+=("$(to_seconds "$proof_busy")")
        verify_times+=("$(to_seconds "$verify_busy")")
    done

    local cons_out constraints size_out proof_size
    cons_out=$( ( cd "$spartan_dir" && NO_COLOR=1 cargo run --release -- -c "$circuit_dir" ) 2>&1 ) || cons_out=""
    constraints=$(echo "$cons_out" | grep -oE 'constraints=[0-9]+' | head -1 | sed 's/constraints=//')
    size_out=$( ( cd "$spartan_dir" && NO_COLOR=1 cargo run --release -- -s "$circuit_dir" ) 2>&1 ) || size_out=""
    proof_size=$(echo "$size_out" | grep -oE 'proof_size=[0-9]+' | head -1 | sed 's/proof_size=//')
    [ -n "$constraints" ] || echo "NOTE: no constraint count for $SHA (flag unsupported?)" >&2
    [ -n "$proof_size" ] || echo "NOTE: no proof size for $SHA (flag unsupported?)" >&2

    local out
    out=$(mktemp "$RESULTS/.tmp.XXXXXX")
    {
        write_csv_header "spartan" "$SPARTAN_LABEL" "$SPARTAN_CIRCUIT"
        stats_row spartan_proof "${proof_times[@]}"
        stats_row spartan_verify "${verify_times[@]}"
        [ -n "$constraints" ] && stats_row spartan_constraints "$constraints"
        [ -n "$proof_size" ] && stats_row spartan_proof_size "$proof_size"
    } > "$out"
    mv "$out" "$RESULTS/spartan-$SHA.csv"
    return 0
}

# --- dispatch -----------------------------------------------------------------

OVERALL_RC=0
if [ "$RUN_NOIR" -eq 1 ]; then
    noir_leg || OVERALL_RC=1
fi
if [ "$RUN_SPARTAN" -eq 1 ]; then
    spartan_leg || OVERALL_RC=1
fi

exit "$OVERALL_RC"
