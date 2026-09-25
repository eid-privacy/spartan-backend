#!/bin/bash
#
# Config-driven benchmark driver: measures noir/barretenberg and spartan-backend
# performance across the commit history described in a config file (see
# benchmarks/swiyu_jwt/config.yaml for an example and BENCHMARK_PLAN.md for the
# full spec). Two curves share one timeline: noir/bb across the commits that bump
# the noir/barretenberg/nargo-t256 flake pins, spartan across our own commits.
# Commits are grouped under the circuit name they were built with (`circuit:` +
# `commits:` under `noir:`/`spartan:`), so renaming a circuit directory only
# means opening a new group for future commits — old groups and their stored
# results keep referencing the name they were actually measured under.
#
# Run from a plain shell, NOT from inside `devbox shell` (nesting devbox
# environments is unsupported). This script itself has zero devbox dependency;
# it only *calls* `devbox run` inside a per-commit checkout so every commit is
# measured with its own pinned toolchain. No yq/jq/python, no devbox shellenv.
#
# A commits entry's ref is normally a git ref (hash/branch/tag). It may
# instead be the literal "commit-msg", in which case the entry's label is used
# to find the commit by searching all refs for a commit whose message has a
# line "Benchmark: <label>" — e.g. "commit-msg optimisations" resolves to
# whichever commit currently carries "Benchmark: optimisations" in its
# message. Rebasing/rewriting a commit doesn't change that message, so the
# config never needs its hash updated afterwards. If several commits carry the
# same trailer, the most recently committed one is used and a warning is
# printed listing the dates of the others.
#
# Usage:
#   scripts/benchmark_commits.sh <config.yaml> [options]
#
#     --force            re-run every leg, ignoring stored results
#     --only <ref>       run only this commit (both of its legs), ignoring stored results
#     --runs <n>         override `runs:` from the config
#     --dry-run          print the work plan and exit
#     -h | --help
#
# Bash 3.2 safe: parallel indexed arrays only, no mapfile/declare -A/${var^^}.

SCRIPT_DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

usage() {
    cat >&2 <<'EOF'
Usage: scripts/benchmark_commits.sh <config.yaml> [options]

  --force            re-run every leg, ignoring stored results
  --only <ref>       run only this commit (both of its legs), ignoring stored results
  --runs <n>         override `runs:` from the config
  --dry-run          print the work plan and exit
  -h | --help
EOF
}

if [ "$#" -eq 0 ]; then
    usage
    exit 1
fi
case "$1" in
    -h|--help) usage; exit 0 ;;
esac

CONFIG="$1"
shift

FORCE=0
ONLY_REF=""
RUNS_OVERRIDE=""
DRY_RUN=0
while [ "$#" -gt 0 ]; do
    case "$1" in
        --force)   FORCE=1; shift ;;
        --only)    ONLY_REF="$2"; shift 2 ;;
        --runs)    RUNS_OVERRIDE="$2"; shift 2 ;;
        --dry-run) DRY_RUN=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *)
            echo "ERROR: unknown argument '$1'" >&2
            usage
            exit 1
            ;;
    esac
done

[ -f "$CONFIG" ] || { echo "ERROR: config file not found: $CONFIG" >&2; exit 1; }

if [ -n "${DEVBOX_SHELL_ENABLED:-}" ]; then
    echo "WARNING: running inside a devbox shell; nested devbox environments are unsupported here." >&2
fi

# --- §3: restricted-YAML config parser ----------------------------------------

parse_error() {
    echo "$CONFIG:$1: cannot parse: $2" >&2
    exit 1
}

NAME=""
RUNS_CFG="5"
NOIR_REFS=(); NOIR_LABELS=(); NOIR_CIRCUITS=()
SPARTAN_REFS=(); SPARTAN_LABELS=(); SPARTAN_CIRCUITS=()

section=""
cur_circuit=""
in_commits=0
lineno=0
while IFS= read -r raw_line || [ -n "$raw_line" ]; do
    lineno=$(( lineno + 1 ))
    raw_line="${raw_line%$'\r'}"
    line=$(printf '%s' "$raw_line" | sed 's/[[:space:]]*#.*$//')

    [ -z "$line" ] && continue

    case "$line" in
        '      - '*)
            [ "$in_commits" -eq 1 ] && [ -n "$cur_circuit" ] || parse_error "$lineno" "$raw_line"
            text="${line#      - }"
            ref="${text%% *}"
            if [ "$ref" = "$text" ]; then
                label=""
            else
                label="${text#* }"
            fi
            case "$section" in
                noir)    NOIR_REFS+=("$ref");    NOIR_LABELS+=("$label");    NOIR_CIRCUITS+=("$cur_circuit") ;;
                spartan) SPARTAN_REFS+=("$ref"); SPARTAN_LABELS+=("$label"); SPARTAN_CIRCUITS+=("$cur_circuit") ;;
                *) parse_error "$lineno" "$raw_line" ;;
            esac
            ;;
        '    commits:'*)
            [ -n "$section" ] && [ -n "$cur_circuit" ] || parse_error "$lineno" "$raw_line"
            in_commits=1
            ;;
        '  - circuit: '*)
            [ -n "$section" ] || parse_error "$lineno" "$raw_line"
            cur_circuit="${line#  - circuit: }"
            in_commits=0
            ;;
        *)
            if [[ "$line" =~ ^(name|runs):[[:space:]]+(.+)$ ]]; then
                key="${BASH_REMATCH[1]}"
                value="${BASH_REMATCH[2]}"
                case "$key" in
                    name) NAME="$value" ;;
                    runs) RUNS_CFG="$value" ;;
                esac
                section=""
                cur_circuit=""
                in_commits=0
            elif [[ "$line" =~ ^(noir|spartan):[[:space:]]*$ ]]; then
                section="${BASH_REMATCH[1]}"
                cur_circuit=""
                in_commits=0
            else
                parse_error "$lineno" "$raw_line"
            fi
            ;;
    esac
done < "$CONFIG"

[ -n "$NAME" ]             || { echo "ERROR: $CONFIG: missing required key 'name'" >&2; exit 1; }
[ "${#NOIR_REFS[@]}" -ge 1 ] || { echo "ERROR: $CONFIG: 'noir' needs at least one circuit group with commits" >&2; exit 1; }

RUNS="${RUNS_OVERRIDE:-$RUNS_CFG}"

# --- §4 step 1: derive paths ---------------------------------------------------

BENCH_DIR="$(cd "$(dirname "$CONFIG")" && pwd)"
RESULTS_DIR="$BENCH_DIR/results"
mkdir -p "$RESULTS_DIR"
REPO_ROOT="$(git rev-parse --show-toplevel)"
CHECKOUT="$REPO_ROOT/benchmarks/checkout"

# --- §4 step 2: resolve refs ---------------------------------------------------

# resolve_ref <ref> <label> -> prints the resolved full SHA on stdout.
# A plain <ref> is passed straight to `git rev-parse`. The literal ref
# "commit-msg" instead searches all refs for the commit(s) whose message
# contains the line "Benchmark: <label>". If more than one commit matches,
# the most recently committed one is used and a warning listing the other
# matching commits' dates is printed to stderr.
resolve_ref() {
    local ref="$1" label="$2"
    if [ "$ref" != "commit-msg" ]; then
        git -C "$REPO_ROOT" rev-parse "$ref" 2>/dev/null
        return
    fi

    [ -n "$label" ] \
        || { echo "ERROR: $CONFIG: 'commit-msg' ref requires a label to search for (matched as 'Benchmark: <label>')" >&2; exit 1; }

    local escaped
    escaped=$(printf '%s' "$label" | sed -E 's/[.[\*^$(){}+?|]/\\&/g; s/\]/\\]/g')

    local hits=() ts=() disp=() sha t d
    while IFS='|' read -r sha t d; do
        [ -n "$sha" ] && { hits+=("$sha"); ts+=("$t"); disp+=("$d"); }
    done < <(git -C "$REPO_ROOT" log --all -E --grep="^Benchmark: ${escaped}\$" --format='%H|%ct|%cI')

    if [ "${#hits[@]}" -eq 0 ]; then
        echo "ERROR: $CONFIG: no commit found with message trailer 'Benchmark: $label'" >&2
        exit 1
    fi

    if [ "${#hits[@]}" -eq 1 ]; then
        printf '%s\n' "${hits[0]}"
        return
    fi

    # Multiple commits carry this trailer: take the most recently committed one
    # (by committer date) and warn, listing the dates of the ones not chosen, so
    # a stale duplicate doesn't silently win forever and the ambiguity is visible.
    local combined=() k
    for ((k = 0; k < ${#hits[@]}; k++)); do
        combined+=("${ts[$k]}|${hits[$k]}|${disp[$k]}")
    done
    local sorted
    sorted=$(printf '%s\n' "${combined[@]}" | sort -t'|' -k1,1nr)

    local chosen_sha chosen_disp
    chosen_sha=$(printf '%s\n' "$sorted" | head -n1 | cut -d'|' -f2)
    chosen_disp=$(printf '%s\n' "$sorted" | head -n1 | cut -d'|' -f3)

    echo "WARNING: $CONFIG: multiple commits found with message trailer 'Benchmark: $label'; using the most recent, $chosen_sha ($chosen_disp). Other commits with this trailer:" >&2
    printf '%s\n' "$sorted" | tail -n +2 | while IFS='|' read -r t sha d; do
        echo "  $sha ($d)" >&2
    done

    printf '%s\n' "$chosen_sha"
}

NOIR_FULL=(); NOIR_SHORT=()
for ((i = 0; i < ${#NOIR_REFS[@]}; i++)); do
    full=$(resolve_ref "${NOIR_REFS[$i]}" "${NOIR_LABELS[$i]}") \
        || { echo "ERROR: noir_commits ref '${NOIR_REFS[$i]}' does not resolve" >&2; exit 1; }
    short=$(git -C "$REPO_ROOT" rev-parse --short "$full")
    NOIR_FULL+=("$full")
    NOIR_SHORT+=("$short")
    [ -n "${NOIR_LABELS[$i]}" ] || NOIR_LABELS[$i]="$short"
done

SPARTAN_FULL=(); SPARTAN_SHORT=()
for ((i = 0; i < ${#SPARTAN_REFS[@]}; i++)); do
    full=$(resolve_ref "${SPARTAN_REFS[$i]}" "${SPARTAN_LABELS[$i]}") \
        || { echo "ERROR: spartan_commits ref '${SPARTAN_REFS[$i]}' does not resolve" >&2; exit 1; }
    short=$(git -C "$REPO_ROOT" rev-parse --short "$full")
    SPARTAN_FULL+=("$full")
    SPARTAN_SHORT+=("$short")
    [ -n "${SPARTAN_LABELS[$i]}" ] || SPARTAN_LABELS[$i]="$short"
done

ONLY_FULL=""
if [ -n "$ONLY_REF" ]; then
    ONLY_FULL=$(git -C "$REPO_ROOT" rev-parse "$ONLY_REF" 2>/dev/null) \
        || { echo "ERROR: --only ref '$ONLY_REF' does not resolve" >&2; exit 1; }
fi

# --- §4 step 3: build the ordered union (oldest first, topological) -----------

ALL_REFS=("${NOIR_FULL[@]}" "${SPARTAN_FULL[@]}")
REQUESTED_FULL="$(printf '%s\n' "${ALL_REFS[@]}" | sort -u)"
ORDERED=()
while IFS= read -r sha; do
    [ -n "$sha" ] && ORDERED+=("$sha")
done < <(git -C "$REPO_ROOT" rev-list --topo-order --reverse "${ALL_REFS[@]}" \
            | grep -Fxf <(printf '%s\n' "$REQUESTED_FULL"))

# --- §4 step 4: skip completed work / print the plan ---------------------------

EXEC_SHA=(); EXEC_SHORT=(); EXEC_LEGS=(); EXEC_NOIR_LABEL=(); EXEC_SPARTAN_LABEL=()
EXEC_NOIR_CIRCUIT=(); EXEC_SPARTAN_CIRCUIT=()
COMMITS_TOTAL="${#ORDERED[@]}"
LEGS_TOTAL=0
LEGS_SKIPPED=0

echo "benchmark $NAME: parsing plan..."
PLAN_LINES=()

for sha in "${ORDERED[@]}"; do
    short=$(git -C "$REPO_ROOT" rev-parse --short "$sha")

    is_noir=0; noir_label=""; noir_circuit=""
    for ((i = 0; i < ${#NOIR_FULL[@]}; i++)); do
        if [ "${NOIR_FULL[$i]}" = "$sha" ]; then
            is_noir=1
            noir_label="${NOIR_LABELS[$i]}"
            noir_circuit="${NOIR_CIRCUITS[$i]}"
            break
        fi
    done

    is_spartan=0; spartan_label=""; spartan_circuit=""
    for ((i = 0; i < ${#SPARTAN_FULL[@]}; i++)); do
        if [ "${SPARTAN_FULL[$i]}" = "$sha" ]; then
            is_spartan=1
            spartan_label="${SPARTAN_LABELS[$i]}"
            spartan_circuit="${SPARTAN_CIRCUITS[$i]}"
            break
        fi
    done

    legs_needed=""
    run_legs=""
    skip_legs=""
    legs_display=""

    # When --only is given, every commit other than the requested one is entirely
    # out of scope for this invocation, regardless of whether its results exist yet.
    in_scope=1
    if [ -n "$ONLY_FULL" ] && [ "$ONLY_FULL" != "$sha" ]; then
        in_scope=0
    fi

    force_this=0
    if [ "$in_scope" -eq 1 ] && { [ "$FORCE" -eq 1 ] || [ -n "$ONLY_FULL" ]; }; then
        force_this=1
    fi

    if [ "$is_noir" -eq 1 ]; then
        legs_display="noir"
        LEGS_TOTAL=$(( LEGS_TOTAL + 1 ))
        file="$RESULTS_DIR/noir-$short.csv"
        if [ "$in_scope" -eq 0 ]; then
            skip_legs="noir"
        elif [ -f "$file" ] && [ "$force_this" -eq 0 ]; then
            LEGS_SKIPPED=$(( LEGS_SKIPPED + 1 ))
            skip_legs="noir"
        else
            legs_needed="noir"
            run_legs="noir"
        fi
    fi

    if [ "$is_spartan" -eq 1 ]; then
        [ -n "$legs_display" ] && legs_display="$legs_display, spartan" || legs_display="spartan"
        LEGS_TOTAL=$(( LEGS_TOTAL + 1 ))
        file="$RESULTS_DIR/spartan-$short.csv"
        if [ "$in_scope" -eq 0 ]; then
            [ -n "$skip_legs" ] && skip_legs="$skip_legs, spartan" || skip_legs="spartan"
        elif [ -f "$file" ] && [ "$force_this" -eq 0 ]; then
            LEGS_SKIPPED=$(( LEGS_SKIPPED + 1 ))
            [ -n "$skip_legs" ] && skip_legs="$skip_legs, spartan" || skip_legs="spartan"
        else
            [ -n "$legs_needed" ] && legs_needed="$legs_needed,spartan" || legs_needed="spartan"
            [ -n "$run_legs" ] && run_legs="$run_legs, spartan" || run_legs="spartan"
        fi
    fi

    if [ -z "$run_legs" ]; then
        if [ "$in_scope" -eq 0 ]; then
            status="skip: not selected (--only)"
        else
            both="both"
            [ "$is_noir" -eq 1 ] && [ "$is_spartan" -eq 1 ] || both="present"
            status="skip: $([ "$both" = "both" ] && echo "both present" || echo "present")"
        fi
    elif [ -z "$skip_legs" ]; then
        status="run"
    else
        status="run $run_legs; $skip_legs present"
    fi

    label="$noir_label"
    if [ "$is_noir" -eq 1 ] && [ "$is_spartan" -eq 1 ] && [ "$noir_label" != "$spartan_label" ]; then
        label="$noir_label / $spartan_label"
    elif [ "$is_noir" -eq 0 ]; then
        label="$spartan_label"
    fi

    PLAN_LINES+=("$(printf '  %-10s %-14s legs: %-16s (%s)' "$short" "$label" "$legs_display" "$status")")

    if [ -n "$legs_needed" ]; then
        EXEC_SHA+=("$sha")
        EXEC_SHORT+=("$short")
        EXEC_LEGS+=("$legs_needed")
        EXEC_NOIR_LABEL+=("$noir_label")
        EXEC_SPARTAN_LABEL+=("$spartan_label")
        EXEC_NOIR_CIRCUIT+=("$noir_circuit")
        EXEC_SPARTAN_CIRCUIT+=("$spartan_circuit")
    fi
done

echo "benchmark $NAME: $COMMITS_TOTAL commits in config, $LEGS_TOTAL legs total, $LEGS_SKIPPED already measured"
for line in "${PLAN_LINES[@]}"; do
    echo "$line"
done

if [ "$DRY_RUN" -eq 1 ]; then
    exit 0
fi

# --- §4 step 5: per commit — one checkout, one devbox invocation --------------

TOTAL_EXEC="${#EXEC_SHA[@]}"
for ((idx = 0; idx < TOTAL_EXEC; idx++)); do
    sha="${EXEC_SHA[$idx]}"
    short="${EXEC_SHORT[$idx]}"
    legs_csv="${EXEC_LEGS[$idx]}"
    noir_label="${EXEC_NOIR_LABEL[$idx]}"
    spartan_label="${EXEC_SPARTAN_LABEL[$idx]}"
    noir_circuit="${EXEC_NOIR_CIRCUIT[$idx]}"
    spartan_circuit="${EXEC_SPARTAN_CIRCUIT[$idx]}"

    echo
    echo "=== commit $(( idx + 1 )) / $TOTAL_EXEC: $short (legs: $legs_csv) ==="

    [ -d "$CHECKOUT" ] || git -C "$REPO_ROOT" worktree add --detach "$CHECKOUT" "$sha"

    if ! git -C "$CHECKOUT" checkout --detach --force "$sha"; then
        echo "WARNING: commit $short failed, continuing" >&2
        continue
    fi
    git -C "$CHECKOUT" clean -xdff -e /.devbox -e /spartan-backend/target

    export CARGO_TARGET_DIR="$CHECKOUT/spartan-backend/target"

    if ! ( cd "$CHECKOUT" && devbox run --quiet -- \
            bash "$SCRIPT_DIR/benchmark_run.sh" \
                --checkout        "$CHECKOUT" \
                --results         "$RESULTS_DIR" \
                --legs            "$legs_csv" \
                --noir-circuit    "$noir_circuit" \
                --spartan-circuit "$spartan_circuit" \
                --sha             "$short" \
                --full-sha        "$sha" \
                --noir-label      "$noir_label" \
                --spartan-label   "$spartan_label" \
                --runs            "$RUNS" ); then
        echo "WARNING: commit $short failed, continuing" >&2
    fi
done

echo
echo "Done. Results in $BENCH_DIR/results/"
echo "Plot with: devbox run plot-commits $CONFIG"
