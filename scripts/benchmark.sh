#!/bin/bash -e

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

N=5  # Number of times each benchmark is run; stats are computed over all N runs

STEPS_INPUT_SIZES="10 100 1000 10000 100000"
#STEPS_ASSERTS="10 100 1000 10000 100000"
#STEPS_INPUT_SIZES="10000 100000"
STEPS_ASSERTS="100"
CIRCUIT=c9000_benchmark
BENCHMARK_DIR="$PWD/circuits/$CIRCUIT"
BENCHMARK_CONSTS="$BENCHMARK_DIR/src/const.nr"
BENCHMARK_PROVER="$BENCHMARK_DIR/Prover.toml"
BENCHMARK_TARGET="$BENCHMARK_DIR/target"
BENCHMARK_BYTECODE="$BENCHMARK_TARGET/$CIRCUIT.json"
BENCHMARK_WITNESS="$BENCHMARK_TARGET/$CIRCUIT.gz"
BENCHMARK_PROOF="$BENCHMARK_DIR/proof"
SPARTAN_DIR="$PWD/spartan-backend"

if [ -n "$DEVBOX_PACKAGES_DIR" ]; then
    TIME_BIN="$DEVBOX_PACKAGES_DIR/bin/time"
else
    TIME_BIN="/app/bin/time"
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

rm -rf "$BENCHMARK_PROOF" "$BENCHMARK_TARGET" stats.txt

echo "input_size,asserts,metric,min,max,mean,stddev" > stats.txt

for input_size in $STEPS_INPUT_SIZES; do
    for asserts in $STEPS_ASSERTS; do
        [[ $asserts -gt $input_size ]] && continue
        echo "INPUT_SIZE: $input_size -- ASSERTS: $asserts"
        echo "pub global NBR_INPUTS_PRIVATE: u32 = $input_size;" > $BENCHMARK_CONSTS
        echo "pub global NBR_ASSERTS: u32 = $asserts;" >> $BENCHMARK_CONSTS

        sum=0
	echo -n "private_numbers = [0" > $BENCHMARK_PROVER
        for input in $( seq 1 $(( input_size - 1)) ); do
            number=$(( input % 256 ))
	    echo -n ", $number" >> $BENCHMARK_PROVER
            sum=$(( sum + number ))
        done
	echo "]" >> $BENCHMARK_PROVER
        echo "public_sum = $sum" >> $BENCHMARK_PROVER

        ( cd $BENCHMARK_DIR && nargo execute --force )
        echo "Writing verifier key ($N runs)"
        WVK_TIMES=$(time_n bb write_vk -b "$BENCHMARK_BYTECODE" -o "$BENCHMARK_PROOF")
        echo "Creating proof ($N runs)"
        PROVE_TIMES=$(time_n bb prove -b "$BENCHMARK_BYTECODE" -w "$BENCHMARK_WITNESS" -k "$BENCHMARK_PROOF/vk" -o "$BENCHMARK_PROOF")
        echo "Verifying proof ($N runs)"
        VERIFY_TIMES=$(time_n bb verify -p "$BENCHMARK_PROOF/proof" -k "$BENCHMARK_PROOF/vk" -i "$BENCHMARK_PROOF/public_inputs")

        ( cd $BENCHMARK_DIR && nargo-t256 compile --force && nargo-t256 execute --force )
        echo "Running Spartan ($N runs)"
        SPARTAN_PROOF_TIMES=()
        SPARTAN_VERIFY_TIMES=()
        for i in $(seq 1 "$N"); do
            SPARTAN_OUTPUT=$(cd "$SPARTAN_DIR" && NO_COLOR=1 cargo run --release -- -v "$BENCHMARK_DIR" 2>&1) || { echo "$SPARTAN_OUTPUT"; exit $?; }
            NORMALIZED=$(echo "$SPARTAN_OUTPUT" | sed 's/µs/us/g')
            PROOF_BUSY=$(echo "$NORMALIZED" | grep 'proof_creation: spartan_backend: close' | grep -oE 'time\.busy=[^ ]+' | sed 's/time\.busy=//')
            VERIFY_BUSY=$(echo "$NORMALIZED" | grep 'verification: spartan_backend: close' | grep -oE 'time\.busy=[^ ]+' | sed 's/time\.busy=//')
            SPARTAN_PROOF_TIMES+=("$(to_seconds "$PROOF_BUSY")")
            SPARTAN_VERIFY_TIMES+=("$(to_seconds "$VERIFY_BUSY")")
        done

        PREFIX="$input_size,$asserts"
        echo "$PREFIX,write_vk,$(stats_csv "$WVK_TIMES")" >> stats.txt
        echo "$PREFIX,prove,$(stats_csv "$PROVE_TIMES")" >> stats.txt
        echo "$PREFIX,verify,$(stats_csv "$VERIFY_TIMES")" >> stats.txt
        echo "$PREFIX,spartan_proof,$(stats_csv "${SPARTAN_PROOF_TIMES[@]}")" >> stats.txt
        echo "$PREFIX,spartan_verify,$(stats_csv "${SPARTAN_VERIFY_TIMES[@]}")" >> stats.txt
        echo "--- stats.txt so far ---"
        cat stats.txt
    done
done
