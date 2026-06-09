#!/bin/bash -e

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
RT=$DIR/time_real.sh

STEPS_INPUT_SIZES="10 100 1000 10000 100000"
STEPS_ASSERTS="10 100 1000 10000 100000"
# STEPS_INPUT_SIZES="10000"
# STEPS_ASSERTS="10000"
CIRCUIT=c0003_benchmark
BENCHMARK_DIR="$PWD/circuits/$CIRCUIT"
BENCHMARK_CONSTS="$BENCHMARK_DIR/src/const.nr"
BENCHMARK_PROVER="$BENCHMARK_DIR/Prover.toml"
BENCHMARK_TARGET="$BENCHMARK_DIR/target"
BENCHMARK_BYTECODE="$BENCHMARK_TARGET/$CIRCUIT.json"
BENCHMARK_WITNESS="$BENCHMARK_TARGET/$CIRCUIT.gz"
BENCHMARK_PROOF="$BENCHMARK_DIR/proof"
SPARTAN_DIR="$PWD/spartan-backend"

to_seconds() {
    local val="$1"
    local num=$(echo "$val" | sed 's/[a-zA-Z]*$//')
    local unit=$(echo "$val" | sed 's/^[0-9.]*//')
    case "$unit" in
        s)   awk "BEGIN {printf \"%.2f\n\", $num}" ;;
        ms)  awk "BEGIN {printf \"%.2f\n\", $num / 1000}" ;;
        us)  awk "BEGIN {printf \"%.2f\n\", $num / 1000000}" ;;
        ns)  awk "BEGIN {printf \"%.2f\n\", $num / 1000000000}" ;;
    esac
}

rm -rf $BENCHMARK_PROOF $BENCHMARK_TARGET stats.txt

for input_size in $STEPS_INPUT_SIZES; do
    for asserts in $STEPS_ASSERTS; do
        [[ $asserts -gt $input_size ]] && continue
        echo "INPUT_SIZE: $input_size -- ASSERTS: $asserts" >> stats.txt
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
        echo "Writing verifier key"
        $RT bb write_vk -b $BENCHMARK_BYTECODE -o $BENCHMARK_PROOF
        echo "Creating proof"
        $RT bb prove -b $BENCHMARK_BYTECODE -w $BENCHMARK_WITNESS -k $BENCHMARK_PROOF/vk -o $BENCHMARK_PROOF
        echo "Verifying proof"
        $RT bb verify -p $BENCHMARK_PROOF/proof -k $BENCHMARK_PROOF/vk -i $BENCHMARK_PROOF/public_inputs

        ( cd $BENCHMARK_DIR && nargo-t256 compile --force && nargo-t256 execute --force )
        SPARTAN_OUTPUT=$(cd "$SPARTAN_DIR" && NO_COLOR=1 cargo run --release -- -v "$BENCHMARK_DIR" 2>&1) || { echo "$SPARTAN_OUTPUT"; exit $?; }
        NORMALIZED=$(echo "$SPARTAN_OUTPUT" | sed 's/µs/us/g')
        PROOF_BUSY=$(echo "$NORMALIZED" | grep 'proof_creation: spartan_backend: close' | grep -oE 'time\.busy=[^ ]+' | sed 's/time\.busy=//')
        VERIFY_BUSY=$(echo "$NORMALIZED" | grep 'verification: spartan_backend: close' | grep -oE 'time\.busy=[^ ]+' | sed 's/time\.busy=//')
        echo "$(to_seconds "$PROOF_BUSY")" >> stats.txt
        echo "$(to_seconds "$VERIFY_BUSY")" >> stats.txt
        echo "The vanilla noir and Barretenberg speed in seconds, followed by spartan proof and verify - Creating vk :: Proving :: Verifying :"
        cat stats.txt
    done
done
