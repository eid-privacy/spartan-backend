#!/bin/bash -e

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"
RT=$DIR/time_real.sh

STEPS_INPUT_SIZES="10 100 1000 10000"
STEPS_ASSERTS="10"
CIRCUIT=c0003_benchmark
BENCHMARK_DIR="$PWD/circuits/$CIRCUIT"
BENCHMARK_CONSTS="$BENCHMARK_DIR/src/const.nr"
BENCHMARK_PROVER="$BENCHMARK_DIR/Prover.toml"
BENCHMARK_TARGET="$BENCHMARK_DIR/target"
BENCHMARK_BYTECODE="$BENCHMARK_TARGET/$CIRCUIT.json"
BENCHMARK_WITNESS="$BENCHMARK_TARGET/$CIRCUIT.gz"
BENCHMARK_PROOF="$BENCHMARK_DIR/proof"
SPARTAN_DIR="$PWD/spartan-backend"

rm -rf $BENCHMARK_PROOF $BENCHMARK_TARGET stats.txt

for input_size in $STEPS_INPUT_SIZES; do
    for asserts in $STEPS_ASSERTS; do
        [[ $asserts -gt $input_size ]] && continue
        echo "INPUT_SIZE: $input_size -- ASSERTS: $asserts" >> stats.txt
        echo "pub global NBR_INPUTS_PRIVATE: u32 = $input_size;" > $BENCHMARK_CONSTS
        echo "pub global NBR_ASSERTS: u32 = $asserts;" >> $BENCHMARK_CONSTS

        sum=0
        numbers="private_numbers = [0"
        for input in $( seq 1 $(( input_size - 1)) ); do
            number=$(( input % 256 ))
            numbers="$numbers, $number"
            sum=$(( sum + number ))
        done
        echo "$numbers]" > $BENCHMARK_PROVER
        echo "public_sum = $sum" >> $BENCHMARK_PROVER

        ( cd $BENCHMARK_DIR && nargo execute --force )
        echo "Writing verifier key"
        $RT bb write_vk -b $BENCHMARK_BYTECODE -o $BENCHMARK_PROOF
        echo "Creating proof"
        $RT bb prove -b $BENCHMARK_BYTECODE -w $BENCHMARK_WITNESS -k $BENCHMARK_PROOF/vk -o $BENCHMARK_PROOF
        echo "Verifying proof"
        $RT bb verify -p $BENCHMARK_PROOF/proof -k $BENCHMARK_PROOF/vk -i $BENCHMARK_PROOF/public_inputs

        ( cd $BENCHMARK_DIR && nargo-t256 execute --force )
        ( cd $SPARTAN_DIR && cargo run --release -- -v $BENCHMARK_DIR )
        echo "The vanilla noir and Barrettenberg speed in seconds - Creating vk :: Proving :: Verifying :"
        cat stats.txt
    done
done
