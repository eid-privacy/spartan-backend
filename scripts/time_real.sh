#!/bin/bash

DIR="$(dirname "$(realpath "${BASH_SOURCE[0]}")")"

if [ -n "$DEVBOX_PACKAGES_DIR" ]; then
    TIME_BIN="$DEVBOX_PACKAGES_DIR/bin/time"
else
    TIME_BIN="/app/bin/time"
fi

$TIME_BIN -f %e -o $DIR/../stats.txt -a $@
