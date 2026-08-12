#!/bin/bash -e

# Regenerate all c0* circuits and verify that only the "hash" entry of each
# generated target JSON matches the version committed in git (HEAD). Unlike a
# plain `git diff`, this ignores changes to noir_version, bytecode, etc.

fail=0

for dir in circuits/c0*/; do
  (cd "$dir" && nargo-t256 compile && nargo-t256 execute)
done