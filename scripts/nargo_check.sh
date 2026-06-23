#!/bin/bash -e

# Regenerate all c0* circuits and verify that only the "hash" entry of each
# generated target JSON matches the version committed in git (HEAD). Unlike a
# plain `git diff`, this ignores changes to noir_version, bytecode, etc.

fail=0

for dir in circuits/c0*/; do
  (cd "$dir" && nargo-t256 execute)
done

for f in circuits/c0*/target/*.json; do
  new=$(jq -r .hash "$f")
  old=$(git show "HEAD:$f" | jq -r .hash)
  if [ "$new" != "$old" ]; then
    echo "HASH MISMATCH: $f (new=$new git=$old)"
    fail=1
  else
    echo "OK: $f ($new)"
  fi
done

exit $fail
