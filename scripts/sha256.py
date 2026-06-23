#!/usr/bin/env python3
"""Compute the SHA-256 hash of a file and print it as hex and as a byte array."""

import hashlib
import sys


def main() -> int:
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <file>", file=sys.stderr)
        return 1

    path = sys.argv[1]
    hasher = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            hasher.update(chunk)

    digest = hasher.digest()
    print(f"hex: {digest.hex()}")
    print(f"bytes: [{', '.join(str(b) for b in digest)}]")
    return 0


if __name__ == "__main__":
    sys.exit(main())
