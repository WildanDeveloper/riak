#!/usr/bin/env python3
"""Independently re-derive RIAK v0.3 wrapper vectors and compare them.

This checker shares no code with the Rust implementation. It parses case files
produced by `examples/v3_fuzz_generate.rs`, recomputes the ciphertext and tag
with `simulator/riak_v3.py`, and additionally confirms that decryption returns
the original plaintext.

A mismatch is a defect in at least one implementation. Agreement across a large
case count is evidence that both are correct on that input family; it is not a
proof of security.

Usage:
    python3 simulator/fuzz_diff_v3.py <case-file> [--verbose]

Exit status:
    0  every case matched
    1  at least one mismatch
    2  the input could not be read or parsed
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import riak_v3  # noqa: E402


def parse_line(line: str) -> tuple[bytes, bytes, bytes, bytes, bytes] | None:
    """Parse one generated case line into its five hex fields.

    The line is a sequence of label/value pairs, and a value may legitimately be
    empty (a zero-length aad or plaintext). A plain `split()` would drop those
    empty fields, so the parser is label-driven and splits on the known labels.
    """
    labels = ["K ", "N ", "A ", "P ", "C "]
    positions = []
    cursor = 0
    for label in labels:
        found = line.find(label, cursor)
        if found < 0:
            raise ValueError(f"missing label {label!r}")
        positions.append(found)
        cursor = found + len(label)

    values = []
    for index, label in enumerate(labels):
        start = positions[index] + len(label)
        end = positions[index + 1] if index + 1 < len(labels) else len(line)
        values.append(line[start:end].strip())

    key = bytes.fromhex(values[0])
    nonce = bytes.fromhex(values[1])
    aad = bytes.fromhex(values[2])
    plaintext = bytes.fromhex(values[3])
    sealed = bytes.fromhex(values[4])
    return key, nonce, aad, plaintext, sealed


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("case_file", help="case file from v3_fuzz_generate")
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="report progress every 10000 cases",
    )
    parser.add_argument(
        "--max-report",
        type=int,
        default=5,
        help="maximum number of mismatches to describe in detail",
    )
    args = parser.parse_args()

    path = Path(args.case_file)
    if not path.is_file():
        print(f"error: {path} does not exist", file=sys.stderr)
        return 2

    total = 0
    mismatches = 0
    roundtrip_failures = 0
    cipher_cache: dict[bytes, riak_v3.RiakV3Cipher] = {}

    with path.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                case = parse_line(line)
            except ValueError as error:
                print(f"error: line {line_number}: {error}", file=sys.stderr)
                return 2
            if case is None:
                continue

            key, nonce, aad, plaintext, sealed = case
            total += 1

            cipher = cipher_cache.get(key)
            if cipher is None:
                cipher = riak_v3.RiakV3Cipher.from_key_bytes(key)
                # Bound the cache so a long run cannot grow without limit.
                if len(cipher_cache) > 512:
                    cipher_cache.clear()
                cipher_cache[key] = cipher

            expected = cipher.seal(nonce, aad, plaintext)

            if expected != sealed:
                mismatches += 1
                if mismatches <= args.max_report:
                    print(f"MISMATCH at line {line_number}")
                    print(f"  key   {key.hex()}")
                    print(f"  nonce {nonce.hex()}")
                    print(f"  aad   {aad.hex()}")
                    print(f"  plain {plaintext.hex()}")
                    print(f"  rust  {sealed.hex()}")
                    print(f"  python{expected.hex()}")
                    for index, (left, right) in enumerate(zip(sealed, expected)):
                        if left != right:
                            print(f"  first difference at byte {index}: {left:02x} vs {right:02x}")
                            break
                continue

            try:
                recovered = cipher.open(nonce, aad, sealed)
            except ValueError as error:
                roundtrip_failures += 1
                if roundtrip_failures <= args.max_report:
                    print(f"ROUNDTRIP FAILURE at line {line_number}: {error}")
                continue
            if recovered != plaintext:
                roundtrip_failures += 1
                if roundtrip_failures <= args.max_report:
                    print(f"ROUNDTRIP MISMATCH at line {line_number}")
                    print(f"  expected {plaintext.hex()}")
                    print(f"  recovered {recovered.hex()}")

            if args.verbose and total % 10000 == 0:
                print(f"  checked {total} case(s)...")

    print(f"cases checked:      {total}")
    print(f"ciphertext/tag:     {total - mismatches} match, {mismatches} mismatch")
    print(f"round-trip decrypt: {total - roundtrip_failures} ok, {roundtrip_failures} failed")

    if mismatches == 0 and roundtrip_failures == 0:
        print("RESULT: all cases agree between the Rust and Python implementations")
        return 0

    print("RESULT: DIVERGENCE DETECTED")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
