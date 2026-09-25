#!/usr/bin/env python3
"""Generate deterministic RIAK v0.3 Rust/Python cross-check fixtures."""

from pathlib import Path
import sys

import riak_v3


def next_word(state: int) -> tuple[int, int]:
    state ^= (state << 13) & 0xFFFFFFFFFFFFFFFF
    state ^= state >> 7
    state ^= (state << 17) & 0xFFFFFFFFFFFFFFFF
    return state & 0xFFFFFFFFFFFFFFFF, state


def hex_bytes(data: bytes) -> str:
    return data.hex() if data else "-"


def main() -> None:
    output = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("tests/data/v3_fuzz_vectors.txt")
    output.parent.mkdir(parents=True, exist_ok=True)
    state = 0x1234_5678_9ABC_DEF0
    lines = []
    for case in range(128):
        key = []
        for _ in range(16):
            state, value = next_word(state)
            key.append(value & 0xFFFFFFFF)
        nonce = bytearray()
        for _ in range(12):
            state, value = next_word(state)
            nonce.append(value & 0xFF)
        aad_len = case % 41
        plaintext_len = (case * 37 + 11) % 257
        aad = bytearray()
        plaintext = bytearray()
        for index in range(aad_len):
            state, value = next_word(state)
            aad.append((value + index) & 0xFF)
        for index in range(plaintext_len):
            state, value = next_word(state)
            plaintext.append((value ^ (index * 29)) & 0xFF)
        sealed = riak_v3.RiakV3Cipher(key).seal(
            bytes(nonce), bytes(aad), bytes(plaintext)
        )
        lines.append(
            " ".join(
                (
                    hex_bytes(b"".join(word.to_bytes(4, "big") for word in key)),
                    hex_bytes(bytes(nonce)),
                    hex_bytes(bytes(aad)),
                    hex_bytes(bytes(plaintext)),
                    hex_bytes(sealed),
                )
            )
        )
    output.write_text("\n".join(lines) + "\n", encoding="ascii")
    print(f"wrote {len(lines)} cases to {output}")


if __name__ == "__main__":
    main()
