#!/usr/bin/env python3
"""Independent Python reference for the experimental RIAK v0.2 candidate.

This file intentionally mirrors the written specification, not the Rust
implementation. It is only a research/test reference; it is not a security
claim and must not be used as a production implementation.
"""

MASK32 = 0xFFFFFFFF
ROUNDS = 24
DOMAIN_DEFAULT = 0
DOMAIN_RACIK = 0x5241_4349  # "RACI"
DOMAIN_MAC = 0x4D41_4349  # "MACI"
PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
    41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
]
MUL_A = 0x9E3779B9
MUL_B = 0x85EBCA6B
MUL_C = 0xC2B2AE35
ADD_A = 0x7F4A7C15
ADD_B = 0x1B873593
MODE_ABSORB_MASK = 0xA5A5A5A5
MODE_IV_MARKER = 0x5241_4349
MAC_CONTEXT = b"RIAK2CUSTOM-v02\x00"
AUTH_TAG_LEN = 16


def rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & MASK32


def mix_a(t: int) -> int:
    t ^= t >> 7
    t = rotl32(t, 11)
    t ^= (t << 9) & MASK32
    return t & MASK32


def mix_b(t: int) -> int:
    t ^= t >> 5
    t = rotl32(t, 7)
    t ^= (t << 13) & MASK32
    return t & MASK32


def mix_c(t: int) -> int:
    t ^= t >> 17
    t = rotl32(t, 19)
    t ^= (t << 15) & MASK32
    return t & MASK32


def round_function(x: int, k: int, c: int) -> int:
    t = (x ^ k) & MASK32
    t = (t + c) & MASK32
    t = (t * MUL_A) & MASK32
    t = mix_a(t)
    t = (t + ADD_A) & MASK32
    t = (t * MUL_B) & MASK32
    t = mix_b(t)
    t = (t + ADD_B) & MASK32
    t = (t * MUL_C) & MASK32
    return mix_c(t)


def key_schedule(
    key: list[int], rounds: int = ROUNDS, domain: int = DOMAIN_DEFAULT
) -> list[int]:
    if len(key) != 16:
        raise ValueError("key must contain 16 words")
    state = list(key)
    round_keys = []
    for r in range(rounds):
        s = state[0] ^ rotl32(state[5], 7) ^ state[11]
        s = round_function(s, PRIMES[r], domain)
        state[0] ^= s
        state = state[1:] + state[:1]
        round_keys.append(s ^ state[3] ^ state[9])
    return round_keys


def encrypt_block(
    words: list[int], round_keys: list[int], rounds: int = ROUNDS
) -> list[int]:
    if len(words) != 4:
        raise ValueError("block must contain 4 words")
    state = list(words)
    for r in range(rounds):
        next_word = state[0] ^ round_function(
            state[1] ^ state[2] ^ state[3], round_keys[r], PRIMES[r]
        )
        state = [state[1], state[2], state[3], next_word]
    return state


def decrypt_block(words: list[int], round_keys: list[int]) -> list[int]:
    state = list(words)
    for r in range(ROUNDS - 1, -1, -1):
        previous = state[3] ^ round_function(
            state[0] ^ state[1] ^ state[2], round_keys[r], PRIMES[r]
        )
        state = [previous, state[0], state[1], state[2]]
    return state


def words_to_bytes(words: list[int]) -> bytes:
    return b"".join(word.to_bytes(4, "big") for word in words)


def bytes_to_words(data: bytes) -> list[int]:
    if len(data) != 16:
        raise ValueError("block must contain 16 bytes")
    return [int.from_bytes(data[i : i + 4], "big") for i in range(0, 16, 4)]


def racik_transform(
    nonce: bytes, data: bytes, round_keys: list[int], decrypt: bool
) -> bytes:
    if len(nonce) != 12:
        raise ValueError("nonce must contain 12 bytes")
    state = [
        int.from_bytes(nonce[0:4], "big"),
        int.from_bytes(nonce[4:8], "big"),
        int.from_bytes(nonce[8:12], "big"),
        MODE_IV_MARKER,
    ]
    state = encrypt_block(state, round_keys)
    output = bytearray()

    for index, offset in enumerate(range(0, len(data), 16)):
        input_block = data[offset : offset + 16]
        counter = list(state)
        counter[0] = (counter[0] + index) & MASK32
        keystream = words_to_bytes(encrypt_block(counter, round_keys))
        output_block = bytes(a ^ b for a, b in zip(input_block, keystream))
        output.extend(output_block)

        absorb_source = input_block if decrypt else output_block
        padded = bytearray(16)
        padded[: len(absorb_source)] = absorb_source
        absorbed = [
            int.from_bytes(padded[i : i + 4], "big") ^ MODE_ABSORB_MASK
            for i in range(0, 16, 4)
        ]
        state = encrypt_block(absorbed, round_keys)

    return bytes(output)


def auth_tag(
    key: list[int], nonce: bytes, aad: bytes, ciphertext: bytes
) -> bytes:
    if len(nonce) != 12:
        raise ValueError("nonce must contain 12 bytes")
    round_keys = key_schedule(key, domain=DOMAIN_MAC)
    mac_input = bytearray()
    mac_input.extend(MAC_CONTEXT)
    mac_input.extend(nonce)
    mac_input.extend(len(aad).to_bytes(8, "little"))
    mac_input.extend(len(ciphertext).to_bytes(8, "little"))
    mac_input.extend(aad)
    mac_input.extend(ciphertext)

    total_len = len(mac_input)
    chain = [0, 0, (total_len >> 32) & MASK32, total_len & MASK32]
    chain = encrypt_block(chain, round_keys)
    for offset in range(0, len(mac_input), 16):
        chunk = mac_input[offset : offset + 16]
        padded = bytearray(16)
        padded[: len(chunk)] = chunk
        block = bytes_to_words(bytes(padded))
        chain = [left ^ right for left, right in zip(chain, block)]
        chain = encrypt_block(chain, round_keys)
    return words_to_bytes(chain)


def fixed_time_equal(left: bytes, right: bytes) -> bool:
    if len(left) != len(right):
        return False
    difference = 0
    for a, b in zip(left, right):
        difference |= a ^ b
    return difference == 0


class RiakV2Cipher:
    def seal(self, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        ciphertext = racik_transform(nonce, plaintext, self.enc_round_keys, False)
        return ciphertext + auth_tag(self._key, nonce, aad, ciphertext)

    def open(self, nonce: bytes, aad: bytes, sealed: bytes) -> bytes:
        if len(sealed) < AUTH_TAG_LEN:
            raise ValueError("authentication failed")
        ciphertext = sealed[:-AUTH_TAG_LEN]
        tag = sealed[-AUTH_TAG_LEN:]
        expected = auth_tag(self._key, nonce, aad, ciphertext)
        if not fixed_time_equal(tag, expected):
            raise ValueError("authentication failed")
        return racik_transform(nonce, ciphertext, self.enc_round_keys, True)

    @classmethod
    def from_key_bytes(cls, key: bytes) -> "RiakV2Cipher":
        if len(key) != 64:
            raise ValueError("key must contain 64 bytes")
        words = [int.from_bytes(key[i : i + 4], "big") for i in range(0, 64, 4)]
        return cls(words)

    def __init__(self, key: list[int]):
        if len(key) != 16:
            raise ValueError("key must contain 16 words")
        self._key = list(key)
        self.enc_round_keys = key_schedule(self._key, domain=DOMAIN_RACIK)


def gf2_rank(images: list[int]) -> int:
    basis: dict[int, int] = {}
    for value in images:
        while value:
            bit = value.bit_length() - 1
            previous = basis.get(bit)
            if previous is None:
                basis[bit] = value
                break
            value ^= previous
    return len(basis)


def self_test() -> None:
    assert all(
        gf2_rank([fn(1 << bit) for bit in range(32)]) == 32
        for fn in (mix_a, mix_b, mix_c)
    ), "linear mixing layer is not full rank"
    key = [0x10203040] * 16
    rk = key_schedule(key)
    block = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]
    encrypted = encrypt_block(block, rk)
    assert decrypt_block(encrypted, rk) == block

    cipher = RiakV2Cipher(key)
    nonce = bytes(range(12))
    plaintext = b"independent reference message"
    aad = b"RIAK2C"
    sealed = cipher.seal(nonce, aad, plaintext)
    assert cipher.open(nonce, aad, sealed) == plaintext
    changed = bytearray(sealed)
    changed[0] ^= 1
    try:
        cipher.open(nonce, aad, bytes(changed))
    except ValueError:
        pass
    else:
        raise AssertionError("tampering was accepted")
    print("RIAK v0.2 reference self-test: PASS")


if __name__ == "__main__":
    self_test()
