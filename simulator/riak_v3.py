#!/usr/bin/env python3
"""Independent Python reference for the experimental RIAK v0.3 candidate.

This mirrors the written v0.3 specification rather than calling Rust. It is a
research/test reference, not a production implementation or a security claim.
"""

MASK32 = 0xFFFFFFFF
ROUNDS = 24
SUBUPDATES = 4
DOMAIN_DEFAULT = 0
DOMAIN_RACIK = 0x52414349  # "RACI"
DOMAIN_MAC = 0x4D414349  # "MACI"
PRIMES = [
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37,
    41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89,
]
SLOT_CONSTANTS = [0x00000000, 0x13579BDF, 0x2468ACE0, 0xFEDCBA98]
EXTRACTION_SEED = 0x9E3779B9
EXTRACTION_TAG = 0x13579BDF
MUL_A = 0x9E3779B9
MUL_B = 0x85EBCA6B
MUL_C = 0xC2B2AE35
ADD_A = 0x7F4A7C15
ADD_B = 0x1B873593
MODE_ABSORB_MASK = 0xA5A5A5A5
MODE_IV_MARKER = 0x52494333  # "RIC3"
MAC_CONTEXT = b"RIAK3CUSTOM-v03\x00"
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


def extract_round_key(state: list[int], round_index: int, domain: int) -> int:
    accumulator = domain ^ ((PRIMES[round_index] * EXTRACTION_SEED) & MASK32)
    for index in range(16):
        step = (index * 0x01000193) & MASK32
        constant = (
            PRIMES[round_index]
            ^ SLOT_CONSTANTS[index & 3]
            ^ step
            ^ EXTRACTION_TAG
        ) & MASK32
        accumulator = round_function(
            accumulator ^ state[index], domain ^ step, constant
        )
    return accumulator & MASK32


def key_schedule(
    key: list[int], rounds: int = ROUNDS, domain: int = DOMAIN_DEFAULT
) -> list[int]:
    if len(key) != 16:
        raise ValueError("key must contain 16 words")
    state = list(key)
    result = []
    for r in range(rounds):
        for index in range(16):
            a = state[(index + 3) & 15]
            b = rotl32(state[(index + 7) & 15], 11)
            c = rotl32(state[(index + 13) & 15], 5)
            mixed = a ^ b ^ c
            step_constant = (index * 0x01000193) & MASK32
            constant = PRIMES[r] ^ SLOT_CONSTANTS[index & 3] ^ step_constant
            state[index] ^= round_function(mixed, domain, constant)
        result.append(extract_round_key(state, r, domain))
    return result


def encrypt_block(
    words: list[int], round_keys: list[int], rounds: int = ROUNDS
) -> list[int]:
    if len(words) != 4:
        raise ValueError("block must contain 4 words")
    if len(round_keys) < rounds:
        raise ValueError("not enough round keys")
    state = list(words)
    for r in range(rounds):
        x0, x1, x2, x3 = state
        y0 = x0 ^ round_function(x1 ^ x2 ^ x3, round_keys[r], PRIMES[r] ^ SLOT_CONSTANTS[0])
        y1 = x1 ^ round_function(y0 ^ x2 ^ x3, round_keys[r], PRIMES[r] ^ SLOT_CONSTANTS[1])
        y2 = x2 ^ round_function(y1 ^ y0 ^ x3, round_keys[r], PRIMES[r] ^ SLOT_CONSTANTS[2])
        y3 = x3 ^ round_function(y2 ^ y1 ^ y0, round_keys[r], PRIMES[r] ^ SLOT_CONSTANTS[3])
        state = [y0, y1, y2, y3]
    return state


def decrypt_block(words: list[int], round_keys: list[int], rounds: int = ROUNDS) -> list[int]:
    if len(words) != 4:
        raise ValueError("block must contain 4 words")
    if len(round_keys) < rounds:
        raise ValueError("not enough round keys")
    state = list(words)
    for r in range(rounds - 1, -1, -1):
        y0, y1, y2, y3 = state
        x3 = y3 ^ round_function(y2 ^ y1 ^ y0, round_keys[r], PRIMES[r] ^ SLOT_CONSTANTS[3])
        x2 = y2 ^ round_function(y1 ^ y0 ^ x3, round_keys[r], PRIMES[r] ^ SLOT_CONSTANTS[2])
        x1 = y1 ^ round_function(y0 ^ x2 ^ x3, round_keys[r], PRIMES[r] ^ SLOT_CONSTANTS[1])
        x0 = y0 ^ round_function(x1 ^ x2 ^ x3, round_keys[r], PRIMES[r] ^ SLOT_CONSTANTS[0])
        state = [x0, x1, x2, x3]
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
        next_state = [word ^ previous for word, previous in zip(absorbed, state)]
        state = encrypt_block(next_state, round_keys)

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


class RiakV3Cipher:
    def __init__(self, key: list[int]):
        if len(key) != 16:
            raise ValueError("key must contain 16 words")
        self._key = list(key)
        self.enc_round_keys = key_schedule(self._key, domain=DOMAIN_RACIK)

    @classmethod
    def from_key_bytes(cls, key: bytes) -> "RiakV3Cipher":
        if len(key) != 64:
            raise ValueError("key must contain 64 bytes")
        return cls([int.from_bytes(key[i : i + 4], "big") for i in range(0, 64, 4)])

    def seal(self, nonce: bytes, aad: bytes, plaintext: bytes) -> bytes:
        ciphertext = racik_transform(nonce, plaintext, self.enc_round_keys, False)
        return ciphertext + auth_tag(self._key, nonce, aad, ciphertext)

    def open(self, nonce: bytes, aad: bytes, sealed: bytes) -> bytes:
        if len(sealed) < AUTH_TAG_LEN:
            raise ValueError("authentication failed")
        ciphertext = sealed[:-AUTH_TAG_LEN]
        tag = sealed[-AUTH_TAG_LEN:]
        if not fixed_time_equal(tag, auth_tag(self._key, nonce, aad, ciphertext)):
            raise ValueError("authentication failed")
        return racik_transform(nonce, ciphertext, self.enc_round_keys, True)


def self_test() -> None:
    key = [0x10203040] * 16
    round_keys = key_schedule(key)
    block = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]
    encrypted = encrypt_block(block, round_keys)
    assert decrypt_block(encrypted, round_keys) == block
    wrapper = RiakV3Cipher(key)
    nonce = bytes(range(12))
    plaintext = b"independent v0.3 wrapper message"
    aad = b"RIAK3C"
    sealed = wrapper.seal(nonce, aad, plaintext)
    assert wrapper.open(nonce, aad, sealed) == plaintext
    changed = bytearray(sealed)
    changed[0] ^= 1
    try:
        wrapper.open(nonce, aad, bytes(changed))
    except ValueError:
        pass
    else:
        raise AssertionError("tampering was accepted")
    import os
    ephemeral_key = [
        int.from_bytes(os.urandom(4), "big") for _ in range(16)
    ]
    ephemeral_nonce = os.urandom(12)
    ephemeral_aad = b"RIAK3C" + ephemeral_nonce
    ephemeral_plaintext = b"ephemeral self-test"
    ephemeral = RiakV3Cipher(ephemeral_key)
    ephemeral_sealed = ephemeral.seal(
        ephemeral_nonce, ephemeral_aad, ephemeral_plaintext
    )
    assert ephemeral.open(
        ephemeral_nonce, ephemeral_aad, ephemeral_sealed
    ) == ephemeral_plaintext
    print("RIAK v0.3 reference self-test: PASS")
    print("block ciphertext:", " ".join(f"{word:08x}" for word in encrypted))


if __name__ == "__main__":
    self_test()
