"""SHA-256 cryptographic hash function implementation.
Includes both a pure from-scratch educational reference implementation
and an optimized path for high-throughput image block hashing.
"""

import hashlib
import struct
from typing import Union


# Initial Hash Values (First 32 bits of the fractional parts of the square roots of the first 8 primes 2..19)
_H_INIT = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]

# Round Constants (First 32 bits of the fractional parts of the cube roots of the first 64 primes 2..311)
_K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

def _rotr(x: int, n: int) -> int:
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def _ch(x: int, y: int, z: int) -> int:
    return (x & y) ^ (~x & z)

def _maj(x: int, y: int, z: int) -> int:
    return (x & y) ^ (x & z) ^ (y & z)

def _sigma0(x: int) -> int:
    return _rotr(x, 2) ^ _rotr(x, 13) ^ _rotr(x, 22)

def _sigma1(x: int) -> int:
    return _rotr(x, 6) ^ _rotr(x, 11) ^ _rotr(x, 25)

def _gamma0(x: int) -> int:
    return _rotr(x, 7) ^ _rotr(x, 18) ^ (x >> 3)

def _gamma1(x: int) -> int:
    return _rotr(x, 17) ^ _rotr(x, 19) ^ (x >> 10)


def sha256_scratch(data: bytes) -> bytes:
    """Pure from-scratch implementation of SHA-256 (FIPS PUB 180-4)."""
    # Pre-processing (Padding)
    orig_len_bits = len(data) * 8
    msg = bytearray(data)
    msg.append(0x80)
    while (len(msg) + 8) % 64 != 0:
        msg.append(0x00)
    msg.extend(struct.pack('>Q', orig_len_bits))

    h0, h1, h2, h3, h4, h5, h6, h7 = _H_INIT

    # Process each 512-bit (64-byte) chunk
    for chunk_idx in range(0, len(msg), 64):
        chunk = msg[chunk_idx:chunk_idx + 64]
        w = list(struct.unpack('>16L', chunk)) + [0] * 48
        for i in range(16, 64):
            s0 = _gamma0(w[i - 15])
            s1 = _gamma1(w[i - 2])
            w[i] = (w[i - 16] + s0 + w[i - 7] + s1) & 0xFFFFFFFF

        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        for i in range(64):
            t1 = (h + _sigma1(e) + _ch(e, f, g) + _K[i] + w[i]) & 0xFFFFFFFF
            t2 = (_sigma0(a) + _maj(a, b, c)) & 0xFFFFFFFF
            h = g
            g = f
            f = e
            e = (d + t1) & 0xFFFFFFFF
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xFFFFFFFF

        h0 = (h0 + a) & 0xFFFFFFFF
        h1 = (h1 + b) & 0xFFFFFFFF
        h2 = (h2 + c) & 0xFFFFFFFF
        h3 = (h3 + d) & 0xFFFFFFFF
        h4 = (h4 + e) & 0xFFFFFFFF
        h5 = (h5 + f) & 0xFFFFFFFF
        h6 = (h6 + g) & 0xFFFFFFFF
        h7 = (h7 + h) & 0xFFFFFFFF

    return struct.pack('>8L', h0, h1, h2, h3, h4, h5, h6, h7)


def sha256_bytes(data: Union[bytes, str], use_scratch: bool = False) -> bytes:
    """Computes SHA-256 digest returning 32 bytes."""
    if isinstance(data, str):
        data = data.encode('utf-8')
    if use_scratch:
        return sha256_scratch(data)
    return hashlib.sha256(data).digest()


def sha256_hex(data: Union[bytes, str], use_scratch: bool = False) -> str:
    """Computes SHA-256 digest returning hexadecimal string."""
    return sha256_bytes(data, use_scratch=use_scratch).hex()
