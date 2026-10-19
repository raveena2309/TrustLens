"""Linear Feedback Shift Registers (LFSR), Geffe Generator, and Berlekamp-Massey Algorithm.
Used for payload encryption and keystream cryptanalysis under Module 4.
"""

import os
import secrets
from typing import List, Tuple, Sequence, Optional
from .hashing import sha256_bytes


class LFSR:
    """Fibonacci Linear Feedback Shift Register."""

    def __init__(self, size: int, taps: Sequence[int], initial_state: int):
        """
        size: bit length of register (e.g. 19)
        taps: 0-indexed tap positions (e.g. [0, 5, 17, 18])
        initial_state: non-zero integer state
        """
        self.size = size
        self.taps = list(taps)
        self.mask = (1 << size) - 1
        self.state = initial_state & self.mask
        if self.state == 0:
            self.state = 1  # State must be non-zero

    def step(self) -> int:
        """Computes feedback bit, shifts register, returns output bit (LSB)."""
        output_bit = self.state & 1
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.state >> tap) & 1
        self.state = (self.state >> 1) | (feedback << (self.size - 1))
        return output_bit

    def generate_bits(self, count: int) -> List[int]:
        return [self.step() for _ in range(count)]


class GeffeGenerator:
    """Nonlinear combination generator using three LFSRs:
    output = (LFSR1 AND LFSR2) XOR (NOT LFSR1 AND LFSR3).
    When LFSR1 is 1, output is LFSR2; when LFSR1 is 0, output is LFSR3.
    """

    # Coprime standard primitive polynomials:
    # Degree 19: x^19 + x^5 + x^2 + x + 1 (taps: [0, 1, 4, 18])
    # Degree 23: x^23 + x^5 + 1 (taps: [0, 4, 22])
    # Degree 29: x^29 + x^2 + 1 (taps: [0, 1, 28])
    def __init__(self, seed_bytes: bytes, nonce: bytes = b""):
        digest = sha256_bytes(seed_bytes + nonce)
        # Partition 32 bytes into 3 seed states
        s1 = int.from_bytes(digest[0:8], "big")
        s2 = int.from_bytes(digest[8:16], "big")
        s3 = int.from_bytes(digest[16:24], "big")

        self.lfsr1 = LFSR(size=19, taps=[0, 1, 4, 18], initial_state=s1)
        self.lfsr2 = LFSR(size=23, taps=[0, 4, 22], initial_state=s2)
        self.lfsr3 = LFSR(size=29, taps=[0, 1, 28], initial_state=s3)

    def step(self) -> int:
        b1 = self.lfsr1.step()
        b2 = self.lfsr2.step()
        b3 = self.lfsr3.step()
        # Geffe nonlinear selector function
        return (b1 & b2) ^ ((1 ^ b1) & b3)

    def generate_bytes(self, length: int) -> bytes:
        result = bytearray(length)
        for i in range(length):
            byte_val = 0
            for _ in range(8):
                byte_val = (byte_val << 1) | self.step()
            result[i] = byte_val
        return bytes(result)


def encrypt_geffe(plaintext: bytes, session_key: bytes, nonce: Optional[bytes] = None) -> bytes:
    """Encrypts plaintext using Geffe keystream with an 8-byte random nonce prepended:
    output = nonce (8 bytes) || (plaintext XOR keystream).
    """
    if nonce is None:
        nonce = secrets.token_bytes(8)
    elif len(nonce) != 8:
        raise ValueError("Nonce must be 8 bytes")

    generator = GeffeGenerator(session_key, nonce=nonce)
    keystream = generator.generate_bytes(len(plaintext))
    ciphertext = bytes(p ^ k for p, k in zip(plaintext, keystream))
    return nonce + ciphertext


def decrypt_geffe(data: bytes, session_key: bytes) -> bytes:
    """Decrypts data where the first 8 bytes are the nonce."""
    if len(data) < 8:
        raise ValueError("Data too short to contain nonce")
    nonce = data[:8]
    ciphertext = data[8:]
    generator = GeffeGenerator(session_key, nonce=nonce)
    keystream = generator.generate_bytes(len(ciphertext))
    return bytes(c ^ k for c, k in zip(ciphertext, keystream))


def berlekamp_massey(sequence: Sequence[int]) -> Tuple[int, List[int]]:
    """Berlekamp-Massey algorithm.
    Given a binary sequence, finds the minimal linear feedback shift register length L
    and connection polynomial C(D) = 1 + c_1 D + c_2 D^2 + ... + c_L D^L.
    Returns (L, connection_polynomial_coefficients).
    """
    n = len(sequence)
    # C is the current connection polynomial
    # B is the previous connection polynomial before discrepancy
    b = [1]
    c = [1]
    l = 0
    m = -1

    for i in range(n):
        # Calculate discrepancy d_i
        d = sequence[i]
        for j in range(1, l + 1):
            if j < len(c):
                d ^= c[j] & sequence[i - j]

        if d != 0:
            t = list(c)
            # c(D) = c(D) + B(D) * D^(i - m)
            shift = i - m
            extended_b = [0] * shift + b
            if len(c) < len(extended_b):
                c.extend([0] * (len(extended_b) - len(c)))
            for j in range(len(extended_b)):
                c[j] ^= extended_b[j]

            if l <= i // 2:
                l = i + 1 - l
                m = i
                b = t

    # Trim trailing zeroes
    while len(c) > 1 and c[-1] == 0:
        c.pop()

    return l, c
