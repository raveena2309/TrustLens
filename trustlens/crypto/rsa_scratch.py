"""RSA implementation from scratch:
- Miller-Rabin probabilistic primality test
- Large prime generation
- Extended Euclidean Algorithm for modular inverse
- PKCS#1 v1.5 padding for digital signatures (EMSA-PKCS1-v1_5 with SHA-256)
- PKCS#1 v1.5 padding for asymmetric encryption (EME-PKCS1-v1_5)
- Key generation, signing, verification, encryption, and decryption
"""

import os
import secrets
from typing import Tuple, Optional
from .hashing import sha256_bytes

# ASN.1 DigestInfo prefix for SHA-256 (RFC 8017 / PKCS#1 v2.2)
SHA256_ASN1_PREFIX = bytes.fromhex("3031300d060960864801650304020105000420")


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm. Returns (g, x, y) such that a*x + b*y = g = gcd(a, b)."""
    if a == 0:
        return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def mod_inverse(e: int, phi: int) -> int:
    """Computes d such that (d * e) % phi == 1."""
    g, x, _ = egcd(e, phi)
    if g != 1:
        raise ValueError(f"e and phi are not coprime (gcd={g})")
    return x % phi


def is_probable_prime(n: int, k: int = 40) -> bool:
    """Miller-Rabin primality test.
    k is the number of test rounds (error probability <= 4^(-k)).
    """
    if n < 2:
        return False
    # Quick trial division for small primes
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47):
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n - 1 as 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

    # Witness loop
    for _ in range(k):
        a = secrets.randbelow(n - 4) + 2
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(bits: int) -> int:
    """Generates a random probable prime of the given bit length."""
    while True:
        # High bit 1 ensures correct bit length, low bit 1 ensures odd
        candidate = (1 << (bits - 1)) | secrets.randbits(bits - 1) | 1
        if is_probable_prime(candidate):
            return candidate


class RSAPublicKey:
    def __init__(self, e: int, n: int, bit_length: Optional[int] = None):
        self.e = e
        self.n = n
        self.bit_length = bit_length or n.bit_length()
        self.byte_length = (self.bit_length + 7) // 8

    def to_dict(self) -> dict:
        return {"e": hex(self.e), "n": hex(self.n), "bits": self.bit_length}

    @classmethod
    def from_dict(cls, d: dict) -> "RSAPublicKey":
        return cls(int(d["e"], 16), int(d["n"], 16), d.get("bits"))


class RSAPrivateKey:
    def __init__(self, d: int, n: int, p: int = 0, q: int = 0, bit_length: Optional[int] = None):
        self.d = d
        self.n = n
        self.p = p
        self.q = q
        self.bit_length = bit_length or n.bit_length()
        self.byte_length = (self.bit_length + 7) // 8

    @property
    def public_key(self) -> RSAPublicKey:
        # Default e = 65537
        return RSAPublicKey(65537, self.n, self.bit_length)

    def to_dict(self) -> dict:
        return {"d": hex(self.d), "n": hex(self.n), "bits": self.bit_length}

    @classmethod
    def from_dict(cls, data: dict) -> "RSAPrivateKey":
        return cls(int(data["d"], 16), int(data["n"], 16), bit_length=data.get("bits"))


def generate_keypair(bits: int = 2048) -> Tuple[RSAPublicKey, RSAPrivateKey]:
    """Generates an RSA keypair of specified bit length (e.g., 1024 or 2048 bits).
    Default e = 65537.
    """
    e = 65537
    prime_bits = bits // 2
    while True:
        p = generate_prime(prime_bits)
        q = generate_prime(prime_bits)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        # Verify gcd(e, phi) == 1
        g, _, _ = egcd(e, phi)
        if g == 1:
            d = mod_inverse(e, phi)
            pub = RSAPublicKey(e, n, bits)
            priv = RSAPrivateKey(d, n, p, q, bits)
            return pub, priv


# ==========================================
# PKCS#1 v1.5 Digital Signatures
# ==========================================

def emsa_pkcs1_v1_5_encode(message: bytes, em_len: int) -> bytes:
    """Encodes a message using EMSA-PKCS1-v1_5 with SHA-256."""
    h = sha256_bytes(message)
    t = SHA256_ASN1_PREFIX + h
    if em_len < len(t) + 11:
        raise ValueError("Intended encoded message length too short")
    # PS length = em_len - len(t) - 3
    ps = b"\xff" * (em_len - len(t) - 3)
    return b"\x00\x01" + ps + b"\x00" + t


def sign(message: bytes, priv_key: RSAPrivateKey) -> bytes:
    """Signs a message using RSA PKCS#1 v1.5 with SHA-256.
    Returns signature bytes matching the key's byte length (e.g., 256 bytes for 2048-bit).
    """
    k = priv_key.byte_length
    em = emsa_pkcs1_v1_5_encode(message, k)
    m_int = int.from_bytes(em, byteorder="big")
    s_int = pow(m_int, priv_key.d, priv_key.n)
    return s_int.to_bytes(k, byteorder="big")


def verify(message: bytes, signature: bytes, pub_key: RSAPublicKey) -> bool:
    """Verifies an RSA PKCS#1 v1.5 signature against the message and public key."""
    k = pub_key.byte_length
    if len(signature) != k:
        return False
    s_int = int.from_bytes(signature, byteorder="big")
    if s_int >= pub_key.n:
        return False
    m_int = pow(s_int, pub_key.e, pub_key.n)
    em = m_int.to_bytes(k, byteorder="big")

    try:
        expected_em = emsa_pkcs1_v1_5_encode(message, k)
        return secrets.compare_digest(em, expected_em)
    except Exception:
        return False


# ==========================================
# PKCS#1 v1.5 Encryption (Key Wrapping)
# ==========================================

def encrypt_pkcs1(plaintext: bytes, pub_key: RSAPublicKey) -> bytes:
    """Encrypts plaintext using EME-PKCS1-v1_5 padding:
    EM = 0x00 || 0x02 || PS || 0x00 || M
    where PS is at least 8 non-zero random bytes.
    """
    k = pub_key.byte_length
    m_len = len(plaintext)
    if m_len > k - 11:
        raise ValueError("Plaintext too long for RSA key size")

    ps_len = k - m_len - 3
    # Generate non-zero random bytes for PS
    ps = bytearray()
    while len(ps) < ps_len:
        b = os.urandom(1)
        if b != b"\x00":
            ps.extend(b)

    em = b"\x00\x02" + bytes(ps) + b"\x00" + plaintext
    m_int = int.from_bytes(em, byteorder="big")
    c_int = pow(m_int, pub_key.e, pub_key.n)
    return c_int.to_bytes(k, byteorder="big")


def decrypt_pkcs1(ciphertext: bytes, priv_key: RSAPrivateKey) -> bytes:
    """Decrypts ciphertext using EME-PKCS1-v1_5 unwrapping."""
    k = priv_key.byte_length
    if len(ciphertext) != k:
        raise ValueError("Ciphertext length does not match key size")
    c_int = int.from_bytes(ciphertext, byteorder="big")
    if c_int >= priv_key.n:
        raise ValueError("Ciphertext representative out of range")

    m_int = pow(c_int, priv_key.d, priv_key.n)
    em = m_int.to_bytes(k, byteorder="big")

    # Verify structure: EM = 0x00 || 0x02 || PS || 0x00 || M
    if em[0] != 0x00 or em[1] != 0x02:
        raise ValueError("Decryption error: invalid PKCS#1 v1.5 padding header")

    # Locate the 0x00 separator after PS (PS must be >= 8 bytes)
    sep_idx = -1
    for i in range(2, len(em)):
        if em[i] == 0x00:
            sep_idx = i
            break

    if sep_idx == -1 or (sep_idx - 2) < 8:
        raise ValueError("Decryption error: invalid padding structure or PS too short")

    return em[sep_idx + 1:]
