"""crypto.py
Consolidated Module 4 Cryptographic Algorithms:
1. Hashing: SHA-256
2. Public-Key: RSA from Scratch (Miller-Rabin, Keygen, Digital Signatures, Key Wrapping)
3. Key Exchange: Diffie-Hellman-Merkle
4. Stream Cipher: LFSR, Geffe Generator, and Berlekamp-Massey Attack
"""

import hashlib
import secrets
from typing import Tuple, List, Optional


# ==========================================
# 1. Hashing (SHA-256)
# ==========================================
def sha256(data: bytes) -> bytes:
    """Computes standard 32-byte SHA-256 hash digest."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).digest()


# ==========================================
# 2. RSA from Scratch (Module 4)
# ==========================================
def is_prime(n: int, k: int = 20) -> bool:
    """Miller-Rabin probabilistic primality test."""
    if n < 2: return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31):
        if n == p: return True
        if n % p == 0: return False

    # Write n - 1 = 2^r * d
    r, d = 0, n - 1
    while d % 2 == 0:
        r += 1
        d //= 2

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
    """Generates a random probable prime of specified bit length."""
    while True:
        candidate = (1 << (bits - 1)) | secrets.randbits(bits - 1) | 1
        if is_prime(candidate):
            return candidate


def egcd(a: int, b: int) -> Tuple[int, int, int]:
    """Extended Euclidean Algorithm: returns (gcd, x, y) such that a*x + b*y = gcd."""
    if a == 0: return b, 0, 1
    g, x1, y1 = egcd(b % a, a)
    return g, y1 - (b // a) * x1, x1


def mod_inv(e: int, phi: int) -> int:
    """Computes modular inverse d such that (d * e) % phi == 1."""
    g, x, _ = egcd(e, phi)
    if g != 1: raise ValueError("Modular inverse does not exist")
    return x % phi


def rsa_keygen(bits: int = 1024) -> Tuple[dict, dict]:
    """Generates RSA public key (e, n) and private key (d, n)."""
    e = 65537
    p = generate_prime(bits // 2)
    q = generate_prime(bits // 2)
    n = p * q
    phi = (p - 1) * (q - 1)
    d = mod_inv(e, phi)
    pub = {"e": e, "n": n, "bits": bits}
    priv = {"d": d, "n": n, "bits": bits}
    return pub, priv


def rsa_sign(message_bytes: bytes, priv_key: dict) -> bytes:
    """Signs message: s = (hash(m))^d mod n."""
    h = int.from_bytes(sha256(message_bytes), "big")
    s = pow(h, priv_key["d"], priv_key["n"])
    byte_len = (priv_key["bits"] + 7) // 8
    return s.to_bytes(byte_len, "big")


def rsa_verify(message_bytes: bytes, signature_bytes: bytes, pub_key: dict) -> bool:
    """Verifies signature: check if s^e mod n == hash(m)."""
    s = int.from_bytes(signature_bytes, "big")
    h_expected = pow(s, pub_key["e"], pub_key["n"])
    h_actual = int.from_bytes(sha256(message_bytes), "big")
    return h_expected == h_actual


def rsa_wrap_key(seed_bytes: bytes, pub_key: dict) -> bytes:
    """Encrypts stego seed with verifier RSA public key: c = m^e mod n."""
    m = int.from_bytes(seed_bytes, "big")
    c = pow(m, pub_key["e"], pub_key["n"])
    byte_len = (pub_key["bits"] + 7) // 8
    return c.to_bytes(byte_len, "big")


def rsa_unwrap_key(cipher_bytes: bytes, priv_key: dict, out_len: int = 16) -> bytes:
    """Decrypts stego seed with verifier RSA private key: m = c^d mod n."""
    c = int.from_bytes(cipher_bytes, "big")
    m = pow(c, priv_key["d"], priv_key["n"])
    return m.to_bytes(out_len, "big")


# ==========================================
# 3. Diffie-Hellman-Merkle (Module 4)
# ==========================================
DH_P = 2305843009213693951  # 2^61 - 1 (Mersenne safe prime)
DH_G = 2

def dh_generate_keypair() -> Tuple[int, int]:
    """Generates private key a and public key A = g^a mod p."""
    priv = secrets.randbelow(DH_P - 2) + 2
    pub = pow(DH_G, priv, DH_P)
    return priv, pub

def dh_shared_secret(our_priv: int, peer_pub: int) -> bytes:
    """Derives shared symmetric session key: K = SHA-256(peer_pub^our_priv mod p)."""
    shared = pow(peer_pub, our_priv, DH_P)
    return sha256(shared.to_bytes(32, "big"))


# ==========================================
# 4. Stream Ciphers: LFSR & Geffe Generator
# ==========================================
class LFSR:
    """Linear Feedback Shift Register with feedback taps."""
    def __init__(self, size: int, taps: List[int], seed: int):
        self.size = size
        self.taps = taps
        self.state = seed & ((1 << size) - 1) or 1

    def step(self) -> int:
        out = self.state & 1
        feedback = 0
        for tap in self.taps:
            feedback ^= (self.state >> tap) & 1
        self.state = (self.state >> 1) | (feedback << (self.size - 1))
        return out


class GeffeGenerator:
    """Nonlinear combination generator combining 3 LFSRs:
    F(x1, x2, x3) = (x1 AND x2) XOR (NOT x1 AND x3)
    Eliminates the linear predictability of a single LFSR!
    """
    def __init__(self, key: bytes):
        h = sha256(key)
        s1 = int.from_bytes(h[0:4], "big")
        s2 = int.from_bytes(h[4:8], "big")
        s3 = int.from_bytes(h[8:12], "big")
        self.lfsr1 = LFSR(19, [0, 1, 4, 18], s1)
        self.lfsr2 = LFSR(23, [0, 4, 22], s2)
        self.lfsr3 = LFSR(29, [0, 1, 28], s3)

    def step(self) -> int:
        x1, x2, x3 = self.lfsr1.step(), self.lfsr2.step(), self.lfsr3.step()
        return (x1 & x2) ^ ((1 ^ x1) & x3)

    def generate_bytes(self, n: int) -> bytes:
        res = bytearray(n)
        for i in range(n):
            byte_val = 0
            for _ in range(8):
                byte_val = (byte_val << 1) | self.step()
            res[i] = byte_val
        return bytes(res)


def geffe_encrypt(data: bytes, key: bytes) -> bytes:
    """Encrypts/Decrypts data by XORing with Geffe keystream."""
    keystream = GeffeGenerator(key).generate_bytes(len(data))
    return bytes(b ^ k for b, k in zip(data, keystream))


def berlekamp_massey(bits: List[int]) -> int:
    """Finds the linear complexity L of a bit sequence.
    Shows that a single 19-bit LFSR is cracked with L=19, while Geffe is not!
    """
    n = len(bits)
    b, c = [1], [1]
    l, m = 0, -1
    for i in range(n):
        d = bits[i]
        for j in range(1, l + 1):
            if j < len(c): d ^= c[j] & bits[i - j]
        if d != 0:
            t = list(c)
            shift = [0] * (i - m) + b
            if len(c) < len(shift): c.extend([0] * (len(shift) - len(c)))
            for j in range(len(shift)): c[j] ^= shift[j]
            if l <= i // 2:
                l = i + 1 - l
                m = i
                b = t
    return l
