"""Diffie-Hellman-Merkle Key Exchange Implementation.
Supports standard RFC 3526 2048-bit MODP group parameters for production,
as well as smaller pedagogical parameters for interactive Crypto Lab step-by-step demos.
"""

import secrets
from typing import Tuple, Optional
from .hashing import sha256_bytes

# RFC 3526 2048-bit MODP Group (Group 14)
# Generator g = 2
DH_2048_G = 2
DH_2048_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
    "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

# Pedagogical small parameters (Group 1-demo)
DH_DEMO_P = 2357
DH_DEMO_G = 2


class DiffieHellman:
    """Represents a Diffie-Hellman party with private and public parameters."""

    def __init__(self, p: int = DH_2048_P, g: int = DH_2048_G, private_key: Optional[int] = None):
        self.p = p
        self.g = g
        if private_key is not None:
            self.private_key = private_key
        else:
            # Generate random private key in [2, p - 2]
            bits = min(p.bit_length() - 1, 256)
            self.private_key = secrets.randbits(bits) | 2

        # Public key: A = g^a mod p
        self.public_key = pow(self.g, self.private_key, self.p)

    def compute_shared_secret(self, peer_public_key: int) -> int:
        """Computes shared secret: s = (B)^a mod p."""
        if not (1 < peer_public_key < self.p - 1):
            raise ValueError("Invalid peer public key range")
        return pow(peer_public_key, self.private_key, self.p)

    def derive_key(self, peer_public_key: int) -> bytes:
        """Computes shared secret and hashes it with SHA-256 to produce a 256-bit symmetric session key."""
        shared_int = self.compute_shared_secret(peer_public_key)
        # Convert integer to big-endian bytes
        length = (self.p.bit_length() + 7) // 8
        shared_bytes = shared_int.to_bytes(length, byteorder="big")
        return sha256_bytes(shared_bytes)


def create_dh_session() -> Tuple[DiffieHellman, DiffieHellman, bytes]:
    """Helper that creates an Issuer and Verifier pair and executes DH exchange.
    Returns (issuer_dh, verifier_dh, session_key).
    """
    issuer_dh = DiffieHellman()
    verifier_dh = DiffieHellman()
    session_key = issuer_dh.derive_key(verifier_dh.public_key)
    assert session_key == verifier_dh.derive_key(issuer_dh.public_key)
    return issuer_dh, verifier_dh, session_key
