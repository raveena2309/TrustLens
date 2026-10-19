"""Crypto module for TrustLens+ covering Module 4 of syllabus:
- Hashing: SHA-256
- Asymmetric: RSA from scratch, Diffie-Hellman-Merkle
- Stream Ciphers: LFSR, Geffe Generator, Rule 30 Cellular Automata
- Cryptanalysis: Berlekamp-Massey Algorithm, Frequency Analysis, Hill Climbing
- Classical Ciphers: Caesar, Beaufort, Columnar, Monoalphabetic, Homophonic, Polyphonic, Cardan Grille
- Permutation Notation: Cyclic notation
"""

from .hashing import sha256_bytes, sha256_hex
from .rsa_scratch import (
    generate_keypair as rsa_generate_keypair,
    sign as rsa_sign,
    verify as rsa_verify,
    encrypt_pkcs1 as rsa_encrypt_pkcs1,
    decrypt_pkcs1 as rsa_decrypt_pkcs1,
    RSAPublicKey,
    RSAPrivateKey,
)
from .dh import DiffieHellman
from .lfsr import LFSR, GeffeGenerator, berlekamp_massey, encrypt_geffe, decrypt_geffe
from .classical import (
    caesar_encrypt, caesar_decrypt, caesar_break,
    beaufort_encrypt, beaufort_decrypt,
    columnar_encrypt, columnar_decrypt
)
from .classical_more import (
    monoalphabetic_encrypt, monoalphabetic_decrypt, monoalphabetic_break,
    homophonic_encrypt, homophonic_decrypt,
    polyphonic_encrypt, polyphonic_decrypt,
    CardanGrille,
    to_cycles, from_cycles
)
from .cellular import Rule30Keystream, compare_stream_generators
