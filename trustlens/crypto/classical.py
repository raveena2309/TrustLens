"""Classical ciphers for Module 4:
- Caesar Cipher with Chi-Square frequency cryptanalysis breaker
- Beaufort Cipher (Reciprocal polyalphabetic cipher)
- Columnar Transposition Cipher
"""

import math
from typing import List, Tuple, Union, Sequence

# Standard English letter frequencies (percentages)
ENGLISH_FREQ = {
    'A': 8.167, 'B': 1.492, 'C': 2.782, 'D': 4.253, 'E': 12.702,
    'F': 2.228, 'G': 2.015, 'H': 6.094, 'I': 6.966, 'J': 0.153,
    'K': 0.772, 'L': 4.025, 'M': 2.406, 'N': 6.749, 'O': 7.507,
    'P': 1.929, 'Q': 0.095, 'R': 5.987, 'S': 6.327, 'T': 9.056,
    'U': 2.758, 'V': 0.978, 'W': 2.360, 'X': 0.150, 'Y': 1.974,
    'Z': 0.074
}


# ==========================================
# Caesar Cipher
# ==========================================

def caesar_encrypt(plaintext: str, shift: int) -> str:
    """Encrypts text using Caesar shift cipher."""
    res = []
    shift = shift % 26
    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            res.append(chr((ord(char) - base + shift) % 26 + base))
        else:
            res.append(char)
    return "".join(res)


def caesar_decrypt(ciphertext: str, shift: int) -> str:
    """Decrypts text encrypted with Caesar cipher."""
    return caesar_encrypt(ciphertext, -shift)


def caesar_break(ciphertext: str) -> Tuple[int, str, float]:
    """Breaks Caesar cipher using Chi-squared goodness-of-fit against English frequencies.
    Returns (best_shift, decrypted_plaintext, chi_sq_score).
    """
    letters_only = [c.upper() for c in ciphertext if c.isalpha()]
    n = len(letters_only)
    if n == 0:
        return 0, ciphertext, 0.0

    best_shift = 0
    best_chi = float('inf')
    best_plaintext = ciphertext

    for shift in range(26):
        decrypted = caesar_decrypt(ciphertext, shift)
        # Count letter frequencies
        counts = {chr(ord('A') + i): 0 for i in range(26)}
        for c in decrypted.upper():
            if 'A' <= c <= 'Z':
                counts[c] += 1

        # Chi-square statistic: sum((observed - expected)^2 / expected)
        chi_sq = 0.0
        for letter, count in counts.items():
            expected = n * (ENGLISH_FREQ[letter] / 100.0)
            if expected > 0:
                chi_sq += ((count - expected) ** 2) / expected

        if chi_sq < best_chi:
            best_chi = chi_sq
            best_shift = shift
            best_plaintext = decrypted

    return best_shift, best_plaintext, best_chi


# ==========================================
# Beaufort Cipher
# ==========================================

def _normalize_key(key: str, length: int) -> List[int]:
    clean_key = [ord(c.upper()) - ord('A') for c in key if c.isalpha()]
    if not clean_key:
        raise ValueError("Key must contain at least one alphabetic character")
    # Repeat key to match length
    return [clean_key[i % len(clean_key)] for i in range(length)]


def beaufort_encrypt(plaintext: str, key: str) -> str:
    """Beaufort cipher encryption:
    C = (K - P) mod 26
    Preserves letter case, leaves non-alphabetic chars unchanged.
    """
    res = []
    alpha_chars = [c for c in plaintext if c.isalpha()]
    key_shifts = _normalize_key(key, len(alpha_chars))
    k_idx = 0

    for char in plaintext:
        if char.isalpha():
            base = ord('A') if char.isupper() else ord('a')
            p = ord(char.upper()) - ord('A')
            k = key_shifts[k_idx]
            c = (k - p) % 26
            res.append(chr(c + base))
            k_idx += 1
        else:
            res.append(char)
    return "".join(res)


def beaufort_decrypt(ciphertext: str, key: str) -> str:
    """Beaufort cipher decryption.
    The Beaufort cipher is an involution (reciprocal cipher):
    P = (K - C) mod 26.
    Decryption is identical to encryption!
    """
    return beaufort_encrypt(ciphertext, key)


# ==========================================
# Columnar Transposition Cipher
# ==========================================

def _key_to_order(key: Union[str, Sequence[int]]) -> List[int]:
    """Converts a keyword (e.g. 'ZEBRA') or permutation list to 0-indexed column order."""
    if isinstance(key, str):
        # Alphabetical sorting with original positions
        indexed = sorted([(char.upper(), idx) for idx, char in enumerate(key)])
        order = [0] * len(key)
        for rank, (_, orig_idx) in enumerate(indexed):
            order[orig_idx] = rank
        return order
    else:
        # Already numerical
        return list(key)


def columnar_encrypt(plaintext: str, key: Union[str, Sequence[int]], pad_char: str = "X") -> str:
    """Encrypts plaintext using columnar transposition."""
    num_cols = len(key)
    order = _key_to_order(key)

    # Pad plaintext to fill rectangle
    pad_needed = (num_cols - (len(plaintext) % num_cols)) % num_cols
    padded_text = plaintext + (pad_char * pad_needed)

    num_rows = len(padded_text) // num_cols
    grid = [padded_text[r * num_cols:(r + 1) * num_cols] for r in range(num_rows)]

    # Read off columns in alphabetical/numerical order of key
    # order gives rank of each column 0..num_cols-1
    # Inverse mapping: column with rank r is at column index c
    rank_to_col = [0] * num_cols
    for col_idx, rank in enumerate(order):
        rank_to_col[rank] = col_idx

    ciphertext = []
    for rank in range(num_cols):
        col_idx = rank_to_col[rank]
        for r in range(num_rows):
            ciphertext.append(grid[r][col_idx])

    return "".join(ciphertext)


def columnar_decrypt(ciphertext: str, key: Union[str, Sequence[int]]) -> str:
    """Decrypts ciphertext created with columnar transposition."""
    num_cols = len(key)
    if len(ciphertext) % num_cols != 0:
        raise ValueError("Ciphertext length must be a multiple of key length")

    num_rows = len(ciphertext) // num_cols
    order = _key_to_order(key)

    rank_to_col = [0] * num_cols
    for col_idx, rank in enumerate(order):
        rank_to_col[rank] = col_idx

    # Reconstruct columns
    cols = {}
    idx = 0
    for rank in range(num_cols):
        col_idx = rank_to_col[rank]
        cols[col_idx] = ciphertext[idx:idx + num_rows]
        idx += num_rows

    # Read row by row
    plaintext = []
    for r in range(num_rows):
        for c in range(num_cols):
            plaintext.append(cols[c][r])

    return "".join(plaintext)
