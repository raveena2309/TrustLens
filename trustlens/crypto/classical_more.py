"""Step 1b: Remaining Module 4 Classical Ciphers and Permutations:
- Monoalphabetic Substitution with Hill-Climbing Bigram/Trigram Cryptanalysis
- Homophonic Substitution with frequency flattening proof
- Polyphonic Substitution with ambiguity and dictionary resolution
- Turning Template (Cardan Grille) 6x6 / 8x8
- Cyclic Notation conversion (to_cycles, from_cycles)
"""

import math
import random
import re
from typing import Dict, List, Tuple, Optional, Set, Sequence

# Common English letter distribution for 100 homophonic slots (approximate percentages)
HOMOPHONIC_WEIGHTS = {
    'E': 13, 'T': 9, 'A': 8, 'O': 8, 'I': 7, 'N': 7, 'S': 6, 'H': 6, 'R': 6,
    'D': 4, 'L': 4, 'C': 3, 'U': 3, 'M': 3, 'W': 2, 'F': 2, 'G': 2, 'Y': 2,
    'P': 2, 'B': 1, 'V': 1, 'K': 1, 'J': 1, 'X': 1, 'Q': 1, 'Z': 1
}

# Standard English bigram log frequencies for hill climbing
# High frequency bigrams: TH, HE, IN, ER, AN, RE, ED, ON, ES, ST, EN, AT, TO, NT, HA, ND, OU, EA, NG, AS, OR, TI, IS, ET, IT, AR, TE, SE, HI, OF
COMMON_BIGRAMS = {
    "TH": 3.56, "HE": 3.07, "IN": 2.43, "ER": 2.05, "AN": 1.99, "RE": 1.85,
    "ED": 1.76, "ON": 1.76, "ES": 1.67, "ST": 1.63, "EN": 1.55, "AT": 1.49,
    "TO": 1.49, "NT": 1.44, "HA": 1.38, "ND": 1.34, "OU": 1.28, "EA": 1.27,
    "NG": 1.25, "AS": 1.25, "OR": 1.23, "TI": 1.22, "IS": 1.21, "ET": 1.20,
    "IT": 1.15, "AR": 1.14, "TE": 1.12, "SE": 1.12, "HI": 1.09, "OF": 1.07
}


# ==========================================
# 1. Monoalphabetic Substitution Cipher
# ==========================================

def generate_monoalphabetic_key() -> str:
    """Generates a random 26-letter substitution alphabet key."""
    letters = list("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    random.shuffle(letters)
    return "".join(letters)


def monoalphabetic_encrypt(plaintext: str, key: str) -> str:
    """Encrypts plaintext with substitution key (26 uppercase letters)."""
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    sub_map = {}
    for p, c in zip(std, key.upper()):
        sub_map[p] = c
        sub_map[p.lower()] = c.lower()

    return "".join(sub_map.get(ch, ch) for ch in plaintext)


def monoalphabetic_decrypt(ciphertext: str, key: str) -> str:
    """Decrypts ciphertext using substitution key."""
    std = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    rev_map = {}
    for p, c in zip(std, key.upper()):
        rev_map[c] = p
        rev_map[c.lower()] = p.lower()

    return "".join(rev_map.get(ch, ch) for ch in ciphertext)


def _score_text(text: str) -> float:
    """Bigram log score for hill climbing."""
    letters = [c for c in text.upper() if 'A' <= c <= 'Z']
    score = 0.0
    for i in range(len(letters) - 1):
        bg = letters[i] + letters[i + 1]
        score += COMMON_BIGRAMS.get(bg, 0.01)
    return score


def monoalphabetic_break(ciphertext: str, max_iterations: int = 2000) -> Tuple[str, str, float]:
    """Breaks monoalphabetic cipher via letter-frequency matching + hill climbing.
    Returns (best_key, decrypted_text, score).
    """
    letters = [c for c in ciphertext.upper() if 'A' <= c <= 'Z']
    if not letters:
        return "ABCDEFGHIJKLMNOPQRSTUVWXYZ", ciphertext, 0.0

    # Initial frequency guess
    freq_order = "ETAOINSHRDLCUMWFGYPBVKJXQZ"
    counts = {}
    for c in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        counts[c] = 0
    for c in letters:
        counts[c] += 1

    sorted_cipher_letters = sorted(counts.keys(), key=lambda x: counts[x], reverse=True)
    # Build initial key map: standard letter -> cipher letter
    initial_key = [''] * 26
    for i, std_char in enumerate(freq_order):
        idx = ord(std_char) - ord('A')
        initial_key[idx] = sorted_cipher_letters[i]

    best_key = list("".join(initial_key))
    best_text = monoalphabetic_decrypt(ciphertext, "".join(best_key))
    best_score = _score_text(best_text)

    # Hill-climbing: swap two characters and check score
    for _ in range(max_iterations):
        cand_key = list(best_key)
        i, j = random.sample(range(26), 2)
        cand_key[i], cand_key[j] = cand_key[j], cand_key[i]

        cand_text = monoalphabetic_decrypt(ciphertext, "".join(cand_key))
        cand_score = _score_text(cand_text)

        if cand_score > best_score:
            best_score = cand_score
            best_key = cand_key
            best_text = cand_text

    return "".join(best_key), best_text, best_score


# ==========================================
# 2. Homophonic Substitution Cipher
# ==========================================

def build_homophonic_table() -> Tuple[Dict[str, List[int]], Dict[int, str]]:
    """Builds a 100-symbol (00-99) homophonic substitution table based on English letter frequencies."""
    encrypt_map: Dict[str, List[int]] = {}
    decrypt_map: Dict[int, str] = {}
    current_symbol = 0

    for letter, count in HOMOPHONIC_WEIGHTS.items():
        symbols = list(range(current_symbol, current_symbol + count))
        encrypt_map[letter] = symbols
        for s in symbols:
            decrypt_map[s] = letter
        current_symbol += count

    return encrypt_map, decrypt_map


def homophonic_encrypt(plaintext: str, encrypt_map: Optional[Dict[str, List[int]]] = None) -> List[int]:
    """Encrypts plaintext into a list of homophonic integer symbols (0..99)."""
    if encrypt_map is None:
        encrypt_map, _ = build_homophonic_table()

    ciphertext = []
    for char in plaintext.upper():
        if char in encrypt_map:
            choices = encrypt_map[char]
            ciphertext.append(random.choice(choices))
    return ciphertext


def homophonic_decrypt(ciphertext: List[int], decrypt_map: Optional[Dict[int, str]] = None) -> str:
    """Decrypts homophonic integer symbols back to plaintext."""
    if decrypt_map is None:
        _, decrypt_map = build_homophonic_table()

    return "".join(decrypt_map.get(s, "?") for s in ciphertext)


def homophonic_frequency_analysis(ciphertext: List[int]) -> Dict[int, float]:
    """Computes symbol frequency in homophonic ciphertext.
    Shows the distribution is substantially flattened across the 100 symbols.
    """
    total = len(ciphertext)
    if total == 0:
        return {}
    counts: Dict[int, int] = {}
    for s in ciphertext:
        counts[s] = counts.get(s, 0) + 1
    return {s: (cnt / total) * 100.0 for s, cnt in counts.items()}


# ==========================================
# 3. Polyphonic Substitution Cipher
# ==========================================

DEFAULT_POLYPHONIC_MAP = {
    # 5 symbols mapping to 5 groups of letters
    '1': ['E', 'T', 'A', 'O', 'I'],
    '2': ['N', 'S', 'H', 'R', 'D'],
    '3': ['L', 'C', 'U', 'M', 'W'],
    '4': ['F', 'G', 'Y', 'P', 'B'],
    '5': ['V', 'K', 'J', 'X', 'Q', 'Z']
}

# Reverse lookup for encryption: letter -> symbol
DEFAULT_LETTER_TO_POLY = {}
for _sym, _letters in DEFAULT_POLYPHONIC_MAP.items():
    for _l in _letters:
        DEFAULT_LETTER_TO_POLY[_l] = _sym

# Basic English word dictionary for ambiguity resolution
COMMON_ENGLISH_WORDS = {
    "THE", "OF", "AND", "TO", "IN", "IS", "YOU", "THAT", "IT", "HE", "WAS", "FOR",
    "ON", "ARE", "AS", "WITH", "HIS", "THEY", "AT", "BE", "THIS", "HAVE", "FROM",
    "TRUST", "DEGREE", "SCIENCE", "HONORS", "GRADE", "VERIFIED", "GENUINE", "COLLEGE",
    "UNIVERSITY", "STUDENT", "RECORD", "EXCELLENCE", "INTEGRITY", "ENGINEERING"
}


def polyphonic_encrypt(plaintext: str, char_map: Optional[Dict[str, str]] = None) -> str:
    """Encrypts plaintext with polyphonic cipher where multiple letters share one symbol."""
    if char_map is None:
        char_map = DEFAULT_LETTER_TO_POLY
    return "".join(char_map.get(c.upper(), c) for c in plaintext if c.isalpha())


def polyphonic_decrypt_candidates(ciphertext: str, poly_map: Optional[Dict[str, List[str]]] = None, beam_width: int = 100) -> List[str]:
    """Generates decipherment candidate strings for polyphonic ciphertext using beam search."""
    if poly_map is None:
        poly_map = DEFAULT_POLYPHONIC_MAP

    candidates = [""]
    for sym in ciphertext:
        options = poly_map.get(sym, [sym])
        new_candidates = []
        for cand in candidates:
            for opt in options:
                new_cand = cand + opt
                # Score candidate prefix
                score = _score_text(new_cand)
                new_candidates.append((score, new_cand))

        # Keep top beam_width
        new_candidates.sort(key=lambda x: x[0], reverse=True)
        candidates = [c[1] for c in new_candidates[:beam_width]]

    return candidates


def polyphonic_decrypt(ciphertext: str, word_dict: Optional[Set[str]] = None) -> Tuple[str, List[str]]:
    """Resolves polyphonic cipher ambiguity using a dictionary check and beam search.
    Returns (best_resolution, top_candidates).
    """
    if word_dict is None:
        word_dict = COMMON_ENGLISH_WORDS

    # Direct dictionary lookup: words whose encryption matches ciphertext
    dict_matches = [w for w in word_dict if polyphonic_encrypt(w) == ciphertext]
    if dict_matches:
        dict_matches.sort(key=lambda w: len(w), reverse=True)
        return dict_matches[0], dict_matches

    candidates = polyphonic_decrypt_candidates(ciphertext, beam_width=200)
    scored = []
    for cand in candidates:
        score = 0
        for w in word_dict:
            if w in cand:
                score += (len(w) ** 2) * 10
        score += _score_text(cand)
        scored.append((score, cand))

    scored.sort(key=lambda x: x[0], reverse=True)
    best_cand = scored[0][1] if scored else ciphertext
    return best_cand, [c[1] for c in scored[:5]]


# ==========================================
# 4. Turning Template (Cardan Grille)
# ==========================================

class CardanGrille:
    """Cardan Grille (turning template) cipher on a 2k x 2k square grid (e.g., 6x6 or 8x8).
    Rotating 90 degrees 4 times covers every cell exactly once without overlapping.
    """

    def __init__(self, size: int = 6):
        if size % 2 != 0:
            raise ValueError("Grille size must be an even integer (e.g. 6 or 8)")
        self.size = size
        self.total_cells = size * size
        self.holes_count = self.total_cells // 4
        self.holes = self._generate_valid_holes()

    def _generate_valid_holes(self) -> List[Tuple[int, int]]:
        """Generates a valid set of holes: one cell from each orbit under 90-degree rotations."""
        holes = []
        k = self.size // 2
        # Partition top-left quadrant k x k
        for r in range(k):
            for c in range(k):
                # Orbit of cell (r, c):
                # 0 deg: (r, c)
                # 90 deg: (c, size - 1 - r)
                # 180 deg: (size - 1 - r, size - 1 - c)
                # 270 deg: (size - 1 - c, r)
                orbit = [
                    (r, c),
                    (c, self.size - 1 - r),
                    (self.size - 1 - r, self.size - 1 - c),
                    (self.size - 1 - c, r)
                ]
                # Pick deterministic or pseudo-random position in orbit
                chosen = orbit[(r + 2 * c) % 4]
                holes.append(chosen)
        return holes

    def _rotate_holes(self, holes: List[Tuple[int, int]]) -> List[Tuple[int, int]]:
        """Rotates holes 90 degrees clockwise."""
        return [(c, self.size - 1 - r) for r, c in holes]

    def encrypt(self, plaintext: str, pad_char: str = "X") -> str:
        """Encrypts plaintext using 4 successive 90-degree rotations."""
        text = plaintext.replace(" ", "").upper()
        if len(text) < self.total_cells:
            text += pad_char * (self.total_cells - len(text))
        text = text[:self.total_cells]

        grid = [["" for _ in range(self.size)] for _ in range(self.size)]
        curr_holes = list(self.holes)
        idx = 0

        # 4 rotations of grille
        for _ in range(4):
            # Sort holes in row-major order
            for r, c in sorted(curr_holes):
                grid[r][c] = text[idx]
                idx += 1
            curr_holes = self._rotate_holes(curr_holes)

        # Read off ciphertext row by row
        return "".join("".join(row) for row in grid)

    def decrypt(self, ciphertext: str) -> str:
        """Decrypts ciphertext using Cardan grille rotations."""
        if len(ciphertext) < self.total_cells:
            raise ValueError(f"Ciphertext must have at least {self.total_cells} characters")

        grid = []
        for r in range(self.size):
            grid.append(list(ciphertext[r * self.size:(r + 1) * self.size]))

        plaintext = []
        curr_holes = list(self.holes)

        for _ in range(4):
            for r, c in sorted(curr_holes):
                plaintext.append(grid[r][c])
            curr_holes = self._rotate_holes(curr_holes)

        return "".join(plaintext)


# ==========================================
# 5. Cyclic Notation & Keys
# ==========================================

def to_cycles(permutation: Sequence[int], one_indexed: bool = False) -> str:
    """Converts a permutation (e.g. [2, 0, 1, 4, 3]) to standard disjoint cycle notation.
    Example: [1, 2, 0, 4, 3] -> (0 1 2)(3 4) or (1 2 3)(4 5) if one_indexed=True.
    """
    n = len(permutation)
    visited = [False] * n
    cycles = []
    offset = 1 if one_indexed else 0

    for i in range(n):
        if not visited[i]:
            cycle = []
            curr = i
            while not visited[curr]:
                visited[curr] = True
                cycle.append(curr + offset)
                curr = permutation[curr]

            if len(cycle) > 1:
                cycles.append(cycle)
            elif len(cycle) == 1 and len(permutation) == 1:
                cycles.append(cycle)

    if not cycles:
        return "()"
    return "".join(f"({' '.join(map(str, c))})" for c in cycles)


def from_cycles(cycle_str: str, length: int, one_indexed: bool = False) -> List[int]:
    """Parses disjoint cycle notation (e.g. '(1 3 2)(4 5)') into a 0-indexed permutation array."""
    perm = list(range(length))
    offset = 1 if one_indexed else 0

    # Match all bracketed cycles
    raw_cycles = re.findall(r"\(([^)]+)\)", cycle_str)
    for raw in raw_cycles:
        elements = [int(x) - offset for x in raw.strip().split() if x.strip()]
        if len(elements) > 1:
            for i in range(len(elements)):
                src = elements[i]
                dst = elements[(i + 1) % len(elements)]
                perm[src] = dst

    return perm
