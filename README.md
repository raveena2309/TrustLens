# 🛡️ TrustLens+: Dual-Layer Certificate Protection, Forensic Verification & Differential Privacy

**TrustLens+** is an end-to-end academic credential protection and verification ecosystem paired with an interactive **Trust Lab** demonstration platform. It solves certificate forgery and privacy leakage by embedding digitally signed, encrypted records inside certificate images across two complementary steganographic layers (fragile and robust), and enables privacy-preserving collaborative statistics using Differential Privacy and Secure Multi-Party Computation.

---

## 🏛️ Syllabus Mapping

| Module | Topic | Implementation in TrustLens+ |
| :--- | :--- | :--- |
| **Module 1** | **Differential Privacy (DP)**: Laplace Mechanism, Exponential Mechanism, Randomized Response, Basic & Advanced Composition | `trustlens/privacy/laplace.py`, `exponential.py`, `randomized_response.py`, `budget.py` |
| **Module 1** | **Multi-Party Computation (SMC)** & Distributed Differential Privacy | `trustlens/privacy/multiparty.py` (Additive Secret Sharing + Gamma Infinite Divisibility) |
| **Module 4** | **Classical Ciphers**: Caesar, Beaufort, Columnar Transposition, Monoalphabetic, Homophonic, Polyphonic, Cardan Grille | `trustlens/crypto/classical.py`, `trustlens/crypto/classical_more.py` |
| **Module 4** | **Permutation & Cyclic Notation**: Disjoint cycles (`to_cycles`, `from_cycles`) | `trustlens/crypto/classical_more.py` |
| **Module 4** | **Stream Ciphers**: LFSR, Geffe Nonlinear Generator, Rule 30 Cellular Automata | `trustlens/crypto/lfsr.py`, `trustlens/crypto/cellular.py` |
| **Module 4** | **Cryptanalysis**: Berlekamp-Massey Algorithm, Chi-Square Frequency Analysis, Hill-Climbing Bigram Breaker | `trustlens/crypto/lfsr.py`, `classical.py`, `classical_more.py` |
| **Module 4** | **Asymmetric Cryptography**: Diffie-Hellman-Merkle Key Exchange, RSA from Scratch (Miller-Rabin, PKCS#1 v1.5) | `trustlens/crypto/dh.py`, `trustlens/crypto/rsa_scratch.py` |
| **Module 5** | **Fragile Steganography**: LSB Embedding, Key-Seeded Permutation, Edge-Adaptive (Sobel 7-bit) | `trustlens/stego/lsb.py` |
| **Module 5** | **High-Capacity Steganography**: BPCS (Canonical Gray Code, border complexity $\alpha$, checkerboard conjugation) | `trustlens/stego/bpcs.py` |
| **Module 5** | **Robust Watermarking**: Quantization Index Modulation (QIM) in 8×8 DCT domain surviving JPEG compression | `trustlens/stego/dct_qim.py` |
| **Module 5** | **Spread Spectrum Steganography**: Direct Sequence Spread Spectrum (DSSS) with PN codes | `trustlens/stego/spread.py` |
| **Module 5** | **Lossless Data Hiding**: Reversible Histogram Shifting (Ni et al.) with exact bit-for-bit image restoration | `trustlens/stego/reversible.py` |
| **Module 5** | **Public-Key Steganography**: RSA-wrapped stego seeds for verifier-only extraction | `trustlens/stego/pubkey_stego.py` |

---

## 🏗️ Architecture

### 1. Issuance Workflow (`issue_certificate`)
```
Details (Name, Roll, Degree, Year, CGPA)
   │
   ├─► Render Certificate Base Image (1600x1152)
   │
   ├─► [Robust Layer]: Embed Certificate ID via DCT-QIM (Mid-frequency (3,2), Q=20, 250x repetition)
   │
   ├─► Sign Record (SHA-256 Digest + RSA-1024 Private Key)
   │
   ├─► Encrypt (Record + Signature + Nonce) via Geffe Stream Cipher (DH Session Key)
   │
   ├─► Frame with Magic 'TL', Version, Length, and CRC-32 (Repeated 7x for Bitwise Majority Voting)
   │
   ├─► Wrap Ephemeral Stego Seed using Verifier's RSA Public Key (EME-PKCS1-v1_5)
   │
   ├─► [Fragile Layer]: Embed Edge-Adaptive LSB (Sobel on upper 7 bit-planes) + 32x32 Block Checksums
   │
   └─► Output: certificate.png
```

### 2. Forensic Verification Workflow (`verify_certificate`)
```
Input Certificate Image
   │
   ├─► Extract & Majority-Vote Robust DCT Watermark ──► Certificate ID
   │
   ├─► Extract RSA-Wrapped Seed from Row 1 Header ──► Unwrap with Verifier Private Key
   │
   ├─► Extract Fragile LSB Payload ──► Bitwise Majority Vote (7 copies) ──► Check CRC-32
   │
   ├─► Geffe Decrypt ──► Verify RSA Signature against Issuer Public Key
   │
   ├─► Recompute 32x32 Block Checksums (Upper 7 bit-planes) ──► 2D Tamper Heatmap & Terrain
   │
   ├─► Optical Character Recognition (OCR) on Printed Fields ──► Fuzzy/Exact Comparison
   │
   └─► Decision Engine ──► Categorical Verdict:
         - GENUINE
         - FORGED / EDITED (Show altered fields & red tamper heatmap)
         - DAMAGED ORIGINAL (Fragile layer destroyed by recompression, DCT ID recovered)
         - NOT A TRUSTLENS CERTIFICATE
```

---

## 🚀 Quickstart Guide

### 1. Installation
Clone or navigate to the project directory:
```bash
cd TrustLens
pip install -r requirements.txt
```

> **Note on Tesseract OCR**:
> On Windows, install [Tesseract OCR](https://github.com/UB-Mannheim/tesseract/wiki) to `C:\Program Files\Tesseract-OCR\tesseract.exe`.
> TrustLens+ automatically detects this path. If Tesseract is not installed, the verification pipeline uses an automated heuristic template reader as a transparent fallback.

### 2. Launch Streamlit "Trust Lab" Web Application
```bash
streamlit run app.py
```
The application will launch in your browser at `http://localhost:8501`.

### 3. Generate Pre-Packaged Sample Certificates
Generate genuine, CGPA-forged, name-forged, block-tampered, and JPEG-damaged test certificates in one click:
```bash
python generate_sample_data.py
```
Files will be saved in the `samples/` directory.

### 4. Run Unit Test Suite
Execute the full 35-test unit testing suite:
```bash
python -m unittest discover tests
```

### 5. Run Automated Evaluation & Generate Benchmarks
Execute all 11 scientific benchmark experiments and generate CSV tables and plots:
```bash
python evaluate.py
```
Outputs are written to `results/`:
- `image_quality.csv` & `plot_image_quality.png`
- `redundancy.csv` & `plot_redundancy.png`
- `privacy_laplace.csv` & `plot_privacy_error.png`
- `compression.csv`, `capacity.csv`, `rejection.csv`, `cipher_strength.csv`

---

## 🎯 Viva Q&A Reference

### Q1: Why are two steganographic layers used instead of one?
**Answer**:
A single layer cannot satisfy both fragility and robustness:
1. **Fragile LSB Layer**: Highly sensitive to pixel modifications. Changing even a single digit (like CGPA from 9.42 to 9.98) alters the upper 7 bit-planes and invalidates the 32×32 block checksum, precisely localizing the tampering.
2. **Robust DCT Layer**: QIM in mid-frequency DCT coefficients survives JPEG lossy compression, resizing, and physical degradation. If a certificate is photocopied or compressed as a JPEG, the fragile layer is destroyed, but the DCT layer still recovers the authentic Certificate ID (`TL-2026-0123`), correctly classifying it as a **Damaged Original** rather than an outright forgery.

### Q2: Why is a single LFSR cryptographically insecure, and how does the Geffe generator fix it?
**Answer**:
A single LFSR with degree $L$ has a linear feedback relation. By the **Berlekamp-Massey algorithm**, an adversary observing just $2L$ consecutive output bits can reconstruct the minimal connection polynomial in $\mathcal{O}(L^2)$ operations, breaking the cipher completely.
The **Geffe generator** solves this by combining three coprime-length LFSRs using a non-linear selector function:
$$f(x_1, x_2, x_3) = (x_1 \land x_2) \oplus (\neg x_1 \land x_3)$$
This non-linear combination dramatically elevates the linear complexity $L_{\text{eff}} \approx L_1 L_2 + (1 + L_1) L_3$, making Berlekamp-Massey infeasible from a small sequence of keystream bits.

### Q3: How does edge-adaptive LSB embedding work without desynchronizing the extractor?
**Answer**:
Edge detection (Sobel filter) is computed **strictly on the upper 7 bit-planes** (`image >> 1`). Because LSB embedding modifies only the least significant bit (plane 0), the upper 7 bit-planes remain 100% untouched. Therefore, the extractor computes the exact same edge magnitude map and visits the identical pixel positions in the same priority order.

### Q4: How does Distributed Laplace noise work in Multi-Party Computation?
**Answer**:
By the infinite divisibility property of the Laplace distribution, a Laplace random variable $\text{Laplace}(0, b)$ can be expressed as the difference of two Gamma variables: $\text{Gamma}(1, b) - \text{Gamma}(1, b)$.
Because the sum of $n$ independent $\text{Gamma}(1/n, b)$ distributions equals $\text{Gamma}(1, b)$, each of the $n$ colleges locally samples:
$$z_i = \text{Gamma}(1/n, b) - \text{Gamma}(1/n, b)$$
When the $n$ colleges sum their secret shares and local noise terms, the total added noise is mathematically identical to a single calibrated $\text{Laplace}(0, b)$ noise term, with zero private count leakage.
