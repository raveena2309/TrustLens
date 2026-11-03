# TrustLens: Academic Credential Protection, Forensic Tamper Localization & Differential Privacy System
**Official Project Documentation & Comprehensive Codebase Architecture Reference**  
*Designed for Indian Institute of Information Technology, Nagpur (IIITN)*  
*Repository: [https://github.com/raveena2309/TrustLens](https://github.com/raveena2309/TrustLens)*

---

## 1. Executive Summary & Project Objectives

Academic credential fraud—ranging from grade point inflation to complete identity forgery—poses a critical challenge to universities, employers, and accreditation bodies worldwide. Traditional paper credentials are easily replicated, basic PDF files are easily manipulated using standard image editing tools, and standard QR codes can be trivially copied and pasted onto forged visual surfaces without detection.

**TrustLens** is an institutional-grade security, forensic verification, and privacy-preserving platform designed specifically for the **Indian Institute of Information Technology, Nagpur (IIITN)**. The platform introduces a multi-tier cryptographic architecture that embeds invisible authentication layers directly into the pixel structure of degree certificates while providing mathematical differential privacy guarantees for publicly released institutional metrics.

### Key Project Capabilities
1. **Dual-Layer Steganography:** Combines a robust DCT (Discrete Cosine Transform) frequency watermark that survives lossy JPEG compression with a fragile LSB (Least Significant Bit) layer that detects pixel-level modifications.
2. **32×32 Block Tamper Localization:** Computes SHA-256 block checksums across 1,800 image blocks, visually highlighting fraudulent alterations (such as inflated CGPA or altered names) on a high-resolution red forensic heatmap.
3. **From-Scratch Public-Key Cryptography:** Implements 1024-bit RSA digital signatures, key wrapping, and 2048-bit Diffie-Hellman session key exchange entirely from mathematical first principles.
4. **Non-Linear Stream Encryption:** Uses a Geffe Generator combining three Linear Feedback Shift Registers (LFSRs) to eliminate linear predictability and defeat Berlekamp-Massey cryptanalysis.
5. **Differential Privacy (DP):** Protects published department graduation counts via calibrated Laplace noise and implements the Exponential Mechanism for anonymous academic honors selection.
6. **Institutional SQLite Backend:** Backed by `trustlens.db` adhering to official IIITN enrollment formats (e.g. `BT22CSE045`).

---

## 2. System Architecture & End-to-End Workflow

```
┌──────────────────────────────────────────────────────────────────────────────────┐
│                             ISSUANCE PIPELINE                                    │
│                                                                                  │
│  [Student Record] ──▶ [RSA Sign & Geffe Stream Encrypt]                          │
│                                  │                                               │
│                                  ▼                                               │
│  [Render Certificate] ──▶ [Embed Robust DCT Watermark (ID)]                      │
│                                  │                                               │
│                                  ▼                                               │
│                         [Embed Fragile LSB Layer]                                │
│                         (1,800 32x32 Block Checksums)                            │
│                                  │                                               │
│                                  ▼                                               │
│                 [Final Protected Stego Certificate PNG]                          │
└──────────────────────────────────┬───────────────────────────────────────────────┘
                                   │
                                   ▼
┌──────────────────────────────────────────────────────────────────────────────────┐
│                           FORENSIC AUDIT PIPELINE                                │
│                                                                                  │
│  Uploaded / Queried Image                                                        │
│         │                                                                        │
│         ├─▶ Recompute 1,800 SHA-256 Block Checksums ──▶ Tamper Localization Map  │
│         │                                              (Red Heatmap if tampered) │
│         │                                                                        │
│         ├─▶ Extract RSA-Wrapped Stego Seed & Decrypt Payload                     │
│         │   └─▶ Verify RSA Digital Signature ──▶ Authentic Original Record       │
│         │                                                                        │
│         └─▶ Extract Robust DCT ID via Majority Voting                            │
│             └─▶ Identifies certificate even after lossy JPEG Q=75 compression    │
└──────────────────────────────────────────────────────────────────────────────────┘
```

### Phase A: Credential Issuance Pipeline
1. **Certificate Rendering:** The university registrar enters student records (Name, Roll Number, Degree Program, Year, CGPA). The system renders a 1600×1152 high-resolution institutional parchment certificate with ornate borders, emblems, and official seals.
2. **Robust Frequency Watermarking (DCT QIM):** The 16-byte Certificate ID (e.g. `IIITN-2026-0045`) is converted to 128 bits and embedded into mid-frequency DCT coefficients (3, 2) across 8×8 pixel blocks of the luminance ($Y$) channel using Quantization Index Modulation (QIM).
3. **Cryptographic Signature & Encryption:** The student record string is hashed with SHA-256 and digitally signed using the Issuer's RSA private key. The bundle (record + digital signature) is encrypted using the Geffe stream cipher keyed by a Diffie-Hellman session key.
4. **Fragile LSB Embedding & Block Checksums:** The encrypted payload is dispersed pseudo-randomly across pixel LSBs using a 128-bit seed. The seed itself is wrapped with the Verifier's RSA public key and stored in Row 1. Finally, each of the 1,800 blocks (32×32 pixels) has its upper 7 bit-planes hashed via SHA-256, storing 32-bit checksums in Row 0 LSBs.
5. **Database Storage:** The finalized stego PNG is stored alongside metadata in the SQLite database (`trustlens.db`).

### Phase B: Forensic Verification Pipeline
When an employer, university, or auditor uploads a certificate (or queries by roll number):
1. **Checksum Validation:** The system recomputes the SHA-256 checksum of every 32×32 block. Any altered pixels cause the block's checksum to fail, localizing the modification and painting a red bounding box onto the Tamper Localization Heatmap.
2. **Seed Unwrapping & Payload Decryption:** The RSA private key unwraps the stego seed from Row 1, allowing the hidden payload to be extracted and decrypted with the session key.
3. **RSA Digital Signature Verification:** The extracted RSA signature is checked against the issuer's public key. If the signature is valid, the authentic original record (even if the visual image was modified) is extracted and displayed side-by-side with the visual surface.
4. **Robust Watermark Recovery:** If fragile LSBs were destroyed by lossy compression (such as converting to JPEG Q=75), the robust DCT extractor recovers the 16-byte Certificate ID via majority voting across redundant 8×8 blocks, proving the certificate originated from IIIT Nagpur.

---

## 3. The Four Application Portals in the Dashboard

The web application (`app.py`) is structured into four distinct, role-based portals designed with warm cream and espresso institutional styling with adaptive Dark Mode support:

| Portal | Target Role | Primary Capabilities |
| :--- | :--- | :--- |
| **🏛️ Administration Portal** | Office of the Registrar & Academic Office | Issue official certificates, validate roll numbers (`BTxxYYYxxx`), inspect SQLite database registry, and audit uploaded or stored certificates with red heatmap tamper localization. |
| **🎓 Student Portal** | Enrolled & Graduated Students | Query official degree credentials by entering University Roll Number (e.g. `BT22CSE045`). Displays degree records and provides one-click official PNG download. |
| **🧪 Tamper Lab (Forgery Simulator)** | Security Evaluators & Examiners | Simulate realistic credential attacks: grade point inflation (CGPA to 9.98), student name identity forgery, verification seal occlusion, and lossy JPEG compression. Download forged certificate for forensic testing. |
| **🛡️ Security & Privacy in Action** | Students, Faculty & Auditors | Interactive demonstrations of Laplace Differential Privacy for department statistics, Exponential Mechanism for honors selection, Geffe stream cipher encryption of student records, and Diffie-Hellman key handshake. |

---

## 4. Comprehensive File-by-File Breakdown (Every File in Git)

### 1. `app.py` — Main Web Application Dashboard (Streamlit)
- **Role:** Orchestrates the graphical user interface, state management, and interaction between modules.
- **Theme:** Custom institutional CSS with CSS variables supporting Light Mode (cream/espresso `#FAF7F2`) and Dark Mode (obsidian/slate/gold `#0F141C`).
- **Portals:** Contains all 4 interactive tabs:
  - Tab 1: Administration Portal (Issue, Audit, Registry).
  - Tab 2: Student Credential Retrieval.
  - Tab 3: Tamper Lab (Attack simulation and forged certificate export).
  - Tab 4: Security & Privacy in Action (Differential Privacy and Cryptography).
- **Caching:** Uses `@st.cache_resource` for persistent institutional keys and instant database loading.

### 2. `certificate.py` — Institutional Certificate Generation Engine
- **Role:** Renders authentic, high-resolution (1600×1152) IIIT Nagpur degree certificates using Pillow (PIL).
- **Visual Elements:** Mathematical parchment texture generation (subtle Gaussian-like background noise), multi-layered ornate borders, decorative corner florets, golden institute verification seal, and official university typography.
- **`FIELD_LAYOUT` Dictionary:** Defines exact bounding boxes for `name`, `roll`, `degree`, `year`, `cgpa`, and `cert_id`.
- **`_get_font(name, size)`:** Implements cross-platform font loading with fallback across Windows (`C:\Windows\Fonts`), Linux (`/usr/share/fonts/truetype/dejavu`), and macOS.

### 3. `crypto.py` — Core Cryptographic Algorithms from Scratch
- **Role:** Pure-Python cryptographic implementations without high-level wrapper libraries.
- **RSA Public-Key:**
  - `is_prime(n, k=20)`: Miller-Rabin probabilistic primality test.
  - `generate_prime(bits)`: Generates cryptographically secure random primes.
  - `rsa_keygen(bits=1024)`: Generates RSA public and private key pairs ($n, e, d$).
  - `rsa_sign(data, priv)`: Computes SHA-256 digest and signs using private exponent $d$.
  - `rsa_verify(data, sig, pub)`: Verifies signature against public exponent $e$.
  - `rsa_wrap_key()` / `rsa_unwrap_key()`: Asymmetric key encapsulation for stego seeds.
- **Diffie-Hellman Key Agreement:**
  - Standard 2048-bit MODP Group 14 parameters ($p, g=2$).
  - `dh_generate_keypair()`: Generates private exponent and public value $A = g^a \bmod p$.
  - `dh_shared_secret()`: Computes shared secret $K = B^a \bmod p$ and hashes to a 256-bit symmetric key.
- **Stream Cipher & Cryptanalysis:**
  - `LFSR`: Linear Feedback Shift Register class with configurable taps and state.
  - `GeffeGenerator`: Combines three LFSRs non-linearly: $z = (x_1 \land x_2) \oplus (\neg x_1 \land x_3)$.
  - `geffe_encrypt(data, key)`: Encrypts and decrypts by XORing with the Geffe keystream.
  - `berlekamp_massey(bits)`: Computes linear complexity $L$, demonstrating that a single 19-bit LFSR is broken in 38 bits while Geffe achieves high non-linear complexity.

### 4. `database.py` — SQLite Database Backend (`trustlens.db`)
- **Role:** Manages persistent certificate storage, credential querying, and schema validation.
- **Schema:** Table `certificates` storing `roll_number` (PRIMARY KEY), `student_name`, `degree_program`, `graduation_year`, `cgpa`, `certificate_id`, `image_png` (BLOB), and `issued_at` timestamp.
- **Roll Validation:** `is_valid_iiitn_roll()` enforces the university format `BTxxYYYxxx` (e.g. `BT22CSE045`).
- **Functions:** `init_db()`, `save_certificate()`, `get_certificate()`, `get_all_records()`, and `seed_initial_records_if_empty()`.

### 5. `stego.py` — Dual-Layer Steganography & Tamper Localization Engine
- **Role:** Embeds hidden digital signatures and watermarks into certificates and runs the forensic verification audit.
- **Robust DCT Layer:** `embed_dct_id()` and `extract_dct_id()` embed a standardized 16-byte Certificate ID into 8×8 DCT mid-frequency coefficient (3, 2) of the luminance ($Y$) channel using Quantization Index Modulation (QIM). Survives lossy JPEG compression down to Quality 75.
- **Fragile LSB Layer:** `embed_lsb_and_checksums()` stores 7x majority-voted payload bits and 32-bit SHA-256 checksums across all 1,800 blocks of 32×32 pixels.
- **Verification & Localization:** `verify_blocks()` recomputes block checksums, flags corrupted blocks on a boolean grid, and renders the alpha-composite red highlight heatmap.
- **Pipeline Wrappers:** `issue_certificate_full()` and `verify_certificate_full()` returning verdicts (`GENUINE`, `FORGED / EDITED`, `DAMAGED ORIGINAL`, or `NOT A TRUSTLENS CERTIFICATE`).

### 6. `privacy.py` — Differential Privacy (DP) Engine
- **Role:** Provides mathematical confidentiality guarantees for published college statistics.
- **Laplace Mechanism:** `laplace_mechanism(true_value, epsilon, sensitivity=1.0)` injects calibrated Laplace noise $\text{Lap}(0, \Delta f / \epsilon)$.
- **Exponential Mechanism:** `exponential_mechanism(score_dict, epsilon, sensitivity=1.0)` samples non-numeric winners (such as Department of the Year) proportional to $\exp(\epsilon \cdot u(r) / 2\Delta u)$.
- **Privacy Budget Manager:** `PrivacyBudget` class tracking total consumed $\epsilon$ against max threshold (5.0 $\epsilon$) to prevent reconstruction attacks.

### 7. `tests.py` — Comprehensive Automated Unit Test Suite
- **Role:** Validates cryptographic correctness and steganographic integrity across 5 core unit test cases (`unittest.TestCase`):
  1. `test_rsa_and_dh`: Tests RSA signing, verification, key wrapping, and Diffie-Hellman key agreement.
  2. `test_lfsr_geffe_and_berlekamp`: Verifies LFSR linear complexity = 4 via Berlekamp-Massey and validates Geffe stream encryption.
  3. `test_dct_robust_id`: Tests DCT ID embedding and verifies survival after JPEG Q=80 lossy compression.
  4. `test_end_to_end_pipeline_and_tampering`: Issues an authentic certificate, verifies GENUINE (0 failed blocks), tampers the CGPA pixels, and asserts FORGED verdict with failed blocks > 0.
  5. `test_privacy_laplace_and_budget`: Tests Laplace noise generation, sensitivity bounds, and privacy budget refusal when budget is exhausted.

### 8. `generate_sample_data.py` — Data & Benchmark Generation Utility
- **Role:** Generates benchmarking datasets, CSV metrics in `results/`, and reference certificate samples in `samples/`.
- **Metrics Tested:** Steganographic payload capacity, stream cipher linear complexity, JPEG compression resistance, image quality (PSNR, SSIM), and differential privacy error deviation.

### 9. `institutional_keys.json` — Persistent Cryptographic Authority Key Store
- **Role:** Stores the institutional RSA private/public keys for the degree issuer (Registrar), the verifier portal, and the symmetric Diffie-Hellman session key.
- **Purpose:** Ensures digital signatures and watermark seeds remain cryptographically verifiable across server restarts, re-deployments, and sessions.

### 10. `trustlens.db` — SQLite Database File
- **Role:** Binary SQLite database containing pre-seeded IIIT Nagpur degree certificates (`BT22CSE045 - Aarav Sharma`, `BT22ECE018 - Priya Deshmukh`, `BT22CSB027 - Rohan Verma`, `BT24CSD022 - Raveena B`).
- **Optimization:** Pre-seeding eliminates cold-boot generation delays on cloud platforms like Render.

### 11. `packages.txt` — Linux Cloud System Dependencies
- **Role:** Declares Debian/Ubuntu system packages required by Streamlit Community Cloud and Render: `libgl1`, `libglib2.0-0`, and `fonts-dejavu-core`.

### 12. `requirements.txt` — Python Package Dependencies
- **Role:** Specifies required Python libraries: `streamlit>=1.30.0`, `numpy>=1.24.0`, `pillow>=10.0.0`, `opencv-python-headless>=4.8.0`, and `pandas>=2.0.0`.

### 13. `README.md` — GitHub Project Documentation
- **Role:** Comprehensive project overview, quickstart instructions, theoretical formulas, screenshots, and security specifications for GitHub visitors.

### 14. `results/` (Directory) — Experimental Metrics & Evaluation Plots
- **CSV Files:** `capacity.csv`, `cipher_strength.csv`, `compression.csv`, `image_quality.csv`, `privacy_laplace.csv`, `redundancy.csv`, `rejection.csv`.
- **Plots:** `plot_image_quality.png`, `plot_privacy_error.png`, `plot_redundancy.png` documenting scientific evaluation.

### 15. `samples/` (Directory) — Reference Test Certificates
- **Files:** `genuine_certificate.png`, `forged_cgpa_certificate.png`, `forged_name_certificate.png`, `block_tampered_certificate.png`, `damaged_jpeg_quality75.jpg`.

---

## 5. Theoretical Foundations & Mathematical Formulations

### A. Robust DCT Quantization Index Modulation (QIM)
For each 8×8 block in the luminance channel $Y$, 2D Discrete Cosine Transform is computed. Coefficient (3, 2) is quantized via step $q=24.0$:
$$k = \text{round}\left(\frac{\text{DCT}[3, 2]}{q}\right)$$
If $(k \bmod 2) \ne \text{target\_bit}$, $k$ is adjusted by $\pm 1$:
$$\text{DCT}'[3, 2] = k \cdot q$$
Majority voting across redundant blocks guarantees bit recovery even after lossy JPEG compression down to Quality 75.

### B. Fragile Block Hash & Localization
The certificate is divided into 1,800 blocks of 32×32 pixels (50 columns × 36 rows). For block $(r, c)$:
$$\text{checksum} = \text{SHA-256}(\text{Block\_Pixels} \gg 1)[0..4]$$
The 32-bit checksum is embedded into the row 0 LSBs of that block. During verification, any alteration to font, numbers, or seals modifies the upper 7 bit-planes, causing the recomputed checksum to mismatch and highlighting the 32×32 region in red.

### C. Geffe Generator Non-Linear Multiplexer
Combines three LFSRs of lengths $L_1, L_2, L_3$ using the non-linear Boolean function:
$$z = (x_1 \land x_2) \oplus (\neg x_1 \land x_3)$$
While a single LFSR with length $L$ has linear complexity $L$ (broken in $2L$ bits by Berlekamp-Massey), the Geffe combiner achieves linear complexity $L \approx L_1 L_2 + (1 + L_2)L_3$, resisting linear cryptanalysis.

### D. Differential Privacy Guarantees
A randomized algorithm $M$ satisfies $\epsilon$-Differential Privacy if for all neighboring datasets $D, D'$ differing on at most one individual record:
$$\Pr[M(D) \in S] \le e^\epsilon \cdot \Pr[M(D') \in S]$$
- **Laplace Mechanism:** $M(D) = f(D) + \text{Lap}\left(0, \frac{\Delta f}{\epsilon}\right)$
- **Exponential Mechanism:** $\Pr[M(D) = r] \propto \exp\left(\frac{\epsilon \cdot u(D, r)}{2 \Delta u}\right)$

---

## 6. How to Run, Test, and Deploy the Project

1. **Localhost Execution:**
   ```bash
   streamlit run app.py
   ```
   Opens live on [http://localhost:8501](http://localhost:8501).

2. **Automated Unit Testing:**
   ```bash
   python tests.py
   ```
   Executes 5 unit tests verifying RSA, DH, Geffe, DCT, Tamper detection, and Laplace DP.

3. **Cloud Deployment:**
   - **Render Live URL:** [https://trustlens-vnh6.onrender.com](https://trustlens-vnh6.onrender.com)
   - Every commit pushed to GitHub `origin/main` automatically triggers continuous deployment.
