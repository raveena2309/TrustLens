# 🛡️ TrustLens: Dual-Layer Certificate Protection & Differential Privacy

A simplified, streamlined implementation of academic certificate protection, forensic tamper detection, and differential privacy covering **Modules 1, 4, and 5** of the syllabus.

---

## 💡 What it Does (In Simple Words)

1. **Issue**: A college generates a certificate. Behind the pixels, it hides an **RSA-signed, Geffe-encrypted copy** of the student record inside the image.
2. **Verify**: Anyone uploads the certificate to the app. The system extracts the hidden record, checks the digital signature, and compares all 1,800 image blocks ($32 \times 32$ pixels each).
   - If genuine: Shows **✅ GENUINE**.
   - If edited (e.g. CGPA changed): Highlights the exact tampered area in **🚨 RED**.
   - If compressed or resized: The robust DCT layer still recovers the **Certificate ID** (**⚠️ DAMAGED ORIGINAL**).
3. **Privacy**: Publishes college statistics with **Differential Privacy (Laplace Mechanism)** so individual student records can never be leaked.

---

## 📁 Simple Code Structure (Only 5 Core Files!)

| File | Purpose | Syllabus Module |
| :--- | :--- | :--- |
| **[`certificate.py`](file:///d:/Projects/TrustLens/certificate.py)** | Generates certificate image ($1600 \times 1152$) with collegiate seal and defines field layout | Image Processing |
| **[`crypto.py`](file:///d:/Projects/TrustLens/crypto.py)** | **RSA from Scratch** (Miller-Rabin, signing, key wrapping), **Diffie-Hellman**, **LFSR & Geffe**, **SHA-256**, **Berlekamp-Massey** | **Module 4** |
| **[`stego.py`](file:///d:/Projects/TrustLens/stego.py)** | **Fragile LSB Layer** ($32 \times 32$ block tamper detection, 7x majority voting) & **Robust DCT Layer** (QIM watermark surviving JPEG) | **Module 5** |
| **[`privacy.py`](file:///d:/Projects/TrustLens/privacy.py)** | **Laplace Mechanism** (inverse CDF), **Exponential Mechanism**, and **Privacy Budget Manager** | **Module 1** |
| **[`app.py`](file:///d:/Projects/TrustLens/app.py)** | Streamlit interactive web dashboard (Issue, Verify, and Interactive Demos) | UI / Demo |

---

## 🚀 How to Run

### 1. Install Dependencies
```powershell
pip install -r requirements.txt
```

### 2. Launch the Web Application
```powershell
streamlit run app.py
```
Open your browser at `http://localhost:8501`.

### 3. Run All Unit Tests
```powershell
python tests.py
```

### 4. Generate Pre-Packaged Test Certificates
```powershell
python generate_sample_data.py
```
Creates `genuine_certificate.png`, `forged_cgpa_certificate.png`, and `damaged_jpeg_quality75.jpg` in the `samples/` directory for instant testing in the UI.

---

## 🎯 Viva Q&A (Study Guide for Exams)

### Q1: Why do we use TWO steganographic layers?
- **Fragile LSB Layer**: Highly sensitive to tampering. If an attacker modifies even one digit (like CGPA from 9.42 to 9.98), that $32 \times 32$ block checksum fails and turns red on the tamper heatmap.
- **Robust DCT Layer**: Embedded into frequency coefficients. Survives lossy JPEG compression and resizing. Even if someone takes a photo or compresses the certificate, the Certificate ID is still recovered, proving it was originally genuine.

### Q2: Why is a single LFSR insecure, and how does the Geffe generator fix it?
- A single LFSR has a linear relationship. An attacker who sees just $2L$ bits can use the **Berlekamp-Massey algorithm** to completely crack the cipher.
- The **Geffe generator** combines 3 separate LFSRs non-linearly: $F(x_1, x_2, x_3) = (x_1 \land x_2) \oplus (\neg x_1 \land x_3)$. This destroys the linearity and defeats the Berlekamp-Massey attack.

### Q3: What is the 7x redundancy and majority voting?
- The signed payload is repeated 7 times inside the pixels.
- On extraction, the decoder looks at each bit position across the 7 copies and takes a **majority vote** (if $\ge 4$ copies say 1, the bit is 1).
- This allows the hidden student record to be recovered perfectly even if local parts of the image are edited or damaged!

### Q4: How does the Laplace mechanism protect privacy?
- To prevent an attacker from guessing if a specific student is in a small department, we add random noise drawn from the Laplace distribution: $\text{Noisy Count} = \text{True Count} + \text{Laplace}(0, 1/\varepsilon)$.
- Smaller $\varepsilon$ (epsilon) means more privacy (more noise); larger $\varepsilon$ means more accuracy (less noise).
