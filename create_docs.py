import docx
from docx.shared import Inches, Pt, RGBColor
from docx.enum.text import WD_ALIGN_PARAGRAPH
from docx.enum.table import WD_TABLE_ALIGNMENT, WD_ALIGN_VERTICAL
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

def set_cell_background(cell, fill_hex):
    tcPr = cell._tc.get_or_add_tcPr()
    shd = OxmlElement('w:shd')
    shd.set(qn('w:val'), 'clear')
    shd.set(qn('w:color'), 'auto')
    shd.set(qn('w:fill'), fill_hex)
    tcPr.append(shd)

def create_document():
    doc = docx.Document()

    # Page Margins
    for section in doc.sections:
        section.top_margin = Inches(1)
        section.bottom_margin = Inches(1)
        section.left_margin = Inches(1)
        section.right_margin = Inches(1)

    # Styles
    normal_style = doc.styles['Normal']
    normal_style.font.name = 'Calibri'
    normal_style.font.size = Pt(11)
    normal_style.font.color.rgb = RGBColor(0x2C, 0x1E, 0x14)

    # Title
    title_p = doc.add_paragraph()
    title_p.paragraph_format.space_before = Pt(0)
    title_p.paragraph_format.space_after = Pt(4)
    title_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_title = title_p.add_run("TrustLens: Academic Credential Protection, Forensic Tamper Localization & Differential Privacy System")
    run_title.font.name = 'Georgia'
    run_title.font.size = Pt(22)
    run_title.font.bold = True
    run_title.font.color.rgb = RGBColor(0x38, 0x28, 0x1C)

    # Subtitle
    sub_p = doc.add_paragraph()
    sub_p.paragraph_format.space_after = Pt(18)
    sub_p.alignment = WD_ALIGN_PARAGRAPH.CENTER
    run_sub = sub_p.add_run("Official Project Documentation & Comprehensive Codebase Architecture Reference\nDesigned for Indian Institute of Information Technology, Nagpur (IIITN)")
    run_sub.font.name = 'Calibri'
    run_sub.font.size = Pt(12)
    run_sub.font.italic = True
    run_sub.font.color.rgb = RGBColor(0x6B, 0x52, 0x3E)

    doc.add_paragraph("—" * 55).alignment = WD_ALIGN_PARAGRAPH.CENTER

    # SECTION 1
    h1 = doc.add_heading("1. Executive Summary & Project Objectives", level=1)
    h1.paragraph_format.space_before = Pt(14)
    h1.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "Academic credential fraud—ranging from grade point inflation to complete identity forgery—poses a critical "
        "challenge to universities, employers, and accreditation bodies worldwide. Traditional paper credentials are easily "
        "replicated, basic PDF files are easily manipulated using standard image editing tools, and standard QR codes can be "
        "trivially copied and pasted onto forged visual surfaces."
    )
    doc.add_paragraph(
        "TrustLens is an institutional-grade security, forensic verification, and privacy-preserving platform designed "
        "specifically for the Indian Institute of Information Technology, Nagpur (IIITN). The platform introduces a multi-tier "
        "cryptographic architecture that embeds invisible authentication layers directly into the pixel structure of degree certificates "
        "while providing differential privacy guarantees for publicly released institutional data."
    )

    # Key Objectives Bullet Points
    doc.add_paragraph("Core Project Innovations & Capabilities:", style='List Bullet')
    p = doc.add_paragraph("Dual-Layer Steganography: Combines a robust DCT (Discrete Cosine Transform) frequency watermark that survives lossy JPEG compression with a fragile LSB (Least Significant Bit) layer that detects pixel-level modifications.", style='List Bullet 2')
    p = doc.add_paragraph("32×32 Block Tamper Localization: Computes SHA-256 block checksums across 1,800 image blocks, visually highlighting fraudulent alterations (e.g., inflated CGPA or altered names) on a high-resolution red forensic heatmap.", style='List Bullet 2')
    p = doc.add_paragraph("From-Scratch Public-Key Cryptography: Implements 1024-bit RSA digital signatures, key wrapping, and 2048-bit Diffie-Hellman session key exchange entirely from mathematical first principles.", style='List Bullet 2')
    p = doc.add_paragraph("Non-Linear Stream Encryption: Uses a Geffe Generator combining three Linear Feedback Shift Registers (LFSRs) to defeat Berlekamp-Massey cryptanalysis.", style='List Bullet 2')
    p = doc.add_paragraph("Differential Privacy (DP): Protects published department graduation counts via calibrated Laplace noise and implements the Exponential Mechanism for anonymous academic honors selection.", style='List Bullet 2')
    p = doc.add_paragraph("Institutional SQLite Backend: Backed by 'trustlens.db' adhering to official IIITN enrollment formats (e.g. BT22CSE045).", style='List Bullet 2')

    # SECTION 2
    h2 = doc.add_heading("2. System Architecture & End-to-End Workflow", level=1)
    h2.paragraph_format.space_before = Pt(14)
    h2.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "The TrustLens workflow operates across three primary phases: Issuance, Distribution/Retrieval, and Forensic Verification."
    )

    # Workflow Steps
    doc.add_heading("Phase A: Credential Issuance Pipeline", level=2)
    doc.add_paragraph(
        "1. Certificate Rendering: The university registrar enters student records (Name, Roll Number, Degree Program, Year, CGPA). "
        "The system renders a 1600×1152 high-resolution institutional parchment certificate with ornate borders, emblems, and official seals.\n"
        "2. Robust Frequency Watermarking (DCT QIM): The 16-byte Certificate ID (e.g. 'IIITN-2026-0045') is converted to 128 bits and "
        "embedded into mid-frequency DCT coefficients (3, 2) across 8×8 pixel blocks of the luminance (Y) channel using Quantization Index Modulation (QIM).\n"
        "3. Cryptographic Signature & Encryption: The student record string is hashed with SHA-256 and digitally signed using the Issuer's RSA private key. "
        "The bundle (record + digital signature) is encrypted using the Geffe stream cipher keyed by a Diffie-Hellman session key.\n"
        "4. Fragile LSB Embedding & Block Checksums: The encrypted payload is dispersed pseudo-randomly across pixel LSBs using a 128-bit seed. "
        "The seed itself is wrapped with the Verifier's RSA public key and stored in Row 1. Finally, each of the 1,800 blocks (32×32 pixels) has its "
        "upper 7 bit-planes hashed via SHA-256, storing 32-bit checksums in Row 0 LSBs.\n"
        "5. Database Storage: The finalized stego PNG is stored alongside metadata in the SQLite database ('trustlens.db')."
    )

    doc.add_heading("Phase B: Forensic Verification Pipeline", level=2)
    doc.add_paragraph(
        "When an employer or auditor uploads a certificate (or queries by roll number):\n"
        "1. Checksum Validation: The system recomputes the SHA-256 checksum of every 32×32 block. Any altered pixels cause the block's checksum "
        "to fail, localizing the modification and painting a red bounding box onto the Tamper Localization Heatmap.\n"
        "2. Seed Unwrapping & Payload Decryption: The RSA private key unwraps the stego seed from Row 1, allowing the hidden payload to be extracted "
        "and decrypted with the session key.\n"
        "3. RSA Digital Signature Verification: The extracted RSA signature is checked against the issuer's public key. If the signature is valid, "
        "the authentic original record (even if the visual image was modified) is extracted and compared side-by-side with the visual surface.\n"
        "4. Robust Watermark Recovery: If fragile LSBs were destroyed by lossy compression (such as converting to JPEG Q=75), the robust DCT extractor "
        "recovers the 16-byte Certificate ID via majority voting across redundant 8×8 blocks, proving the certificate originated from IIIT Nagpur."
    )

    # SECTION 3
    h3 = doc.add_heading("3. The Four Application Portals in the Web Dashboard", level=1)
    h3.paragraph_format.space_before = Pt(14)
    h3.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "The web application (app.py) is structured into four distinct, role-based portals designed with warm cream and espresso institutional styling "
        "with adaptive Dark Mode support:"
    )

    # Table of Portals
    table = doc.add_table(rows=5, cols=3)
    table.alignment = WD_TABLE_ALIGNMENT.CENTER
    headers = ["Portal Name", "Target User / Role", "Primary Functions & Capabilities"]
    for i, h in enumerate(headers):
        cell = table.cell(0, i)
        cell.text = h
        set_cell_background(cell, "38281C")
        for p in cell.paragraphs:
            for r in p.runs:
                r.font.bold = True
                r.font.color.rgb = RGBColor(0xFF, 0xFF, 0xFF)

    portal_data = [
        ("🏛️ Administration Portal", "Office of the Registrar & Academic Office", "Issue official certificates, validate roll numbers (BTxxYYYxxx), inspect SQLite database registry, and audit uploaded or stored certificates with red heatmap tamper localization."),
        ("🎓 Student Portal", "Enrolled & Graduated Students", "Query official degree credentials by entering University Roll Number (e.g. BT22CSE045). Displays degree records and provides one-click official PNG download."),
        ("🧪 Tamper Lab (Forgery Simulator)", "Security Evaluators & Examiners", "Simulate realistic credential attacks: grade point inflation (CGPA to 9.98), student name identity forgery, verification seal occlusion, and lossy JPEG compression. Download forged certificate for forensic testing."),
        ("🛡️ Security & Privacy in Action", "Students, Faculty & Auditors", "Interactive demonstrations of Laplace Differential Privacy for department statistics, Exponential Mechanism for honors selection, Geffe stream cipher encryption of student records, and Diffie-Hellman key handshake.")
    ]

    for row_idx, data in enumerate(portal_data, start=1):
        for col_idx, text in enumerate(data):
            cell = table.cell(row_idx, col_idx)
            cell.text = text
            if row_idx % 2 == 0:
                set_cell_background(cell, "FAF7F2")

    # SECTION 4
    h4 = doc.add_heading("4. Comprehensive File-by-File Breakdown of the Git Repository", level=1)
    h4.paragraph_format.space_before = Pt(16)
    h4.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "Every file in the repository has a dedicated, modular role in the TrustLens architecture. Below is a detailed breakdown of each file:"
    )

    files_info = [
        ("app.py", "Main Web Application Dashboard (Streamlit)", [
            "Role: Orchestrates the graphical user interface, state management, and interaction between modules.",
            "Theme: Custom institutional CSS with CSS variables supporting Light Mode (cream/espresso) and Dark Mode (obsidian/slate/gold).",
            "Key Logic: Integrates all 4 tabs (Administration, Student Portal, Tamper Lab, Security & Privacy System).",
            "Caching: Uses @st.cache_resource for persistent system key loading and fast database boot."
        ]),
        ("certificate.py", "Institutional Certificate Image Generation Engine", [
            "Role: Renders authentic, high-resolution (1600×1152) IIIT Nagpur degree certificates using Pillow (PIL).",
            "Features: Mathematical parchment texture generation (subtle Gaussian-like background noise), multi-layered ornate borders, decorative corner florets, golden institute verification seal, and university typography.",
            "Key Constants: FIELD_LAYOUT defining exact bounding boxes for 'name', 'roll', 'degree', 'year', 'cgpa', and 'cert_id'.",
            "Key Function _get_font(): Implements cross-platform font loading with fallback across Windows (C:\\Windows\\Fonts), Linux (/usr/share/fonts/truetype/dejavu), and macOS."
        ]),
        ("crypto.py", "Core Cryptographic Algorithms from Scratch", [
            "Role: Contains pure-Python cryptographic implementations without high-level wrapper libraries.",
            "RSA Public-Key: Miller-Rabin primality test (is_prime), prime generation (generate_prime), keygen (rsa_keygen), signing with SHA-256 (rsa_sign), verification (rsa_verify), and key wrapping (rsa_wrap_key, rsa_unwrap_key).",
            "Diffie-Hellman Key Agreement: 2048-bit MODP Group 14 parameters, keypair generation (dh_generate_keypair), and shared secret derivation (dh_shared_secret).",
            "Stream Cipher: Linear Feedback Shift Register (LFSR class), Geffe Generator combining 3 registers non-linearly (GeffeGenerator class, geffe_encrypt), and Berlekamp-Massey cryptanalysis algorithm (berlekamp_massey)."
        ]),
        ("database.py", "SQLite Database Backend (trustlens.db)", [
            "Role: Manages persistent certificate storage, credential querying, and schema validation.",
            "Schema: Table 'certificates' storing roll_number (PK), student_name, degree_program, graduation_year, cgpa, certificate_id, image_png (BLOB), and issued_at timestamp.",
            "Roll Validation: is_valid_iiitn_roll() enforces the university format 'BTxxYYYxxx' (BT + 2-digit year + Department code + 3-digit number).",
            "Functions: init_db(), save_certificate(), get_certificate(), get_all_records(), and seed_initial_records_if_empty()."
        ]),
        ("stego.py", "Dual-Layer Steganography & Tamper Localization Engine", [
            "Role: Embeds hidden digital signatures and watermarks into certificates and runs the forensic verification audit.",
            "Robust DCT Layer: embed_dct_id() and extract_dct_id() embed a 16-byte fixed ID into 8×8 DCT mid-frequency coefficient (3, 2) using Quantization Index Modulation (QIM). Survives lossy JPEG compression down to Quality 75.",
            "Fragile LSB Layer: embed_lsb_and_checksums() stores 7x majority-voted payload bits and 32-bit SHA-256 checksums across all 1,800 blocks of 32×32 pixels.",
            "Verification & Localization: verify_blocks() recomputes block checksums, flags corrupted blocks on a boolean grid, and renders the alpha-composite red highlight heatmap.",
            "Pipeline Wrappers: issue_certificate_full() and verify_certificate_full() returning verdicts ('GENUINE', 'FORGED / EDITED', 'DAMAGED ORIGINAL', or 'NOT A TRUSTLENS CERTIFICATE')."
        ]),
        ("privacy.py", "Differential Privacy (DP) Engine", [
            "Role: Provides mathematical confidentiality guarantees for published college statistics.",
            "Laplace Mechanism: laplace_mechanism(true_value, epsilon, sensitivity=1.0) injects calibrated Laplace noise Lap(0, sensitivity / epsilon).",
            "Exponential Mechanism: exponential_mechanism(score_dict, epsilon, sensitivity=1.0) samples non-numeric winners (e.g. Department of the Year) proportional to exp(epsilon * score / 2).",
            "Privacy Budget Manager: PrivacyBudget class tracking total consumed epsilon against max threshold (e.g. 5.0 epsilon) to prevent reconstruction attacks."
        ]),
        ("tests.py", "Comprehensive Automated Unit Test Suite", [
            "Role: Validates cryptographic correctness and steganographic integrity across 5 core test cases.",
            "test_rsa_and_dh: Tests RSA signing, signature verification, key wrapping, and Diffie-Hellman shared secret agreement.",
            "test_lfsr_geffe_and_berlekamp: Verifies LFSR linear complexity = 4 via Berlekamp-Massey and validates Geffe stream encryption/decryption.",
            "test_dct_robust_id: Tests DCT ID embedding and verifies survival after JPEG Q=80 lossy compression.",
            "test_end_to_end_pipeline_and_tampering: Issues an authentic certificate, verifies GENUINE (0 failed blocks), tampers the CGPA pixels, and asserts FORGED verdict with failed blocks > 0.",
            "test_privacy_laplace_and_budget: Tests Laplace noise generation, sensitivity bounds, and privacy budget refusal when budget is exhausted."
        ]),
        ("generate_sample_data.py", "Data & Benchmark Generation Utility", [
            "Role: Generates benchmarking datasets, CSV metrics in results/, and reference certificate samples in samples/.",
            "Metrics Tested: Steganographic payload capacity, stream cipher linear complexity, JPEG compression resistance, image quality (PSNR, SSIM), and differential privacy error deviation."
        ]),
        ("institutional_keys.json", "Persistent Cryptographic Authority Key Store", [
            "Role: Stores the institutional RSA private/public keys for the degree issuer (Registrar), the verifier portal, and the symmetric Diffie-Hellman session key.",
            "Purpose: Ensures digital signatures and watermark seeds remain cryptographically verifiable across server restarts, re-deployments, and sessions."
        ]),
        ("trustlens.db", "SQLite Database File", [
            "Role: Binary SQLite database containing pre-seeded IIIT Nagpur degree certificates (Aarav Sharma BT22CSE045, Priya Deshmukh BT22ECE018, Rohan Verma BT22CSB027, Raveena B BT24CSD022).",
            "Optimization: Pre-seeding eliminates cold-boot generation delays on cloud platforms like Render."
        ]),
        ("packages.txt", "Linux Cloud System Dependencies", [
            "Role: Declares Debian/Ubuntu system packages required by Streamlit Community Cloud and Render: libgl1, libglib2.0-0, and fonts-dejavu-core."
        ]),
        ("requirements.txt", "Python Package Dependencies", [
            "Role: Specifies required Python libraries: streamlit>=1.30.0, numpy>=1.24.0, pillow>=10.0.0, opencv-python-headless>=4.8.0, and pandas>=2.0.0."
        ]),
        ("README.md", "GitHub Project Documentation", [
            "Role: Comprehensive project overview, quickstart instructions, theoretical formulas, screenshots, and security specifications for GitHub visitors."
        ]),
        ("results/ (Folder)", "Experimental Metrics & Evaluation Plots", [
            "CSV Files: capacity.csv, cipher_strength.csv, compression.csv, image_quality.csv, privacy_laplace.csv, redundancy.csv, rejection.csv.",
            "Plots: plot_image_quality.png, plot_privacy_error.png, plot_redundancy.png documenting scientific rigor."
        ]),
        ("samples/ (Folder)", "Reference Test Certificates", [
            "PNG/JPEG Files: genuine_certificate.png, forged_cgpa_certificate.png, forged_name_certificate.png, block_tampered_certificate.png, damaged_jpeg_quality75.jpg."
        ])
    ]

    for fname, fdesc, fpoints in files_info:
        doc.add_heading(f"📄 {fname} — {fdesc}", level=2)
        for pt in fpoints:
            doc.add_paragraph(pt, style='List Bullet')

    # SECTION 5
    h5 = doc.add_heading("5. Theoretical Foundations & Mathematical Formulations", level=1)
    h5.paragraph_format.space_before = Pt(16)
    h5.paragraph_format.space_after = Pt(6)

    doc.add_paragraph("Below are the mathematical models implemented within TrustLens:")

    doc.add_heading("A. Robust DCT Quantization Index Modulation (QIM)", level=2)
    doc.add_paragraph(
        "For each 8×8 block in the luminance channel Y, 2D Discrete Cosine Transform is computed. Coefficient (3, 2) is quantized via step q:\n"
        "k = round(DCT[3, 2] / q)\n"
        "If (k mod 2) != target_bit, k is adjusted by ±1.\n"
        "DCT'[3, 2] = k * q\n"
        "Majority voting across redundant blocks guarantees bit recovery even after JPEG coefficient truncation."
    )

    doc.add_heading("B. Fragile Block Hash & Localization", level=2)
    doc.add_paragraph(
        "The certificate is divided into 1,800 blocks of 32×32 pixels (50 columns × 36 rows). For block (r, c):\n"
        "checksum = SHA-256(Block_Pixels >> 1)[0..4]\n"
        "The 32-bit checksum is embedded into the row 0 LSBs of that block. During verification, any alteration to font, numbers, or seals "
        "modifies the upper 7 bit-planes, causing the recomputed checksum to mismatch and highlighting the 32×32 region in red."
    )

    doc.add_heading("C. Geffe Generator Non-Linear Multiplexer", level=2)
    doc.add_paragraph(
        "Combines three LFSRs of lengths L1, L2, L3 using the non-linear Boolean function:\n"
        "z = (x1 ∧ x2) ⊕ (¬x1 ∧ x3)\n"
        "While a single LFSR with length L has linear complexity L (broken in 2L bits by Berlekamp-Massey), "
        "the Geffe combiner achieves linear complexity L ≈ L1·L2 + (1 + L2)·L3, resisting linear cryptanalysis."
    )

    doc.add_heading("D. Differential Privacy Guarantees", level=2)
    doc.add_paragraph(
        "A mechanism M satisfies ε-Differential Privacy if for any two neighboring datasets D and D' differing by one student:\n"
        "Pr[M(D) ∈ S] ≤ exp(ε) · Pr[M(D') ∈ S]\n"
        "Laplace Mechanism: M(D) = f(D) + Lap(0, Δf / ε)\n"
        "Exponential Mechanism: Pr[M(D) = r] ∝ exp( ε · u(D, r) / (2 · Δu) )"
    )

    # SECTION 6
    h6 = doc.add_heading("6. How to Run, Test, and Deploy the Project", level=1)
    h6.paragraph_format.space_before = Pt(16)
    h6.paragraph_format.space_after = Pt(6)

    doc.add_paragraph(
        "1. Localhost Execution:\n"
        "   Command: streamlit run app.py\n"
        "   Opens live on: http://localhost:8501\n\n"
        "2. Automated Testing:\n"
        "   Command: python tests.py\n"
        "   Executes 5 unit tests verifying RSA, DH, Geffe, DCT, Tamper detection, and Laplace DP.\n\n"
        "3. Cloud Deployment:\n"
        "   The repository is connected to Render (https://trustlens-vnh6.onrender.com) and Streamlit Community Cloud. "
        "   Every commit pushed to GitHub origin/main triggers automatic continuous deployment."
    )

    # Save Document
    doc_path = "TrustLens_Project_Documentation.docx"
    doc.save(doc_path)
    print(f"Documentation generated successfully at: {doc_path}")

create_document()
