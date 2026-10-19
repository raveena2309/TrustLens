"""Trust Lab: TrustLens+ Interactive Demonstration Web Application.
Built with Streamlit and Plotly covering Modules 1, 4, and 5 of the syllabus.

Tabs:
1. Issue & Verify: End-to-end certificate issuance, forgery attack simulation, and verification engine.
2. Hiding Lab: Comparative steganography (LSB, Edge-Adaptive, BPCS, DCT-QIM, Spread Spectrum, Reversible).
3. Crypto Lab: Diffie-Hellman, LFSR, Geffe, Berlekamp-Massey, Classical Ciphers, Cardan Grille, Rule 30 CA.
4. Privacy Lab: Laplace mechanism, Exponential mechanism, Randomized Response, Budgeting, Multiparty SMC.
"""

import io
import math
import random
import numpy as np
import pandas as pd
import streamlit as st
import streamlit.components.v1 as components
import plotly.express as px
import plotly.graph_objects as go
from PIL import Image

# TrustLens modules
from trustlens.certificate import generate_certificate, FIELD_LAYOUT
from trustlens.crypto.rsa_scratch import generate_keypair
from trustlens.crypto.dh import DiffieHellman, create_dh_session, DH_DEMO_P, DH_DEMO_G
from trustlens.crypto.lfsr import LFSR, GeffeGenerator, berlekamp_massey
from trustlens.crypto.classical import (
    caesar_encrypt, caesar_decrypt, caesar_break,
    beaufort_encrypt, beaufort_decrypt,
    columnar_encrypt, columnar_decrypt
)
from trustlens.crypto.classical_more import (
    monoalphabetic_encrypt, monoalphabetic_decrypt, monoalphabetic_break,
    generate_monoalphabetic_key,
    homophonic_encrypt, homophonic_decrypt, homophonic_frequency_analysis,
    polyphonic_encrypt, polyphonic_decrypt,
    CardanGrille, to_cycles, from_cycles
)
from trustlens.crypto.cellular import Rule30Keystream, compare_stream_generators
from trustlens.stego.metrics import compute_metrics, compute_psnr, compute_ssim
from trustlens.stego.lsb import embed_lsb, extract_lsb
from trustlens.stego.bpcs import embed_bpcs, extract_bpcs
from trustlens.stego.dct_qim import embed_dct_id, extract_dct_id
from trustlens.stego.spread import embed_spread_spectrum, extract_spread_spectrum
from trustlens.stego.reversible import embed_reversible, extract_and_restore
from trustlens.pipeline import issue_certificate, verify_certificate, VerificationReport
from trustlens.verify.verdict import Verdict
from trustlens.verify.attacks import (
    attack_retype_field, attack_block_tamper, attack_jpeg_compress,
    attack_resize, attack_crop, attack_splice
)
from trustlens.privacy.laplace import laplace_mechanism, evaluate_laplace_error
from trustlens.privacy.exponential import exponential_mechanism, evaluate_exponential_accuracy
from trustlens.privacy.randomized_response import simulate_randomized_response
from trustlens.privacy.budget import PrivacyBudget
from trustlens.privacy.multiparty import run_multiparty_dp_sum

# 3D Visualizations
from viz3d import (
    plot_3d_bitplane_stack, plot_3d_dct_bars,
    plot_3d_tamper_terrain, plot_3d_noise_cloud
)

# Page configuration
st.set_page_config(
    page_title="TrustLens+ | Trust Lab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Styling
st.markdown("""
<style>
    .main-header { font-size: 2.2rem; font-weight: 700; color: #1E3A8A; margin-bottom: 0.2rem; }
    .sub-header { font-size: 1.1rem; color: #4B5563; margin-bottom: 1.5rem; }
    .verdict-genuine { background-color: #D1FAE5; border-left: 6px solid #10B981; padding: 1rem; border-radius: 4px; }
    .verdict-forged { background-color: #FEE2E2; border-left: 6px solid #EF4444; padding: 1rem; border-radius: 4px; }
    .verdict-damaged { background-color: #FEF3C7; border-left: 6px solid #F59E0B; padding: 1rem; border-radius: 4px; }
    .metric-card { background-color: #F3F4F6; padding: 1rem; border-radius: 8px; border: 1px solid #E5E7EB; }
</style>
""", unsafe_allow_html=True)


# Session state initialization & cached keys
@st.cache_resource(show_spinner="Generating 1024-bit RSA scratch keys & DH session...")
def initialize_crypto_keys():
    issuer_pub, issuer_priv = generate_keypair(bits=1024)
    verifier_pub, verifier_priv = generate_keypair(bits=1024)
    _, _, session_key = create_dh_session()
    return issuer_pub, issuer_priv, verifier_pub, verifier_priv, session_key


if "issuer_pub" not in st.session_state:
    i_pub, i_priv, v_pub, v_priv, s_key = initialize_crypto_keys()
    st.session_state.issuer_pub = i_pub
    st.session_state.issuer_priv = i_priv
    st.session_state.verifier_pub = v_pub
    st.session_state.verifier_priv = v_priv
    st.session_state.session_key = s_key

if "privacy_budget" not in st.session_state:
    st.session_state.privacy_budget = PrivacyBudget(max_epsilon=5.0)

if "current_cert_image" not in st.session_state:
    # Default initial certificate
    init_details = {
        "name": "Alex Mercer",
        "roll": "CS-2022-8491",
        "degree": "Bachelor of Technology in Computer Science",
        "year": "2026",
        "cgpa": "9.42",
        "cert_id": "TL-2026-0123"
    }
    stego_img, _, _ = issue_certificate(
        init_details,
        st.session_state.issuer_priv,
        st.session_state.verifier_pub,
        st.session_state.session_key
    )
    st.session_state.current_cert_image = stego_img
    st.session_state.current_details = init_details

# Header
st.markdown('<div class="main-header">🛡️ TrustLens+ & Trust Lab</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">Dual-Layer Steganographic Certificate Protection, Verification Engine & Differential Privacy</div>', unsafe_allow_html=True)

# Tabs
tab1, tab2, tab3, tab4 = st.tabs([
    "📜 1. Issue & Verify",
    "🔬 2. Hiding Lab",
    "🔐 3. Crypto Lab",
    "📊 4. Privacy Lab"
])


# =====================================================================
# TAB 1: ISSUE & VERIFY
# =====================================================================
with tab1:
    st.header("Certificate Lifecycle: Issuance, Attack Simulation & Forensic Verification")
    col_issue, col_verify = st.columns([1, 1], gap="large")

    with col_issue:
        st.subheader("1. Issue Genuine Certificate")
        with st.form("issue_form"):
            name = st.text_input("Student Name", value="Alex Mercer")
            roll = st.text_input("Roll Number", value="CS-2022-8491")
            degree = st.text_input("Degree Program", value="Bachelor of Technology in Computer Science")
            c1, c2 = st.columns(2)
            year = c1.text_input("Graduation Year", value="2026")
            cgpa = c2.text_input("CGPA (out of 10.0)", value="9.42")
            cert_id = st.text_input("Certificate ID (Robust DCT Layer)", value="TL-2026-0123")

            submit_issue = st.form_submit_button("Generate & Embed Certificate", use_container_width=True)

        if submit_issue:
            details = {
                "name": name, "roll": roll, "degree": degree,
                "year": year, "cgpa": cgpa, "cert_id": cert_id
            }
            with st.spinner("Embedding robust DCT and fragile edge-adaptive layers..."):
                stego_cert, _, _ = issue_certificate(
                    details,
                    st.session_state.issuer_priv,
                    st.session_state.verifier_pub,
                    st.session_state.session_key
                )
                st.session_state.current_cert_image = stego_cert
                st.session_state.current_details = details
            st.success("Certificate issued successfully with dual-layer steganography!")

        # Preview & Download
        st.image(st.session_state.current_cert_image, caption="Issued Certificate (1600x1152 PNG)", use_container_width=True)

        buf = io.BytesIO()
        st.session_state.current_cert_image.save(buf, format="PNG")
        st.download_button(
            label="⬇️ Download Certificate PNG",
            data=buf.getvalue(),
            file_name=f"{st.session_state.current_details['roll']}_certificate.png",
            mime="image/png",
            use_container_width=True
        )

        # Attack Simulator
        st.markdown("---")
        st.subheader("2. Simulate Forgery Attacks")
        attack_type = st.selectbox(
            "Select Attack to Apply:",
            [
                "None (Keep Genuine)",
                "Retype Field: Forged CGPA (e.g. 9.98)",
                "Retype Field: Forged Student Name",
                "Block Tampering: Modify Seal/Text Region",
                "Lossy Recompression: JPEG (Quality 75)",
                "Lossy Recompression: JPEG (Quality 50)",
                "Physical Distortion: Crop Borders",
                "Resolution Downscaling: Resize (75%)"
            ]
        )

        if st.button("Apply Selected Attack to Certificate", use_container_width=True):
            base_img = st.session_state.current_cert_image
            if "Forged CGPA" in attack_type:
                st.session_state.current_cert_image = attack_retype_field(base_img, "cgpa", "9.98")
                st.warning("Attack applied: CGPA field repainted and retyped to '9.98'!")
            elif "Forged Student Name" in attack_type:
                st.session_state.current_cert_image = attack_retype_field(base_img, "name", "Dr. Victor Forger")
                st.warning("Attack applied: Student Name repainted to 'Dr. Victor Forger'!")
            elif "Block Tampering" in attack_type:
                st.session_state.current_cert_image = attack_block_tamper(base_img, box=(600, 800, 950, 920))
                st.warning("Attack applied: Region overwritten with forged pixels!")
            elif "Quality 75" in attack_type:
                st.session_state.current_cert_image = attack_jpeg_compress(base_img, quality=75)
                st.warning("Attack applied: Compressed as JPEG at Quality 75!")
            elif "Quality 50" in attack_type:
                st.session_state.current_cert_image = attack_jpeg_compress(base_img, quality=50)
                st.warning("Attack applied: Compressed as JPEG at Quality 50!")
            elif "Crop Borders" in attack_type:
                st.session_state.current_cert_image = attack_crop(base_img, crop_margin=35)
                st.warning("Attack applied: Cropped borders!")
            elif "Resize" in attack_type:
                st.session_state.current_cert_image = attack_resize(base_img, scale=0.75)
                st.warning("Attack applied: Scaled down to 75% and resized back!")
            st.rerun()

    # Verification Column
    with col_verify:
        st.subheader("3. Verification Engine")
        uploaded_file = st.file_uploader("Upload Certificate for Forensic Inspection (or test current image):", type=["png", "jpg", "jpeg"])

        if uploaded_file is not None:
            inspect_image = Image.open(uploaded_file).convert("RGB")
        else:
            inspect_image = st.session_state.current_cert_image

        if st.button("🔍 Run Full Forensic Verification", use_container_width=True, type="primary"):
            with st.spinner("Analyzing fragile LSB layer, recomputing 32x32 checksums, verifying RSA signature, and extracting DCT watermark..."):
                report = verify_certificate(
                    inspect_image,
                    st.session_state.verifier_priv,
                    st.session_state.issuer_pub,
                    st.session_state.session_key,
                    expected_details=st.session_state.current_details
                )
                st.session_state.last_report = report

        if "last_report" in st.session_state:
            rep: VerificationReport = st.session_state.last_report

            # Verdict Card Banner
            if rep.verdict == Verdict.GENUINE:
                st.markdown(f"""
                <div class="verdict-genuine">
                    <h3 style="color:#065F46; margin:0;">✅ VERDICT: GENUINE CERTIFICATE</h3>
                    <p style="margin:0.5rem 0 0 0; color:#064E3B;">{rep.reason}</p>
                </div>
                """, unsafe_allow_html=True)
            elif rep.verdict == Verdict.FORGED_EDITED:
                st.markdown(f"""
                <div class="verdict-forged">
                    <h3 style="color:#991B1B; margin:0;">🚨 VERDICT: FORGED / EDITED CERTIFICATE</h3>
                    <p style="margin:0.5rem 0 0 0; color:#7F1D1D;">{rep.reason}</p>
                </div>
                """, unsafe_allow_html=True)
            elif rep.verdict == Verdict.DAMAGED_ORIGINAL:
                st.markdown(f"""
                <div class="verdict-damaged">
                    <h3 style="color:#92400E; margin:0;">⚠️ VERDICT: DAMAGED ORIGINAL</h3>
                    <p style="margin:0.5rem 0 0 0; color:#78350F;">{rep.reason}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.error(f"❌ {rep.verdict.value}: {rep.reason}")

            # Diagnostics Grid
            st.markdown("#### Diagnostic Layers")
            d1, d2, d3, d4 = st.columns(4)
            d1.metric("Fragile TL Header", "Found" if rep.has_header else "Missing / Corrupt")
            d2.metric("RSA Signature", "Valid" if rep.signature_valid else "Invalid")
            d3.metric("Tampered Blocks", f"{rep.tamper_stats['failed_blocks']} / {rep.tamper_stats['total_blocks']}")
            d4.metric("Recovered DCT ID", rep.dct_id if rep.dct_id else "Unrecoverable")

            # Field-by-Field Table
            if rep.field_comparison:
                st.markdown("#### Field-by-Field Integrity Comparison")
                rows = []
                for f_name, data in rep.field_comparison["fields"].items():
                    rows.append({
                        "Field": f_name.upper(),
                        "Printed (Visual/OCR)": data["printed"],
                        "Hidden (Signed Payload)": data["hidden"],
                        "Match Status": "✅ MATCH" if data["match"] else "❌ MISMATCH",
                        "Similarity": f"{data['similarity'] * 100:.1f}%"
                    })
                st.dataframe(pd.DataFrame(rows), use_container_width=True)

            # Tamper Heatmap & 3D Topography
            st.markdown("#### Tamper Localization Map (32x32 Block Grid)")
            t_col1, t_col2 = st.columns(2)
            with t_col1:
                st.image(rep.heatmap_image, caption="Tamper Heatmap (Red Overlays Highlight Failed Blocks)", use_container_width=True)
            with t_col2:
                fig_terrain = plot_3d_tamper_terrain(rep.tamper_grid)
                st.plotly_chart(fig_terrain, use_container_width=True)


# =====================================================================
# TAB 2: HIDING LAB
# =====================================================================
with tab2:
    st.header("Comparative Steganography & Frequency Transform Lab")
    st.markdown("Experiment with the 5 data hiding techniques covered in Module 5:")

    stego_method = st.selectbox(
        "Choose Steganography Technique:",
        [
            "1. Fragile LSB (Plain Sequential)",
            "2. Fragile LSB (Edge-Adaptive Sobel 7-bit)",
            "3. BPCS (Canonical Gray Code & Complexity alpha)",
            "4. Robust DCT-QIM (Luminance Y-Channel)",
            "5. Direct Sequence Spread Spectrum (DSSS)",
            "6. Reversible Data Hiding (Histogram Shifting)"
        ]
    )

    base_sample_img = generate_certificate()

    col_h1, col_h2 = st.columns([1, 1], gap="large")

    if "Reversible" in stego_method:
        with col_h1:
            st.subheader("Lossless Histogram Shifting (Ni et al.)")
            st.info("Histogram shifting identifies the peak bin P and an empty zero bin Z, shifts the intermediate histogram bins, and writes payload bits. On extraction, it recovers the data and restores the EXACT original image bit-for-bit!")
            payload_len = st.slider("Payload Length (bits)", min_value=64, max_value=2000, value=512, step=64)
            test_bits = [random.randint(0, 1) for _ in range(payload_len)]

            stego_rev, meta = embed_reversible(base_sample_img, test_bits, channel_idx=1)
            metrics = compute_metrics(base_sample_img, stego_rev, payload_bits=payload_len)

            st.metric("PSNR (dB)", f"{metrics['psnr_db']} dB")
            st.metric("Peak Bin P", meta["P"])
            st.metric("Zero Bin Z", meta["Z"])
            st.image(stego_rev, caption="Stego Image with Histogram Shifted Payload", use_container_width=True)

        with col_h2:
            st.subheader("Exact Bit-for-Bit Image Restoration")
            if st.button("Restore Exact Original Image", use_container_width=True):
                extracted_bits, restored_img = extract_and_restore(stego_rev, meta)
                is_exact = np.array_equal(np.array(base_sample_img), np.array(restored_img))

                if is_exact:
                    st.success("✅ EXACT RESTORATION CONFIRMED: np.array_equal(original, restored) is True! Zero pixel distortion!")
                else:
                    st.error("Restoration failed.")

                st.metric("Bits Recovered", len(extracted_bits))
                st.metric("Bit Error Rate (BER)", f"{(np.array(test_bits) != np.array(extracted_bits)).mean() * 100:.2f}%")
                st.image(restored_img, caption="Restored Original Certificate", use_container_width=True)

    elif "DCT-QIM" in stego_method:
        with col_h1:
            st.subheader("Robust DCT Quantization Index Modulation")
            dct_q_slider = st.slider("Quantization Step Size Q", min_value=10.0, max_value=40.0, value=20.0, step=2.0)
            cert_id_input = st.text_input("Payload ID String", value="TL-2026-0123")

            stego_dct = embed_dct_id(base_sample_img, cert_id_input, q=dct_q_slider)
            metrics_dct = compute_metrics(base_sample_img, stego_dct, payload_bits=120)

            st.metric("PSNR (dB)", f"{metrics_dct['psnr_db']} dB")
            st.metric("SSIM", f"{metrics_dct['ssim']}")
            st.image(stego_dct, caption="DCT Watermarked Image", use_container_width=True)

        with col_h2:
            st.subheader("3D DCT Coefficient Matrix & Carrier Analysis")
            # Compute sample 8x8 DCT block near center
            arr_gray = np.array(base_sample_img.convert("L"), dtype=np.float32)
            sample_blk = arr_gray[500:508, 800:808]
            sample_dct = cv2.dct(sample_blk)
            fig_dct = plot_3d_dct_bars(sample_dct, carrier_pos=(3, 2))
            st.plotly_chart(fig_dct, use_container_width=True)

    else:
        with col_h1:
            st.subheader("Spatial Bit-Plane & Capacity Analysis")
            payload_bits = [random.randint(0, 1) for _ in range(4000)]
            if "Edge-Adaptive" in stego_method:
                stego_sp = embed_lsb(base_sample_img, payload_bits, stego_seed=42, edge_adaptive=True)
            elif "BPCS" in stego_method:
                stego_sp = embed_bpcs(base_sample_img, payload_bits, alpha_threshold=0.3)
            elif "Spread Spectrum" in stego_method:
                stego_sp = embed_spread_spectrum(base_sample_img, payload_bits[:64], seed=42, alpha=3.0)
            else:
                stego_sp = embed_lsb(base_sample_img, payload_bits, stego_seed=None, edge_adaptive=False)

            metrics = compute_metrics(base_sample_img, stego_sp, payload_bits=len(payload_bits))
            st.metric("PSNR (dB)", f"{metrics['psnr_db']} dB")
            st.metric("Structural Similarity (SSIM)", f"{metrics['ssim']}")
            st.metric("Modified Pixels", f"{metrics['pixels_modified']} ({metrics['pixels_modified_pct']}%)")
            st.image(stego_sp, caption="Stego Output Image", use_container_width=True)

        with col_h2:
            st.subheader("3D Bit-Plane Decomposition Stack")
            fig_stack = plot_3d_bitplane_stack(base_sample_img, stego_sp, crop_size=40)
            st.plotly_chart(fig_stack, use_container_width=True)


# =====================================================================
# TAB 3: CRYPTO LAB
# =====================================================================
with tab3:
    st.header("Classical Cryptography, Stream Ciphers & Cryptanalysis (Module 4)")

    crypto_tool = st.selectbox(
        "Choose Cryptographic Primitive / Lab:",
        [
            "1. Classical Ciphers (Caesar, Beaufort, Columnar)",
            "2. Advanced Substitution & Breakers (Monoalphabetic, Homophonic, Polyphonic)",
            "3. Turning Template (Cardan Grille) & Cyclic Notation",
            "4. Shift Registers: LFSR vs Geffe vs Berlekamp-Massey Attack",
            "5. Rule 30 Cellular Automaton Keystream vs LFSR/Geffe",
            "6. Diffie-Hellman-Merkle Key Exchange"
        ]
    )

    if "Classical Ciphers" in crypto_tool:
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            st.subheader("Caesar Cipher with Chi-Square Breaker")
            c_plain = st.text_input("Plaintext to Encrypt:", value="DEFEND THE EAST WALL OF THE CASTLE")
            c_shift = st.slider("Caesar Shift Key (k)", 1, 25, 7)
            c_enc = caesar_encrypt(c_plain, c_shift)
            st.code(f"Ciphertext: {c_enc}")

            if st.button("Break Caesar with Chi-Square Frequency Analysis"):
                best_k, cracked_text, score = caesar_break(c_enc)
                st.success(f"Cracked Key k = {best_k} (Chi-sq score = {score:.2f})")
                st.code(f"Recovered Plaintext: {cracked_text}")

        with col_c2:
            st.subheader("Beaufort Reciprocal Cipher")
            b_plain = st.text_input("Beaufort Plaintext:", value="TRUSTLENS")
            b_key = st.text_input("Keyword:", value="CIPHER")
            b_enc = beaufort_encrypt(b_plain, b_key)
            st.code(f"Beaufort Ciphertext (C = (K - P) mod 26): {b_enc}")
            # Reciprocal property
            b_dec = beaufort_decrypt(b_enc, b_key)
            st.code(f"Decrypted with Same Operation: {b_dec}")

    elif "Advanced Substitution" in crypto_tool:
        col_s1, col_s2 = st.columns(2)
        with col_s1:
            st.subheader("Monoalphabetic Hill-Climbing Breaker")
            m_text = st.text_area("Plaintext:", value="EXPERIENCE IS THE TEACHER OF ALL THINGS AND INTEGRITY IS THE BEDROCK OF KNOWLEDGE", height=100)
            m_key = generate_monoalphabetic_key()
            st.code(f"Generated Random 26-Letter Key: {m_key}")
            m_cipher = monoalphabetic_encrypt(m_text, m_key)
            st.code(f"Ciphertext:\n{m_cipher}")

            if st.button("Run Hill-Climbing Bigram Breaker"):
                with st.spinner("Optimizing key permutation via bigram log-likelihood..."):
                    cracked_k, cracked_p, score = monoalphabetic_break(m_cipher, max_iterations=1500)
                    st.success(f"Hill-Climber Score: {score:.1f}")
                    st.code(f"Decrypted Preview:\n{cracked_p[:120]}...")

        with col_s2:
            st.subheader("Homophonic Frequency Flattening")
            st.info("Homophonic ciphers assign multiple symbols to frequent letters (e.g. 13 symbols for 'E', 9 for 'T') to completely flatten the ciphertext letter frequency distribution and defeat single-letter frequency analysis.")
            h_text = "TRUST UNIVERSITY ISSUES DIGITAL CERTIFICATES VERIFIED THROUGH REVERSIBLE AND ROBUST WATERMARKING"
            h_enc = homophonic_encrypt(h_text)
            freq = homophonic_frequency_analysis(h_enc)

            # Frequency distribution chart
            fig_freq = px.bar(
                x=list(freq.keys()), y=list(freq.values()),
                labels={"x": "Homophonic Symbol (0..99)", "y": "Empirical Frequency (%)"},
                title="Flattened Symbol Frequency Distribution in Homophonic Ciphertext"
            )
            st.plotly_chart(fig_freq, use_container_width=True)

    elif "Cardan Grille" in crypto_tool:
        col_g1, col_g2 = st.columns(2)
        with col_g1:
            st.subheader("Cardan Grille (Turning Template)")
            grille_size = st.radio("Grille Grid Size:", [6, 8], horizontal=True)
            grille = CardanGrille(size=grille_size)
            g_input = st.text_input("Text to Encrypt:", value="TRUSTLENSSECUREACADEMICRECORDSSYSTEM")

            g_enc = grille.encrypt(g_input)
            st.code(f"Ciphertext after 4 successive 90° rotations:\n{g_enc}")
            g_dec = grille.decrypt(g_enc)
            st.code(f"Decrypted Plaintext:\n{g_dec}")

        with col_g2:
            st.subheader("Permutation Cycles: to_cycles & from_cycles")
            st.info("Permutation keys can be represented compactly as disjoint cycles, e.g. (1 3 2)(4 5).")
            perm_str = st.text_input("Enter 0-indexed Permutation (comma-separated):", value="1, 2, 0, 4, 3")
            perm_list = [int(x.strip()) for x in perm_str.split(",")]
            cycle_repr = to_cycles(perm_list, one_indexed=False)
            st.success(f"Disjoint Cycle Notation: {cycle_repr}")

            reconstructed_perm = from_cycles(cycle_repr, length=len(perm_list), one_indexed=False)
            st.code(f"Reconstructed Permutation List: {reconstructed_perm}")

    elif "Shift Registers" in crypto_tool:
        st.subheader("LFSR Insecurity vs Geffe Generator & Berlekamp-Massey Attack")
        col_l1, col_l2 = st.columns(2)
        with col_l1:
            st.markdown("#### 1. Single LFSR (Degree 19)")
            lfsr_seed = st.number_input("LFSR Seed State:", value=1337, step=1)
            single_lfsr = LFSR(size=19, taps=[0, 1, 4, 18], initial_state=lfsr_seed)
            bits = single_lfsr.generate_bits(64)
            st.code(f"First 64 Bits Generated:\n{''.join(map(str, bits))}")

            if st.button("Break LFSR with Berlekamp-Massey"):
                lc, poly = berlekamp_massey(bits)
                st.error(f"🚨 LFSR BROKEN! Linear Complexity L = {lc} (Matches register degree 19!).")
                st.info("A single LFSR provides zero cryptographic security because an adversary observing 2*L bits can recover the entire connection polynomial and future keystream.")

        with col_l2:
            st.markdown("#### 2. Geffe Nonlinear Combination Generator")
            st.info("Combines 3 LFSRs with nonlinear function: F(x1, x2, x3) = (x1 AND x2) XOR (NOT x1 AND x3).")
            geffe = GeffeGenerator(seed_bytes=b"SECRET_KEY_12345")
            g_bits = [geffe.step() for _ in range(64)]
            st.code(f"First 64 Geffe Bits:\n{''.join(map(str, g_bits))}")

            if st.button("Attack Geffe with Berlekamp-Massey"):
                g_lc, _ = berlekamp_massey(g_bits)
                st.success(f"✅ Geffe Linear Complexity L = {g_lc} (Significantly exceeds single LFSR!).")

    elif "Rule 30" in crypto_tool:
        st.subheader("Wolfram Rule 30 Cellular Automaton vs LFSR & Geffe")
        ca_seed = st.text_input("Rule 30 Key Seed:", value="RULE30_SECRET_SEED_2026")
        comp = compare_stream_generators(ca_seed.encode("utf-8"), num_bits=128)

        st.dataframe(pd.DataFrame({
            "Generator": ["LFSR (Degree 19)", "Geffe Generator", "Rule 30 Cellular Automaton"],
            "Linear Complexity (L)": [comp["LFSR_19"]["linear_complexity"], comp["Geffe"]["linear_complexity"], comp["Rule30_CA"]["linear_complexity"]],
            "1s Ratio (%)": [f"{comp['LFSR_19']['bit_balance']['ones_pct']:.1f}%", f"{comp['Geffe']['bit_balance']['ones_pct']:.1f}%", f"{comp['Rule30_CA']['bit_balance']['ones_pct']:.1f}%"],
            "Chi-Square Score": [comp["LFSR_19"]["bit_balance"]["chi_sq"], comp["Geffe"]["bit_balance"]["chi_sq"], comp["Rule30_CA"]["bit_balance"]["chi_sq"]],
            "Easily Broken by Berlekamp-Massey?": ["🚨 YES (L=19)", "🛡️ NO", "🛡️ NO"]
        }), use_container_width=True)

    elif "Diffie-Hellman" in crypto_tool:
        st.subheader("Diffie-Hellman-Merkle Key Exchange (Pedagogical Walkthrough)")
        p_val = DH_DEMO_P
        g_val = DH_DEMO_G
        st.latex(rf"p = {p_val}, \quad g = {g_val}")

        dh_alice = DiffieHellman(p=p_val, g=g_val)
        dh_bob = DiffieHellman(p=p_val, g=g_val)

        c_dh1, c_dh2 = st.columns(2)
        with c_dh1:
            st.markdown("#### Issuer (Alice)")
            st.write(f"Private Key a: `{dh_alice.private_key}`")
            st.write(f"Public Key A = g^a mod p: `{dh_alice.public_key}`")
        with c_dh2:
            st.markdown("#### Verifier (Bob)")
            st.write(f"Private Key b: `{dh_bob.private_key}`")
            st.write(f"Public Key B = g^b mod p: `{dh_bob.public_key}`")

        k_alice = dh_alice.derive_key(dh_bob.public_key)
        k_bob = dh_bob.derive_key(dh_alice.public_key)

        st.success(f"✅ Shared Symmetric Key Derived via SHA-256:\n`{k_alice.hex()}`")
        st.write("Both parties arrived at the identical 256-bit session key without transmitting it over the network!")


# =====================================================================
# TAB 4: PRIVACY LAB
# =====================================================================
with tab4:
    st.header("Differential Privacy & Secure Multi-Party Statistics (Module 1)")

    # Synthetic verification queries
    dept_counts = {
        "Computer Science": 428,
        "Mechanical Engineering": 215,
        "Electrical Engineering": 194,
        "Civil Engineering": 112,
        "Biotechnology": 68
    }

    col_p1, col_p2 = st.columns([1, 1], gap="large")

    with col_p1:
        st.subheader("1. Laplace Mechanism for Department Verification Counts")
        eps_slider = st.slider("Privacy Budget Parameter (ε):", min_value=0.1, max_value=5.0, value=1.0, step=0.1)

        # Spend budget
        budget: PrivacyBudget = st.session_state.privacy_budget
        st.progress(budget.percent_consumed / 100.0, text=f"Privacy Budget: {budget.spent_epsilon:.2f} / {budget.max_epsilon:.2f} ε spent ({budget.percent_consumed:.1f}%)")

        if st.button("Query Noisy Department Counts", use_container_width=True):
            if budget.spend(eps_slider, description=f"Query dept counts (eps={eps_slider})"):
                st.success(f"Query approved! Spent {eps_slider:.2f} ε.")
            else:
                st.error("🚨 QUERY REFUSED! Privacy budget exceeded!")

        # Generate noisy counts
        noisy_counts = {}
        for dept, cnt in dept_counts.items():
            noisy_counts[dept] = laplace_mechanism(cnt, epsilon=eps_slider)

        df_chart = pd.DataFrame({
            "Department": list(dept_counts.keys()),
            "True Count": list(dept_counts.values()),
            "Noisy Reported Count": list(noisy_counts.values())
        })

        fig_bars = px.bar(
            df_chart, x="Department", y=["True Count", "Noisy Reported Count"],
            barmode="group",
            title=f"True vs Differentially Private Counts (ε = {eps_slider})"
        )
        st.plotly_chart(fig_bars, use_container_width=True)

        st.subheader("2. Exponential Mechanism (Department of the Year Selection)")
        exp_eps = st.slider("Exponential Mechanism ε:", min_value=0.2, max_value=5.0, value=1.5, step=0.2)
        chosen_dept, probs = exponential_mechanism(dept_counts, epsilon=exp_eps)
        st.success(f"Selected Department: **{chosen_dept}**")
        st.bar_chart(probs)

    with col_p2:
        st.subheader("3. Warner's Randomized Response Survey")
        p_val = st.slider("Truthful Probability (p):", min_value=0.55, max_value=0.95, value=0.75, step=0.05)
        rr_res = simulate_randomized_response(true_rate=0.68, num_respondents=5000, p=p_val)

        m1, m2, m3 = st.columns(3)
        m1.metric("Local DP (ε)", f"{rr_res['epsilon']:.2f}")
        m2.metric("Reported Yes", f"{rr_res['reported_yes_rate']*100:.1f}%")
        m3.metric("De-Biased Estimate", f"{rr_res['estimated_true_rate']*100:.1f}%")

        st.subheader("4. Collaborative Multi-Party DP Sum Across Colleges")
        st.info("Three colleges collaborate to compute total degrees awarded without revealing their individual counts to each other or a central authority, combining Additive Secret Sharing and Distributed Laplace Noise.")

        college_data = {
            "Metropolitan College": 340,
            "Institute of Technology": 520,
            "State Polytechnic": 210
        }
        mp_res = run_multiparty_dp_sum(college_data, epsilon=1.0)
        st.write(f"**True Grand Total:** {mp_res['true_sum']}")
        st.write(f"**Combined Noisy Total:** {mp_res['noisy_total']}")
        st.write(f"**Distributed Noise Term Added:** {mp_res['total_distributed_noise']}")

        # 3D Noise Cloud
        st.subheader("5. 3D Differential Privacy Noise Cloud")
        sample_eps = np.random.uniform(0.1, 5.0, 300)
        sample_true = np.random.randint(100, 1000, 300)
        sample_noisy = np.array([laplace_mechanism(int(t), float(e)) for t, e in zip(sample_true, sample_eps)])
        fig_cloud = plot_3d_noise_cloud(sample_true, sample_eps, sample_noisy)
        st.plotly_chart(fig_cloud, use_container_width=True)
