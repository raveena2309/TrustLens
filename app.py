"""app.py
TrustLens: Simple, Elegant Web Application for Certificate Protection & Privacy.
Run with: streamlit run app.py
"""

import io
import numpy as np
import pandas as pd
import streamlit as st
from PIL import Image

from certificate import generate_certificate
from crypto import (
    rsa_keygen, dh_generate_keypair, dh_shared_secret,
    LFSR, GeffeGenerator, berlekamp_massey
)
from stego import issue_certificate_full, verify_certificate_full
from privacy import laplace_mechanism, exponential_mechanism, PrivacyBudget

st.set_page_config(page_title="TrustLens", page_icon="🛡️", layout="wide")

# Custom CSS for clean UI
st.markdown("""
<style>
    .title { font-size: 2.2rem; font-weight: 700; color: #1E3A8A; margin-bottom: 0.2rem; }
    .subtitle { font-size: 1.05rem; color: #4B5563; margin-bottom: 1.5rem; }
    .card-genuine { background-color: #ECFDF5; border-left: 6px solid #10B981; padding: 1.2rem; border-radius: 6px; }
    .card-forged { background-color: #FEF2F2; border-left: 6px solid #EF4444; padding: 1.2rem; border-radius: 6px; }
    .card-damaged { background-color: #FFFBEB; border-left: 6px solid #F59E0B; padding: 1.2rem; border-radius: 6px; }
</style>
""", unsafe_allow_html=True)


# Cache cryptographic keys in session so app loads fast
@st.cache_resource(show_spinner="Initializing RSA & Diffie-Hellman keys...")
def get_system_keys():
    i_pub, i_priv = rsa_keygen(bits=1024)
    v_pub, v_priv = rsa_keygen(bits=1024)
    a_priv, a_pub = dh_generate_keypair()
    b_priv, b_pub = dh_generate_keypair()
    session_key = dh_shared_secret(a_priv, b_pub)
    return i_pub, i_priv, v_pub, v_priv, session_key


i_pub, i_priv, v_pub, v_priv, session_key = get_system_keys()

if "budget" not in st.session_state:
    st.session_state.budget = PrivacyBudget(max_epsilon=5.0)

if "active_cert" not in st.session_state:
    default_info = {
        "name": "Alex Mercer", "roll": "CS-2022-8491",
        "degree": "Bachelor of Technology in Computer Science",
        "year": "2026", "cgpa": "9.42", "cert_id": "TL-2026-0123"
    }
    st.session_state.active_cert = issue_certificate_full(default_info, i_priv, v_pub, session_key)
    st.session_state.active_info = default_info

# App Header
st.markdown('<div class="title">🛡️ TrustLens</div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">Dual-Layer Certificate Protection, Forensic Verification & Differential Privacy</div>', unsafe_allow_html=True)

tab1, tab2, tab3 = st.tabs(["📜 1. Issue Certificate", "🔍 2. Verify Certificate", "🔬 3. Crypto & Privacy Demos"])


# =====================================================================
# TAB 1: ISSUE CERTIFICATE
# =====================================================================
with tab1:
    col_form, col_view = st.columns([1, 1], gap="large")

    with col_form:
        st.subheader("Student Details")
        with st.form("cert_form"):
            name = st.text_input("Student Name", value="Alex Mercer")
            roll = st.text_input("Roll Number", value="CS-2022-8491")
            degree = st.text_input("Degree Program", value="Bachelor of Technology in Computer Science")
            c1, c2 = st.columns(2)
            year = c1.text_input("Year", value="2026")
            cgpa = c2.text_input("CGPA", value="9.42")
            cert_id = st.text_input("Certificate ID (Robust Watermark)", value="TL-2026-0123")

            issue_btn = st.form_submit_button("Generate & Protect Certificate", use_container_width=True)

        if issue_btn:
            info = {"name": name, "roll": roll, "degree": degree, "year": year, "cgpa": cgpa, "cert_id": cert_id}
            with st.spinner("Embedding fragile LSB layer and robust DCT watermark..."):
                st.session_state.active_cert = issue_certificate_full(info, i_priv, v_pub, session_key)
                st.session_state.active_info = info
            st.success("Certificate issued successfully with digital signature and dual-layer steganography!")

        st.markdown("---")
        st.subheader("Simulate Attack / Forgery")
        st.write("Test the verification system by tampering with this certificate:")
        c_a1, c_a2 = st.columns(2)
        if c_a1.button("🚨 Forge CGPA to 9.98", use_container_width=True):
            arr = np.array(st.session_state.active_cert)
            # Blank out CGPA box and redraw forged number
            from PIL import ImageDraw, ImageFont
            img = Image.fromarray(arr)
            d = ImageDraw.Draw(img)
            d.rectangle([600, 840, 1000, 910], fill=(250, 248, 240))
            d.text((800, 875), "Cumulative Grade Point Average (CGPA): 9.98 / 10.0", fill=(128, 20, 20), anchor="mm")
            st.session_state.active_cert = img
            st.warning("CGPA field modified to 9.98! Go to Tab 2 to verify.")
            st.rerun()

        if c_a2.button("⚠️ Compress as JPEG (Q=75)", use_container_width=True):
            buf = io.BytesIO()
            st.session_state.active_cert.save(buf, "JPEG", quality=75)
            buf.seek(0)
            st.session_state.active_cert = Image.open(buf).convert("RGB")
            st.warning("Compressed as lossy JPEG! Fragile layer destroyed, but robust DCT layer will survive.")
            st.rerun()

    with col_view:
        st.subheader("Certificate Preview")
        st.image(st.session_state.active_cert, caption="Protected Certificate Image (1600x1152)", use_container_width=True)

        buf = io.BytesIO()
        st.session_state.active_cert.save(buf, format="PNG")
        st.download_button(
            label="⬇️ Download Certificate PNG",
            data=buf.getvalue(),
            file_name=f"{st.session_state.active_info.get('roll', 'cert')}.png",
            mime="image/png",
            use_container_width=True
        )


# =====================================================================
# TAB 2: VERIFY CERTIFICATE
# =====================================================================
with tab2:
    st.header("Forensic Certificate Verification")
    st.write("Upload any certificate image to verify its authenticity, check digital signatures, and detect tamper locations.")

    upload = st.file_uploader("Upload Certificate for Inspection:", type=["png", "jpg", "jpeg"])
    inspect_img = Image.open(upload).convert("RGB") if upload else st.session_state.active_cert

    if st.button("🔍 Run Forensic Verification", type="primary", use_container_width=True):
        with st.spinner("Verifying digital signature and checking 1,800 image blocks..."):
            rep = verify_certificate_full(inspect_img, v_priv, i_pub, session_key)
            st.session_state.rep = rep

    if "rep" in st.session_state:
        rep = st.session_state.rep
        st.markdown("---")

        # 1. Verdict Banner
        if rep["verdict"] == "GENUINE":
            st.markdown(f"""
            <div class="card-genuine">
                <h3 style="color:#065F46; margin:0;">✅ VERDICT: GENUINE CERTIFICATE</h3>
                <p style="margin:0.5rem 0 0 0; color:#047857;">{rep['reason']}</p>
            </div>
            """, unsafe_allow_html=True)
        elif rep["verdict"] == "FORGED / EDITED":
            st.markdown(f"""
            <div class="card-forged">
                <h3 style="color:#991B1B; margin:0;">🚨 VERDICT: FORGED / TAMPERED CERTIFICATE</h3>
                <p style="margin:0.5rem 0 0 0; color:#B91C1C;">{rep['reason']}</p>
            </div>
            """, unsafe_allow_html=True)
        elif rep["verdict"] == "DAMAGED ORIGINAL":
            st.markdown(f"""
            <div class="card-damaged">
                <h3 style="color:#92400E; margin:0;">⚠️ VERDICT: DAMAGED ORIGINAL</h3>
                <p style="margin:0.5rem 0 0 0; color:#B45309;">{rep['reason']}</p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.error(f"❌ {rep['verdict']}: {rep['reason']}")

        # 2. Key Metrics
        m1, m2, m3 = st.columns(3)
        m1.metric("Digital Signature", "✅ Valid" if rep["sig_valid"] else "❌ Invalid")
        m2.metric("Tampered 32x32 Blocks", f"{rep['failed_blocks']} / 1,800")
        m3.metric("Robust Watermark ID", rep["dct_id"] or "Not found")

        # 3. Side-by-Side: Certificate vs Tamper Heatmap
        c_v1, c_v2 = st.columns(2)
        with c_v1:
            st.subheader("Certificate Image")
            st.image(inspect_img, use_container_width=True)

        with c_v2:
            st.subheader("Tamper Localization Heatmap")
            st.image(rep["heatmap"], caption="Failed blocks highlighted in red", use_container_width=True)

        # 4. Extracted Record
        if rep["hidden_record"]:
            st.subheader("Authentic Encrypted Record Recovered from Stego Layer")
            st.dataframe(pd.DataFrame([rep["hidden_record"]]), use_container_width=True)


# =====================================================================
# TAB 3: CRYPTO & PRIVACY DEMOS
# =====================================================================
with tab3:
    st.header("Syllabus Interactive Demos (Modules 1 & 4)")

    col_dp, col_cr = st.columns([1, 1], gap="large")

    with col_dp:
        st.subheader("1. Differential Privacy: Laplace Mechanism (Module 1)")
        st.info("Differential Privacy protects individual student privacy by adding calibrated Laplace noise to published statistics.")

        true_count = st.number_input("True Student Count in Department:", value=350, step=10)
        eps = st.slider("Privacy Parameter ε (Epsilon):", min_value=0.1, max_value=5.0, value=1.0, step=0.1)

        # Budget meter
        b = st.session_state.budget
        st.progress(b.percent_consumed / 100.0, text=f"Privacy Budget: {b.spent_epsilon:.1f} / {b.max_epsilon:.1f} ε spent")

        if st.button("Query Noisy Count", use_container_width=True):
            if b.spend(eps):
                noisy_result = laplace_mechanism(true_count, eps)
                err = abs(noisy_result - true_count)
                st.success(f"Reported Noisy Count: **{noisy_result}** (Error: {err}, Theoretical Expected Error: ~{1.0/eps:.2f})")
            else:
                st.error("🚨 QUERY REFUSED! Privacy budget exhausted.")

        if st.button("Reset Privacy Budget"):
            b.reset()
            st.rerun()

        st.markdown("---")
        st.subheader("2. Exponential Mechanism (Module 1)")
        st.write("Privately selects the top department without leaking raw counts:")
        depts = {"Computer Science": 420, "Mechanical": 210, "Electrical": 180, "Civil": 95}
        exp_eps = st.slider("Exponential ε:", 0.2, 5.0, 1.5, 0.2)
        if st.button("Select Top Department Privately"):
            winner, probs = exponential_mechanism(depts, exp_eps)
            st.success(f"Selected: **{winner}**")
            st.bar_chart(probs)

    with col_cr:
        st.subheader("3. Stream Ciphers: LFSR vs Geffe (Module 4)")
        st.info("A single LFSR is cryptographically insecure because Berlekamp-Massey cracks it with 2*L bits. Geffe combines 3 LFSRs nonlinearly to prevent this attack!")

        # LFSR demo
        lfsr = LFSR(size=19, taps=[0, 1, 4, 18], seed=12345)
        bits = [lfsr.step() for _ in range(40)]
        st.code(f"19-bit LFSR Output:\n{''.join(map(str, bits))}")

        lc = berlekamp_massey(bits)
        st.warning(f"Berlekamp-Massey linear complexity: L = {lc} (Cracked! Matches LFSR degree 19).")

        # Geffe demo
        geffe = GeffeGenerator(b"secret_key_123")
        g_bits = [geffe.step() for _ in range(40)]
        st.code(f"Geffe Nonlinear Keystream:\n{''.join(map(str, g_bits))}")
        st.success(f"Geffe Linear Complexity: L = {berlekamp_massey(g_bits)} (Secure against Berlekamp-Massey!).")

        st.markdown("---")
        st.subheader("4. Diffie-Hellman Key Exchange (Module 4)")
        st.write("Alice (Issuer) and Bob (Verifier) compute a shared session key over an insecure channel:")
        if st.button("Simulate Diffie-Hellman Key Exchange", use_container_width=True):
            a_priv, a_pub = dh_generate_keypair()
            b_priv, b_pub = dh_generate_keypair()
            k_alice = dh_shared_secret(a_priv, b_pub)
            k_bob = dh_shared_secret(b_priv, a_pub)
            st.write(f"Alice's Public Key: `{a_pub}`")
            st.write(f"Bob's Public Key: `{b_pub}`")
            st.success(f"✅ Shared Symmetric Session Key Derived by Both:\n`{k_alice.hex()}`")
