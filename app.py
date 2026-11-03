"""app.py
TrustLens: Comprehensive Academic Credential Protection, Forensic Verification & Privacy System.
Run with: streamlit run app.py
"""

import io
import numpy as np
import pandas as pd
import streamlit as st
from PIL import Image, ImageDraw

from certificate import generate_certificate, _get_font, FIELD_LAYOUT
from crypto import (
    rsa_keygen, dh_generate_keypair, dh_shared_secret,
    LFSR, GeffeGenerator, berlekamp_massey
)
from stego import issue_certificate_full, verify_certificate_full
from privacy import laplace_mechanism, exponential_mechanism, PrivacyBudget

# Streamlit Page Setup
st.set_page_config(
    page_title="TrustLens - Academic Credential Protection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Professional CSS Styling
st.markdown("""
<style>
    .main-title { font-size: 2.3rem; font-weight: 700; color: #1E3A8A; margin-bottom: 0.2rem; }
    .main-sub { font-size: 1.05rem; color: #4B5563; margin-bottom: 1.4rem; }
    .portal-badge { display: inline-block; padding: 0.25rem 0.75rem; border-radius: 9999px; font-size: 0.85rem; font-weight: 600; margin-bottom: 0.5rem; }
    .badge-admin { background-color: #DBEAFE; color: #1E40AF; }
    .badge-student { background-color: #DCFCE7; color: #166534; }
    .badge-lab { background-color: #FEF3C7; color: #92400E; }
    .badge-tech { background-color: #F3E8FF; color: #6B21A8; }
    .card-genuine { background-color: #ECFDF5; border-left: 6px solid #10B981; padding: 1.2rem; border-radius: 6px; margin: 1rem 0; }
    .card-forged { background-color: #FEF2F2; border-left: 6px solid #EF4444; padding: 1.2rem; border-radius: 6px; margin: 1rem 0; }
    .card-damaged { background-color: #FFFBEB; border-left: 6px solid #F59E0B; padding: 1.2rem; border-radius: 6px; margin: 1rem 0; }
    .student-card { background-color: #F8FAFC; border: 1px solid #E2E8F0; padding: 1.2rem; border-radius: 8px; margin-bottom: 1rem; }
</style>
""", unsafe_allow_html=True)


# Initialize and Cache Core Cryptographic Keys
@st.cache_resource(show_spinner="Initializing Institutional Cryptographic Authority...")
def get_system_keys():
    i_pub, i_priv = rsa_keygen(bits=1024)
    v_pub, v_priv = rsa_keygen(bits=1024)
    a_priv, a_pub = dh_generate_keypair()
    b_priv, b_pub = dh_generate_keypair()
    session_key = dh_shared_secret(a_priv, b_pub)
    return i_pub, i_priv, v_pub, v_priv, session_key


i_pub, i_priv, v_pub, v_priv, session_key = get_system_keys()

# Initialize Session State
if "budget" not in st.session_state:
    st.session_state.budget = PrivacyBudget(max_epsilon=5.0)

if "issued_certificates" not in st.session_state:
    st.session_state.issued_certificates = {}

if "tampered_certificate" not in st.session_state:
    st.session_state.tampered_certificate = None

if "inspect_image_source" not in st.session_state:
    st.session_state.inspect_image_source = None

# Pre-populate sample certificates if empty
if not st.session_state.issued_certificates:
    sample_records = [
        {
            "name": "Alex Mercer",
            "roll": "CS-2022-8491",
            "degree": "Bachelor of Technology in Computer Science",
            "year": "2026",
            "cgpa": "9.42",
            "cert_id": "TL-2026-0123"
        },
        {
            "name": "Priya Sharma",
            "roll": "EC-2022-1042",
            "degree": "Bachelor of Technology in Electronics & Communication",
            "year": "2026",
            "cgpa": "9.68",
            "cert_id": "TL-2026-0124"
        },
        {
            "name": "David Chen",
            "roll": "ME-2022-3109",
            "degree": "Bachelor of Technology in Mechanical Engineering",
            "year": "2026",
            "cgpa": "8.85",
            "cert_id": "TL-2026-0125"
        }
    ]
    for rec in sample_records:
        cert_img = issue_certificate_full(rec, i_priv, v_pub, session_key)
        st.session_state.issued_certificates[rec["roll"]] = {
            "details": rec,
            "image": cert_img
        }

# App Header
st.markdown('<div class="main-title">🛡️ TrustLens Certificate Security & Verification System</div>', unsafe_allow_html=True)
st.markdown('<div class="main-sub">Digital Credential Issuance, Forensic Tamper Localization & Privacy-Preserving Analytics</div>', unsafe_allow_html=True)

# 4 Main Portals
tab_admin, tab_student, tab_tamper, tab_tech = st.tabs([
    "🏛️ Administration Portal",
    "🎓 Student Portal",
    "🧪 Tamper Lab (Forgery Simulator)",
    "🛡️ Security & Privacy System"
])


# =====================================================================
# TAB 1: ADMINISTRATION PORTAL (ISSUE & VERIFY)
# =====================================================================
with tab_admin:
    st.markdown('<span class="portal-badge badge-admin">INSTITUTIONAL ADMINISTRATION</span>', unsafe_allow_html=True)
    st.header("University Administrative Operations")

    admin_action = st.radio(
        "Administrative Function:",
        ["📜 Issue New Protected Certificate", "🔍 Audit & Verify Certificate Authenticity"],
        horizontal=True
    )
    st.markdown("---")

    # 1. ISSUE SECTION
    if admin_action == "📜 Issue New Protected Certificate":
        col_form, col_view = st.columns([1, 1], gap="large")

        with col_form:
            st.subheader("Issue Degree Certificate")
            st.caption("Fills student record, applies digital signature, encrypts payload with Geffe stream cipher, and embeds robust DCT and fragile LSB watermarks.")

            with st.form("admin_issue_form"):
                f_name = st.text_input("Full Student Name", value="Alex Mercer")
                f_roll = st.text_input("University Roll Number", value="CS-2022-8491")
                f_degree = st.text_input("Degree Program", value="Bachelor of Technology in Computer Science")
                c1, c2 = st.columns(2)
                f_year = c1.text_input("Graduation Year", value="2026")
                f_cgpa = c2.text_input("Cumulative GPA (CGPA)", value="9.42")
                f_cid = st.text_input("Certificate Unique ID (Robust Layer)", value=f"TL-2026-{len(st.session_state.issued_certificates)+100:04d}")

                btn_issue = st.form_submit_button("🛡️ Secure & Issue Certificate", use_container_width=True)

            if btn_issue:
                new_details = {
                    "name": f_name.strip(),
                    "roll": f_roll.strip().upper(),
                    "degree": f_degree.strip(),
                    "year": f_year.strip(),
                    "cgpa": f_cgpa.strip(),
                    "cert_id": f_cid.strip()
                }
                with st.spinner("Signing record, embedding dual-layer watermarks, and calculating 1,800 block integrity hashes..."):
                    new_img = issue_certificate_full(new_details, i_priv, v_pub, session_key)
                    st.session_state.issued_certificates[new_details["roll"]] = {
                        "details": new_details,
                        "image": new_img
                    }
                    st.session_state.inspect_image_source = new_img
                st.success(f"Certificate for {new_details['name']} ({new_details['roll']}) issued and stored successfully!")

        with col_view:
            st.subheader("Official Certificate Output")
            # Select roll number to preview
            avail_rolls = list(st.session_state.issued_certificates.keys())
            preview_roll = st.selectbox("Select Issued Certificate to Preview:", avail_rolls, index=len(avail_rolls)-1)
            selected_record = st.session_state.issued_certificates[preview_roll]

            st.image(selected_record["image"], caption=f"Protected Official Certificate ({preview_roll})", use_container_width=True)

            buf = io.BytesIO()
            selected_record["image"].save(buf, format="PNG")
            st.download_button(
                label=f"⬇️ Download Official Certificate ({preview_roll}.png)",
                data=buf.getvalue(),
                file_name=f"{preview_roll}_certificate.png",
                mime="image/png",
                use_container_width=True
            )

    # 2. VERIFY SECTION
    else:
        st.subheader("Forensic Verification & Tamper Detection")
        st.write("Examines any certificate image against the university cryptographic authority to verify digital signatures, inspect all 1,800 blocks for pixel alterations, and read robust watermarks.")

        col_src, col_opts = st.columns([2, 1])
        with col_src:
            verify_source = st.radio(
                "Select Certificate Source for Verification:",
                ["📁 Upload Certificate File (PNG/JPEG)", "🧪 Inspect Certificate from Tamper Lab", "📜 Verify Last Issued Certificate"],
                horizontal=True
            )

        inspect_img = None
        if verify_source == "📁 Upload Certificate File (PNG/JPEG)":
            uploaded = st.file_uploader("Upload Certificate Image to Audit:", type=["png", "jpg", "jpeg"])
            if uploaded:
                inspect_img = Image.open(uploaded).convert("RGB")
        elif verify_source == "🧪 Inspect Certificate from Tamper Lab":
            if st.session_state.tampered_certificate is not None:
                inspect_img = st.session_state.tampered_certificate
                st.info("Loaded tampered certificate from the Tamper Lab.")
            else:
                st.warning("No certificate has been modified in the Tamper Lab yet. Go to the 'Tamper Lab' tab to create a test forgery!")
        else:
            if st.session_state.issued_certificates:
                last_roll = list(st.session_state.issued_certificates.keys())[-1]
                inspect_img = st.session_state.issued_certificates[last_roll]["image"]
                st.info(f"Loaded genuine certificate for {last_roll}.")

        if inspect_img is not None:
            if st.button("🔍 Run Forensic Verification Audit", type="primary", use_container_width=True):
                with st.spinner("Checking RSA digital signature, recomputing 32x32 block checksums, and reading DCT watermark..."):
                    audit_rep = verify_certificate_full(inspect_img, v_priv, i_pub, session_key)
                    st.session_state.audit_rep = audit_rep
                    st.session_state.last_audited_img = inspect_img

        if "audit_rep" in st.session_state and st.session_state.get("last_audited_img") is not None:
            rep = st.session_state.audit_rep
            audited_image = st.session_state.last_audited_img

            # Verdict Banner
            if rep["verdict"] == "GENUINE":
                st.markdown(f"""
                <div class="card-genuine">
                    <h3 style="color:#065F46; margin:0;">✅ VERDICT: GENUINE CERTIFICATE</h3>
                    <p style="margin:0.5rem 0 0 0; color:#047857; font-size:1.05rem;">{rep['reason']}</p>
                </div>
                """, unsafe_allow_html=True)
            elif rep["verdict"] == "FORGED / EDITED":
                st.markdown(f"""
                <div class="card-forged">
                    <h3 style="color:#991B1B; margin:0;">🚨 VERDICT: FORGED / TAMPERED CERTIFICATE</h3>
                    <p style="margin:0.5rem 0 0 0; color:#B91C1C; font-size:1.05rem;">{rep['reason']}</p>
                </div>
                """, unsafe_allow_html=True)
            elif rep["verdict"] == "DAMAGED ORIGINAL":
                st.markdown(f"""
                <div class="card-damaged">
                    <h3 style="color:#92400E; margin:0;">⚠️ VERDICT: DAMAGED ORIGINAL</h3>
                    <p style="margin:0.5rem 0 0 0; color:#B45309; font-size:1.05rem;">{rep['reason']}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.error(f"❌ {rep['verdict']}: {rep['reason']}")

            # Audit Metrics
            m1, m2, m3 = st.columns(3)
            m1.metric("Cryptographic Signature", "✅ Valid & Untampered" if rep["sig_valid"] else "❌ Invalid / Failed")
            m2.metric("Failed 32x32 Image Blocks", f"{rep['failed_blocks']} / 1,800 blocks")
            m3.metric("Robust DCT Identifier", rep["dct_id"] if rep["dct_id"] else "Destroyed / Not Found")

            # Side-by-side Inspection
            st.markdown("#### Visual Tamper Localization Map")
            c_img1, c_img2 = st.columns(2)
            with c_img1:
                st.subheader("Audited Certificate")
                st.image(audited_image, use_container_width=True)

            with c_img2:
                st.subheader("Tamper Heatmap (Block Integrity)")
                st.image(rep["heatmap"], caption="Failed blocks highlighted in red", use_container_width=True)

            if rep["hidden_record"]:
                st.markdown("#### Authentic Encrypted Record Recovered from Steganographic Layer")
                st.dataframe(pd.DataFrame([rep["hidden_record"]]), use_container_width=True)


# =====================================================================
# TAB 2: STUDENT PORTAL (OPEN WITH ROLL NO & DOWNLOAD)
# =====================================================================
with tab2:
    st.markdown('<span class="portal-badge badge-student">STUDENT CREDENTIAL ACCESS</span>', unsafe_allow_html=True)
    st.header("Student Degree Credential Portal")
    st.write("Students can access, view, and download their official tamper-proof degree certificate using their University Roll Number.")

    col_search, col_space = st.columns([2, 1])
    with col_search:
        # Roll number input
        search_roll = st.text_input("Enter University Roll Number:", value="CS-2022-8491", placeholder="e.g. CS-2022-8491").strip().upper()
        
        # Quick selection helper
        st.caption("Issued roll numbers currently in system:")
        quick_cols = st.columns(min(len(st.session_state.issued_certificates), 4))
        for idx, r_num in enumerate(list(st.session_state.issued_certificates.keys())[:4]):
            if quick_cols[idx].button(f"👉 {r_num}", key=f"q_{r_num}", use_container_width=True):
                search_roll = r_num

    st.markdown("---")

    if search_roll in st.session_state.issued_certificates:
        student_data = st.session_state.issued_certificates[search_roll]
        s_details = student_data["details"]
        s_image = student_data["image"]

        st.markdown(f"""
        <div class="student-card">
            <h3 style="color:#1E3A8A; margin:0 0 0.5rem 0;">🎓 Official Student Record: {s_details['name']}</h3>
            <div style="display:flex; gap:2rem; flex-wrap:wrap; color:#374151;">
                <div><b>Roll Number:</b> {s_details['roll']}</div>
                <div><b>Program:</b> {s_details['degree']}</div>
                <div><b>Graduation Year:</b> {s_details['year']}</div>
                <div><b>CGPA:</b> <span style="color:#B91C1C; font-weight:700;">{s_details['cgpa']} / 10.0</span></div>
                <div><b>Certificate ID:</b> {s_details['cert_id']}</div>
            </div>
        </div>
        """, unsafe_allow_html=True)

        col_st_img, col_st_dl = st.columns([3, 1], gap="large")
        with col_st_img:
            st.image(s_image, caption=f"Official Degree Certificate - {s_details['name']} ({s_details['roll']})", use_container_width=True)

        with col_st_dl:
            st.markdown("### Credential Actions")
            st.success("✅ This certificate is cryptographically signed and protected with dual-layer steganography.")
            buf_dl = io.BytesIO()
            s_image.save(buf_dl, format="PNG")
            st.download_button(
                label="⬇️ Download Official Certificate (PNG)",
                data=buf_dl.getvalue(),
                file_name=f"{s_details['roll']}_Official_Certificate.png",
                mime="image/png",
                use_container_width=True
            )
            st.info("💡 You can submit this PNG certificate directly to any verifying authority or employer. Any tampering with digits or text will be immediately detected.")
    else:
        st.warning(f"No certificate found for Roll Number '{search_roll}'. Please check the roll number or contact the registrar.")
        st.info(f"Available Roll Numbers: {', '.join(st.session_state.issued_certificates.keys())}")


# =====================================================================
# TAB 3: TAMPER LAB (FORGERY SIMULATOR)
# =====================================================================
with tab3:
    st.markdown('<span class="portal-badge badge-lab">ATTACK SIMULATION & AUDITING</span>', unsafe_allow_html=True)
    st.header("Tamper Lab: Forgery Simulator")
    st.write("Make targeted edits or simulate forgery attacks on a genuine certificate. Then, send it to the **Administration Portal** to watch the tamper engine detect and locate the exact edits!")

    # 1. Select certificate to tamper
    rolls = list(st.session_state.issued_certificates.keys())
    selected_target_roll = st.selectbox("Select Certificate to Modify:", rolls, index=0)
    base_target_img = st.session_state.issued_certificates[selected_target_roll]["image"]
    base_target_details = st.session_state.issued_certificates[selected_target_roll]["details"]

    col_t_ops, col_t_preview = st.columns([1, 1], gap="large")

    with col_t_ops:
        st.subheader("Choose Forgery / Alteration Technique")

        tamper_mode = st.radio(
            "Select Modification Type:",
            [
                "🔢 Alter CGPA Grade (Digit Tampering)",
                "👤 Alter Student Name (Identity Forgery)",
                "🔲 Tamper Collegiate Seal / Signature (Region Occlusion)",
                "📉 Lossy Image Compression (JPEG Conversion)"
            ]
        )

        modified_img = None

        if tamper_mode == "🔢 Alter CGPA Grade (Digit Tampering)":
            st.write(f"Original CGPA: **{base_target_details['cgpa']}**")
            new_cgpa_val = st.text_input("Enter Forged CGPA:", value="9.98")
            if st.button("Apply CGPA Tampering", use_container_width=True):
                # Repaint CGPA field box
                arr = np.array(base_target_img)
                img = Image.fromarray(arr)
                d = ImageDraw.Draw(img)
                x1, y1, x2, y2 = FIELD_LAYOUT["cgpa"]
                d.rectangle([x1, y1, x2, y2], fill=(250, 248, 240))
                d.text(((x1+x2)//2, (y1+y2)//2), f"Cumulative Grade Point Average (CGPA): {new_cgpa_val} / 10.0", font=_get_font("arial", 28), fill=(128, 20, 20), anchor="mm")
                st.session_state.tampered_certificate = img
                st.session_state.last_tamper_desc = f"CGPA altered from {base_target_details['cgpa']} to {new_cgpa_val}"
                st.success("Applied CGPA tampering!")

        elif tamper_mode == "👤 Alter Student Name (Identity Forgery)":
            st.write(f"Original Name: **{base_target_details['name']}**")
            forged_name = st.text_input("Enter Forged Student Name:", value="Dr. Victor Forger")
            if st.button("Apply Name Forgery", use_container_width=True):
                arr = np.array(base_target_img)
                img = Image.fromarray(arr)
                d = ImageDraw.Draw(img)
                x1, y1, x2, y2 = FIELD_LAYOUT["name"]
                d.rectangle([x1, y1, x2, y2], fill=(250, 248, 240))
                d.text(((x1+x2)//2, (y1+y2)//2), forged_name, font=_get_font("georgia", 38), fill=(128, 20, 20), anchor="mm")
                st.session_state.tampered_certificate = img
                st.session_state.last_tamper_desc = f"Student Name altered to '{forged_name}'"
                st.success("Applied Name forgery!")

        elif tamper_mode == "🔲 Tamper Collegiate Seal / Signature (Region Occlusion)":
            st.write("Overwrites the official golden verification seal with unauthorized pixels:")
            if st.button("Tamper Seal Region", use_container_width=True):
                arr = np.array(base_target_img)
                img = Image.fromarray(arr)
                d = ImageDraw.Draw(img)
                # Seal coordinates around (320, 1010)
                d.rectangle([250, 940, 390, 1080], fill=(220, 38, 38, 255))
                d.text((320, 1010), "FORGED", font=_get_font("arial", 24), fill=(255, 255, 255), anchor="mm")
                st.session_state.tampered_certificate = img
                st.session_state.last_tamper_desc = "Collegiate seal overwritten with invalid graphic"
                st.success("Applied seal tampering!")

        else:
            st.write("Compresses the certificate as lossy JPEG (Quality 75). This destroys the fragile LSB bit-planes while testing if the robust DCT watermark survives:")
            jpeg_q = st.slider("JPEG Compression Quality:", min_value=30, max_value=90, value=75, step=5)
            if st.button("Apply JPEG Compression", use_container_width=True):
                buf_jpg = io.BytesIO()
                base_target_img.save(buf_jpg, format="JPEG", quality=jpeg_q)
                buf_jpg.seek(0)
                jpg_img = Image.open(buf_jpg).convert("RGB")
                st.session_state.tampered_certificate = jpg_img
                st.session_state.last_tamper_desc = f"Lossy JPEG compressed at Quality {jpeg_q}"
                st.success(f"Applied JPEG Compression (Q={jpeg_q})!")

        # Direct transfer to Administration Verification
        if st.session_state.tampered_certificate is not None:
            st.markdown("---")
            st.subheader("Transfer to Administration")
            st.write(f"Current Modified Certificate: **{st.session_state.get('last_tamper_desc', 'Custom alteration')}**")
            if st.button("🔍 Send to Administration for Verification ➡️", type="primary", use_container_width=True):
                st.session_state.audit_rep = verify_certificate_full(st.session_state.tampered_certificate, v_priv, i_pub, session_key)
                st.session_state.last_audited_img = st.session_state.tampered_certificate
                st.success("Transferred to Administration! Switch to the 'Administration Portal' tab to view the forensic detection results and red heatmap.")

    with col_t_preview:
        st.subheader("Tampered Certificate Preview")
        if st.session_state.tampered_certificate is not None:
            st.image(st.session_state.tampered_certificate, caption=f"Modified Certificate: {st.session_state.get('last_tamper_desc', '')}", use_container_width=True)

            buf_t = io.BytesIO()
            st.session_state.tampered_certificate.save(buf_t, format="PNG")
            st.download_button(
                label="⬇️ Download Tampered Certificate (PNG)",
                data=buf_t.getvalue(),
                file_name="tampered_test_certificate.png",
                mime="image/png",
                use_container_width=True
            )
        else:
            st.info("Select an alteration option on the left and click 'Apply' to see the modified certificate here.")
            st.image(base_target_img, caption="Currently Genuine Certificate", use_container_width=True)


# =====================================================================
# TAB 4: SYSTEM SECURITY & PRIVACY ENGINE
# =====================================================================
with tab_tech:
    st.markdown('<span class="portal-badge badge-tech">SECURITY ARCHITECTURE</span>', unsafe_allow_html=True)
    st.header("System Security & Privacy Technologies")
    st.write("An overview and interactive simulation of the core security algorithms powering TrustLens.")

    col_sec1, col_sec2 = st.columns([1, 1], gap="large")

    # SECTION 1: PRIVACY-PRESERVING STATISTICS
    with col_sec1:
        st.subheader("1. Privacy-Preserving Institutional Statistics")
        st.write("When universities publish aggregate graduation counts or department performance metrics, publishing raw figures can leak individual student statuses, especially in small departments. TrustLens implements **Differential Privacy** to mathematically prevent privacy leakage.")

        st.markdown("#### Laplace Noise Injection")
        st.caption("Adds calibrated noise drawn from the Laplace distribution: Noisy Count = True Count + Laplace(0, Sensitivity / ε).")

        true_grad_count = st.number_input("True Department Graduate Count:", value=420, step=10)
        eps_slider = st.slider("Privacy Parameter ε (Epsilon):", min_value=0.1, max_value=5.0, value=1.0, step=0.1,
                               help="Smaller ε provides stronger privacy protection (more noise). Larger ε provides higher accuracy.")

        # Real-time Privacy Budget Tracking
        b_mgr = st.session_state.budget
        st.progress(b_mgr.percent_consumed / 100.0, text=f"Institutional Privacy Budget: {b_mgr.spent_epsilon:.1f} / {b_mgr.max_epsilon:.1f} ε spent ({b_mgr.percent_consumed:.0f}%)")

        c_q1, c_q2 = st.columns(2)
        if c_q1.button("Query Noisy Count", use_container_width=True):
            if b_mgr.spend(eps_slider):
                noisy_val = laplace_mechanism(true_grad_count, eps_slider)
                err = abs(noisy_val - true_grad_count)
                st.success(f"Reported Graduate Count: **{noisy_val}** (Noise Deviation: ±{err}, Expected Error: ~{1.0/eps_slider:.2f})")
            else:
                st.error("🚨 QUERY REFUSED: Privacy budget for this evaluation period is exhausted!")

        if c_q2.button("Reset Privacy Budget", use_container_width=True):
            b_mgr.reset()
            st.rerun()

        st.markdown("---")
        st.markdown("#### Private Department Honors Award")
        st.caption("Selects the top department using the **Exponential Mechanism**, probabilistically choosing the winner proportional to score without revealing exact student figures.")

        dept_scores = {
            "Computer Science": 420,
            "Electronics & Comm": 310,
            "Mechanical Eng": 240,
            "Civil Engineering": 110
        }
        exp_eps_val = st.slider("Selection Privacy ε:", 0.2, 5.0, 1.5, 0.2)
        if st.button("Run Private Department Selection", use_container_width=True):
            top_dept, prob_dist = exponential_mechanism(dept_scores, exp_eps_val)
            st.success(f"Awarded Department: **{top_dept}**")
            st.bar_chart(prob_dist)

    # SECTION 2: CRYPTOGRAPHIC INTEGRITY & STREAM CIPHERS
    with col_sec2:
        st.subheader("2. Cryptographic Integrity & Stream Encryption")
        st.write("Student records hidden inside certificates are digitally signed and stream-encrypted using non-linear combination keystream generators.")

        st.markdown("#### Keystream Security: LFSR vs Geffe Generator")
        st.caption("A standard Linear Feedback Shift Register (LFSR) has linear predictability and can be broken with the Berlekamp-Massey algorithm. TrustLens uses a **Geffe Generator** which non-linearly combines three registers to eliminate linear predictability.")

        lfsr_seed = 12345
        sample_lfsr = LFSR(size=19, taps=[0, 1, 4, 18], seed=lfsr_seed)
        lfsr_bits = [sample_lfsr.step() for _ in range(40)]
        st.code(f"19-bit Linear LFSR Stream (First 40 bits):\n{''.join(map(str, lfsr_bits))}")

        lc_lfsr = berlekamp_massey(lfsr_bits)
        st.warning(f"Linear Complexity: L = {lc_lfsr} ⚠️ (Vulnerable! Broken at degree 19 by Berlekamp-Massey).")

        geffe_engine = GeffeGenerator(b"institutional_secret_key_2026")
        geffe_bits = [geffe_engine.step() for _ in range(40)]
        st.code(f"Geffe Non-Linear Stream (First 40 bits):\n{''.join(map(str, geffe_bits))}")

        lc_geffe = berlekamp_massey(geffe_bits)
        st.success(f"Linear Complexity: L = {lc_geffe} ✅ (High non-linear complexity resists Berlekamp-Massey cryptanalysis).")

        st.markdown("---")
        st.markdown("#### Institutional Session Key Agreement")
        st.caption("Uses **Diffie-Hellman Key Exchange** so the issuing authority and verifying portal compute an identical 256-bit symmetric session key over an insecure channel without transmitting the key itself.")

        if st.button("Simulate Diffie-Hellman Key Agreement", use_container_width=True):
            p1_priv, p1_pub = dh_generate_keypair()
            p2_priv, p2_pub = dh_generate_keypair()
            k1 = dh_shared_secret(p1_priv, p2_pub)
            k2 = dh_shared_secret(p2_priv, p1_pub)

            st.write(f"Issuer Authority Public Key: `{p1_pub}`")
            st.write(f"Verifier Portal Public Key: `{p2_pub}`")
            st.success(f"✅ Shared Symmetric Key Agreed by Both Authorities:\n`{k1.hex()}`")
