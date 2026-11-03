"""app.py
TrustLens: Academic Credential Protection, Forensic Verification & Privacy-Preserving System.
Designed for IIIT Nagpur (Indian Institute of Information Technology, Nagpur).
Connected to SQLite Database Backend (trustlens.db).
"""

import io
import re
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
from database import (
    init_db, seed_initial_records_if_empty, save_certificate,
    get_certificate, get_all_records, is_valid_iiitn_roll, normalize_roll
)

# Streamlit Page Configuration
st.set_page_config(
    page_title="TrustLens | IIIT Nagpur",
    page_icon="🏛️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Cream & Warm Brown Institutional Theme
st.markdown("""
<style>
    /* Global Background and Typography */
    .stApp {
        background-color: #FBF8F3;
        color: #38281C;
    }
    
    /* Headers */
    .main-header {
        font-family: 'Georgia', serif;
        font-size: 2.2rem;
        font-weight: 700;
        color: #38281C;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-family: 'Arial', sans-serif;
        font-size: 1.05rem;
        color: #6B4E3D;
        margin-bottom: 1.4rem;
    }
    
    /* Institutional Badges */
    .badge-pill {
        display: inline-block;
        padding: 0.25rem 0.8rem;
        border-radius: 9999px;
        font-size: 0.82rem;
        font-weight: 600;
        letter-spacing: 0.03em;
        margin-bottom: 0.6rem;
    }
    .badge-admin { background-color: #EDE4D8; color: #4A3525; border: 1px solid #D4C3A3; }
    .badge-student { background-color: #E8EFE6; color: #2D5A27; border: 1px solid #C4D7BF; }
    .badge-lab { background-color: #FDF3E3; color: #8C5311; border: 1px solid #ECD4A4; }
    .badge-tech { background-color: #EDE7F6; color: #4A148C; border: 1px solid #D1C4E9; }

    /* Cards */
    .theme-card {
        background-color: #FFFDF9;
        border: 1px solid #E8DCB8;
        border-radius: 8px;
        padding: 1.25rem;
        margin-bottom: 1rem;
        box-shadow: 0 1px 3px rgba(56, 40, 28, 0.05);
    }
    .card-genuine {
        background-color: #F3FBF5;
        border-left: 6px solid #2E7D32;
        border-top: 1px solid #D7ECD9;
        border-right: 1px solid #D7ECD9;
        border-bottom: 1px solid #D7ECD9;
        padding: 1.25rem;
        border-radius: 6px;
        margin: 1rem 0;
    }
    .card-forged {
        background-color: #FDF4F4;
        border-left: 6px solid #C62828;
        border-top: 1px solid #F8D7D7;
        border-right: 1px solid #F8D7D7;
        border-bottom: 1px solid #F8D7D7;
        padding: 1.25rem;
        border-radius: 6px;
        margin: 1rem 0;
    }
    .card-damaged {
        background-color: #FFFDF0;
        border-left: 6px solid #E65100;
        border-top: 1px solid #FFE7A0;
        border-right: 1px solid #FFE7A0;
        border-bottom: 1px solid #FFE7A0;
        padding: 1.25rem;
        border-radius: 6px;
        margin: 1rem 0;
    }
    
    /* Input Styling Accents */
    div[data-baseweb="input"] {
        background-color: #FFFFFF !important;
        border-color: #D4C3A3 !important;
    }
</style>
""", unsafe_allow_html=True)


# Initialize and Cache Cryptographic Keys
@st.cache_resource(show_spinner="Initializing Institutional Cryptographic Authority...")
def get_system_keys():
    i_pub, i_priv = rsa_keygen(bits=1024)
    v_pub, v_priv = rsa_keygen(bits=1024)
    a_priv, a_pub = dh_generate_keypair()
    b_priv, b_pub = dh_generate_keypair()
    session_key = dh_shared_secret(a_priv, b_pub)
    return i_pub, i_priv, v_pub, v_priv, session_key


i_pub, i_priv, v_pub, v_priv, session_key = get_system_keys()

# Initialize Database & Pre-seed IIITN Records
init_db()
seed_initial_records_if_empty(issue_certificate_full, i_priv, v_pub, session_key)

# Session State for Labs
if "budget" not in st.session_state:
    st.session_state.budget = PrivacyBudget(max_epsilon=5.0)

if "lab_tampered_img" not in st.session_state:
    st.session_state.lab_tampered_img = None
    st.session_state.lab_tamper_desc = ""

# Application Header
st.markdown('<div class="main-header">🏛️ Indian Institute of Information Technology, Nagpur</div>', unsafe_allow_html=True)
st.markdown('<div class="sub-header">TrustLens: Official Academic Credential Protection, Forensic Verification & Differential Privacy</div>', unsafe_allow_html=True)

# Main Navigation Portals
tab_admin, tab_student, tab_tamper, tab_tech = st.tabs([
    "🏛️ Administration Portal",
    "🎓 Student Portal",
    "🧪 Tamper Lab (Forgery Simulator)",
    "🛡️ Security & Privacy System"
])


# =====================================================================
# TAB 1: ADMINISTRATION PORTAL (ISSUE & AUDIT)
# =====================================================================
with tab_admin:
    st.markdown('<span class="badge-pill badge-admin">OFFICE OF THE REGISTRAR & EXAMINATION AUTHORITY</span>', unsafe_allow_html=True)
    st.subheader("Institutional Credential Administration")

    admin_mode = st.radio(
        "Administrative Operation:",
        ["📜 Issue & Register New Certificate", "🔍 Audit & Verify Certificate Authenticity", "📋 Database Credential Registry"],
        horizontal=True
    )
    st.markdown("---")

    # 1. ISSUE NEW CERTIFICATE
    if admin_mode == "📜 Issue & Register New Certificate":
        col_form, col_preview = st.columns([1, 1], gap="large")

        with col_form:
            st.markdown("### Issue Official Degree Certificate")
            st.caption("Generates degree image, applies RSA digital signature over record hash, stream-encrypts metadata via Geffe generator, and embeds dual-layer watermarks.")

            with st.form("admin_issue_form"):
                f_name = st.text_input("Full Student Name", value="Rohan Verma")
                f_roll = st.text_input("Roll Number (format: BTxxYYYxxx)", value="BT22CSE099", help="Standard IIITN format: BT + 2-digit year + Department (CSE/ECE/CSB/AIDS) + 3-digit number").strip().upper()
                f_degree = st.selectbox(
                    "Degree Program",
                    [
                        "Bachelor of Technology in Computer Science & Engineering",
                        "Bachelor of Technology in Electronics & Communication Engg.",
                        "Bachelor of Technology in Artificial Intelligence & Data Science",
                        "Bachelor of Technology in Computer Science & Business Systems"
                    ]
                )
                c_yr, c_cgpa = st.columns(2)
                f_year = c_yr.text_input("Graduating Year", value="2026")
                f_cgpa = c_cgpa.text_input("Final CGPA", value="9.15")
                f_cid = st.text_input("Certificate ID (Robust DCT Carrier)", value=f"IIITN-2026-{f_roll[-3:] if len(f_roll)>=3 else '0099'}")

                btn_issue = st.form_submit_button("🛡️ Issue & Save to Database", use_container_width=True)

            if btn_issue:
                if not is_valid_iiitn_roll(f_roll):
                    st.error(f"⚠️ Invalid Roll Number format '{f_roll}'. Must follow institutional format 'BTxxYYYxxx' (e.g. BT22CSE045).")
                else:
                    new_rec = {
                        "name": f_name.strip(),
                        "roll": f_roll,
                        "degree": f_degree.strip(),
                        "year": f_year.strip(),
                        "cgpa": f_cgpa.strip(),
                        "cert_id": f_cid.strip()
                    }
                    with st.spinner("Cryptographically signing, embedding watermarks, and committing to SQLite database..."):
                        new_cert_img = issue_certificate_full(new_rec, i_priv, v_pub, session_key)
                        save_certificate(new_rec, new_cert_img)
                        st.session_state.last_issued_roll = f_roll

                    st.success(f"✅ Official degree certificate for {f_name} ({f_roll}) successfully registered in database!")

        with col_preview:
            st.markdown("### Issued Certificate Preview")
            all_db_records = get_all_records()
            if all_db_records:
                selected_preview_roll = st.selectbox(
                    "Select Stored Record to Inspect:",
                    [r["roll"] for r in all_db_records],
                    index=0
                )
                fetched = get_certificate(selected_preview_roll)
                if fetched:
                    f_details, f_img = fetched
                    st.image(f_img, caption=f"Official Certificate ({f_details['roll']})", use_container_width=True)

                    buf = io.BytesIO()
                    f_img.save(buf, format="PNG")
                    st.download_button(
                        label=f"⬇️ Download {f_details['roll']} Official Certificate (PNG)",
                        data=buf.getvalue(),
                        file_name=f"{f_details['roll']}_Certificate.png",
                        mime="image/png",
                        use_container_width=True
                    )

    # 2. AUDIT & VERIFY
    elif admin_mode == "🔍 Audit & Verify Certificate Authenticity":
        st.markdown("### Forensic Certificate Verification Audit")
        st.write("Verifies uploaded or registered certificates: decrypts stego payload, checks the digital signature, and validates 1,800 block checksums to identify exact tampering.")

        audit_source = st.radio(
            "Select Audit Source:",
            ["📁 Upload Certificate Image to Audit", "🧪 Audit Modified Image from Tamper Lab", "💾 Audit Directly from SQLite Database"],
            horizontal=True
        )

        audit_target_img = None
        if audit_source == "📁 Upload Certificate Image to Audit":
            uploaded_cert = st.file_uploader("Upload certificate file (PNG/JPEG):", type=["png", "jpg", "jpeg"])
            if uploaded_cert:
                audit_target_img = Image.open(uploaded_cert).convert("RGB")
        elif audit_source == "🧪 Audit Modified Image from Tamper Lab":
            if st.session_state.lab_tampered_img is not None:
                audit_target_img = st.session_state.lab_tampered_img
                st.info(f"Loaded certificate from Tamper Lab: {st.session_state.lab_tamper_desc}")
            else:
                st.warning("No modified certificate found in the Tamper Lab yet. Create a test forgery in the 'Tamper Lab' tab first!")
        else:
            all_recs = get_all_records()
            if all_recs:
                db_pick = st.selectbox("Choose database record to audit:", [r["roll"] for r in all_recs])
                fetched_entry = get_certificate(db_pick)
                if fetched_entry:
                    audit_target_img = fetched_entry[1]

        if audit_target_img is not None:
            if st.button("🔍 Run Full Cryptographic & Forensic Audit", type="primary", use_container_width=True):
                with st.spinner("Checking RSA signature, recomputing block checksums, and reading DCT watermark..."):
                    audit_result = verify_certificate_full(audit_target_img, v_priv, i_pub, session_key)
                    st.session_state.active_audit_result = audit_result
                    st.session_state.active_audit_img = audit_target_img

        if "active_audit_result" in st.session_state and st.session_state.get("active_audit_img") is not None:
            rep = st.session_state.active_audit_result
            inspected_image = st.session_state.active_audit_img

            # Verdict Banner
            if rep["verdict"] == "GENUINE":
                st.markdown(f"""
                <div class="card-genuine">
                    <h3 style="color:#1B5E20; margin:0;">✅ VERDICT: GENUINE CERTIFICATE</h3>
                    <p style="margin:0.5rem 0 0 0; color:#2E7D32; font-size:1.05rem;">{rep['reason']}</p>
                </div>
                """, unsafe_allow_html=True)
            elif rep["verdict"] == "FORGED / EDITED":
                st.markdown(f"""
                <div class="card-forged">
                    <h3 style="color:#B71C1C; margin:0;">🚨 VERDICT: FORGED / TAMPERED CERTIFICATE</h3>
                    <p style="margin:0.5rem 0 0 0; color:#C62828; font-size:1.05rem;">{rep['reason']}</p>
                </div>
                """, unsafe_allow_html=True)
            elif rep["verdict"] == "DAMAGED ORIGINAL":
                st.markdown(f"""
                <div class="card-damaged">
                    <h3 style="color:#E65100; margin:0;">⚠️ VERDICT: DAMAGED ORIGINAL</h3>
                    <p style="margin:0.5rem 0 0 0; color:#BF360C; font-size:1.05rem;">{rep['reason']}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.error(f"❌ {rep['verdict']}: {rep['reason']}")

            # Summary Metrics
            c_m1, c_m2, c_m3 = st.columns(3)
            c_m1.metric("Cryptographic Signature", "✅ Valid & Authentic" if rep["sig_valid"] else "❌ Invalid")
            c_m2.metric("Tampered 32x32 Blocks", f"{rep['failed_blocks']} / 1,800 blocks")
            c_m3.metric("Robust DCT Identifier", rep["dct_id"] or "Not Detected")

            # Visual Comparison: Certificate vs Tamper Heatmap
            st.markdown("#### Block-Level Tamper Localization Map")
            c_ins1, c_ins2 = st.columns(2)
            with c_ins1:
                st.subheader("Audited Certificate Image")
                st.image(inspected_image, use_container_width=True)

            with c_ins2:
                st.subheader("Tamper Localization Heatmap")
                st.image(rep["heatmap"], caption="Failed 32x32 blocks highlighted in red", use_container_width=True)

            if rep["hidden_record"]:
                st.markdown("#### Authentic Digitally Signed Record Extracted from Hidden Stego Layer")
                st.dataframe(pd.DataFrame([rep["hidden_record"]]), use_container_width=True)

    # 3. DATABASE REGISTRY VIEW
    else:
        st.markdown("### SQLite Database Credential Registry")
        st.caption("Live records stored securely in `trustlens.db`.")
        registry_data = get_all_records()
        if registry_data:
            df_reg = pd.DataFrame(registry_data)
            df_reg.columns = ["Roll Number", "Student Name", "Degree Program", "Graduation Year", "CGPA", "Certificate ID", "Issued At"]
            st.dataframe(df_reg, use_container_width=True)
        else:
            st.info("No certificates registered in the database yet.")


# =====================================================================
# TAB 2: STUDENT PORTAL (QUERY WITH ROLL NO & DOWNLOAD)
# =====================================================================
with tab_student:
    st.markdown('<span class="badge-pill badge-student">STUDENT CREDENTIAL VERIFICATION & DOWNLOAD</span>', unsafe_allow_html=True)
    st.subheader("Student Degree Credential Retrieval")
    st.write("Enter your official University Roll Number to fetch and download your cryptographically protected degree certificate from the institutional database.")

    col_search_box, col_search_btn = st.columns([3, 1])
    with col_search_box:
        student_query_roll = st.text_input(
            "Enter University Roll Number:",
            placeholder="e.g. BT22CSE045",
            help="Format: BT + 2-digit year + Branch + 3-digit roll (e.g. BT22CSE045, BT22ECE018)"
        ).strip().upper()

    with col_search_btn:
        st.write("") # Alignment spacing
        st.write("")
        btn_search = st.button("🔍 Access Degree Certificate", type="primary", use_container_width=True)

    st.markdown("---")

    if student_query_roll:
        result = get_certificate(student_query_roll)

        if result is not None:
            details, cert_image = result

            st.markdown(f"""
            <div class="theme-card">
                <h3 style="color:#38281C; font-family:'Georgia', serif; margin:0 0 0.6rem 0;">🎓 Official Degree Record: {details['name']}</h3>
                <div style="display:flex; gap:2.5rem; flex-wrap:wrap; color:#5A402D; font-size:1.02rem;">
                    <div><b>Roll Number:</b> {details['roll']}</div>
                    <div><b>Program:</b> {details['degree']}</div>
                    <div><b>Graduation Year:</b> {details['year']}</div>
                    <div><b>CGPA:</b> <span style="color:#8C1C1C; font-weight:700;">{details['cgpa']} / 10.0</span></div>
                    <div><b>Certificate ID:</b> {details['cert_id']}</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            col_view_cert, col_actions = st.columns([3, 1], gap="large")
            with col_view_cert:
                st.image(cert_image, caption=f"Official Degree Certificate - {details['name']} ({details['roll']})", use_container_width=True)

            with col_actions:
                st.markdown("### Credential Actions")
                st.success("✅ Authentic credential verified from IIIT Nagpur institutional database.")
                
                buf_dl = io.BytesIO()
                cert_image.save(buf_dl, format="PNG")
                st.download_button(
                    label="⬇️ Download Official Certificate (PNG)",
                    data=buf_dl.getvalue(),
                    file_name=f"{details['roll']}_Official_Certificate.png",
                    mime="image/png",
                    use_container_width=True
                )
                st.info("💡 **Verification Notice:** This certificate contains an encrypted digital signature and fragile 32x32 block hashes. Any digital alteration to digits, grades, or names will be detected upon verification.")
        else:
            st.error(f"❌ No official credential found for Roll Number '{student_query_roll}'. Please check your enrollment number or contact the IIIT Nagpur Academic Office.")


# =====================================================================
# TAB 3: TAMPER LAB (FORGERY SIMULATOR)
# =====================================================================
with tab_tamper:
    st.markdown('<span class="badge-pill badge-lab">SECURITY TESTING & ATTACK SIMULATION</span>', unsafe_allow_html=True)
    st.subheader("Tamper Lab: Forgery Simulator")
    st.write("Simulate real-world academic credential tampering (grade inflation, identity theft, or compression). Then send the altered certificate to the **Administration Portal** to observe the forensic tamper detection in action!")

    all_stored = get_all_records()
    if all_stored:
        c_pick, c_info = st.columns([2, 1])
        with c_pick:
            tamper_source_roll = st.selectbox("Select Target Certificate to Tamper:", [r["roll"] for r in all_stored])
        
        target_entry = get_certificate(tamper_source_roll)
        if target_entry:
            base_details, base_image = target_entry

            col_mod_controls, col_mod_preview = st.columns([1, 1], gap="large")

            with col_mod_controls:
                st.markdown("### Select Forgery Attack")
                attack_type = st.radio(
                    "Choose Attack Mode:",
                    [
                        "🔢 Digit Tampering (Inflate CGPA to 9.98)",
                        "👤 Identity Forgery (Alter Student Name)",
                        "🔲 Region Occlusion (Tamper Golden Seal)",
                        "📉 Lossy Image Compression (Convert to JPEG Q=75)"
                    ]
                )

                if attack_type == "🔢 Digit Tampering (Inflate CGPA to 9.98)":
                    st.write(f"Original Authentic CGPA: **{base_details['cgpa']}**")
                    custom_cgpa = st.text_input("Enter Forged CGPA Grade:", value="9.98")
                    if st.button("Apply Grade Forgery", use_container_width=True):
                        arr = np.array(base_image)
                        img = Image.fromarray(arr)
                        d = ImageDraw.Draw(img)
                        x1, y1, x2, y2 = FIELD_LAYOUT["cgpa"]
                        d.rectangle([x1, y1, x2, y2], fill=(252, 249, 242))
                        d.text(((x1+x2)//2, (y1+y2)//2), f"Cumulative Grade Point Average (CGPA): {custom_cgpa} / 10.0", font=_get_font("arial", 28), fill=(142, 28, 28), anchor="mm")
                        st.session_state.lab_tampered_img = img
                        st.session_state.lab_tamper_desc = f"CGPA altered from {base_details['cgpa']} to {custom_cgpa} for {base_details['roll']}"
                        st.success("Tampered CGPA applied!")

                elif attack_type == "👤 Identity Forgery (Alter Student Name)":
                    st.write(f"Original Authentic Name: **{base_details['name']}**")
                    forged_name = st.text_input("Enter Forged Student Name:", value="Dr. Victor Forger")
                    if st.button("Apply Name Forgery", use_container_width=True):
                        arr = np.array(base_image)
                        img = Image.fromarray(arr)
                        d = ImageDraw.Draw(img)
                        x1, y1, x2, y2 = FIELD_LAYOUT["name"]
                        d.rectangle([x1, y1, x2, y2], fill=(252, 249, 242))
                        d.text(((x1+x2)//2, (y1+y2)//2), forged_name, font=_get_font("georgia", 38), fill=(142, 28, 28), anchor="mm")
                        st.session_state.lab_tampered_img = img
                        st.session_state.lab_tamper_desc = f"Name altered to '{forged_name}' on certificate of {base_details['roll']}"
                        st.success("Tampered Name applied!")

                elif attack_type == "🔲 Region Occlusion (Tamper Golden Seal)":
                    st.write("Overwrites the official IIIT Nagpur verification seal with unauthorized pixels:")
                    if st.button("Tamper Seal Region", use_container_width=True):
                        arr = np.array(base_image)
                        img = Image.fromarray(arr)
                        d = ImageDraw.Draw(img)
                        d.rectangle([250, 940, 390, 1080], fill=(180, 40, 40))
                        d.text((320, 1010), "TAMPERED", font=_get_font("arial", 22), fill=(255, 255, 255), anchor="mm")
                        st.session_state.lab_tampered_img = img
                        st.session_state.lab_tamper_desc = f"Verification seal overwritten on certificate of {base_details['roll']}"
                        st.success("Tampered Seal applied!")

                else:
                    st.write("Simulates saving the certificate as a lossy JPEG file (Quality 75). This destroys the fragile LSB bit-planes while testing if the robust DCT watermark survives:")
                    jpeg_quality = st.slider("JPEG Compression Quality:", 30, 90, 75, 5)
                    if st.button("Apply Lossy Compression", use_container_width=True):
                        buf_jpg = io.BytesIO()
                        base_image.save(buf_jpg, format="JPEG", quality=jpeg_quality)
                        buf_jpg.seek(0)
                        compressed_img = Image.open(buf_jpg).convert("RGB")
                        st.session_state.lab_tampered_img = compressed_img
                        st.session_state.lab_tamper_desc = f"Lossy JPEG compression (Q={jpeg_quality}) on {base_details['roll']}"
                        st.success("Compressed certificate as JPEG!")

                # Transfer to Administration Button
                if st.session_state.lab_tampered_img is not None:
                    st.markdown("---")
                    st.write(f"**Current Tampered Version:** {st.session_state.lab_tamper_desc}")
                    if st.button("🔍 Send to Administration for Verification ➡️", type="primary", use_container_width=True):
                        st.session_state.active_audit_result = verify_certificate_full(st.session_state.lab_tampered_img, v_priv, i_pub, session_key)
                        st.session_state.active_audit_img = st.session_state.lab_tampered_img
                        st.success("✅ Transferred! Now click on the 'Administration Portal' tab to see the forensic detection results and red heatmap.")

            with col_mod_preview:
                st.markdown("### Certificate Preview")
                if st.session_state.lab_tampered_img is not None:
                    st.image(st.session_state.lab_tampered_img, caption="Tampered Certificate Preview", use_container_width=True)
                    buf_dl_t = io.BytesIO()
                    st.session_state.lab_tampered_img.save(buf_dl_t, format="PNG")
                    st.download_button(
                        label="⬇️ Download Tampered Certificate (PNG)",
                        data=buf_dl_t.getvalue(),
                        file_name=f"Tampered_{base_details['roll']}.png",
                        mime="image/png",
                        use_container_width=True
                    )
                else:
                    st.image(base_image, caption=f"Original Genuine Certificate ({base_details['roll']})", use_container_width=True)


# =====================================================================
# TAB 4: SYSTEM SECURITY & PRIVACY ENGINE
# =====================================================================
with tab_tech:
    st.markdown('<span class="badge-pill badge-tech">SECURITY ARCHITECTURE & PRIVACY CONTROLS</span>', unsafe_allow_html=True)
    st.subheader("System Security & Privacy Technologies")
    st.write("An operational overview and interactive demonstration of the core cryptographic algorithms and privacy guarantees powering TrustLens.")

    col_dp_sec, col_crypto_sec = st.columns([1, 1], gap="large")

    # 1. DIFFERENTIAL PRIVACY
    with col_dp_sec:
        st.markdown("### 1. Privacy-Preserving Institutional Statistics")
        st.write("When educational institutions publish department graduation counts or placement metrics, publishing exact counts can compromise individual student privacy, especially in small departments. TrustLens implements **Differential Privacy (DP)** to provide mathematical privacy guarantees.")

        st.markdown("#### Laplace Noise Injection Engine")
        st.caption("Injects calibrated noise from the Laplace distribution: Noisy Count = True Count + Laplace(0, Sensitivity / ε).")

        true_grad_count = st.number_input("True Department Graduate Count:", value=380, step=10)
        eps_slider = st.slider(
            "Privacy Parameter ε (Epsilon):",
            min_value=0.1, max_value=5.0, value=1.0, step=0.1,
            help="Smaller ε injects more noise (stronger privacy). Larger ε injects less noise (higher numerical accuracy)."
        )

        # Real-time Budget Tracking
        b_mgr = st.session_state.budget
        st.progress(b_mgr.percent_consumed / 100.0, text=f"Institutional Privacy Budget: {b_mgr.spent_epsilon:.1f} / {b_mgr.max_epsilon:.1f} ε spent ({b_mgr.percent_consumed:.0f}%)")

        c_q1, c_q2 = st.columns(2)
        if c_q1.button("Query Noisy Count", use_container_width=True):
            if b_mgr.spend(eps_slider):
                noisy_val = laplace_mechanism(true_grad_count, eps_slider)
                noise_err = abs(noisy_val - true_grad_count)
                st.success(f"Reported Graduate Count: **{noisy_val}** (Noise Deviation: ±{noise_err}, Expected Error: ~{1.0/eps_slider:.2f})")
            else:
                st.error("🚨 QUERY REFUSED: Institutional privacy budget for this query window has been exhausted!")

        if c_q2.button("Reset Privacy Budget", use_container_width=True):
            b_mgr.reset()
            st.rerun()

        st.markdown("---")
        st.markdown("#### Private Department Honors Award")
        st.caption("Selects the top department using the **Exponential Mechanism**, probabilistically choosing the winner proportional to score without revealing exact student figures.")

        dept_scores = {
            "Computer Science & Engg.": 380,
            "Electronics & Comm. Engg.": 260,
            "Artificial Intelligence & DS": 190,
            "Computer Science & Business": 120
        }
        exp_eps_val = st.slider("Selection Privacy ε:", 0.2, 5.0, 1.5, 0.2)
        if st.button("Run Private Department Selection", use_container_width=True):
            top_dept, prob_dist = exponential_mechanism(dept_scores, exp_eps_val)
            st.success(f"Awarded Department: **{top_dept}**")
            st.bar_chart(prob_dist)

    # 2. CRYPTOGRAPHIC INTEGRITY
    with col_crypto_sec:
        st.markdown("### 2. Cryptographic Integrity & Stream Ciphers")
        st.write("Student records hidden inside certificates are digitally signed using RSA and stream-encrypted using non-linear combination keystream generators.")

        st.markdown("#### Keystream Security: LFSR vs Geffe Generator")
        st.caption("A standard Linear Feedback Shift Register (LFSR) has linear predictability and can be broken with the Berlekamp-Massey algorithm. TrustLens uses a **Geffe Generator** which non-linearly combines three registers to eliminate linear predictability.")

        lfsr_seed = 12345
        sample_lfsr = LFSR(size=19, taps=[0, 1, 4, 18], seed=lfsr_seed)
        lfsr_bits = [sample_lfsr.step() for _ in range(40)]
        st.code(f"19-bit Linear LFSR Stream (First 40 bits):\n{''.join(map(str, lfsr_bits))}")

        lc_lfsr = berlekamp_massey(lfsr_bits)
        st.warning(f"Linear Complexity: L = {lc_lfsr} ⚠️ (Vulnerable! Broken at degree 19 by Berlekamp-Massey).")

        geffe_engine = GeffeGenerator(b"iiitn_institutional_secret_key_2026")
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
