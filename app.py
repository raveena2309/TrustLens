"""app.py
TrustLens: Academic Credential Protection, Forensic Verification & Privacy-Preserving System.
Designed for IIIT Nagpur (Indian Institute of Information Technology, Nagpur).
Connected to SQLite Database Backend (trustlens.db).
"""

import os
import io
import re
import json
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

# Cream & Warm Brown Institutional Theme (Supporting both Light Mode & Dark Mode)
st.markdown("""
<style>
    /* CSS Variables for Institutional Security Theme */
    :root {
        --bg-app: #FAF7F2;
        --card-bg: #FFFDF9;
        --card-border: #E8DCCB;
        --text-primary: #2C1E14;
        --text-secondary: #6B523E;
        --accent-gold: #966023;
        --accent-border: #D8C3A5;
        
        --badge-admin-bg: #EDE4D8;
        --badge-admin-txt: #4A3525;
        --badge-admin-bdr: #D4C3A3;
        
        --badge-stud-bg: #E8EFE6;
        --badge-stud-txt: #2D5A27;
        --badge-stud-bdr: #C4D7BF;
        
        --badge-lab-bg: #FDF3E3;
        --badge-lab-txt: #8C5311;
        --badge-lab-bdr: #ECD4A4;
        
        --badge-tech-bg: #EDE7F6;
        --badge-tech-txt: #4A148C;
        --badge-tech-bdr: #D1C4E9;
        
        --gen-bg: #F0FDF4;
        --gen-bdr: #22C55E;
        --gen-title: #15803D;
        --gen-txt: #166534;
        
        --forg-bg: #FEF2F2;
        --forg-bdr: #EF4444;
        --forg-title: #B91C1C;
        --forg-txt: #991B1B;
        
        --dmg-bg: #FFFBEB;
        --dmg-bdr: #F59E0B;
        --dmg-title: #B45309;
        --dmg-txt: #92400E;
    }

    @media (prefers-color-scheme: dark) {
        :root {
            --bg-app: #0F141C;
            --card-bg: #161D26;
            --card-border: #2A3645;
            --text-primary: #F3EFE9;
            --text-secondary: #B6AEA2;
            --accent-gold: #E5A93C;
            --accent-border: #4A5B73;
            
            --badge-admin-bg: rgba(229, 169, 60, 0.15);
            --badge-admin-txt: #F5C77E;
            --badge-admin-bdr: rgba(229, 169, 60, 0.35);
            
            --badge-stud-bg: rgba(34, 197, 94, 0.15);
            --badge-stud-txt: #86EFAC;
            --badge-stud-bdr: rgba(34, 197, 94, 0.35);
            
            --badge-lab-bg: rgba(239, 68, 68, 0.15);
            --badge-lab-txt: #FCA5A5;
            --badge-lab-bdr: rgba(239, 68, 68, 0.35);
            
            --badge-tech-bg: rgba(168, 85, 247, 0.15);
            --badge-tech-txt: #D8B4FE;
            --badge-tech-bdr: rgba(168, 85, 247, 0.35);
            
            --gen-bg: #072314;
            --gen-bdr: #22C55E;
            --gen-title: #4ADE80;
            --gen-txt: #A7F3D0;
            
            --forg-bg: #2B0C10;
            --forg-bdr: #EF4444;
            --forg-title: #F87171;
            --forg-txt: #FECACA;
            
            --dmg-bg: #2B1B06;
            --dmg-bdr: #F59E0B;
            --dmg-title: #FBBF24;
            --dmg-txt: #FDE68A;
        }
    }

    [data-theme="dark"], .stApp[data-theme="dark"] {
        --bg-app: #0F141C !important;
        --card-bg: #161D26 !important;
        --card-border: #2A3645 !important;
        --text-primary: #F3EFE9 !important;
        --text-secondary: #B6AEA2 !important;
        --accent-gold: #E5A93C !important;
        --accent-border: #4A5B73 !important;
        
        --badge-admin-bg: rgba(229, 169, 60, 0.15) !important;
        --badge-admin-txt: #F5C77E !important;
        --badge-admin-bdr: rgba(229, 169, 60, 0.35) !important;
        
        --badge-stud-bg: rgba(34, 197, 94, 0.15) !important;
        --badge-stud-txt: #86EFAC !important;
        --badge-stud-bdr: rgba(34, 197, 94, 0.35) !important;
        
        --badge-lab-bg: rgba(239, 68, 68, 0.15) !important;
        --badge-lab-txt: #FCA5A5 !important;
        --badge-lab-bdr: rgba(239, 68, 68, 0.35) !important;
        
        --badge-tech-bg: rgba(168, 85, 247, 0.15) !important;
        --badge-tech-txt: #D8B4FE !important;
        --badge-tech-bdr: rgba(168, 85, 247, 0.35) !important;
        
        --gen-bg: #072314 !important;
        --gen-bdr: #22C55E !important;
        --gen-title: #4ADE80 !important;
        --gen-txt: #A7F3D0 !important;
        
        --forg-bg: #2B0C10 !important;
        --forg-bdr: #EF4444 !important;
        --forg-title: #F87171 !important;
        --forg-txt: #FECACA !important;
        
        --dmg-bg: #2B1B06 !important;
        --dmg-bdr: #F59E0B !important;
        --dmg-title: #FBBF24 !important;
        --dmg-txt: #FDE68A !important;
    }

    [data-theme="light"], .stApp[data-theme="light"] {
        --bg-app: #FAF7F2 !important;
        --card-bg: #FFFDF9 !important;
        --card-border: #E8DCCB !important;
        --text-primary: #2C1E14 !important;
        --text-secondary: #6B523E !important;
        --accent-gold: #966023 !important;
        --accent-border: #D8C3A5 !important;
        
        --badge-admin-bg: #EDE4D8 !important;
        --badge-admin-txt: #4A3525 !important;
        --badge-admin-bdr: #D4C3A3 !important;
        
        --badge-stud-bg: #E8EFE6 !important;
        --badge-stud-txt: #2D5A27 !important;
        --badge-stud-bdr: #C4D7BF !important;
        
        --badge-lab-bg: #FDF3E3 !important;
        --badge-lab-txt: #8C5311 !important;
        --badge-lab-bdr: #ECD4A4 !important;
        
        --badge-tech-bg: #EDE7F6 !important;
        --badge-tech-txt: #4A148C !important;
        --badge-tech-bdr: #D1C4E9 !important;
        
        --gen-bg: #F0FDF4 !important;
        --gen-bdr: #22C55E !important;
        --gen-title: #15803D !important;
        --gen-txt: #166534 !important;
        
        --forg-bg: #FEF2F2 !important;
        --forg-bdr: #EF4444 !important;
        --forg-title: #B91C1C !important;
        --forg-txt: #991B1B !important;
        
        --dmg-bg: #FFFBEB !important;
        --dmg-bdr: #F59E0B !important;
        --dmg-title: #B45309 !important;
        --dmg-txt: #92400E !important;
    }

    .stApp {
        background-color: var(--bg-app);
        color: var(--text-primary);
    }
    
    .main-header {
        font-family: 'Georgia', serif;
        font-size: 2.2rem;
        font-weight: 700;
        color: var(--text-primary);
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
        font-size: 1.05rem;
        color: var(--text-secondary);
        margin-bottom: 1.4rem;
    }
    
    .badge-pill {
        display: inline-block;
        padding: 0.28rem 0.85rem;
        border-radius: 9999px;
        font-size: 0.8rem;
        font-weight: 700;
        letter-spacing: 0.04em;
        margin-bottom: 0.6rem;
    }
    .badge-admin { background-color: var(--badge-admin-bg); color: var(--badge-admin-txt); border: 1px solid var(--badge-admin-bdr); }
    .badge-student { background-color: var(--badge-stud-bg); color: var(--badge-stud-txt); border: 1px solid var(--badge-stud-bdr); }
    .badge-lab { background-color: var(--badge-lab-bg); color: var(--badge-lab-txt); border: 1px solid var(--badge-lab-bdr); }
    .badge-tech { background-color: var(--badge-tech-bg); color: var(--badge-tech-txt); border: 1px solid var(--badge-tech-bdr); }

    .theme-card {
        background-color: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 10px;
        padding: 1.3rem;
        margin-bottom: 1rem;
        box-shadow: 0 1px 4px rgba(0, 0, 0, 0.05);
    }
    
    .card-genuine {
        background-color: var(--gen-bg);
        border-left: 6px solid var(--gen-bdr);
        border-top: 1px solid var(--gen-bdr);
        border-right: 1px solid var(--gen-bdr);
        border-bottom: 1px solid var(--gen-bdr);
        padding: 1.3rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .card-genuine h3 { color: var(--gen-title) !important; margin: 0; }
    .card-genuine p { color: var(--gen-txt) !important; margin: 0.4rem 0 0 0; font-size: 1.05rem; }

    .card-forged {
        background-color: var(--forg-bg);
        border-left: 6px solid var(--forg-bdr);
        border-top: 1px solid var(--forg-bdr);
        border-right: 1px solid var(--forg-bdr);
        border-bottom: 1px solid var(--forg-bdr);
        padding: 1.3rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .card-forged h3 { color: var(--forg-title) !important; margin: 0; }
    .card-forged p { color: var(--forg-txt) !important; margin: 0.4rem 0 0 0; font-size: 1.05rem; }

    .card-damaged {
        background-color: var(--dmg-bg);
        border-left: 6px solid var(--dmg-bdr);
        border-top: 1px solid var(--dmg-bdr);
        border-right: 1px solid var(--dmg-bdr);
        border-bottom: 1px solid var(--dmg-bdr);
        padding: 1.3rem;
        border-radius: 8px;
        margin: 1rem 0;
    }
    .card-damaged h3 { color: var(--dmg-title) !important; margin: 0; }
    .card-damaged p { color: var(--dmg-txt) !important; margin: 0.4rem 0 0 0; font-size: 1.05rem; }

    [data-testid="stMetric"] {
        background-color: var(--card-bg);
        border: 1px solid var(--card-border);
        border-radius: 8px;
        padding: 0.8rem 1rem;
    }
</style>
""", unsafe_allow_html=True)


# Initialize and Cache Cryptographic Keys
@st.cache_resource(show_spinner="Initializing Institutional Cryptographic Authority...")
def get_system_keys():
    key_file = "institutional_keys.json"
    if os.path.exists(key_file):
        try:
            with open(key_file, "r") as f:
                data = json.load(f)
            return (
                data["i_pub"], data["i_priv"],
                data["v_pub"], data["v_priv"],
                bytes.fromhex(data["session_key"])
            )
        except Exception:
            pass

    i_pub, i_priv = rsa_keygen(bits=1024)
    v_pub, v_priv = rsa_keygen(bits=1024)
    a_priv, a_pub = dh_generate_keypair()
    b_priv, b_pub = dh_generate_keypair()
    session_key = dh_shared_secret(a_priv, b_pub)

    try:
        with open(key_file, "w") as f:
            json.dump({
                "i_pub": i_pub, "i_priv": i_priv,
                "v_pub": v_pub, "v_priv": v_priv,
                "session_key": session_key.hex()
            }, f)
    except Exception:
        pass
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
        st.markdown('<span class="badge-pill badge-admin">FORENSIC VERIFICATION ENGINE</span>', unsafe_allow_html=True)
        st.markdown("### Cryptographic Credential Audit & Tamper Localization")
        st.write("Verifies certificate authenticity against digital signatures and computes 1,800 block checksums to identify exact tampering down to 32×32 pixel regions.")

        audit_method = st.radio(
            "Select Audit Verification Method:",
            ["📁 Upload Certificate Image File (PNG / JPEG)", "🎓 Audit by University Roll Number (BTxxYYYxxx)"],
            horizontal=True
        )

        audit_target_img = None
        audit_source_label = ""

        if audit_method == "📁 Upload Certificate Image File (PNG / JPEG)":
            st.markdown("#### Upload Certificate for Forensic Verification")
            st.caption("Upload any official certificate or a modified certificate exported from the Tamper Lab.")
            uploaded_file = st.file_uploader(
                "Upload Certificate Image (PNG or JPEG):",
                type=["png", "jpg", "jpeg"],
                key="audit_file_uploader"
            )

            if uploaded_file is not None:
                audit_target_img = Image.open(uploaded_file).convert("RGB")
                audit_source_label = f"Uploaded file: {uploaded_file.name}"
                file_sig = f"{uploaded_file.name}_{uploaded_file.size}"

                c_aud_btn, c_aud_info = st.columns([1, 2])
                with c_aud_btn:
                    btn_run_audit = st.button("🔍 Run Forensic Verification Audit", type="primary", use_container_width=True)
                with c_aud_info:
                    st.info(f"Loaded: **{uploaded_file.name}** ({uploaded_file.size // 1024} KB)")

                # Auto-run when file changes or when button is clicked
                if btn_run_audit or st.session_state.get("last_audited_file_sig") != file_sig:
                    st.session_state.last_audited_file_sig = file_sig
                    with st.spinner("Executing cryptographic audit, verifying RSA signature, and checking 1,800 block checksums..."):
                        st.session_state.active_audit_result = verify_certificate_full(audit_target_img, v_priv, i_pub, session_key)
                        st.session_state.active_audit_img = audit_target_img
                        st.session_state.active_audit_label = audit_source_label

        else:
            st.markdown("#### Audit Stored Credential by University Roll Number")
            st.caption("Verify official degree credentials stored in the institutional SQLite database.")

            all_records = get_all_records()
            c_r1, c_r2 = st.columns([2, 1])
            with c_r1:
                audit_roll_input = st.text_input(
                    "Enter Roll Number (BTxxYYYxxx):",
                    placeholder="e.g. BT22CSE045",
                    help="Official format: BT + Year + Branch + Roll"
                ).strip().upper()
            with c_r2:
                quick_pick_roll = st.selectbox(
                    "Or pick from registered records:",
                    ["-- Select from Database --"] + [f"{r['roll']} - {r['name']}" for r in all_records]
                )

            selected_roll = audit_roll_input if audit_roll_input else (quick_pick_roll.split(" - ")[0] if quick_pick_roll != "-- Select from Database --" else "")

            if selected_roll:
                c_btn_r, _ = st.columns([1, 2])
                with c_btn_r:
                    btn_audit_roll = st.button(f"🔍 Audit Credential for {selected_roll}", type="primary", use_container_width=True)
                
                roll_sig = f"roll_{selected_roll}"
                if btn_audit_roll or st.session_state.get("last_audited_roll_sig") != roll_sig:
                    st.session_state.last_audited_roll_sig = roll_sig
                    db_entry = get_certificate(selected_roll)
                    if db_entry:
                        det, cert_img = db_entry
                        audit_target_img = cert_img
                        audit_source_label = f"Database Record: {selected_roll} ({det['name']})"
                        with st.spinner(f"Verifying cryptographic integrity for {selected_roll}..."):
                            st.session_state.active_audit_result = verify_certificate_full(audit_target_img, v_priv, i_pub, session_key)
                            st.session_state.active_audit_img = audit_target_img
                            st.session_state.active_audit_label = audit_source_label
                    else:
                        st.error(f"❌ No record found for Roll Number '{selected_roll}'.")

        # DISPLAY AUDIT RESULTS
        if "active_audit_result" in st.session_state and st.session_state.get("active_audit_img") is not None:
            rep = st.session_state.active_audit_result
            inspected_image = st.session_state.active_audit_img

            st.markdown("---")
            st.caption(f"Audit Target: **{st.session_state.get('active_audit_label', 'Certificate Image')}**")

            # Verdict Banner
            if rep["verdict"] == "GENUINE":
                st.markdown(f"""
                <div class="card-genuine">
                    <h3>✅ VERDICT: GENUINE CERTIFICATE</h3>
                    <p>{rep['reason']}</p>
                </div>
                """, unsafe_allow_html=True)
            elif rep["verdict"] == "FORGED / EDITED":
                st.markdown(f"""
                <div class="card-forged">
                    <h3>🚨 VERDICT: FORGED / TAMPERED CERTIFICATE</h3>
                    <p>{rep['reason']}</p>
                </div>
                """, unsafe_allow_html=True)
            elif rep["verdict"] == "DAMAGED ORIGINAL":
                st.markdown(f"""
                <div class="card-damaged">
                    <h3>⚠️ VERDICT: DAMAGED ORIGINAL</h3>
                    <p>{rep['reason']}</p>
                </div>
                """, unsafe_allow_html=True)
            else:
                st.error(f"❌ {rep['verdict']}: {rep['reason']}")

            # Summary Metrics
            c_m1, c_m2, c_m3 = st.columns(3)
            c_m1.metric("Cryptographic Signature", "✅ Valid & Authentic" if rep["sig_valid"] else "❌ Invalid")
            tamper_pct = (rep['failed_blocks'] / 1800.0) * 100.0
            c_m2.metric("Tampered 32x32 Blocks", f"{rep['failed_blocks']} / 1,800 ({tamper_pct:.1f}%)")
            c_m3.metric("Robust DCT Identifier", rep["dct_id"] or "Not Detected")

            # Visual Comparison: Certificate vs Tamper Heatmap
            st.markdown("#### Block-Level Tamper Localization Map")
            c_ins1, c_ins2 = st.columns(2)
            with c_ins1:
                st.subheader("Audited Certificate Image")
                st.image(inspected_image, use_container_width=True)

            with c_ins2:
                st.subheader("Tamper Localization Heatmap")
                caption_text = "All 1,800 blocks passed checksums" if rep['failed_blocks'] == 0 else f"{rep['failed_blocks']} altered blocks highlighted in red"
                st.image(rep["heatmap"], caption=caption_text, use_container_width=True)

            if rep["hidden_record"]:
                st.markdown("#### Authentic Digitally Signed Record Extracted from Hidden Stego Layer")
                if rep["verdict"] == "FORGED / EDITED":
                    st.warning("⚠️ **Forensic Discrepancy Detected:** While the visual pixels on the certificate were modified, the cryptographically signed and encrypted steganographic record below was extracted directly from the authentic issuer payload.")
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
                <h3 style="color:var(--text-primary); font-family:'Georgia', serif; margin:0 0 0.6rem 0;">🎓 Official Degree Record: {details['name']}</h3>
                <div style="display:flex; gap:2.5rem; flex-wrap:wrap; color:var(--text-secondary); font-size:1.02rem;">
                    <div><b>Roll Number:</b> {details['roll']}</div>
                    <div><b>Program:</b> {details['degree']}</div>
                    <div><b>Graduation Year:</b> {details['year']}</div>
                    <div><b>CGPA:</b> <span style="color:var(--accent-gold); font-weight:700;">{details['cgpa']} / 10.0</span></div>
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

                if st.session_state.lab_tampered_img is not None:
                    st.markdown("---")
                    st.info(f"🧪 **Active Attack Simulation:** {st.session_state.lab_tamper_desc}")
                    st.caption("⬇️ Use the download button on the right to save this modified certificate image. Then navigate to **Administration Portal ➔ Audit & Verify Certificate Authenticity** and upload it to test the forensic tamper detection.")

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
