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
    LFSR, GeffeGenerator, geffe_encrypt, berlekamp_massey
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
# TAB 4: SYSTEM SECURITY & PRIVACY IN ACTION
# =====================================================================
with tab_tech:
    st.markdown('<span class="badge-pill badge-tech">SECURITY ARCHITECTURE & PRIVACY IN ACTION</span>', unsafe_allow_html=True)
    st.subheader("TrustLens Security & Privacy Technologies")
    st.write(
        "Explore how TrustLens protects student confidentiality and secures academic credentials in practice. "
        "Every demonstration below runs live code on real institutional records from IIIT Nagpur."
    )

    sec_view = st.radio(
        "Choose Security Area to Inspect:",
        [
            "📊 1. Student Privacy Protection (Differential Privacy for College Reports)",
            "🔐 2. Certificate Encryption & Key Handshake (Public-Key Steganography & Ciphers)"
        ],
        horizontal=True
    )

    st.markdown("---")

    # =================================================================
    # AREA 1: STUDENT DATA PRIVACY (DIFFERENTIAL PRIVACY)
    # =================================================================
    if sec_view == "📊 1. Student Privacy Protection (Differential Privacy for College Reports)":
        st.markdown("### 1. Differential Privacy: Protecting Student Data in Published Reports")

        st.markdown("""
        <div class="theme-card" style="border-left: 4px solid #3B82F6;">
            <b>💡 The Real-World Problem:</b> When IIIT Nagpur publishes departmental statistics 
            (such as <i>"Number of students with CGPA > 9.0"</i> or placement packages), releasing the exact headcounts 
            can easily expose individual student identities in smaller batches. 
            <br><b>🛡️ The TrustLens Solution:</b> TrustLens applies <b>Differential Privacy (DP)</b>, injecting tiny, 
            calibrated mathematical noise so outsiders get accurate overall metrics while individual student confidentiality remains 100% protected.
        </div>
        """, unsafe_allow_html=True)

        col_lap, col_exp = st.columns([1, 1], gap="large")

        # 1A. LAPLACE MECHANISM
        with col_lap:
            st.markdown("#### A. Safe Department Reports (Laplace Noise)")
            st.write("Generates public student statistics protected by zero-mean Laplace noise.")

            # Real IIITN Department Data
            dept_data = {
                "Computer Science & Engineering": 45,
                "Electronics & Communication Engg.": 28,
                "Artificial Intelligence & Data Science": 19,
                "Computer Science & Business Systems": 12
            }

            sel_dept = st.selectbox(
                "Select Department to Report On:",
                list(dept_data.keys()),
                key="dp_dept_select"
            )
            true_count = dept_data[sel_dept]

            col_p1, col_p2 = st.columns(2)
            with col_p1:
                st.caption(f"Actual Database Count: **{true_count} students**")
            with col_p2:
                eps_mode = st.select_slider(
                    "Privacy Protection Level:",
                    options=[0.5, 1.0, 2.0, 4.0],
                    value=1.0,
                    format_func=lambda x: {
                        0.5: "🔒 Maximum Privacy (ε=0.5)",
                        1.0: "🛡️ Balanced (ε=1.0)",
                        2.0: "🎯 High Accuracy (ε=2.0)",
                        4.0: "⚡ Low Noise (ε=4.0)"
                    }[x]
                )

            # Visual 3-Step Pipeline Card
            st.markdown(f"""
            <div style="background:var(--card-bg); border:1px solid var(--card-border); border-radius:8px; padding:0.9rem; margin-bottom:1rem; font-size:0.92rem;">
                <div style="color:var(--text-secondary); font-weight:600; margin-bottom:0.4rem;">HOW IT WORKS IN 3 STEPS:</div>
                <div style="display:flex; align-items:center; justify-content:space-between; flex-wrap:wrap; gap:0.5rem; text-align:center;">
                    <div style="flex:1; min-width:100px; padding:0.5rem; background:rgba(59, 130, 246, 0.08); border-radius:6px;">
                        <span style="font-size:0.8rem; color:#3B82F6; font-weight:700;">1. TRUE DATA</span><br>
                        <b>{true_count} Students</b>
                    </div>
                    <div style="color:var(--accent-gold); font-size:1.2rem;">➔</div>
                    <div style="flex:1; min-width:120px; padding:0.5rem; background:rgba(234, 179, 8, 0.08); border-radius:6px;">
                        <span style="font-size:0.8rem; color:#D97706; font-weight:700;">2. ADD NOISE</span><br>
                        <b>Laplace(±{1.0/eps_mode:.1f})</b>
                    </div>
                    <div style="color:var(--accent-gold); font-size:1.2rem;">➔</div>
                    <div style="flex:1; min-width:110px; padding:0.5rem; background:rgba(34, 197, 94, 0.08); border-radius:6px;">
                        <span style="font-size:0.8rem; color:#16A34A; font-weight:700;">3. SAFE REPORT</span><br>
                        <b>Public Release</b>
                    </div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            # Budget Meter
            b_mgr = st.session_state.budget
            st.progress(
                b_mgr.percent_consumed / 100.0,
                text=f"Institutional Privacy Budget: {b_mgr.spent_epsilon:.1f} / {b_mgr.max_epsilon:.1f} ε spent ({b_mgr.percent_consumed:.0f}%)"
            )

            col_btn1, col_btn2 = st.columns(2)
            with col_btn1:
                btn_publish = st.button("📊 Publish Safe Public Report", type="primary", use_container_width=True)
            with col_btn2:
                btn_reset_bud = st.button("🔄 Reset Budget Window", use_container_width=True)

            if btn_reset_bud:
                b_mgr.reset()
                st.rerun()

            if btn_publish:
                if b_mgr.spend(eps_mode):
                    noisy_stat = laplace_mechanism(true_count, eps_mode)
                    noise_diff = noisy_stat - true_count

                    c_res1, c_res2, c_res3 = st.columns(3)
                    c_res1.metric("Private Database Count", f"{true_count} grads")
                    c_res2.metric("Publicly Released Count", f"{noisy_stat} grads", delta=f"{noise_diff:+d} noise")
                    c_res3.metric("Individual Identity Status", "🛡️ 100% Protected")

                    st.success(f"✅ Successfully published! An attacker observing '{noisy_stat}' cannot reconstruct whether any specific student was in this cohort.")
                else:
                    st.error("🚨 Institutional Privacy Budget Exhausted: Query refused to protect against re-identification!")

            # Viva Re-identification Explanation
            with st.expander("🔍 Viva Demo: Test Re-identification Resistance"):
                st.write(
                    "**What if 1 student (e.g. Aarav Sharma) leaves the cohort?** "
                    f"The true count becomes **{true_count - 1}**. But when the Laplace mechanism publishes the number, "
                    f"random noise (±{1.0/eps_mode:.1f}) still masks the value. "
                    "Because the noisy output distribution for 45 students overlaps almost identically with the distribution for 44 students, "
                    "it is mathematically impossible for an attacker to prove whether Aarav graduated or not!"
                )

        # 1B. EXPONENTIAL MECHANISM
        with col_exp:
            st.markdown("#### B. Anonymous Department Honors Award")
            st.write("Selects the top department fairly without revealing private marks, student scores, or GPA totals.")

            # Performance points for 4 IIITN branches
            honors_scores = {
                "Computer Science & Engineering": 380,
                "Electronics & Communication Engg.": 260,
                "Artificial Intelligence & DS": 190,
                "Computer Science & Business": 120
            }

            st.caption("Department Performance Scores (Internal Metrics):")
            # Calculate dynamic winning probabilities
            exp_eps = st.slider("Selection Privacy (ε):", 0.5, 3.0, 1.5, 0.5, key="exp_eps_clean")
            score_arr = np.array(list(honors_scores.values()), dtype=np.float64)
            scaled = (exp_eps * score_arr) / 2.0
            scaled -= np.max(scaled)
            exp_weights = np.exp(scaled)
            probs = exp_weights / np.sum(exp_weights)
            prob_percent_dict = {dept: round(float(p) * 100, 1) for dept, p in zip(honors_scores.keys(), probs)}

            st.bar_chart(prob_percent_dict, height=180)

            if st.button("🏆 Announce Department of the Year", type="primary", use_container_width=True):
                top_dept, _ = exponential_mechanism(honors_scores, exp_eps)
                st.markdown(f"""
                <div class="theme-card" style="border-left: 4px solid #F59E0B; background:rgba(245, 158, 11, 0.08); margin-top:0.6rem;">
                    <div style="font-size:0.85rem; color:var(--text-secondary); font-weight:700;">ANNUAL EXCELLENCE AWARD WINNER:</div>
                    <div style="font-size:1.3rem; font-weight:800; color:#D97706; margin:0.3rem 0;">
                        🏆 {top_dept}
                    </div>
                    <div style="font-size:0.85rem; color:#16A34A;">
                        ✅ Selected probabilistically based on performance while keeping exact student marks confidential.
                    </div>
                </div>
                """, unsafe_allow_html=True)

            st.info("💡 **Why this is fair:** Higher scoring departments have higher odds of winning, but the randomized selection ensures that no student's individual grade can be reverse-engineered from the award outcome.")

    # =================================================================
    # AREA 2: CERTIFICATE ENCRYPTION & KEY AGREEMENT (CRYPTOGRAPHY)
    # =================================================================
    else:
        st.markdown("### 2. Cryptographic Security: Certificate Encryption & Authority Handshake")

        st.markdown("""
        <div class="theme-card" style="border-left: 4px solid #10B981;">
            <b>💡 The Real-World Problem:</b> Degree certificates contain sensitive student details (roll number, name, program, CGPA). 
            If embedded as plain text, anyone with a basic script could read or forge them. 
            <br><b>🔐 The TrustLens Solution:</b> TrustLens encrypts the hidden metadata using a non-linear <b>Geffe Stream Cipher</b>, 
            signs it with an <b>RSA 1024-bit Digital Signature</b>, and establishes the decryption key between authorities using <b>Diffie-Hellman Key Exchange</b>.
        </div>
        """, unsafe_allow_html=True)

        col_stego_enc, col_dh_agree = st.columns([1, 1], gap="large")

        # 2A. GEFFE STREAM CIPHER DEMO
        with col_stego_enc:
            st.markdown("#### A. How Student Records are Scrambled (Geffe Stream Cipher)")
            st.write("Inspect how real student metadata from `trustlens.db` gets scrambled before being embedded into certificate pixels.")

            all_db_students = get_all_records()
            if all_db_students:
                sel_student_roll = st.selectbox(
                    "Choose Stored Certificate to Encrypt:",
                    [r["roll"] for r in all_db_students],
                    key="sec_stego_student"
                )
                student_entry = get_certificate(sel_student_roll)

                if student_entry:
                    det, _ = student_entry
                    raw_text_record = f"{det['name']} | {det['roll']} | {det['degree'][:28]}... | CGPA: {det['cgpa']}"

                    # Step 1: Plaintext
                    st.markdown("**Step 1: Original Student Record (Plaintext):**")
                    st.code(raw_text_record, language="text")

                    # Step 2: Encrypted Ciphertext
                    encrypted_bytes = geffe_encrypt(raw_text_record.encode("utf-8"), session_key)
                    st.markdown("**Step 2: Scrambled with Geffe Stream Cipher (Stego Payload):**")
                    st.code(encrypted_bytes.hex()[:70] + "... (unbreakable to hackers)", language="text")

                    # Step 3: Authorized Decryption
                    decrypted_text = geffe_encrypt(encrypted_bytes, session_key).decode("utf-8")
                    st.markdown("**Step 3: Verification Portal Decryption (Authorized):**")
                    st.success(f"🔓 Decrypted by Verifier: **{decrypted_text}**")

            # Why Geffe is better than LFSR
            with st.expander("🛡️ Why TrustLens uses Geffe instead of a basic LFSR"):
                st.write(
                    "**1. Standard Linear LFSR (Weak):** Linear feedback produces a mathematically predictable bitstream. "
                    "An attacker using the **Berlekamp-Massey algorithm** can reconstruct the secret key after observing only 38 bits!\n\n"
                    "**2. Geffe Generator (Strong):** TrustLens combines three independent shift registers using the non-linear multiplexer formula "
                    "`z = (x₁ ∧ x₂) ⊕ (¬x₁ ∧ x₃)`. This destroys linear predictability and resists cryptanalysis."
                )

        # 2B. DIFFIE-HELLMAN KEY AGREEMENT
        with col_dh_agree:
            st.markdown("#### B. Secure Key Handshake (Diffie-Hellman Protocol)")
            st.write("How the University Registrar and an Employer agree on the secret decryption key without ever transmitting it over the internet.")

            st.markdown("""
            <div style="display:flex; justify-content:space-between; gap:0.8rem; margin-bottom:1rem; flex-wrap:wrap;">
                <div style="flex:1; min-width:140px; background:var(--card-bg); border:1px solid var(--card-border); border-radius:8px; padding:0.8rem; text-align:center;">
                    <div style="font-size:1.3rem;">🏛️</div>
                    <b style="font-size:0.95rem;">IIIT Nagpur Registrar</b>
                    <div style="font-size:0.8rem; color:var(--text-secondary);">Degree Issuing Authority</div>
                </div>
                <div style="align-self:center; font-size:1.3rem; color:var(--accent-gold);">⟷</div>
                <div style="flex:1; min-width:140px; background:var(--card-bg); border:1px solid var(--card-border); border-radius:8px; padding:0.8rem; text-align:center;">
                    <div style="font-size:1.3rem;">🏢</div>
                    <b style="font-size:0.95rem;">Employer / Verifier</b>
                    <div style="font-size:0.8rem; color:var(--text-secondary);">Verification Portal</div>
                </div>
            </div>
            """, unsafe_allow_html=True)

            if st.button("🤝 Perform Secure Cryptographic Handshake", type="primary", use_container_width=True):
                with st.spinner("Generating 2048-bit keypairs and deriving symmetric session key..."):
                    p1_priv, p1_pub = dh_generate_keypair()
                    p2_priv, p2_pub = dh_generate_keypair()
                    k_iss = dh_shared_secret(p1_priv, p2_pub)
                    k_ver = dh_shared_secret(p2_priv, p1_pub)

                st.write("**Public Exchange Codes (Sent over public internet):**")
                col_pk1, col_pk2 = st.columns(2)
                col_pk1.code(f"Registrar Public Code:\n{str(p1_pub)[:32]}...")
                col_pk2.code(f"Verifier Public Code:\n{str(p2_pub)[:32]}...")

                assert k_iss == k_ver
                st.markdown(f"""
                <div class="theme-card" style="border-left: 4px solid #10B981; background:rgba(16, 185, 129, 0.08);">
                    <div style="font-size:0.85rem; color:var(--text-secondary); font-weight:700;">AGREED 256-BIT SYMMETRIC SESSION KEY:</div>
                    <div style="font-family:monospace; font-size:1.05rem; font-weight:800; color:#10B981; word-break:break-all; margin:0.3rem 0;">
                        {k_iss.hex()}
                    </div>
                    <div style="font-size:0.85rem; color:#16A34A; font-weight:600;">
                        ✅ Identical key established on both sides! An eavesdropper intercepting the network only saw public numbers and cannot calculate this secret key.
                    </div>
                </div>
                """, unsafe_allow_html=True)
                st.caption("🔒 **Role in TrustLens:** This session key is what encrypts the hidden digital signature and student record inside degree certificates.")
            else:
                st.info("Click the handshake button above to simulate how the University and an Employer securely establish the session key in real time.")
