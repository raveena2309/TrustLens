"""database.py
SQLite Backend for TrustLens Academic Credential System.
Stores official certificates, cryptographically protected images, and student records.
"""

import io
import re
import sqlite3
from typing import Optional, Tuple, Dict, List
from PIL import Image

DB_PATH = "trustlens.db"


def get_connection() -> sqlite3.Connection:
    """Creates a database connection with binary support."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes the database schema."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS certificates (
                roll_number TEXT PRIMARY KEY,
                student_name TEXT NOT NULL,
                degree_program TEXT NOT NULL,
                graduation_year TEXT NOT NULL,
                cgpa TEXT NOT NULL,
                certificate_id TEXT NOT NULL,
                image_png BLOB NOT NULL,
                issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()


def normalize_roll(roll: str) -> str:
    """Normalizes roll number to uppercase and strips whitespace."""
    return roll.strip().upper()


def is_valid_iiitn_roll(roll: str) -> bool:
    """Validates roll number against the btxxyyyxxx format (e.g. BT22CSE045).
    bt + 2 digits (xx) + 3-4 letters (yyy) + 3 digits (xxx).
    """
    cleaned = normalize_roll(roll)
    pattern = r"^BT\d{2}[A-Z]{3,4}\d{3}$"
    return bool(re.match(pattern, cleaned))


def save_certificate(details: dict, image: Image.Image):
    """Saves or updates a certificate in the SQLite database."""
    roll = normalize_roll(details["roll"])

    buf = io.BytesIO()
    image.save(buf, format="PNG")
    blob_bytes = buf.getvalue()

    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO certificates (
                roll_number, student_name, degree_program, graduation_year, cgpa, certificate_id, image_png
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(roll_number) DO UPDATE SET
                student_name=excluded.student_name,
                degree_program=excluded.degree_program,
                graduation_year=excluded.graduation_year,
                cgpa=excluded.cgpa,
                certificate_id=excluded.certificate_id,
                image_png=excluded.image_png,
                issued_at=CURRENT_TIMESTAMP
        """, (
            roll,
            details["name"].strip(),
            details["degree"].strip(),
            details["year"].strip(),
            details["cgpa"].strip(),
            details["cert_id"].strip(),
            blob_bytes
        ))
        conn.commit()


def get_certificate(roll_number: str) -> Optional[Tuple[Dict[str, str], Image.Image]]:
    """Retrieves a certificate record and PIL image by roll number."""
    roll = normalize_roll(roll_number)
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT roll_number, student_name, degree_program, graduation_year, cgpa, certificate_id, image_png
            FROM certificates WHERE roll_number = ?
        """, (roll,))
        row = cursor.fetchone()

        if row is None:
            return None

        details = {
            "roll": row["roll_number"],
            "name": row["student_name"],
            "degree": row["degree_program"],
            "year": row["graduation_year"],
            "cgpa": row["cgpa"],
            "cert_id": row["certificate_id"]
        }
        image = Image.open(io.BytesIO(row["image_png"])).convert("RGB")
        return details, image


def get_all_records() -> List[Dict[str, str]]:
    """Returns a summary list of all issued certificates (for Administration view only)."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT roll_number, student_name, degree_program, graduation_year, cgpa, certificate_id, issued_at
            FROM certificates ORDER BY issued_at DESC
        """)
        rows = cursor.fetchall()
        return [
            {
                "roll": r["roll_number"],
                "name": r["student_name"],
                "degree": r["degree_program"],
                "year": r["graduation_year"],
                "cgpa": r["cgpa"],
                "cert_id": r["certificate_id"],
                "issued_at": r["issued_at"]
            }
            for r in rows
        ]


def seed_initial_records_if_empty(issue_func, issuer_priv, verifier_pub, session_key):
    """Pre-seeds realistic IIITN records if the database is currently empty."""
    init_db()
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) as count FROM certificates")
        count = cursor.fetchone()["count"]

    if count == 0:
        sample_iiitn_students = [
            {
                "name": "Aarav Sharma",
                "roll": "BT22CSE045",
                "degree": "Bachelor of Technology in Computer Science & Engineering",
                "year": "2026",
                "cgpa": "9.42",
                "cert_id": "IIITN-2026-0045"
            },
            {
                "name": "Priya Deshmukh",
                "roll": "BT22ECE018",
                "degree": "Bachelor of Technology in Electronics & Communication Engg.",
                "year": "2026",
                "cgpa": "9.68",
                "cert_id": "IIITN-2026-0018"
            },
            {
                "name": "Rohan Verma",
                "roll": "BT22CSB027",
                "degree": "Bachelor of Technology in Computer Science & Business Systems",
                "year": "2026",
                "cgpa": "8.95",
                "cert_id": "IIITN-2026-0027"
            }
        ]
        for s in sample_iiitn_students:
            img = issue_func(s, issuer_priv, verifier_pub, session_key)
            save_certificate(s, img)
