"""certificate.py
Generates academic certificate images using Pillow (PIL).
Features IIIT Nagpur institutional styling, parchment texture, ornate borders, and seal.
"""

import math
import numpy as np
from PIL import Image, ImageDraw, ImageFont

# 1600x1152 divides evenly into 50x36 blocks of 32x32 pixels
IMAGE_WIDTH = 1600
IMAGE_HEIGHT = 1152
BLOCK_SIZE = 32

# Exact bounding boxes for each printed field: (x1, y1, x2, y2)
FIELD_LAYOUT = {
    "name": (350, 470, 1250, 550),
    "roll": (550, 580, 1050, 640),
    "degree": (250, 670, 1350, 750),
    "year": (550, 770, 1050, 830),
    "cgpa": (580, 840, 1020, 910),
    "cert_id": (1180, 80, 1530, 130),
}


def _get_font(name: str, size: int) -> ImageFont.ImageFont:
    """Loads a font safely with fallbacks."""
    for path in [f"C:\\Windows\\Fonts\\{name}.ttf", "arial.ttf", "times.ttf", "georgia.ttf"]:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            pass
    return ImageFont.load_default()


def generate_certificate(details: dict = None) -> Image.Image:
    """Draws a complete IIIT Nagpur certificate with ornate borders, headers, and seal."""
    if details is None:
        details = {
            "name": "Aarav Sharma",
            "roll": "BT22CSE045",
            "degree": "Bachelor of Technology in Computer Science & Engineering",
            "year": "2026",
            "cgpa": "9.42",
            "cert_id": "IIITN-2026-0045"
        }

    # 1. Warm Parchment Cream Background
    np.random.seed(42)
    base = np.full((IMAGE_HEIGHT, IMAGE_WIDTH, 3), [252, 249, 242], dtype=np.float32)
    noise = np.random.normal(0, 1.8, base.shape)
    img_data = np.clip(base + noise, 0, 255).astype(np.uint8)
    image = Image.fromarray(img_data, mode="RGB")
    draw = ImageDraw.Draw(image)

    # Color palette (Warm Espresso, Antique Bronze, Crimson, Deep Charcoal)
    espresso = (52, 36, 24)       # Deep rich brown
    warm_brown = (88, 62, 44)     # Medium warm brown
    gold = (180, 130, 16)         # Antique gold
    crimson = (142, 28, 28)       # Deep crimson highlight
    charcoal = (45, 45, 45)       # Body text

    # 2. Ornate Academic Borders (Espresso & Gold)
    draw.rectangle([38, 38, IMAGE_WIDTH - 38, IMAGE_HEIGHT - 38], outline=espresso, width=6)
    draw.rectangle([50, 50, IMAGE_WIDTH - 50, IMAGE_HEIGHT - 50], outline=gold, width=2)
    draw.rectangle([56, 56, IMAGE_WIDTH - 56, IMAGE_HEIGHT - 56], outline=warm_brown, width=1)

    # 3. Institutional Header: IIIT Nagpur
    draw.text((IMAGE_WIDTH // 2, 120), "INDIAN INSTITUTE OF INFORMATION TECHNOLOGY, NAGPUR", font=_get_font("georgia", 38), fill=espresso, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 168), "AN INSTITUTE OF NATIONAL IMPORTANCE • MINISTRY OF EDUCATION, GOVT. OF INDIA", font=_get_font("arial", 17), fill=crimson, anchor="mm")
    draw.line([(450, 196), (1150, 196)], fill=gold, width=2)

    # Certificate ID top-right
    cert_id = details.get("cert_id", "IIITN-2026-0045")
    draw.text((1350, 100), f"Certificate ID: {cert_id}", font=_get_font("arial", 15), fill=warm_brown, anchor="mm")

    # 4. Degree Body
    draw.text((IMAGE_WIDTH // 2, 275), "DEGREE OF BACHELOR OF TECHNOLOGY", font=_get_font("times", 42), fill=espresso, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 330), "UPON THE RECOMMENDATION OF THE SENATE HEREBY CONFERS UPON", font=_get_font("arial", 15), fill=charcoal, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 410), "THIS IS TO CERTIFY THAT", font=_get_font("times", 22), fill=warm_brown, anchor="mm")

    # Student Details
    student_name = details.get("name", "Aarav Sharma")
    draw.text((IMAGE_WIDTH // 2, 510), student_name, font=_get_font("georgia", 38), fill=crimson, anchor="mm")
    draw.line([(440, 545), (1160, 545)], fill=espresso, width=1)

    roll_num = details.get("roll", "BT22CSE045")
    draw.text((IMAGE_WIDTH // 2, 605), f"Enrollment / Roll No: {roll_num}", font=_get_font("arial", 28), fill=charcoal, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 660), "HAS SUCCESSFULLY COMPLETED THE DEGREE REQUIREMENTS FOR", font=_get_font("times", 22), fill=charcoal, anchor="mm")

    degree_prog = details.get("degree", "Bachelor of Technology in Computer Science & Engineering")
    draw.text((IMAGE_WIDTH // 2, 715), degree_prog, font=_get_font("arial", 27), fill=espresso, anchor="mm")

    year_val = details.get("year", "2026")
    draw.text((IMAGE_WIDTH // 2, 798), f"Graduating Class of {year_val}", font=_get_font("arial", 26), fill=charcoal, anchor="mm")

    cgpa_val = details.get("cgpa", "9.42")
    draw.text((IMAGE_WIDTH // 2, 875), f"Cumulative Grade Point Average (CGPA): {cgpa_val} / 10.0", font=_get_font("arial", 28), fill=crimson, anchor="mm")

    # 5. Golden IIITN Verification Seal
    cx, cy, radius = 320, 1010, 75
    points = []
    for i in range(72):
        angle = i * math.pi / 36
        r = radius if i % 2 == 0 else radius - 8
        points.append((cx + r * math.cos(angle), cy + r * math.sin(angle)))
    draw.polygon(points, fill=(240, 204, 90), outline=gold)
    draw.ellipse((cx - 60, cy - 60, cx + 60, cy + 60), fill=(215, 162, 34), outline=espresso, width=2)
    draw.text((cx, cy - 14), "IIIT NAGPUR", font=_get_font("arial", 15), fill=(52, 36, 24), anchor="mm")
    draw.text((cx, cy + 14), "VERIFIED", font=_get_font("times", 18), fill=(52, 36, 24), anchor="mm")

    # 6. Dignitary Signatures
    # Registrar Signature
    draw.line([(620, 1040), (860, 1040)], fill=espresso, width=2)
    draw.text((740, 1020), "Dr. J. Henderson", font=_get_font("georgia", 22), fill=espresso, anchor="mm")
    draw.text((740, 1060), "REGISTRAR", font=_get_font("arial", 16), fill=warm_brown, anchor="mm")

    # Director Signature
    draw.line([(1100, 1040), (1340, 1040)], fill=espresso, width=2)
    draw.text((1220, 1020), "Prof. Eleanor Vance", font=_get_font("georgia", 22), fill=espresso, anchor="mm")
    draw.text((1220, 1060), "DIRECTOR, IIIT NAGPUR", font=_get_font("arial", 16), fill=warm_brown, anchor="mm")

    return image
