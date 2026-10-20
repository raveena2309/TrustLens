"""certificate.py
Generates academic certificate images using Pillow (PIL).
Defines standard dimensions (1600x1152) and field coordinates for verification.
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
    "name": (400, 470, 1200, 550),
    "roll": (550, 580, 1050, 640),
    "degree": (300, 670, 1300, 750),
    "year": (550, 770, 1050, 830),
    "cgpa": (600, 840, 1000, 910),
    "cert_id": (1180, 80, 1520, 130),
}


def _get_font(name: str, size: int) -> ImageFont.ImageFont:
    """Loads a font safely with fallbacks."""
    for path in [f"C:\\Windows\\Fonts\\{name}.ttf", "arial.ttf", "times.ttf"]:
        try:
            return ImageFont.truetype(path, size)
        except Exception:
            pass
    return ImageFont.load_default()


def generate_certificate(details: dict = None) -> Image.Image:
    """Draws a complete certificate with decorative borders, text, and university seal."""
    if details is None:
        details = {
            "name": "Alex Mercer",
            "roll": "CS-2022-8491",
            "degree": "Bachelor of Technology in Computer Science",
            "year": "2026",
            "cgpa": "9.42",
            "cert_id": "TL-2026-0123"
        }

    # 1. Parchment textured background (light cream with subtle noise)
    np.random.seed(42)
    base = np.full((IMAGE_HEIGHT, IMAGE_WIDTH, 3), [250, 248, 240], dtype=np.float32)
    noise = np.random.normal(0, 2.0, base.shape)
    img_data = np.clip(base + noise, 0, 255).astype(np.uint8)
    image = Image.fromarray(img_data, mode="RGB")
    draw = ImageDraw.Draw(image)

    # Color palette
    navy = (15, 34, 64)
    crimson = (128, 20, 20)
    charcoal = (40, 40, 40)
    gold = (184, 134, 11)

    # 2. Ornate Borders
    draw.rectangle([40, 40, IMAGE_WIDTH - 40, IMAGE_HEIGHT - 40], outline=navy, width=5)
    draw.rectangle([52, 52, IMAGE_WIDTH - 52, IMAGE_HEIGHT - 52], outline=gold, width=2)
    draw.rectangle([58, 58, IMAGE_WIDTH - 58, IMAGE_HEIGHT - 58], outline=navy, width=1)

    # 3. Header
    draw.text((IMAGE_WIDTH // 2, 130), "TRUST UNIVERSITY", font=_get_font("georgia", 46), fill=navy, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 185), "OFFICE OF ACADEMIC AFFAIRS & THE REGISTRAR", font=_get_font("arial", 18), fill=crimson, anchor="mm")
    draw.line([(500, 215), (1100, 215)], fill=gold, width=2)

    # Certificate ID top-right
    draw.text((1350, 105), f"Certificate ID: {details.get('cert_id', 'TL-2026-0123')}", font=_get_font("arial", 16), fill=charcoal, anchor="mm")

    # 4. Certificate Body
    draw.text((IMAGE_WIDTH // 2, 290), "DEGREE CERTIFICATE", font=_get_font("times", 44), fill=navy, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 345), "WITH ALL RIGHTS, PRIVILEGES, AND HONORS THEREUNTO APPERTAINING", font=_get_font("arial", 16), fill=charcoal, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 420), "THIS IS TO CERTIFY THAT", font=_get_font("times", 24), fill=charcoal, anchor="mm")

    # Student Details
    draw.text((IMAGE_WIDTH // 2, 510), details.get("name", ""), font=_get_font("georgia", 38), fill=crimson, anchor="mm")
    draw.line([(450, 545), (1150, 545)], fill=navy, width=1)

    draw.text((IMAGE_WIDTH // 2, 605), f"Roll Number: {details.get('roll', '')}", font=_get_font("arial", 28), fill=charcoal, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 660), "HAS SUCCESSFULLY COMPLETED THE DEGREE PROGRAM OF", font=_get_font("times", 24), fill=charcoal, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 715), details.get("degree", ""), font=_get_font("arial", 28), fill=navy, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 800), f"Graduating Class of {details.get('year', '')}", font=_get_font("arial", 28), fill=charcoal, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 875), f"Cumulative Grade Point Average (CGPA): {details.get('cgpa', '')} / 10.0", font=_get_font("arial", 28), fill=crimson, anchor="mm")

    # 5. Seal & Signatures
    # Starburst Golden Seal
    cx, cy, radius = 320, 1010, 75
    points = []
    for i in range(72):
        angle = i * math.pi / 36
        r = radius if i % 2 == 0 else radius - 8
        points.append((cx + r * math.cos(angle), cy + r * math.sin(angle)))
    draw.polygon(points, fill=(238, 201, 85), outline=gold)
    draw.ellipse((cx - 60, cy - 60, cx + 60, cy + 60), fill=(218, 165, 32), outline=gold, width=2)
    draw.text((cx, cy), "VERIFIED", font=_get_font("times", 18), fill=(70, 45, 10), anchor="mm")

    # Signature lines
    draw.line([(620, 1040), (860, 1040)], fill=charcoal, width=2)
    draw.text((740, 1020), "Dr. J. Henderson", font=_get_font("georgia", 22), fill=navy, anchor="mm")
    draw.text((740, 1060), "REGISTRAR", font=_get_font("arial", 16), fill=charcoal, anchor="mm")

    draw.line([(1100, 1040), (1340, 1040)], fill=charcoal, width=2)
    draw.text((1220, 1020), "Prof. E. Vance", font=_get_font("georgia", 22), fill=navy, anchor="mm")
    draw.text((1220, 1060), "CHANCELLOR", font=_get_font("arial", 16), fill=charcoal, anchor="mm")

    return image
