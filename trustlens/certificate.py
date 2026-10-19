"""Certificate generation and rendering module.
Generates academic certificates with standard 1600x1152 resolution (50x36 blocks of 32x32),
including precise field coordinates for OCR verification and tamper localization.
"""

import math
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from typing import Dict, Tuple, Optional

# Standard dimensions (exactly 50x36 blocks of 32x32 pixels)
IMAGE_WIDTH = 1600
IMAGE_HEIGHT = 1152
BLOCK_SIZE = 32
GRID_COLS = IMAGE_WIDTH // BLOCK_SIZE   # 50
GRID_ROWS = IMAGE_HEIGHT // BLOCK_SIZE  # 36

# Field layout bounding boxes: (x1, y1, x2, y2)
FIELD_LAYOUT: Dict[str, Tuple[int, int, int, int]] = {
    "name": (400, 470, 1200, 550),
    "roll": (550, 580, 1050, 640),
    "degree": (300, 670, 1300, 750),
    "year": (550, 770, 1050, 830),
    "cgpa": (600, 840, 1000, 910),
    "cert_id": (1180, 80, 1520, 130),
}


def _get_font(name: str, size: int) -> ImageFont.ImageFont:
    """Loads a TrueType font with fallbacks."""
    font_paths = [
        f"C:\\Windows\\Fonts\\{name}.ttf",
        f"C:\\Windows\\Fonts\\arial.ttf",
        f"C:\\Windows\\Fonts\\times.ttf",
        name
    ]
    for p in font_paths:
        try:
            return ImageFont.truetype(p, size)
        except Exception:
            continue
    return ImageFont.load_default()


def _draw_ornate_seal(draw: ImageDraw.ImageDraw, cx: int, cy: int, radius: int = 80):
    """Draws a gold embossed collegiate seal."""
    gold_outer = (184, 134, 11)
    gold_inner = (218, 165, 32)
    gold_light = (238, 201, 85)

    # Starburst teeth
    num_teeth = 36
    points = []
    for i in range(num_teeth * 2):
        angle = i * math.pi / num_teeth
        r = radius if i % 2 == 0 else radius - 8
        px = cx + r * math.cos(angle)
        py = cy + r * math.sin(angle)
        points.append((px, py))
    draw.polygon(points, fill=gold_light, outline=gold_outer)

    # Concentric rings
    draw.ellipse((cx - radius + 10, cy - radius + 10, cx + radius - 10, cy + radius - 10), fill=gold_inner, outline=gold_outer, width=2)
    draw.ellipse((cx - radius + 20, cy - radius + 20, cx + radius - 20, cy + radius - 20), outline=gold_outer, width=2)

    # Central emblem star
    font_small = _get_font("times", 18)
    draw.text((cx, cy - 20), "VERITAS", font=font_small, fill=(70, 45, 10), anchor="mm")
    draw.text((cx, cy), "ET", font=font_small, fill=(70, 45, 10), anchor="mm")
    draw.text((cx, cy + 20), "VIRTUS", font=font_small, fill=(70, 45, 10), anchor="mm")


def generate_certificate(details: Optional[Dict[str, str]] = None) -> Image.Image:
    """Generates an academic certificate PNG image (1600x1152 RGB).
    details keys: 'name', 'roll', 'degree', 'year', 'cgpa', 'cert_id'
    """
    if details is None:
        details = {
            "name": "Alex Mercer",
            "roll": "CS-2022-8491",
            "degree": "Bachelor of Technology in Computer Science",
            "year": "2026",
            "cgpa": "9.42",
            "cert_id": "TL-2026-0123"
        }

    # Generate parchment textured background
    # Base cream: RGB(250, 248, 240) with subtle noise
    np.random.seed(42)
    base_color = np.array([250, 248, 240], dtype=np.float32)
    noise = np.random.normal(0, 2.5, (IMAGE_HEIGHT, IMAGE_WIDTH, 3))
    # Subtle vignette gradient
    y_coords, x_coords = np.ogrid[:IMAGE_HEIGHT, :IMAGE_WIDTH]
    dist_from_center = np.sqrt(((x_coords - IMAGE_WIDTH / 2) / (IMAGE_WIDTH / 2)) ** 2 +
                               ((y_coords - IMAGE_HEIGHT / 2) / (IMAGE_HEIGHT / 2)) ** 2)
    vignette = (1.0 - 0.05 * np.clip(dist_from_center, 0, 1))[..., np.newaxis]

    img_data = np.clip(base_color * vignette + noise, 0, 255).astype(np.uint8)
    image = Image.fromarray(img_data, mode="RGB")
    draw = ImageDraw.Draw(image)

    # Color palette
    navy = (15, 34, 64)
    crimson = (128, 20, 20)
    charcoal = (40, 40, 40)
    light_gold = (184, 134, 11)

    # Outer and inner borders
    draw.rectangle([40, 40, IMAGE_WIDTH - 40, IMAGE_HEIGHT - 40], outline=navy, width=5)
    draw.rectangle([52, 52, IMAGE_WIDTH - 52, IMAGE_HEIGHT - 52], outline=light_gold, width=2)
    draw.rectangle([58, 58, IMAGE_WIDTH - 58, IMAGE_HEIGHT - 58], outline=navy, width=1)

    # Header fonts
    font_univ = _get_font("georgia", 46)
    font_sub = _get_font("arial", 18)
    font_title = _get_font("times", 44)
    font_body = _get_font("times", 24)
    font_value_large = _get_font("georgia", 38)
    font_value_bold = _get_font("arial", 28)
    font_small = _get_font("arial", 16)

    # Certificate ID top-right
    cert_id = details.get("cert_id", "TL-2026-0123")
    draw.text((1350, 105), f"Certificate ID: {cert_id}", font=font_small, fill=charcoal, anchor="mm")

    # Header titles
    draw.text((IMAGE_WIDTH // 2, 130), "TRUST UNIVERSITY", font=font_univ, fill=navy, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 185), "OFFICE OF ACADEMIC AFFAIRS & THE REGISTRAR", font=font_sub, fill=crimson, anchor="mm")
    draw.line([(500, 215), (1100, 215)], fill=light_gold, width=2)

    # Certificate Heading
    draw.text((IMAGE_WIDTH // 2, 290), "DEGREE CERTIFICATE", font=font_title, fill=navy, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 345), "WITH ALL RIGHTS, PRIVILEGES, AND HONORS THEREUNTO APPERTAINING", font=font_small, fill=charcoal, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 420), "THIS IS TO CERTIFY THAT", font=font_body, fill=charcoal, anchor="mm")

    # Student Name
    name = details.get("name", "Alex Mercer")
    draw.text((IMAGE_WIDTH // 2, 510), name, font=font_value_large, fill=crimson, anchor="mm")
    draw.line([(450, 545), (1150, 545)], fill=navy, width=1)

    # Roll Number
    roll = details.get("roll", "CS-2022-8491")
    draw.text((IMAGE_WIDTH // 2, 605), f"Roll Number: {roll}", font=font_value_bold, fill=charcoal, anchor="mm")

    # Degree Program
    degree = details.get("degree", "Bachelor of Technology in Computer Science")
    draw.text((IMAGE_WIDTH // 2, 660), "HAS SUCCESSFULLY COMPLETED THE DEGREE PROGRAM OF", font=font_body, fill=charcoal, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 715), degree, font=font_value_bold, fill=navy, anchor="mm")

    # Year & CGPA
    year = details.get("year", "2026")
    cgpa = details.get("cgpa", "9.42")
    draw.text((IMAGE_WIDTH // 2, 800), f"Graduating Class of {year}", font=font_value_bold, fill=charcoal, anchor="mm")
    draw.text((IMAGE_WIDTH // 2, 875), f"Cumulative Grade Point Average (CGPA): {cgpa} / 10.0", font=font_value_bold, fill=crimson, anchor="mm")

    # Seal at bottom center-left
    _draw_ornate_seal(draw, cx=320, cy=1010, radius=75)

    # Signatures
    # Registrar
    draw.line([(600, 1040), (880, 1040)], fill=charcoal, width=2)
    draw.text((740, 1020), "Dr. J. Henderson", font=_get_font("georgia", 22), fill=navy, anchor="mm")
    draw.text((740, 1060), "REGISTRAR", font=font_small, fill=charcoal, anchor="mm")

    # Dean / Chancellor
    draw.line([(1080, 1040), (1360, 1040)], fill=charcoal, width=2)
    draw.text((1220, 1020), "Prof. Eleanor Vance", font=_get_font("georgia", 22), fill=navy, anchor="mm")
    draw.text((1220, 1060), "CHANCELLOR", font=font_small, fill=charcoal, anchor="mm")

    return image


def get_field_crop(image: Image.Image, field_name: str) -> Image.Image:
    """Crops the specified field region from the certificate image using FIELD_LAYOUT."""
    if field_name not in FIELD_LAYOUT:
        raise ValueError(f"Unknown field: {field_name}. Valid: {list(FIELD_LAYOUT.keys())}")
    box = FIELD_LAYOUT[field_name]
    return image.crop(box)
