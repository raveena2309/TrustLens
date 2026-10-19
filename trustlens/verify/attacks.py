"""Step 7: Certificate Attack Simulator.
Simulates various physical and digital forgery attacks:
1. Retyping / editing printed fields (e.g., modifying CGPA from 9.42 to 9.98)
2. Block-level tampering (erasing, drawing shapes, editing logos)
3. JPEG lossy compression (Q = 90, 75, 50)
4. Cropping margins / borders
5. Resizing / downscaling and upscaling
6. Splice attack (pasting a region from a forged certificate)
7. Transplant attack (extracting LSB payload and pasting onto a fraudulent certificate)
"""

import io
import numpy as np
from PIL import Image, ImageDraw, ImageFont
from typing import Dict, Optional, Tuple
from ..certificate import FIELD_LAYOUT, _get_font


def attack_retype_field(
    image: Image.Image,
    field_name: str,
    new_value: str
) -> Image.Image:
    """Simulates an attacker digitally editing a printed field on the certificate
    (e.g., painting over the CGPA and printing a forged higher grade).
    """
    if field_name not in FIELD_LAYOUT:
        raise ValueError(f"Unknown field: {field_name}")

    img = image.copy()
    draw = ImageDraw.Draw(img)
    x0, y0, x1, y1 = FIELD_LAYOUT[field_name]

    # Paint over the field with parchment background color: RGB(250, 248, 240)
    draw.rectangle([x0, y0, x1, y1], fill=(250, 248, 240))

    # Center coordinates
    cx = (x0 + x1) // 2
    cy = (y0 + y1) // 2

    # Render forged text matching font styling
    crimson = (128, 20, 20)
    charcoal = (40, 40, 40)
    navy = (15, 34, 64)

    if field_name == "cgpa":
        font = _get_font("arial", 28)
        draw.text((cx, cy), f"Cumulative Grade Point Average (CGPA): {new_value} / 10.0", font=font, fill=crimson, anchor="mm")
    elif field_name == "name":
        font = _get_font("georgia", 38)
        draw.text((cx, cy), new_value, font=font, fill=crimson, anchor="mm")
    elif field_name == "roll":
        font = _get_font("arial", 28)
        draw.text((cx, cy), f"Roll Number: {new_value}", font=font, fill=charcoal, anchor="mm")
    elif field_name == "year":
        font = _get_font("arial", 28)
        draw.text((cx, cy), f"Graduating Class of {new_value}", font=font, fill=charcoal, anchor="mm")
    elif field_name == "degree":
        font = _get_font("arial", 28)
        draw.text((cx, cy), new_value, font=font, fill=navy, anchor="mm")

    return img


def attack_block_tamper(
    image: Image.Image,
    box: Tuple[int, int, int, int] = (600, 800, 900, 900)
) -> Image.Image:
    """Modifies a rectangular region of the image by adding noise or drawing."""
    img = image.copy()
    draw = ImageDraw.Draw(img)
    draw.rectangle(box, fill=(230, 200, 200), outline=(200, 0, 0), width=3)
    return img


def attack_jpeg_compress(image: Image.Image, quality: int = 75) -> Image.Image:
    """Compresses the image as JPEG with the specified quality and decodes back."""
    buf = io.BytesIO()
    image.save(buf, format="JPEG", quality=quality)
    buf.seek(0)
    return Image.open(buf).convert("RGB")


def attack_resize(image: Image.Image, scale: float = 0.8) -> Image.Image:
    """Downscales the image and then rescales back to original dimensions."""
    w, h = image.size
    new_w = int(w * scale)
    new_h = int(h * scale)
    downscaled = image.resize((new_w, new_h), Image.Resampling.BILINEAR)
    return downscaled.resize((w, h), Image.Resampling.BILINEAR)


def attack_crop(image: Image.Image, crop_margin: int = 30) -> Image.Image:
    """Crops margins from image edges and places back on black background."""
    w, h = image.size
    cropped = image.crop((crop_margin, crop_margin, w - crop_margin, h - crop_margin))
    base = Image.new("RGB", (w, h), (0, 0, 0))
    base.paste(cropped, (crop_margin, crop_margin))
    return base


def attack_splice(
    base_image: Image.Image,
    donor_image: Image.Image,
    box: Tuple[int, int, int, int] = (400, 450, 1200, 560)
) -> Image.Image:
    """Copies a region (e.g. student name) from donor_image onto base_image."""
    result = base_image.copy()
    donor_region = donor_image.crop(box)
    result.paste(donor_region, box)
    return result


def attack_transplant_lsb(
    legit_stego_image: Image.Image,
    fraud_image: Image.Image
) -> Image.Image:
    """Transplants the LSB bit-plane from a legitimate certificate onto a different fraudulent certificate."""
    arr_legit = np.array(legit_stego_image, dtype=np.uint8)
    arr_fraud = np.array(fraud_image, dtype=np.uint8)

    # Copy LSB of all channels
    transplanted = (arr_fraud & 0xFE) | (arr_legit & 1)
    return Image.fromarray(transplanted, mode="RGB")
