"""Tamper map analysis and visualization overlay for 32x32 image blocks."""

import numpy as np
from PIL import Image, ImageDraw
from typing import Dict, List, Tuple
from ..stego.lsb import verify_block_checksums, BLOCK_SIZE


def generate_tamper_map(image: Image.Image) -> Tuple[np.ndarray, Dict[str, any]]:
    """Analyzes the image for tampering by checking 32x32 block checksums.
    Returns (tamper_grid_boolean_2d, stats_dict).
    """
    arr = np.array(image, dtype=np.uint8)
    tamper_grid = verify_block_checksums(arr)

    num_rows, num_cols = tamper_grid.shape
    total_blocks = num_rows * num_cols
    failed_blocks = int(np.count_nonzero(tamper_grid))
    tampered_pct = round((failed_blocks / total_blocks) * 100.0, 2)

    # Find list of tampered block coordinates: (row, col)
    tampered_coords = []
    for r in range(num_rows):
        for c in range(num_cols):
            if tamper_grid[r, c]:
                tampered_coords.append((r, c))

    stats = {
        "total_blocks": total_blocks,
        "failed_blocks": failed_blocks,
        "intact_blocks": total_blocks - failed_blocks,
        "tamper_percentage": tampered_pct,
        "is_tampered": (failed_blocks > 0),
        "tampered_coords": tampered_coords
    }

    return tamper_grid, stats


def create_tamper_heatmap(
    image: Image.Image,
    tamper_grid: np.ndarray,
    alpha: int = 120
) -> Image.Image:
    """Overlays a highlighted red heatmap and border on tampered 32x32 blocks."""
    base = image.convert("RGBA")
    overlay = Image.new("RGBA", base.size, (0, 0, 0, 0))
    draw = ImageDraw.Draw(overlay)

    num_rows, num_cols = tamper_grid.shape
    red_fill = (255, 20, 20, alpha)
    red_border = (255, 0, 0, 240)

    for r in range(num_rows):
        for c in range(num_cols):
            if tamper_grid[r, c]:
                x0 = c * BLOCK_SIZE
                y0 = r * BLOCK_SIZE
                x1 = x0 + BLOCK_SIZE
                y1 = y0 + BLOCK_SIZE
                # Draw red fill
                draw.rectangle([x0, y0, x1, y1], fill=red_fill)
                # Draw high-visibility border
                draw.rectangle([x0, y0, x1, y1], outline=red_border, width=2)

    # Composite overlay on original image
    result = Image.alpha_composite(base, overlay)
    return result.convert("RGB")
