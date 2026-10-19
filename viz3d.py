"""Plotly 3D interactive visualizations for Trust Lab (Step 10):
1. Bit-Plane Stack: 3D layered surfaces of 8 bit-planes (64x64 crop near CGPA) highlighting modified LSBs.
2. DCT Bars: 3D bar representation of 8x8 DCT matrix with highlighted carrier frequencies.
3. Tamper Terrain: 3D topography surface over the 50x36 block grid with elevation at tampered coordinates.
4. Noise Cloud: Scatter3d distribution of epsilon vs true count vs noisy count.
"""

import numpy as np
import plotly.graph_objects as go
from PIL import Image
from typing import Optional, Tuple
from trustlens.certificate import FIELD_LAYOUT, get_field_crop


def plot_3d_bitplane_stack(
    original_img: Image.Image,
    stego_img: Image.Image,
    crop_size: int = 48
) -> go.Figure:
    """Renders 8 stacked 3D bit-plane surfaces from a crop near the CGPA field,
    highlighting altered LSB bits on plane 0.
    """
    # Crop around CGPA
    x0, y0, x1, y1 = FIELD_LAYOUT["cgpa"]
    cx, cy = (x0 + x1) // 2, (y0 + y1) // 2
    r_crop = original_img.crop((cx - crop_size // 2, cy - crop_size // 2, cx + crop_size // 2, cy + crop_size // 2))
    s_crop = stego_img.crop((cx - crop_size // 2, cy - crop_size // 2, cx + crop_size // 2, cy + crop_size // 2))

    orig_arr = np.array(r_crop.convert("L"))[:crop_size, :crop_size]
    stego_arr = np.array(s_crop.convert("L"))[:crop_size, :crop_size]

    fig = go.Figure()
    x_grid = np.arange(crop_size)
    y_grid = np.arange(crop_size)
    X, Y = np.meshgrid(x_grid, y_grid)

    colorscales = ["Blues", "Purples", "Teal", "Viridis", "Cividis", "YlGn", "Oranges", "Reds"]

    # Draw each bit-plane from 0 (bottom) to 7 (top)
    for plane_idx in range(8):
        plane_bits = ((stego_arr >> plane_idx) & 1).astype(float)
        # Z height spacing: plane_idx * 1.5 + bit_value * 0.4
        Z = plane_idx * 2.0 + plane_bits * 0.5

        fig.add_trace(go.Surface(
            x=X, y=Y, z=Z,
            surfacecolor=plane_bits,
            colorscale=colorscales[plane_idx],
            showscale=False,
            opacity=0.75,
            name=f"Bit-Plane {plane_idx}"
        ))

    # Highlight modified LSBs on plane 0
    orig_lsb = orig_arr & 1
    stego_lsb = stego_arr & 1
    diff_mask = (orig_lsb != stego_lsb)
    diff_y, diff_x = np.where(diff_mask)

    if len(diff_x) > 0:
        fig.add_trace(go.Scatter3d(
            x=diff_x,
            y=diff_y,
            z=np.ones_like(diff_x) * 0.6,
            mode="markers",
            marker=dict(size=5, color="red", symbol="diamond"),
            name="Modified LSBs"
        ))

    fig.update_layout(
        title="3D Bit-Plane Decomposition Stack (LSB Plane 0 to MSB Plane 7)",
        scene=dict(
            xaxis_title="Pixel X",
            yaxis_title="Pixel Y",
            zaxis_title="Bit-Plane Layer",
            camera=dict(eye=dict(x=1.6, y=-1.6, z=1.2))
        ),
        margin=dict(l=10, r=10, b=10, t=40)
    )
    return fig


def plot_3d_dct_bars(
    dct_block: np.ndarray,
    carrier_pos: Tuple[int, int] = (3, 2),
    title: str = "8x8 DCT Frequency Spectrum & Carrier Coefficient"
) -> go.Figure:
    """Visualizes an 8x8 DCT block as a 3D bar / surface chart,
    highlighting the chosen carrier coefficient.
    """
    fig = go.Figure()
    u = np.arange(8)
    v = np.arange(8)
    U, V = np.meshgrid(u, v)

    # Use log magnitude for dynamic range
    log_mag = np.log1p(np.abs(dct_block))

    fig.add_trace(go.Surface(
        x=U, y=V, z=log_mag,
        colorscale="Viridis",
        colorbar=dict(title="ln(1 + |DCT|)")
    ))

    # Highlight carrier coefficient
    r_c, c_c = carrier_pos
    carrier_z = log_mag[r_c, c_c]

    fig.add_trace(go.Scatter3d(
        x=[c_c], y=[r_c], z=[carrier_z + 0.3],
        mode="markers+text",
        marker=dict(size=8, color="crimson", symbol="diamond"),
        text=[f"Carrier ({r_c},{c_c})"],
        textposition="top center",
        name="Carrier Coefficient"
    ))

    fig.update_layout(
        title=title,
        scene=dict(
            xaxis_title="Horizontal Frequency (u)",
            yaxis_title="Vertical Frequency (v)",
            zaxis_title="Log Magnitude"
        ),
        margin=dict(l=10, r=10, b=10, t=40)
    )
    return fig


def plot_3d_tamper_terrain(tamper_grid: np.ndarray) -> go.Figure:
    """Draws a 3D topographic surface over the 50x36 block grid,
    elevating tampered blocks into prominent red peaks.
    """
    num_rows, num_cols = tamper_grid.shape
    X = np.arange(num_cols)
    Y = np.arange(num_rows)
    X_grid, Y_grid = np.meshgrid(X, Y)

    # Elevation: 0 for intact, 1.0 for tampered
    Z = tamper_grid.astype(float)

    # Smooth slightly for topographic visual appeal
    from scipy.ndimage import gaussian_filter
    Z_smooth = gaussian_filter(Z * 5.0, sigma=0.6)

    fig = go.Figure(data=[go.Surface(
        x=X_grid,
        y=Y_grid,
        z=Z_smooth,
        colorscale=[[0, "rgb(230,240,250)"], [0.2, "rgb(180,210,240)"], [0.5, "rgb(250,150,150)"], [1, "rgb(220,20,20)"]],
        colorbar=dict(title="Tamper Severity")
    )])

    fig.update_layout(
        title="3D Tamper Localization Terrain (50x36 Block Grid)",
        scene=dict(
            xaxis_title="Block Column (0..49)",
            yaxis_title="Block Row (0..35)",
            zaxis_title="Tamper Flag Elevation",
            camera=dict(eye=dict(x=1.4, y=-1.5, z=1.3))
        ),
        margin=dict(l=10, r=10, b=10, t=40)
    )
    return fig


def plot_3d_noise_cloud(
    true_counts: np.ndarray,
    epsilons: np.ndarray,
    noisy_counts: np.ndarray
) -> go.Figure:
    """Scatter3d plotting epsilon vs true count vs noisy count with color-mapped error."""
    errors = np.abs(noisy_counts - true_counts)

    fig = go.Figure(data=[go.Scatter3d(
        x=epsilons,
        y=true_counts,
        z=noisy_counts,
        mode="markers",
        marker=dict(
            size=3.5,
            color=errors,
            colorscale="Plasma",
            colorbar=dict(title="|Noise Error|"),
            opacity=0.8
        )
    )])

    fig.update_layout(
        title="3D Differential Privacy Noise Cloud (ε vs True Count vs Noisy Count)",
        scene=dict(
            xaxis_title="Privacy Budget (ε)",
            yaxis_title="True Count",
            zaxis_title="Noisy Reported Count",
            camera=dict(eye=dict(x=1.5, y=-1.5, z=1.2))
        ),
        margin=dict(l=10, r=10, b=10, t=40)
    )
    return fig
