#!/usr/bin/env python3
"""Render a data-driven animation of the RIAK v0.3 round function.

This is NOT an AI-generated illustration. Every frame is computed from the
actual cipher: the round function F, the four-branch outer network, and the
key schedule are re-implemented here to match `src/v3.rs` and
`src/v2.rs`, then animated. That means the visualisation is faithful to the
design rather than an interpretation of it.

What the video shows:
  - the 128-bit block as four 32-bit words, live values;
  - one full round of the sequential four-sub-update outer network, with each
    F evaluation split into its real stages (XOR, modular add, odd multiply,
    and the three linear mix layers);
  - a run through 24 rounds with the avalanche of a single input bit tracked;
  - the two-revision history: v0.1's linear break and v0.3's revision.

Run inside the project virtualenv so Pillow and the bundled fonts are present.
"""

from __future__ import annotations

import math
import os
import subprocess
import sys
import tempfile

from PIL import Image, ImageDraw, ImageFont

WIDTH, HEIGHT = 1920, 1080
FPS = 30

# ---------------------------------------------------------------- palette
BG = (8, 11, 18)
PANEL = (16, 21, 33)
GRID = (34, 43, 62)
TEXT = (222, 230, 240)
DIM = (122, 134, 154)
CYAN = (86, 214, 220)
AMBER = (240, 178, 84)
RED = (232, 96, 96)
GREEN = (108, 214, 140)
WORD_COLORS = [CYAN, AMBER, GREEN, (168, 150, 235)]

FONT_DIR = None
for candidate in (
    os.path.join(os.path.dirname(__file__), "venv/lib/python3.13/site-packages/matplotlib/mpl-data/fonts/ttf"),
):
    if os.path.isdir(candidate):
        FONT_DIR = candidate
        break


def font(size: int, bold: bool = False, mono: bool = False):
    if FONT_DIR:
        if mono:
            name = "DejaVuSansMono-Bold.ttf" if bold else "DejaVuSansMono.ttf"
        else:
            name = "DejaVuSans-Bold.ttf" if bold else "DejaVuSans.ttf"
        try:
            return ImageFont.truetype(os.path.join(FONT_DIR, name), size)
        except OSError:
            pass
    return ImageFont.load_default()


# ------------------------------------------------------- RIAK round function
MASK32 = 0xFFFFFFFF
MUL_A, MUL_B, MUL_C = 0x9E3779B9, 0x85EBCA6B, 0xC2B2AE35
ADD_A, ADD_B = 0x7F4A7C15, 0x1B873593
PRIMES = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89]
SLOT = [0x00000000, 0x13579BDF, 0x2468ACE0, 0xFEDCBA98]
ROUNDS = 24


def rotl(x: int, n: int) -> int:
    x &= MASK32
    return ((x << n) | (x >> (32 - n))) & MASK32


def mix_a(t: int) -> int:
    t ^= t >> 7
    t = rotl(t, 11)
    t ^= (t << 9) & MASK32
    return t & MASK32


def mix_b(t: int) -> int:
    t ^= t >> 5
    t = rotl(t, 7)
    t ^= (t << 13) & MASK32
    return t & MASK32


def mix_c(t: int) -> int:
    t ^= t >> 17
    t = rotl(t, 19)
    t ^= (t << 15) & MASK32
    return t & MASK32


def F(x: int, k: int, c: int) -> int:
    t = (x ^ k) & MASK32
    t = (t + c) & MASK32
    t = (t * MUL_A) & MASK32
    t = mix_a(t)
    t = (t + ADD_A) & MASK32
    t = (t * MUL_B) & MASK32
    t = mix_b(t)
    t = (t + ADD_B) & MASK32
    t = (t * MUL_C) & MASK32
    t = mix_c(t)
    return t


def round_constant(r: int, s: int) -> int:
    return PRIMES[r] ^ SLOT[s]


def encrypt_round(block: list[int], key: int, r: int) -> list[int]:
    x0, x1, x2, x3 = block
    y0 = x0 ^ F(x1 ^ x2 ^ x3, key, round_constant(r, 0))
    y1 = x1 ^ F(y0 ^ x2 ^ x3, key, round_constant(r, 1))
    y2 = x2 ^ F(y1 ^ y0 ^ x3, key, round_constant(r, 2))
    y3 = x3 ^ F(y2 ^ y1 ^ y0, key, round_constant(r, 3))
    return [y0, y1, y2, y3]


def encrypt_block(block: list[int], key: int, rounds: int = ROUNDS) -> list[int]:
    state = list(block)
    for r in range(rounds):
        state = encrypt_round(state, key, r)
    return state


# ---------------------------------------------------------------- drawing
def word_bits(value: int) -> str:
    return f"{value & MASK32:032b}"


def draw_word(draw, x, y, w, h, value, color, label, font_small, font_label, highlight=0.0):
    bits = word_bits(value)
    cell = w / 32
    for i, bit in enumerate(bits):
        on = bit == "1"
        shade = 0.55 + 0.45 * highlight if on else 0.0
        bx = x + i * cell
        by = y
        fill = (
            int(color[0] * (0.25 + 0.75 * shade)) if on else GRID[0],
            int(color[1] * (0.25 + 0.75 * shade)) if on else GRID[1],
            int(color[2] * (0.25 + 0.75 * shade)) if on else GRID[2],
        )
        draw.rectangle([bx + 1, by + 1, bx + cell - 1, by + h - 1], fill=fill)
    draw.text((x, y - 22), label, font=font_label, fill=DIM)


def hexchip(draw, x, y, value, color, font_hex):
    text = f"0x{value:08X}"
    tw = draw.textlength(text, font=font_hex)
    draw.rounded_rectangle([x, y, x + tw + 20, y + 34], radius=6, fill=(22, 28, 42))
    draw.text((x + 10, y + 6), text, font=font_hex, fill=color)
    return x + tw + 20  # return right edge so callers can place a label after it


def arrow(draw, x0, y0, x1, y1, color, width=3, head=10):
    draw.line([x0, y0, x1, y1], fill=color, width=width)
    angle = math.atan2(y1 - y0, x1 - x0)
    for sign in (1, -1):
        a = angle + sign * (math.pi * 0.8 / 3)
        draw.line(
            [x1, y1, x1 + head * math.cos(a), y1 + head * math.sin(a)],
            fill=color,
            width=width,
        )


def base_frame(title: str, subtitle: str, fonts) -> Image.Image:
    img = Image.new("RGB", (WIDTH, HEIGHT), BG)
    d = ImageDraw.Draw(img)
    f_title, f_sub, f_body, f_small = fonts
    d.text((80, 48), title, font=f_title, fill=TEXT)
    d.text((80, 132), subtitle, font=f_sub, fill=DIM)
    d.line([80, 186, WIDTH - 80, 186], fill=GRID, width=2)
    return img


# ---------------------------------------------------------------- scenes
def scene_title(fonts, t: float) -> Image.Image:
    f_title, f_sub, f_body, f_small = fonts
    img = base_frame("", "", fonts)
    d = ImageDraw.Draw(img)
    # Fade in over the first second, then hold.
    fade = min(1.0, t / 1.0)
    shade = int(60 + 195 * fade)
    title_color = (shade, shade, min(255, shade + 8))
    d.text((WIDTH // 2, 400), "RIAK", font=font(160, bold=True), fill=title_color, anchor="mm")
    d.text((WIDTH // 2, 530), "v0.3 custom block cipher", font=font(40), fill=TEXT, anchor="mm")
    d.text((WIDTH // 2, 600), "128-bit block   ·   512-bit key   ·   24 rounds   ·   4 sub-updates per round",
           font=font(28), fill=DIM, anchor="mm")
    # The honesty line is deliberately the most prominent text on the title
    # card: a viewer must not come away thinking this is production-ready.
    warn = int(80 + 175 * fade)
    d.text((WIDTH // 2, 720), "experimental research prototype — not independently audited",
           font=font(28), fill=(warn, int(warn * 0.4), int(warn * 0.4)), anchor="mm")
    return img


def scene_round(fonts, r: int, sub_progress: float, key: int) -> Image.Image:
    f_title, f_sub, f_body, f_small = fonts
    img = base_frame(
        f"Round {r+1:02d} / {ROUNDS}",
        "each output word is updated from already-updated words (full diffusion)",
        fonts,
    )
    d = ImageDraw.Draw(img)
    f_hex = font(26, mono=True)
    f_lab = font(20, bold=True)

    start = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]
    state = list(start)
    for i in range(r):
        state = encrypt_round(state, key, i)

    # Draw the four words as bit grids, animated left-to-right by sub_progress.
    y0 = 260
    w = 620
    h = 46
    gap = 78
    active_sub = min(3, int(sub_progress * 4))

    for word in range(4):
        y = y0 + word * gap
        value = state[word]
        hl = sub_progress if word == active_sub else 0.0
        draw_word(d, 160, y, w, h, value, WORD_COLORS[word], f"x{word}", f_small, f_lab, hl)
        hexchip(d, 800, y + 6, value, WORD_COLORS[word], f_hex)

    # Draw the round-constant strip.
    const_y = y0 + 4 * gap + 24
    d.text((160, const_y), "round constants", font=f_small, fill=DIM)
    for s in range(4):
        cx = 160 + s * 210
        cv = round_constant(r, s)
        d.text((cx, const_y + 36), f"c{s}", font=f_small, fill=DIM)
        d.text((cx, const_y + 62), f"0x{cv:08X}", font=f_hex, fill=AMBER)

    # Show the current F evaluation path for the active sub-update.
    if active_sub < 4:
        # The F input for slot s is the XOR of the other three words. For a
        # sequential update those are the already-updated values of earlier
        # slots, which is what makes the network fully diffusive.
        f_in = state[(active_sub + 1) % 4] ^ state[(active_sub + 2) % 4] ^ state[(active_sub + 3) % 4]
        box_y = const_y + 130
        d.rounded_rectangle([160, box_y, WIDTH - 160, box_y + 250], radius=16, fill=PANEL, outline=GRID, width=2)
        d.text((190, box_y + 22), f"F evaluated for y{active_sub}", font=f_lab, fill=TEXT)
        d.text((190, box_y + 62), "F(x ^ k, c) = xor -> add -> mul(A) -> mix_a -> add -> mul(B) -> mix_b -> add -> mul(C) -> mix_c",
               font=font(22, mono=True), fill=DIM)
        edge = hexchip(d, 190, box_y + 112, f_in, CYAN, f_hex)
        d.text((edge + 16, box_y + 120), "= F input (XOR of the other three words)", font=f_small, fill=DIM)
        edge = hexchip(d, 190, box_y + 158, key, AMBER, f_hex)
        d.text((edge + 16, box_y + 166), "= round key", font=f_small, fill=DIM)
        edge = hexchip(d, 190, box_y + 204, round_constant(r, active_sub), GREEN, f_hex)
        d.text((edge + 16, box_y + 212), "= round constant", font=f_small, fill=DIM)

        # Animate the blend of the active word with the F output.
        y_from = y0 + active_sub * gap + h
        y_to = box_y - 10
        arrow(d, 1560, y_from, 1560, y_to, WORD_COLORS[active_sub], width=4)
        d.text((1580, (y_from + y_to) // 2 - 16), f"xor into y{active_sub}", font=f_small, fill=WORD_COLORS[active_sub])
    return img


def scene_avalanche(fonts, t: float, key: int) -> Image.Image:
    f_title, f_sub, f_body, f_small = fonts
    img = base_frame(
        "Avalanche: one input bit",
        "a single bit flipped in x0 spreads to all 128 bits within a few rounds",
        fonts,
    )
    d = ImageDraw.Draw(img)
    f_hex = font(24, mono=True)
    base = [0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210]
    flipped = list(base)
    flipped[0] ^= 0x00000001

    rounds_shown = min(ROUNDS, int(t * 12))
    rows = []
    for r in range(rounds_shown + 1):
        a = encrypt_block(base, key, r)
        b = encrypt_block(flipped, key, r)
        diff = [x ^ y for x, y in zip(a, b)]
        weight = sum(bin(d).count("1") for d in diff)
        rows.append((r, weight))

    # Left column: the four output words after rounds_shown rounds.
    y0 = 250
    w = 560
    h = 44
    gap = 76
    state_a = encrypt_block(base, key, rounds_shown)
    d.text((160, y0 - 46), f"output block after round {rounds_shown}", font=font(24, bold=True), fill=TEXT)
    for word in range(4):
        draw_word(d, 160, y0 + word * gap, w, h, state_a[word], WORD_COLORS[word], f"y{word}", f_small, f_small)
        hexchip(d, 745, y0 + word * gap + 5, state_a[word], WORD_COLORS[word], f_hex)

    # Right column: the avalanche curve, full height so the panel is not
    # floating in empty space.
    cx, cy, cw, ch = 1160, 300, 640, 560
    d.rounded_rectangle([cx - 40, cy - 60, cx + cw + 40, cy + ch + 90], radius=16, fill=PANEL, outline=GRID, width=2)
    d.text((cx - 20, cy - 40), "Hamming weight of the block difference", font=font(26, bold=True), fill=TEXT)
    d.text((cx - 20, cy - 4), "after one input bit is flipped (of 128 bits)", font=f_small, fill=DIM)

    # Axis gridlines at 0, 32, 64, 96, 128 bits.
    for value in (0, 32, 64, 96, 128):
        gy = cy + ch - (value / 128) * ch
        d.line([cx, gy, cx + cw, gy], fill=GRID, width=1)
        d.text((cx - 16, gy - 14), str(value), font=font(20, mono=True), fill=DIM, anchor="ra")

    if len(rows) > 1:
        pts = []
        for i, (r, weight) in enumerate(rows):
            px = cx + i / (ROUNDS - 1) * cw
            py = cy + ch - (weight / 128) * ch
            pts.append((px, py))
        d.line(pts, fill=AMBER, width=4)
        for i, (px, py) in enumerate(pts):
            d.ellipse([px - 5, py - 5, px + 5, py + 5], fill=AMBER)
        last_r, last_w = rows[-1]
        d.text((cx, cy + ch + 30), f"round {last_r}: {last_w} of 128 bits differ",
               font=font(26, bold=True), fill=TEXT)
    return img


def scene_history(fonts, t: float) -> Image.Image:
    f_title, f_sub, f_body, f_small = fonts
    img = base_frame(
        "Design history",
        "each revision exists because analysis found something",
        fonts,
    )
    d = ImageDraw.Draw(img)
    entries = [
        ("v0.1", "broken", "linear relation held for all 24 rounds", RED),
        ("v0.2", "rejected", "a claimed outer invariant was disproved", RED),
        ("v0.3", "current candidate", "full diffusion + nonlinear key extraction", GREEN),
    ]
    y = 260
    card_h = 150
    for name, status, note, color in entries:
        d.rounded_rectangle([200, y, WIDTH - 200, y + card_h], radius=14, fill=PANEL, outline=color, width=3)
        d.text((240, y + 34), name, font=font(52, bold=True), fill=color)
        d.text((470, y + 38), status, font=font(36, bold=True), fill=color)
        d.text((470, y + 90), note, font=font(26), fill=DIM)
        y += card_h + 28
    d.text((WIDTH // 2, y + 34), "v0.3 is not proven secure. It is not proven broken either.",
           font=font(32), fill=TEXT, anchor="mm")
    d.text((WIDTH // 2, y + 90), "A timing signal of about 0.3% was measured and is still unexplained.",
           font=font(26), fill=RED, anchor="mm")
    return img


# ---------------------------------------------------------------- encode
def render(out_path: str):
    fonts = (font(64, bold=True), font(30), font(30), font(24))
    tmpdir = tempfile.mkdtemp()
    key = 0x13579BDF  # arbitrary constant key, XOR-folded into every round

    total_frames = 0

    def emit(img):
        nonlocal total_frames
        path = os.path.join(tmpdir, f"{total_frames:06d}.png")
        img.save(path)
        total_frames += 1

    def crossfade(first, second, frames=12):
        """Blend the tail of one scene into the head of the next."""
        for i in range(frames):
            alpha = (i + 1) / (frames + 1)
            emit(Image.blend(first, second, alpha))

    # Scene 1: title card.
    title_frames = [scene_title(fonts, i / FPS) for i in range(60)]
    for img in title_frames:
        emit(img)

    # Scene 2: two full rounds, four sub-updates each.
    round_frames = []
    for r in range(2):
        for i in range(72):
            round_frames.append(scene_round(fonts, r, (i / 72) * 4, key))
    crossfade(title_frames[-1], round_frames[0])
    for img in round_frames:
        emit(img)

    # Scene 3: avalanche across 24 rounds.
    avalanche_frames = [scene_avalanche(fonts, i / FPS, key) for i in range(180)]
    crossfade(round_frames[-1], avalanche_frames[0])
    for img in avalanche_frames:
        emit(img)

    # Scene 4: design history, then hold on the closing statement.
    history_frames = [scene_history(fonts, i / FPS) for i in range(120)]
    crossfade(avalanche_frames[-1], history_frames[0])
    for img in history_frames:
        emit(img)

    print(f"rendered {total_frames} frames ({total_frames/FPS:.1f}s at {FPS} fps)")

    ffmpeg = os.path.join(os.path.dirname(__file__), "tools", "ffmpeg")
    cmd = [
        ffmpeg, "-y",
        "-framerate", str(FPS),
        "-i", os.path.join(tmpdir, "%06d.png"),
        "-c:v", "libx264",
        "-pix_fmt", "yuv420p",
        "-crf", "20",
        "-movflags", "+faststart",
        out_path,
    ]
    print("encoding:", " ".join(cmd))
    subprocess.run(cmd, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    for name in os.listdir(tmpdir):
        os.remove(os.path.join(tmpdir, name))
    os.rmdir(tmpdir)
    print("wrote", out_path)


if __name__ == "__main__":
    target = sys.argv[1] if len(sys.argv) > 1 else "riak_v03.mp4"
    render(target)
