#!/usr/bin/env python3
"""Make docs/assets/gate-a-replay.gif from the real output of docs/demo/gate-a-replay.sh.

The GIF is a replay (typed out frame by frame). It is not a live recording. GIFs carry no sound.
Run from the repo root after: cargo build --release -p cop-cli -p cop-hook
"""
import subprocess
from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "docs/assets/gate-a-replay.gif"
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"
W, H = 1180, 400
BG, FG, DIM, GREEN, RED, BAR = (24, 26, 32), (220, 224, 232), (120, 126, 140), (120, 220, 140), (240, 110, 110), (40, 44, 54)

replay = subprocess.run([str(ROOT / "docs/demo/gate-a-replay.sh")], capture_output=True, text=True, check=True).stdout
lines = [l for l in replay.splitlines() if l.strip()]

font = ImageFont.truetype(FONT, 17)
small = ImageFont.truetype(FONT, 13)


def colour(line: str):
    if line.startswith("$"):
        return DIM
    if "deny" in line and "decision" in line:
        return RED
    if line.startswith("decision") or line.startswith("reason"):
        return GREEN if "allow" in line else FG
    return FG


def frame(shown: list[tuple[str, tuple]], cursor_text: str | None):
    img = Image.new("RGB", (W, H), BG)
    d = ImageDraw.Draw(img)
    d.rectangle([0, 0, W, 34], fill=BAR)
    d.text((14, 9), "AgentCop Gate A replay (not a live session)", font=small, fill=DIM)
    y = 50
    for text, fill in shown:
        d.text((20, y), text, font=font, fill=fill)
        y += 26
    if cursor_text is not None:
        d.text((20, y), cursor_text + "_", font=font, fill=FG)
    return img


frames, durations = [], []
shown: list[tuple[str, tuple]] = []
for line in lines:
    fill = colour(line)
    for i in range(0, len(line) + 1, 3):
        frames.append(frame(shown, line[:i]))
        durations.append(60)
    shown.append((line, fill))
    frames.append(frame(shown, None))
    durations.append(600)
for _ in range(6):  # hold the last frame
    frames.append(frame(shown, None))
    durations.append(800)

OUT.parent.mkdir(parents=True, exist_ok=True)
frames[0].save(OUT, save_all=True, append_images=frames[1:], duration=durations, loop=0, optimize=True)
print("wrote", OUT, f"({len(frames)} frames, {OUT.stat().st_size // 1024} KB)")
