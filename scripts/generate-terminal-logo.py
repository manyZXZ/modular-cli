#!/usr/bin/env python3
"""Generate Modular's terminal Braille mark from the authoritative PNG.

This is a development helper only. The CLI ships the generated Unicode rows and
does not require Python or Pillow at runtime.
"""

from __future__ import annotations

import argparse
import hashlib
import sys
from pathlib import Path

from PIL import Image


EXPECTED_SHA256 = "cbd0bb3c877a66420f487b088d8534bbb03583f8076ba01f6f547da043537e19"
DOT_COLUMNS = 84
DOT_ROWS = 96
ALPHA_THRESHOLD = 96


def braille_bit(x: int, y: int) -> int:
    return (
        ((1, 8), (2, 16), (4, 32), (64, 128))[y % 4][x % 2]
    )


def render(source: Path, dot_columns: int, dot_rows: int, threshold: int) -> tuple[list[str], tuple[int, int, int, int]]:
    source_bytes = source.read_bytes()
    digest = hashlib.sha256(source_bytes).hexdigest()
    if digest != EXPECTED_SHA256:
        raise SystemExit(
            "Refusing to redraw an unverified logo asset. "
            f"Expected {EXPECTED_SHA256}, received {digest}."
        )

    with Image.open(source) as image:
        alpha = image.convert("RGBA").getchannel("A")
        bounds = alpha.getbbox()
        if bounds is None:
            raise SystemExit("The logo asset contains no visible pixels.")
        cropped = alpha.crop(bounds)
        cropped.thumbnail((dot_columns, dot_rows), Image.Resampling.LANCZOS)
        raster = Image.new("L", (dot_columns, dot_rows), 0)
        offset = (
            (dot_columns - cropped.width) // 2,
            (dot_rows - cropped.height) // 2,
        )
        raster.paste(cropped, offset)

    rows: list[str] = []
    for cell_y in range(0, dot_rows, 4):
        characters: list[str] = []
        for cell_x in range(0, dot_columns, 2):
            bits = 0
            for dot_y in range(4):
                for dot_x in range(2):
                    if raster.getpixel((cell_x + dot_x, cell_y + dot_y)) >= threshold:
                        bits |= braille_bit(dot_x, dot_y)
            characters.append(chr(0x2800 + bits) if bits else " ")
        rows.append("".join(characters).rstrip())
    return rows, bounds


def main() -> None:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    default_source = Path(__file__).resolve().parents[1] / "assets" / "modular-logo.png"
    parser = argparse.ArgumentParser()
    parser.add_argument("source", nargs="?", type=Path, default=default_source)
    parser.add_argument("--dot-columns", type=int, default=DOT_COLUMNS)
    parser.add_argument("--dot-rows", type=int, default=DOT_ROWS)
    parser.add_argument("--threshold", type=int, default=ALPHA_THRESHOLD)
    arguments = parser.parse_args()
    if arguments.dot_columns <= 0 or arguments.dot_columns % 2:
        parser.error("--dot-columns must be a positive multiple of 2")
    if arguments.dot_rows <= 0 or arguments.dot_rows % 4:
        parser.error("--dot-rows must be a positive multiple of 4")
    if not 0 <= arguments.threshold <= 255:
        parser.error("--threshold must be between 0 and 255")
    rows, bounds = render(arguments.source, arguments.dot_columns, arguments.dot_rows, arguments.threshold)
    art_digest = hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()
    print(f"// source-sha256: {EXPECTED_SHA256}")
    print(f"// terminal-art-sha256: {art_digest}")
    print(f"// source-visible-bounds: {bounds}")
    print("export const MODULAR_BRAILLE_LOGO = Object.freeze([")
    for row in rows:
        print(f"  {row!r},")
    print("]);" )


if __name__ == "__main__":
    main()
