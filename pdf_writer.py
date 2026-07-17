"""
Minimal PDF writer — standard library only, no external dependencies.

Produces a simple multi-page tabular PDF good enough for audit evidence:
title, metadata, summary line, and a table of results. Not a full layout
engine — just clean, timestamped, printable output.
"""

import datetime


def _esc(s):
    s = str(s)
    # PDF base fonts are latin-1; replace common unicode, drop the rest
    s = (s.replace("\u2014", "-").replace("\u2013", "-")
           .replace("\u2018", "'").replace("\u2019", "'")
           .replace("\u201c", '"').replace("\u201d", '"')
           .replace("\u2026", "..."))
    s = s.encode("latin-1", "replace").decode("latin-1")
    return s.replace("\\", r"\\").replace("(", r"\(").replace(")", r"\)")


def _wrap(text, width):
    text = str(text)
    out, line = [], ""
    for word in text.split():
        if len(line) + len(word) + 1 <= width:
            line = (line + " " + word).strip()
        else:
            if line:
                out.append(line)
            # hard-break very long tokens
            while len(word) > width:
                out.append(word[:width])
                word = word[width:]
            line = word
    if line:
        out.append(line)
    return out or [""]


def build_pdf(path, title, meta_lines, rows, headers):
    """
    rows: list of tuples matching headers order.
    Renders monospaced (Courier) so columns align.
    """
    # Column widths in characters (Courier ~ fixed). Tune to fit Letter width.
    col_w = [22, 10, 26, 8, 8, 40]
    line_h = 12
    font_size = 8
    top = 760
    left = 36
    bottom_margin = 48
    lines_per_page = int((top - bottom_margin) / line_h)

    def fmt_row(cells):
        # each cell may wrap; produce list of physical lines
        wrapped = [_wrap(c, w) for c, w in zip(cells, col_w)]
        height = max(len(w) for w in wrapped)
        physical = []
        for i in range(height):
            parts = []
            for cell_lines, w in zip(wrapped, col_w):
                seg = cell_lines[i] if i < len(cell_lines) else ""
                parts.append(seg.ljust(w))
            physical.append("  ".join(parts))
        return physical

    # Build the full list of physical text lines
    all_lines = []
    all_lines.append((title, True))
    all_lines.append(("", False))
    for m in meta_lines:
        all_lines.append((m, False))
    all_lines.append(("", False))
    header_line = "  ".join(h.ljust(w) for h, w in zip(headers, col_w))
    all_lines.append((header_line, False))
    all_lines.append(("-" * len(header_line), False))
    for r in rows:
        for pl in fmt_row(r):
            all_lines.append((pl, False))

    # Paginate
    pages = [all_lines[i:i + lines_per_page]
             for i in range(0, len(all_lines), lines_per_page)]

    # Build PDF objects
    objects = []
    # 1: Catalog, 2: Pages, 3..: page + content + font
    font_obj_num = 3
    page_obj_nums = []
    content_obj_nums = []
    n = 4
    for _ in pages:
        page_obj_nums.append(n); n += 1
        content_obj_nums.append(n); n += 1

    kids = " ".join(f"{p} 0 R" for p in page_obj_nums)
    objects.append((1, f"<< /Type /Catalog /Pages 2 0 R >>"))
    objects.append((2, f"<< /Type /Pages /Kids [{kids}] /Count {len(pages)} >>"))
    objects.append((font_obj_num,
        "<< /Type /Font /Subtype /Type1 /BaseFont /Courier >>"))

    for idx, page_lines in enumerate(pages):
        pnum = page_obj_nums[idx]
        cnum = content_obj_nums[idx]
        # content stream
        parts = ["BT", f"/F1 {font_size} Tf", f"{line_h} TL", f"{left} {top} Td"]
        first = True
        for text, is_title in page_lines:
            size = 14 if is_title else font_size
            if is_title:
                parts.append(f"/F1 {size} Tf")
                parts.append(f"({_esc(text)}) Tj")
                parts.append(f"/F1 {font_size} Tf")
                parts.append("T*")
            else:
                parts.append(f"({_esc(text)}) Tj")
                parts.append("T*")
        parts.append("ET")
        stream = "\n".join(parts)
        objects.append((pnum,
            f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
            f"/Resources << /Font << /F1 {font_obj_num} 0 R >> >> "
            f"/Contents {cnum} 0 R >>"))
        objects.append((cnum,
            f"<< /Length {len(stream)} >>\nstream\n{stream}\nendstream"))

    # Serialize with xref
    objects.sort(key=lambda o: o[0])
    out = b"%PDF-1.4\n"
    offsets = {}
    for num, body in objects:
        offsets[num] = len(out)
        out += f"{num} 0 obj\n{body}\nendobj\n".encode("latin-1")
    xref_pos = len(out)
    maxnum = max(o[0] for o in objects)
    out += f"xref\n0 {maxnum + 1}\n".encode()
    out += b"0000000000 65535 f \n"
    for i in range(1, maxnum + 1):
        out += f"{offsets.get(i, 0):010d} 00000 n \n".encode()
    out += (f"trailer\n<< /Size {maxnum + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_pos}\n%%EOF").encode()

    with open(path, "wb") as f:
        f.write(out)
    return path
