"""A small drawing of how the code fits together, for a security report.

Placed after the executive summary, on a landscape page of its own, for a
reader who wants to see what the findings are about before reading them.
It is kept simple on purpose: a few cards in up to four columns (who uses
it, where it is reached, what does the work, where data goes), arrows
between them, and on each card the numbers of the open issues found in that
part of the code, colored by rating.  The repository diagram page is the
detailed one.

The parts come from the model's read of the repository, so everything here
is untrusted text.  It is cut short, checked against a fixed list of kinds,
and only ever placed into SVG as escaped text.  Which issue sits in which
part is worked out here, from the folders the model named and the files the
issues are in, never taken from the model.
"""

from __future__ import annotations

import html
import re

MAX_PARTS = 8
MAX_LINKS = 10
MAX_PATHS = 4
MAX_PILLS = 4
KINDS = ("user", "client", "web", "service", "data", "external")
# The column each kind stands in, left to right.
TIER = {"user": 0, "client": 0, "web": 1, "service": 2, "data": 3, "external": 3}
TIER_NAMES = ("Who uses it", "Where it is reached", "What does the work",
              "Data and outside services")
ACCENT = {"user": "#5B7DB1", "client": "#5B7DB1", "web": "#E07B39",
          "service": "#3E9B6B", "data": "#C9A227", "external": "#8A94A3"}
# The same colors as the rating badges everywhere else in the report and in
# the Word copy, so a pill reads as its rating at a glance.
RATING_FILL = {"Critical": "#C00000", "High": "#E36C0A", "Medium": "#FFC000",
               "Low": "#70AD47"}
RATING_TEXT = {"Critical": "#FFFFFF", "High": "#FFFFFF", "Medium": "#000000",
               "Low": "#FFFFFF"}
# Only these are drawn: a Low on every card is the clutter that hides the
# ones that matter.
RATING_ORDER = ("Critical", "High", "Medium")
INK = "#1F2A37"
SOFT = "#6B7480"
LINE = "#A7B0BC"
WIDTH = 1000
CARD_H = 78
ROW = 98
TOP = 44


def _text(value, limit: int) -> str:
    text = re.sub(r"\s+", " ", str(value or "")).strip()
    return text[:limit].rstrip()


def _slug(value) -> str:
    return re.sub(r"[^a-z0-9]+", "-", str(value or "").lower()).strip("-")[:40]


def _path(value) -> str:
    """A folder or file the model named, as a relative prefix, or ""."""
    text = str(value or "").strip().replace("\\", "/")
    if not text or ".." in text.split("/") or text.startswith("/") or len(text) > 160:
        return ""
    while text.startswith("./"):
        text = text[2:]
    return text.rstrip("*").rstrip("/")


def clean(raw) -> dict:
    """The model's design, checked.  {} when there is nothing worth drawing."""
    if not isinstance(raw, dict):
        return {}
    parts, ids = [], set()
    for p in (raw.get("components") or [])[:MAX_PARTS]:
        if not isinstance(p, dict):
            continue
        pid = _slug(p.get("id") or p.get("name"))
        name = _text(p.get("name"), 40)
        kind = str(p.get("kind") or "").strip().lower()
        if not pid or not name or pid in ids:
            continue
        ids.add(pid)
        paths = [x for x in (_path(v) for v in (p.get("paths") or [])[:MAX_PATHS]
                             if isinstance(v, str)) if x]
        parts.append({"id": pid, "name": name,
                      "kind": kind if kind in KINDS else "service", "paths": paths})
    links = []
    for link in (raw.get("links") or [])[:MAX_LINKS * 2]:
        if not isinstance(link, dict):
            continue
        a, b = _slug(link.get("from")), _slug(link.get("to"))
        if a in ids and b in ids and a != b:
            links.append({"from": a, "to": b, "label": _text(link.get("label"), 24)})
        if len(links) >= MAX_LINKS:
            break
    if len(parts) < 2:
        return {}
    return {"components": parts, "links": links}


def _item_file(item: dict) -> str:
    """The file an issue is in, from what a report stores."""
    if item.get("file"):
        return str(item["file"])
    location = str(item.get("location") or "")
    return location.split(", line")[0] if "/" in location or "." in location else ""


def place(design: dict, items: list) -> tuple:
    """-> ({part id: [(issue id, rating)]}, [issue ids placed nowhere]).

    Only open Critical, High and Medium issues: a Low, a false alarm, an
    unverified package or a waived issue is not drawn, so the cards show
    what needs work first.  An
    issue goes to the part whose folder is the longest match for its file.
    """
    placed = {p["id"]: [] for p in design.get("components") or []}
    loose = []
    for item in items:
        if (item.get("rating") not in RATING_ORDER or item.get("waived")
                or item.get("unverified")):
            continue
        rel = _item_file(item)
        while rel.startswith("./"):
            rel = rel[2:]
        best, size = None, -1
        for p in design.get("components") or []:
            for prefix in p.get("paths") or []:
                if rel and (rel == prefix or rel.startswith(prefix + "/")) and len(prefix) > size:
                    best, size = p["id"], len(prefix)
        if best is None:
            loose.append(item["id"])
        else:
            placed[best].append((item["id"], item["rating"]))
    for pid in placed:
        placed[pid].sort(key=lambda x: (RATING_ORDER.index(x[1]), x[0]))
    return placed, loose


def columns(design: dict, placed: dict | None = None) -> list:
    """[(tier name, [parts with their issues])], only tiers that hold something."""
    placed = placed or {}
    out = []
    for n, name in enumerate(TIER_NAMES):
        members = [{**p, "issues": placed.get(p["id"], [])}
                   for p in design.get("components") or [] if TIER[p["kind"]] == n]
        if members:
            out.append((name, members))
    return out


def _lines(name: str, room: int) -> list:
    """A name in at most two lines that fit a card."""
    lines, line = [], ""
    for w in name.split():
        if len(line) + len(w) + (1 if line else 0) <= room:
            line = f"{line} {w}".strip()
        else:
            if line:
                lines.append(line)
            line = w[:room]
        if len(lines) == 2:
            break
    if line and len(lines) < 2:
        lines.append(line)
    return lines[:2]


def svg(design: dict, placed: dict | None = None) -> str:
    """The design as SVG that scales to the page width.  "" when none."""
    cols = columns(design or {}, placed)
    if not cols:
        return ""
    width_each = WIDTH / len(cols)
    card_w = min(230, width_each - 70)
    rows = max(len(m) for _, m in cols)
    height = TOP + rows * ROW
    font = "font-family=\"Helvetica, Arial, sans-serif\""
    where = {}
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {WIDTH} {height:.0f}" '
           f'width="100%" role="img" aria-label="How the code fits together" {font}>',
           '<defs><marker id="arrow" viewBox="0 0 10 10" refX="8" refY="5" '
           'markerWidth="6" markerHeight="6" orient="auto-start-reverse">'
           f'<path d="M0,1 L9,5 L0,9 z" fill="{LINE}"/></marker></defs>']
    cards = []
    for c, (title, members) in enumerate(cols):
        cx = width_each * c + width_each / 2
        out.append(f'<text x="{cx:.0f}" y="16" text-anchor="middle" font-size="11" '
                   f'letter-spacing="1.2" fill="{SOFT}">{html.escape(title.upper())}</text>')
        out.append(f'<line x1="{cx - 30:.0f}" y1="24" x2="{cx + 30:.0f}" y2="24" '
                   f'stroke="#D6DCE4" stroke-width="2" stroke-linecap="round"/>')
        offset = (rows - len(members)) * ROW / 2
        for r, p in enumerate(members):
            x, y = cx - card_w / 2, TOP + offset + r * ROW
            where[p["id"]] = (x, y, c)
            cards.append((x, y, cx, p))
    # Arrows first, so the cards sit on top of them.
    for link in design.get("links") or []:
        a, b = where.get(link["from"]), where.get(link["to"])
        if not a or not b:
            continue
        (ax, ay, ac), (bx, by, bc) = a, b
        y1, y2 = ay + CARD_H / 2, by + CARD_H / 2
        if ac != bc:
            x1, x2 = (ax + card_w, bx) if ac < bc else (ax, bx + card_w)
            bend = (x2 - x1) / 2
            path = (f"M{x1:.0f},{y1:.0f} C{x1 + bend:.0f},{y1:.0f} "
                    f"{x2 - bend:.0f},{y2:.0f} {x2:.0f},{y2:.0f}")
        else:
            x1 = x2 = ax + card_w
            path = (f"M{x1:.0f},{y1:.0f} C{x1 + 26:.0f},{y1:.0f} "
                    f"{x2 + 26:.0f},{y2:.0f} {x2:.0f},{y2:.0f}")
        out.append(f'<path d="{path}" fill="none" stroke="{LINE}" stroke-width="1.6" '
                   'marker-end="url(#arrow)"/>')
        if link["label"] and ac != bc:
            mx, my = (x1 + x2) / 2, (y1 + y2) / 2 + 4
            # A small chip behind the words, so the line never runs through
            # them.  (paint-order is not drawn by every PDF renderer.)
            w = 12 + len(link["label"]) * 5.6
            out.append(f'<rect x="{mx - w / 2:.0f}" y="{my - 11:.0f}" width="{w:.0f}" '
                       f'height="15" rx="7.5" fill="#F3F5F8" stroke="#E1E6EC"/>')
            out.append(f'<text x="{mx:.0f}" y="{my:.0f}" text-anchor="middle" font-size="9.5" '
                       f'fill="{SOFT}">{html.escape(link["label"])}</text>')
    for x, y, cx, p in cards:
        accent = ACCENT[p["kind"]]
        issues = p.get("issues") or []
        # A soft shadow, a white card, and a colored edge saying what it is.
        out.append(f'<rect x="{x + 1:.0f}" y="{y + 3:.0f}" width="{card_w:.0f}" '
                   f'height="{CARD_H}" rx="12" fill="#1F2A37" fill-opacity="0.07"/>')
        border = RATING_FILL[issues[0][1]] if issues else "#E1E6EC"
        out.append(f'<rect x="{x:.0f}" y="{y:.0f}" width="{card_w:.0f}" height="{CARD_H}" '
                   f'rx="12" fill="#FFFFFF" stroke="{border}" '
                   f'stroke-width="{1.6 if issues else 1}"/>')
        out.append(f'<rect x="{x + 12:.0f}" y="{y + 12:.0f}" width="4" height="{CARD_H - 24}" '
                   f'rx="2" fill="{accent}"/>')
        lines = _lines(p["name"], max(10, int((card_w - 40) / 7.2)))
        name_y = y + (24 if issues else CARD_H / 2 - (len(lines) - 1) * 8 + 5)
        for n, line in enumerate(lines):
            out.append(f'<text x="{x + 26:.0f}" y="{name_y + n * 16:.0f}" font-size="13.5" '
                       f'font-weight="bold" fill="{INK}">{html.escape(line)}</text>')
        if issues:
            px, py = x + 26, y + CARD_H - 26
            shown = issues[:MAX_PILLS]
            for issue_id, rating in shown:
                w = 9 + len(issue_id) * 7
                out.append(f'<rect x="{px:.0f}" y="{py:.0f}" width="{w}" height="17" rx="8.5" '
                           f'fill="{RATING_FILL[rating]}"/>')
                out.append(f'<text x="{px + w / 2:.0f}" y="{py + 12:.0f}" text-anchor="middle" '
                           f'font-size="10" font-weight="bold" fill="{RATING_TEXT[rating]}">'
                           f'{html.escape(issue_id)}</text>')
                px += w + 5
            if len(issues) > len(shown):
                out.append(f'<text x="{px + 2:.0f}" y="{py + 12:.0f}" font-size="10" '
                           f'fill="{SOFT}">+{len(issues) - len(shown)} more</text>')
    out.append("</svg>")
    return "".join(out)


def link_lines(design: dict) -> list:
    """The links as short sentences, for the Word report and screen readers."""
    names = {p["id"]: p["name"] for p in design.get("components") or []}
    return [f"{names[l['from']]} to {names[l['to']]}" + (f": {l['label']}" if l["label"] else "")
            for l in design.get("links") or [] if l["from"] in names and l["to"] in names]
