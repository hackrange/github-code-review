"""A logic diagram of the code, for a security report.

Placed after the executive summary, on a landscape page of its own, for a
reader who wants to see what the findings are about before reading them.
The parts are the main logic units of the code (the handlers, services and
jobs that do the work), the people and systems around them, and the data
stores they keep.  Requests flow left to right through numbered arrows, a
dashed line marks what is inside the application, and each logic unit
carries the numbers of the open Critical, High and Medium issues found in
it, in the colors of their ratings, so a developer sees where the flaws sit
in the logic.  The repository diagram page is the detailed one.

Laid out once, as plain shapes, and painted twice: as SVG for the PDF and
as a PNG for the Word copy, so both show the same picture.  Sized to print:
on a landscape A4 page the names come out near 10 point.

The parts come from the model's read of the repository, so everything here
is untrusted text.  It is cut short, checked against a fixed list of kinds,
and only ever placed into SVG as escaped text.  Which issue sits in which
part is worked out here, from the folders the model named and the files the
issues are in, never taken from the model.
"""

from __future__ import annotations

import html
import io
import re

MAX_PARTS = 10
MAX_LINKS = 12
MAX_PATHS = 4
MAX_PILLS = 4
MAX_PER_COLUMN = 4
KINDS = ("user", "client", "web", "service", "data", "external")
KIND_WORDS = {"user": "PEOPLE", "client": "CLIENT APP", "web": "ENTRY POINT",
              "service": "LOGIC", "data": "DATA STORE", "external": "OUTSIDE SERVICE"}
ACCENT = {"user": "#4C6FA8", "client": "#4C6FA8", "web": "#D9692B",
          "service": "#2E8B62", "data": "#B8901A", "external": "#7A8494"}
TINT = {"user": "#E9EFF8", "client": "#E9EFF8", "web": "#FCEBDF",
        "service": "#E3F3EB", "data": "#FBF3DC", "external": "#EEF0F3"}
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
SOFT = "#5F6B7A"
EDGE = "#3C4A5C"
CARD_LINE = "#D3DAE3"
WIDTH = 1200
NODE_W = 210
NODE_H = 100
ROW_GAP = 26
PAD = 20
FONT = "/usr/share/fonts/truetype/dejavu/DejaVuSans.ttf"
FONT_BOLD = "/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf"


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
            links.append({"from": a, "to": b, "label": _text(link.get("label"), 40)})
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
    unverified package or a waived issue is not drawn, so the parts show
    what needs work first.  An issue goes to the part whose folder is the
    longest match for its file.
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


# ------------------------------------------------------------------ layout

def _columns(design: dict) -> list:
    """The parts in left to right layers, the way a request travels.

    People and client apps outside on the left, then the entry points, the
    logic units stacked in the middle, the data stores, and outside services
    on the right.  Layers rather than one column per hop: a column per hop
    made seven narrow columns on a real repository, and names no one could
    read.  A layer that holds too many is split in two beside itself.
    """
    layers = (("outside", ("user", "client")), ("inside", ("web",)),
              ("inside", ("service",)), ("inside", ("data",)), ("outside", ("external",)))
    out = []
    for zone, kinds in layers:
        ids = [p["id"] for p in design["components"] if p["kind"] in kinds]
        if not ids:
            continue
        # Split evenly: three and two, not four and one.
        parts = -(-len(ids) // MAX_PER_COLUMN)
        size = -(-len(ids) // parts)
        for start in range(0, len(ids), size):
            out.append((zone, ids[start:start + size]))
    return out


def _order(cols: list, links: list) -> list:
    """Each column ordered by where its parts' neighbors stand, to cut crossings."""
    pos = {}
    out = []
    for n, (zone, ids) in enumerate(cols):
        if n:
            def key(pid, ids=ids):
                near = [pos[l["from"]] for l in links if l["to"] == pid and l["from"] in pos]
                near += [pos[l["to"]] for l in links if l["from"] == pid and l["to"] in pos]
                return (sum(near) / len(near)) if near else ids.index(pid)
            ids = sorted(ids, key=key)
        for i, pid in enumerate(ids):
            pos[pid] = i - (len(ids) - 1) / 2
        out.append((zone, ids))
    return out


_FONTS = {}


def _measure(text: str, size: float, bold: bool = True) -> float:
    """How wide text is in layout units, from the font that draws it."""
    key = (size, bold)
    if key not in _FONTS:
        try:
            from PIL import ImageFont
            _FONTS[key] = ImageFont.truetype(FONT_BOLD if bold else FONT, size * 10)
        except Exception:      # no font file: a safe overestimate
            _FONTS[key] = None
    font = _FONTS[key]
    if font is None:
        return len(text) * size * 0.68
    return font.getlength(text) / 10


def _fit_name(name: str, room: float) -> tuple:
    """-> (lines, size): a name in at most two lines inside room.

    Smaller type before a cut word: a name is only shortened, with an
    ellipsis, when even the smallest size will not hold it.
    """
    for size in (13.5, 12.5, 11.5, 10.5):
        lines, line = [], ""
        for word in name.split():
            trial = f"{line} {word}".strip()
            if _measure(trial, size) <= room:
                line = trial
            else:
                if line:
                    lines.append(line)
                line = word
        if line:
            lines.append(line)
        if len(lines) <= 2 and all(_measure(x, size) <= room for x in lines):
            return lines, size
    words = lines[:2]
    last = words[-1] if words else name
    while last and _measure(last + "\u2026", 10.5) > room:
        last = last[:-1]
    return (words[:1] + [last.rstrip() + "\u2026"]) if len(words) > 1 else [last + "\u2026"], 10.5


def _lines(name: str, room: int) -> list:
    """A name in at most two lines that fit a part."""
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


def layout(design: dict, placed: dict | None = None) -> dict:
    """The drawing as plain shapes.  {} when there is nothing to draw.

    -> {"width", "height", "shapes": [...], "steps": [...]}.  A shape is a
    dict with a "type" of rect, ellipse, line, polygon or text; both
    painters below read the same list.
    """
    if not design or len(design.get("components") or []) < 2:
        return {}
    placed = placed or {}
    parts = {p["id"]: p for p in design["components"]}
    cols = _order(_columns(design), design["links"])
    n = len(cols)
    col_w = (WIDTH - 2 * PAD) / n
    node_w = min(NODE_W, col_w - 52)
    rows = max(len(ids) for _, ids in cols)
    top = PAD + 30
    body = rows * NODE_H + (rows - 1) * ROW_GAP
    height = top + body + PAD + 10
    box = {}
    for c, (_, ids) in enumerate(cols):
        cx = PAD + col_w * c + col_w / 2
        offset = (rows - len(ids)) * (NODE_H + ROW_GAP) / 2
        for r, pid in enumerate(ids):
            box[pid] = (cx - node_w / 2, top + offset + r * (NODE_H + ROW_GAP), c)
    shapes = []

    # The application boundary: everything inside it is this code.
    inner = [box[pid] for zone, ids in cols if zone == "inside" for pid in ids]
    if inner:
        x0 = min(b[0] for b in inner) - 18
        x1 = max(b[0] for b in inner) + node_w + 18
        y0 = min(b[1] for b in inner) - 30
        y1 = max(b[1] for b in inner) + NODE_H + 16
        shapes.append({"type": "rect", "x": x0, "y": y0, "w": x1 - x0, "h": y1 - y0,
                       "r": 18, "fill": "#F7F9FC", "stroke": "#9AA8BA", "sw": 1.4,
                       "dash": True})
        shapes.append({"type": "text", "x": x0 + 4, "y": y0 - 8, "text": "THE APPLICATION",
                       "size": 11, "bold": True, "fill": "#7A889A", "anchor": "start"})

    # Arrows under the parts, each with its step number.
    steps, routes = [], []
    for link in design["links"]:
        a, b = box.get(link["from"]), box.get(link["to"])
        if a and b:
            steps.append({"n": len(steps) + 1, "from": parts[link["from"]]["name"],
                          "to": parts[link["to"]]["name"], "label": link["label"]})
            routes.append((link, a, b, len(steps)))
    # Where each arrow leaves and enters a part.  Several on one side of a
    # part are spread along it, so no two heads land on the same point.
    ports = {}
    for link, (ax, ay, ac), (bx, by, bc), _ in routes:
        if ac == bc:
            continue
        out_side, in_side = ("right", "left") if ac < bc else ("left", "right")
        ports.setdefault((link["from"], out_side), []).append((by, link["to"]))
        ports.setdefault((link["to"], in_side), []).append((ay, link["from"]))

    def port_y(pid, side, other, top_y):
        users = sorted(ports.get((pid, side), []))
        k = len(users)
        i = [u[1] for u in users].index(other)
        step = min(16, (NODE_H - 36) / max(1, k - 1)) if k > 1 else 0
        return top_y + NODE_H / 2 + (i - (k - 1) / 2) * step

    col_x = {}
    for pid, (x, y, c) in box.items():
        col_x[c] = x
    boxes = [(x, y, x + node_w, y + NODE_H) for x, y, _ in box.values()]
    lanes = {}
    for link, (ax, ay, ac), (bx, by, bc), num in routes:
        if ac != bc:
            forward = ac < bc
            x1 = ax + node_w if forward else ax
            x2 = bx if forward else bx + node_w
            y1 = port_y(link["from"], "right" if forward else "left", link["to"], ay)
            y2 = port_y(link["to"], "left" if forward else "right", link["from"], by)
            # Arrows through the same gap each get their own vertical lane.
            gap_a = min(ac, bc) if forward else max(ac, bc) - 1
            lane = lanes.get(gap_a, 0)
            lanes[gap_a] = lane + 1
            nudge = ((lane + 1) // 2) * 10 * (1 if lane % 2 else -1)
            xa = x1 + (col_w - node_w) / 2 * (1 if forward else -1) + nudge
            if abs(bc - ac) == 1:
                pts = [(x1, y1), (xa, y1), (xa, y2), (x2, y2)]
                long_v = abs(y1 - y2) > 34
                badge = (xa, (y1 + y2) / 2) if long_v else ((x1 + x2) / 2, y1)
            else:
                # Past a column: run along the clear channel nearest the two
                # ends, above, below or between the rows, so the arrow never
                # crosses a part on its way.
                lo, hi = min(x1, x2), max(x1, x2)
                between = [bxy for bxy in boxes if bxy[0] < hi - 1 and bxy[2] > lo + 1]
                cands = [min(bxy[1] for bxy in boxes) - 14, max(bxy[3] for bxy in boxes) + 14]
                cands += [y for y in range(int(top), int(top + body), 4)]
                clear = [c for c in cands
                         if all(not (bxy[1] - 16 < c < bxy[3] + 16) for bxy in between)]
                chan = min(clear, key=lambda c: abs(c - y1) + abs(c - y2)) if clear else cands[0]
                xb = x2 - (col_w - node_w) / 2 * (1 if forward else -1) - nudge
                pts = [(x1, y1), (xa, y1), (xa, chan), (xb, chan), (xb, y2), (x2, y2)]
                badge = ((xa + xb) / 2, chan)
        elif abs(by - ay) <= NODE_H + ROW_GAP + 1:
            # Neighbors in one layer: a short straight drop between them.
            down = by > ay
            x = ax + node_w * 0.72
            y1 = ay + NODE_H if down else ay
            y2 = by if down else by + NODE_H
            pts = [(x, y1), (x, y2)]
            badge = (x, (y1 + y2) / 2)
        else:
            # Further apart in one layer: out of the right side, down the
            # gap beside the layer and back in, never across a part between.
            lane = lanes.get(("side", ac), 0)
            lanes[("side", ac)] = lane + 1
            xr = ax + node_w
            xs = xr + 14 + lane * 8
            y1, y2 = ay + NODE_H / 2 + 8, by + NODE_H / 2 - 8
            pts = [(xr, y1), (xs, y1), (xs, y2), (xr, y2)]
            badge = (xs, (y1 + y2) / 2)
        # Drop points that do not move, so a straight run stays one segment.
        clean_pts = [pts[0]]
        for pt in pts[1:]:
            if abs(pt[0] - clean_pts[-1][0]) > 0.5 or abs(pt[1] - clean_pts[-1][1]) > 0.5:
                clean_pts.append(pt)
        shapes.append({"type": "line", "points": clean_pts, "stroke": EDGE, "sw": 1.8,
                       "arrow": True, "num": num, "badge": badge})

    # The parts.
    for pid, (x, y, _) in box.items():
        p = parts[pid]
        issues = placed.get(pid) or []
        accent = ACCENT[p["kind"]]
        border = RATING_FILL[issues[0][1]] if issues else CARD_LINE
        sw = 2.4 if issues else 1.2
        if p["kind"] == "data":
            # A cylinder, the shape everyone reads as a database.
            ry = 11
            shapes.append({"type": "rect", "x": x + 1, "y": y + 4, "w": node_w, "h": NODE_H,
                           "r": 12, "fill": "#1F2A37", "opacity": 0.06})
            shapes.append({"type": "ellipse", "cx": x + node_w / 2, "cy": y + NODE_H - ry,
                           "rx": node_w / 2, "ry": ry, "fill": "#FFFFFF", "stroke": border, "sw": sw})
            shapes.append({"type": "rect", "x": x, "y": y + ry, "w": node_w, "h": NODE_H - 2 * ry,
                           "r": 0, "fill": "#FFFFFF", "stroke": None})
            shapes.append({"type": "line", "points": [(x, y + ry), (x, y + NODE_H - ry)],
                           "stroke": border, "sw": sw})
            shapes.append({"type": "line", "points": [(x + node_w, y + ry),
                                                      (x + node_w, y + NODE_H - ry)],
                           "stroke": border, "sw": sw})
            shapes.append({"type": "ellipse", "cx": x + node_w / 2, "cy": y + ry,
                           "rx": node_w / 2, "ry": ry, "fill": TINT["data"], "stroke": border,
                           "sw": sw})
        else:
            shapes.append({"type": "rect", "x": x + 1, "y": y + 4, "w": node_w, "h": NODE_H,
                           "r": 14, "fill": "#1F2A37", "opacity": 0.07})
            shapes.append({"type": "rect", "x": x, "y": y, "w": node_w, "h": NODE_H, "r": 14,
                           "fill": "#FFFFFF", "stroke": border, "sw": sw,
                           "dash": p["kind"] == "external"})
            shapes.append({"type": "rect", "x": x, "y": y + 14, "w": 5, "h": NODE_H - 28,
                           "r": 2.5, "fill": accent})
        # Top row: a small icon and what kind of part it is.  Below it the
        # name across the whole card, and the issue pills along the bottom.
        dy = 8 if p["kind"] == "data" else 0
        _icon(shapes, p["kind"], x + 27, y + 22 + dy, accent, 0.78)
        shapes.append({"type": "text", "x": x + 44, "y": y + 26 + dy,
                       "text": KIND_WORDS[p["kind"]], "size": 9.5, "bold": True,
                       "fill": accent, "anchor": "start"})
        lines, size = _fit_name(p["name"], node_w - 30)
        for i, line in enumerate(lines):
            shapes.append({"type": "text", "x": x + 17,
                           "y": y + 48 + dy + i * (size + 3),
                           "text": line, "size": size, "bold": True, "fill": INK,
                           "anchor": "start"})
        if issues:
            px, py = x + 15, y + NODE_H - (34 if p["kind"] == "data" else 28)
            # As many as fit inside the part, with room left for "+N".
            def fits(chosen, room):
                return sum(14 + len(i) * 7.6 + 5 for i, _ in chosen) - 5 <= room

            room = node_w - 28
            shown = list(issues[:MAX_PILLS])
            if len(shown) < len(issues) or not fits(shown, room):
                while shown and not fits(shown, room - 34):
                    shown.pop()
            for issue_id, rating in shown:
                w = 14 + len(issue_id) * 7.6
                shapes.append({"type": "rect", "x": px, "y": py, "w": w, "h": 19, "r": 9.5,
                               "fill": RATING_FILL[rating]})
                shapes.append({"type": "text", "x": px + w / 2, "y": py + 13.5,
                               "text": issue_id, "size": 11, "bold": True,
                               "fill": RATING_TEXT[rating], "anchor": "middle"})
                px += w + 5
            if len(issues) > len(shown):
                shapes.append({"type": "text", "x": px + 1, "y": py + 13.5,
                               "text": f"+{len(issues) - len(shown)}", "size": 11,
                               "bold": True, "fill": SOFT, "anchor": "start"})

    # Step numbers on top of everything, each slid along its own arrow to a
    # place clear of the parts and of every other number, so nothing written
    # sits on anything else.
    taken = []
    arrows = [s for s in shapes if s.get("num")]
    for s in arrows:
        others = [seg for o in arrows if o is not s
                  for seg in zip(o["points"], o["points"][1:])]
        bx, by = _clear_spot(s["points"], s["badge"], boxes, taken, others)
        taken.append((bx, by))
        shapes.append({"type": "ellipse", "cx": bx, "cy": by, "rx": 11, "ry": 11,
                       "fill": EDGE, "stroke": "#FFFFFF", "sw": 2})
        shapes.append({"type": "text", "x": bx, "y": by + 4, "text": str(s["num"]),
                       "size": 11, "bold": True, "fill": "#FFFFFF", "anchor": "middle"})
    return {"width": WIDTH, "height": round(height), "shapes": shapes, "steps": steps}


def _seg_dist(pt, seg) -> float:
    (x, y), ((ax, ay), (bx, by)) = pt, seg
    dx, dy = bx - ax, by - ay
    t = max(0.0, min(1.0, ((x - ax) * dx + (y - ay) * dy) / ((dx * dx + dy * dy) or 1)))
    return ((x - ax - t * dx) ** 2 + (y - ay - t * dy) ** 2) ** 0.5


def _clear_spot(pts: list, preferred: tuple, boxes: list, taken: list,
                others: list = ()) -> tuple:
    """A point on the arrow for its number, clear of parts and other numbers."""
    segs = list(zip(pts, pts[1:]))
    lengths = [abs(b[0] - a[0]) + abs(b[1] - a[1]) for a, b in segs]
    total = sum(lengths) or 1

    def at(frac):
        left = frac * total
        for (a, b), length in zip(segs, lengths):
            if left <= length and length:
                t = left / length
                return (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t)
            left -= length
        return pts[-1]

    def ok(pt):
        x, y = pt
        if any(bx0 - 13 < x < bx1 + 13 and by0 - 13 < y < by1 + 13
               for bx0, by0, bx1, by1 in boxes):
            return False
        if any(_seg_dist(pt, seg) < 13 for seg in others):
            return False
        return all((x - tx) ** 2 + (y - ty) ** 2 >= 26 ** 2 for tx, ty in taken)

    fracs = [0.5, 0.4, 0.6, 0.3, 0.7, 0.2, 0.8, 0.15, 0.85, 0.1, 0.9, 0.35, 0.65, 0.25, 0.75]
    tries = [preferred] + [at(f) for f in fracs]
    for pt in tries:
        if ok(pt):
            return pt
    # Nowhere fully clear: at least keep off the parts and the other numbers.
    loose = [pt for pt in tries
             if not any(bx0 - 13 < pt[0] < bx1 + 13 and by0 - 13 < pt[1] < by1 + 13
                        for bx0, by0, bx1, by1 in boxes)
             and all((pt[0] - tx) ** 2 + (pt[1] - ty) ** 2 >= 26 ** 2 for tx, ty in taken)]
    return loose[0] if loose else preferred


def _icon(shapes: list, kind: str, cx: float, cy: float, color: str,
          scale: float = 1.0) -> None:
    """A small glyph in a tinted circle, saying what kind of part this is."""
    start = len(shapes)
    _glyph(shapes, kind, 0, 0, color)
    for sh in shapes[start:]:
        for key in ("x", "cx"):
            if key in sh:
                sh[key] = cx + sh[key] * scale
        for key in ("y", "cy"):
            if key in sh:
                sh[key] = cy + sh[key] * scale
        for key in ("w", "h", "rx", "ry", "r", "sw"):
            if key in sh and sh[key]:
                sh[key] = sh[key] * scale
        if "points" in sh:
            sh["points"] = [(cx + px * scale, cy + py * scale) for px, py in sh["points"]]


def _glyph(shapes: list, kind: str, cx: float, cy: float, color: str) -> None:
    shapes.append({"type": "ellipse", "cx": cx, "cy": cy, "rx": 15, "ry": 15,
                   "fill": TINT[kind], "stroke": None})
    if kind == "user":
        shapes.append({"type": "ellipse", "cx": cx, "cy": cy - 4, "rx": 4.5, "ry": 4.5,
                       "fill": color, "stroke": None})
        shapes.append({"type": "rect", "x": cx - 8, "y": cy + 2, "w": 16, "h": 8, "r": 4,
                       "fill": color})
    elif kind == "client":
        shapes.append({"type": "rect", "x": cx - 9, "y": cy - 7, "w": 18, "h": 14, "r": 2,
                       "fill": "#FFFFFF", "stroke": color, "sw": 1.8})
        shapes.append({"type": "rect", "x": cx - 9, "y": cy - 7, "w": 18, "h": 4, "r": 1,
                       "fill": color})
    elif kind == "web":
        shapes.append({"type": "ellipse", "cx": cx, "cy": cy, "rx": 8.5, "ry": 8.5,
                       "fill": None, "stroke": color, "sw": 1.8})
        shapes.append({"type": "ellipse", "cx": cx, "cy": cy, "rx": 3.8, "ry": 8.5,
                       "fill": None, "stroke": color, "sw": 1.4})
        shapes.append({"type": "line", "points": [(cx - 8.5, cy), (cx + 8.5, cy)],
                       "stroke": color, "sw": 1.4})
    elif kind == "service":
        shapes.append({"type": "line", "points": [(cx - 3, cy - 7), (cx - 9, cy), (cx - 3, cy + 7)],
                       "stroke": color, "sw": 2.2})
        shapes.append({"type": "line", "points": [(cx + 3, cy - 7), (cx + 9, cy), (cx + 3, cy + 7)],
                       "stroke": color, "sw": 2.2})
    elif kind == "data":
        shapes.append({"type": "rect", "x": cx - 8, "y": cy - 6, "w": 16, "h": 12, "r": 0,
                       "fill": color})
        shapes.append({"type": "ellipse", "cx": cx, "cy": cy + 6, "rx": 8, "ry": 3,
                       "fill": color, "stroke": None})
        shapes.append({"type": "ellipse", "cx": cx, "cy": cy - 6, "rx": 8, "ry": 3,
                       "fill": TINT[kind], "stroke": color, "sw": 1.4})
    else:
        for dx, dy, r in ((-5, 1, 5), (1, -3, 6.5), (6, 2, 4.5)):
            shapes.append({"type": "ellipse", "cx": cx + dx, "cy": cy + dy, "rx": r, "ry": r,
                           "fill": color, "stroke": None})
        shapes.append({"type": "rect", "x": cx - 10, "y": cy + 1, "w": 20, "h": 6, "r": 3,
                       "fill": color})


# ------------------------------------------------------------------ painters

def _arrow_head(pts: list) -> list:
    (x1, y1), (x2, y2) = pts[-2], pts[-1]
    if x1 == x2 and y1 == y2 and len(pts) > 2:
        (x1, y1) = pts[-3]
    dx, dy = x2 - x1, y2 - y1
    length = max(1e-6, (dx * dx + dy * dy) ** 0.5)
    ux, uy = dx / length, dy / length
    size = 9
    bx, by = x2 - ux * size, y2 - uy * size
    return [(x2, y2), (bx - uy * size * 0.55, by + ux * size * 0.55),
            (bx + uy * size * 0.55, by - ux * size * 0.55)]


def _rounded(pts: list, r: float = 10) -> str:
    """An SVG path through the points, with the corners rounded."""
    out = [f"M{pts[0][0]:.1f},{pts[0][1]:.1f}"]
    for i in range(1, len(pts) - 1):
        (px, py), (cx, cy), (nx, ny) = pts[i - 1], pts[i], pts[i + 1]
        d1 = max(abs(cx - px), abs(cy - py))
        d2 = max(abs(nx - cx), abs(ny - cy))
        rr = min(r, d1 / 2, d2 / 2)
        if rr < 1:
            out.append(f"L{cx:.1f},{cy:.1f}")
            continue
        ax = cx - (cx - px) / d1 * rr if d1 else cx
        ay = cy - (cy - py) / d1 * rr if d1 else cy
        bx = cx + (nx - cx) / d2 * rr if d2 else cx
        by = cy + (ny - cy) / d2 * rr if d2 else cy
        out.append(f"L{ax:.1f},{ay:.1f} Q{cx:.1f},{cy:.1f} {bx:.1f},{by:.1f}")
    # Stop short of the end, so the line does not poke through the head.
    (x1, y1), (x2, y2) = pts[-2], pts[-1]
    length = max(1e-6, ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5)
    ex, ey = x2 - (x2 - x1) / length * 7, y2 - (y2 - y1) / length * 7
    out.append(f"L{ex:.1f},{ey:.1f}")
    return " ".join(out)


# The room the diagram has on a landscape A4 page, under its heading and
# above the list of steps.  The printable area is about 265 by 176 mm.
PAGE_W_MM = 265
PAGE_H_MM = 112


def svg(design: dict, placed: dict | None = None) -> str:
    """The diagram as SVG sized in millimeters to fit its page.  "" when none.

    Sized here rather than by the page's CSS, because a PDF renderer that
    cannot shrink an SVG to a maximum height pushes it to the next page.
    """
    lay = layout(design or {}, placed)
    if not lay:
        return ""
    width_mm = min(PAGE_W_MM, PAGE_H_MM * lay["width"] / lay["height"])
    height_mm = width_mm * lay["height"] / lay["width"]
    out = [f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {lay["width"]} {lay["height"]}" '
           f'width="{width_mm:.1f}mm" height="{height_mm:.1f}mm" role="img" '
           f'aria-label="Logic diagram of the code" '
           f'font-family="DejaVu Sans, Helvetica, Arial, sans-serif">']
    for s in lay["shapes"]:
        t = s["type"]
        stroke = (f' stroke="{s["stroke"]}" stroke-width="{s.get("sw", 1)}"'
                  if s.get("stroke") else "")
        dash = ' stroke-dasharray="6 5"' if s.get("dash") else ""
        fill = s.get("fill") or "none"
        opacity = f' fill-opacity="{s["opacity"]}"' if s.get("opacity") else ""
        if t == "rect":
            out.append(f'<rect x="{s["x"]:.1f}" y="{s["y"]:.1f}" width="{s["w"]:.1f}" '
                       f'height="{s["h"]:.1f}" rx="{s["r"]}" fill="{fill}"{opacity}{stroke}{dash}/>')
        elif t == "ellipse":
            out.append(f'<ellipse cx="{s["cx"]:.1f}" cy="{s["cy"]:.1f}" rx="{s["rx"]:.1f}" '
                       f'ry="{s["ry"]:.1f}" fill="{fill}"{stroke}/>')
        elif t == "line":
            if s.get("arrow"):
                out.append(f'<path d="{_rounded(s["points"])}" fill="none"{stroke} '
                           'stroke-linejoin="round" stroke-linecap="round"/>')
                head = " ".join(f"{x:.1f},{y:.1f}" for x, y in _arrow_head(s["points"]))
                out.append(f'<polygon points="{head}" fill="{s["stroke"]}"/>')
            else:
                pts = " ".join(f"{x:.1f},{y:.1f}" for x, y in s["points"])
                out.append(f'<polyline points="{pts}" fill="none"{stroke} '
                           'stroke-linejoin="round" stroke-linecap="round"/>')
        elif t == "text":
            weight = ' font-weight="bold"' if s.get("bold") else ""
            out.append(f'<text x="{s["x"]:.1f}" y="{s["y"]:.1f}" font-size="{s["size"]}"'
                       f'{weight} fill="{s["fill"]}" text-anchor="{s["anchor"]}">'
                       f'{html.escape(s["text"])}</text>')
    out.append("</svg>")
    return "".join(out)


def png(design: dict, placed: dict | None = None, scale: float = 2.5) -> bytes:
    """The same diagram as a PNG, for the Word copy.  b"" when none.

    Drawn at two and a half times the layout size, which prints sharp at
    the width of a landscape page.
    """
    lay = layout(design or {}, placed)
    if not lay:
        return b""
    from PIL import Image, ImageDraw, ImageFont

    def font(size, bold):
        try:
            return ImageFont.truetype(FONT_BOLD if bold else FONT, round(size * scale))
        except OSError:
            return ImageFont.load_default(size=round(size * scale))

    def rgb(color, opacity=1.0):
        c = color.lstrip("#")
        r, g, b = int(c[0:2], 16), int(c[2:4], 16), int(c[4:6], 16)
        return (r, g, b, round(255 * opacity))

    w, h = round(lay["width"] * scale), round(lay["height"] * scale)
    image = Image.new("RGBA", (w, h), (255, 255, 255, 255))

    def sc(v):
        return v * scale

    for s in lay["shapes"]:
        t = s["type"]
        # Each shape on its own layer, so a soft shadow blends rather than paints over.
        layer = Image.new("RGBA", (w, h), (0, 0, 0, 0))
        d = ImageDraw.Draw(layer)
        width = max(1, round(s.get("sw", 1) * scale))
        outline = rgb(s["stroke"]) if s.get("stroke") else None
        fill = rgb(s["fill"], s.get("opacity", 1.0)) if s.get("fill") else None
        if t == "rect":
            box = [sc(s["x"]), sc(s["y"]), sc(s["x"] + s["w"]), sc(s["y"] + s["h"])]
            d.rounded_rectangle(box, radius=sc(s["r"]), fill=fill,
                                outline=None if s.get("dash") else outline, width=width)
            if s.get("dash") and outline:
                _dashed_round_rect(d, box, sc(s["r"]), outline, width, scale)
        elif t == "ellipse":
            d.ellipse([sc(s["cx"] - s["rx"]), sc(s["cy"] - s["ry"]),
                       sc(s["cx"] + s["rx"]), sc(s["cy"] + s["ry"])],
                      fill=fill, outline=outline, width=width)
        elif t == "line":
            pts = [(sc(x), sc(y)) for x, y in s["points"]]
            if s.get("arrow"):
                (x1, y1), (x2, y2) = pts[-2], pts[-1]
                length = max(1e-6, ((x2 - x1) ** 2 + (y2 - y1) ** 2) ** 0.5)
                pts = pts[:-1] + [(x2 - (x2 - x1) / length * 7 * scale,
                                   y2 - (y2 - y1) / length * 7 * scale)]
            d.line(pts, fill=outline, width=width, joint="curve")
            if s.get("arrow"):
                d.polygon([(sc(x), sc(y)) for x, y in _arrow_head(s["points"])], fill=outline)
        elif t == "text":
            anchor = {"start": "ls", "middle": "ms", "end": "rs"}[s["anchor"]]
            d.text((sc(s["x"]), sc(s["y"])), s["text"], font=font(s["size"], s.get("bold")),
                   fill=rgb(s["fill"]), anchor=anchor)
        image = Image.alpha_composite(image, layer)
    buffer = io.BytesIO()
    image.convert("RGB").save(buffer, "PNG", optimize=True)
    return buffer.getvalue()


def _dashed_round_rect(d, box, radius, color, width, scale):
    """A dashed outline: straight dashes on the sides, arcs left solid."""
    x0, y0, x1, y1 = box
    dash, gap = 6 * scale, 5 * scale
    for (ax, ay, bx, by) in ((x0 + radius, y0, x1 - radius, y0), (x0 + radius, y1, x1 - radius, y1),
                             (x0, y0 + radius, x0, y1 - radius), (x1, y0 + radius, x1, y1 - radius)):
        length = max(abs(bx - ax), abs(by - ay))
        pos = 0.0
        while pos < length:
            end = min(pos + dash, length)
            if ax == bx:
                d.line([(ax, ay + pos), (ax, ay + end)], fill=color, width=width)
            else:
                d.line([(ax + pos, ay), (ax + end, ay)], fill=color, width=width)
            pos = end + gap
    for start, (cx, cy) in ((180, (x0 + radius, y0 + radius)), (270, (x1 - radius, y0 + radius)),
                            (0, (x1 - radius, y1 - radius)), (90, (x0 + radius, y1 - radius))):
        d.arc([cx - radius, cy - radius, cx + radius, cy + radius], start, start + 90,
              fill=color, width=width)


def steps(design: dict) -> list:
    """The numbered steps under the diagram: {n, from, to, label}."""
    lay = layout(design or {}, {})
    return lay.get("steps", []) if lay else []


def link_lines(design: dict) -> list:
    """The steps as short sentences, for the Word report and screen readers."""
    return [f"{s['n']}.  {s['from']} to {s['to']}" + (f": {s['label']}" if s["label"] else "")
            for s in steps(design)]


def columns(design: dict, placed: dict | None = None) -> list:
    """Kept for callers that list the parts: [(zone, [parts with issues])]."""
    if not design or len(design.get("components") or []) < 2:
        return []
    placed = placed or {}
    parts = {p["id"]: p for p in design["components"]}
    return [(zone, [{**parts[pid], "issues": placed.get(pid, [])} for pid in ids])
            for zone, ids in _order(_columns(design), design["links"])]
