"""Turning a series into the shapes a page or a report can draw.

The geometry is worked out here rather than in a template because a template
doing arithmetic is a template nobody can read, and because the page and the
generated report draw the same picture and must not drift into two pictures.

Everything comes out as plain numbers and path strings.  Nothing here knows
about color, which lives in the stylesheet with the rest of the palette, so
the same chart works in either theme without being drawn twice.
"""

from __future__ import annotations

# Worst at the bottom of the stack, so the most serious band sits on the axis
# where the eye lands rather than floating on top of everything else.
BANDS = ("critical", "high", "medium", "low", "info")

# The same colors the badges use, as literal values rather than as variables.
#
# The page could take these from the stylesheet and does for everything else,
# but the PDF cannot: the renderer that turns the report into a document draws
# inline SVG with its own drawing code and never applies the page stylesheet to
# it, so a shape styled only by a class comes out filled with the default,
# which is solid black.  A chart of five severity bands rendered as one black
# mass is not a subtle failure, and it only appears in the PDF, so the fill
# travels with the shape.
INK = {
    "critical": ("#b42318", 1.0),
    "high":     ("#b42318", 0.62),
    "medium":   ("#9a6700", 0.78),
    "low":      ("#1f4f82", 0.55),
    "info":     ("#8a8a8a", 0.35),
}


# Four gaps between five gridlines, so the ceiling has to divide by four or
# the labels come out as 0, 12, 25, 38, 50.  Those are correct and nobody
# wants to read them: an axis exists to be glanced at, and a glance at 38
# costs more than a glance at 40.
GRID_STEPS = 4


def _nice_ceiling(value: int) -> int:
    """A round number at or above the largest point, divisible by the grid.

    Two things at once.  The top of the axis sits above the data, because a
    chart whose highest point touches the frame reads as though it ran out of
    room.  And it divides by four exactly, because there are four gaps between
    the five gridlines and a ceiling that does not divide gives an axis
    labeled 0, 12, 25, 38, 50.  Those numbers are correct and nobody wants to
    read them: an axis is glanced at, and a glance at 38 costs more than a
    glance at 40.

    The gap comes off the usual ladder, the one every chart has used since
    graph paper: ones, twos, two and a halves, fives, and the same again at
    each power of ten.
    """
    if value <= 0:
        return GRID_STEPS

    needed = -(-value // GRID_STEPS)          # the smallest gap that reaches
    scale = 1
    while True:
        for step in (1, 2, 2.5, 5):
            gap = step * scale
            if gap >= needed:
                return int(gap * GRID_STEPS)
        scale *= 10


def stacked_area(points: list, width: int = 960, height: int = 260,
                 pad_left: int = 48, pad_bottom: int = 28,
                 pad_top: int = 12, pad_right: int = 12) -> dict:
    """-> everything a stacked area chart needs, already positioned.

    One band per severity, stacked worst first.  A single day is drawn as a
    flat line across the width rather than as one invisible point, because a
    chart with one reading is a legitimate thing to be looking at on the day
    somebody first opens this.
    """
    if not points:
        return {"empty": True, "width": width, "height": height}

    plot_w = width - pad_left - pad_right
    plot_h = height - pad_top - pad_bottom

    totals = [sum(p.get(band, 0) for band in BANDS) for p in points]
    top = _nice_ceiling(max(totals) if totals else 0)

    count = len(points)
    def x_at(index):
        if count == 1:
            return pad_left + plot_w / 2.0
        return pad_left + (plot_w * index / (count - 1.0))

    def y_at(value):
        return pad_top + plot_h - (plot_h * min(value, top) / float(top))

    # Each band is drawn as a closed shape between its own running total and
    # the one below it, so they stack without overlapping.
    running = [0.0] * count
    areas = []
    for band in BANDS:
        lower = list(running)
        for i, point in enumerate(points):
            running[i] += point.get(band, 0)
        if not any(running[i] - lower[i] for i in range(count)):
            continue                      # a band with nothing in it
        top_edge = " ".join("%.1f,%.1f" % (x_at(i), y_at(running[i]))
                            for i in range(count))
        bottom_edge = " ".join("%.1f,%.1f" % (x_at(i), y_at(lower[i]))
                               for i in range(count - 1, -1, -1))
        if count == 1:
            # One reading: widen it into a bar so there is something to see.
            left, right = pad_left, pad_left + plot_w
            top_edge = "%.1f,%.1f %.1f,%.1f" % (left, y_at(running[0]),
                                                right, y_at(running[0]))
            bottom_edge = "%.1f,%.1f %.1f,%.1f" % (right, y_at(lower[0]),
                                                   left, y_at(lower[0]))
        color, opacity = INK[band]
        areas.append({"band": band, "points": top_edge + " " + bottom_edge,
                      "fill": color, "opacity": opacity})

    # Five lines including the axis itself: enough to read a value off, few
    # enough to stay out of the way of the shape.  The ceiling divides by four
    # exactly, so every label here is a whole number.
    grid = []
    for step in range(GRID_STEPS + 1):
        value = top * step // GRID_STEPS
        grid.append({"value": value, "y": round(y_at(value), 1)})

    # A label every few days rather than on all of them, or a month of dates
    # overlaps into a gray smear.
    every = max(1, count // 8)
    wanted = [i for i in range(count) if i % every == 0]
    # The last date is always worth showing, but a regular label landing a few
    # pixels short of it prints as two overlapping dates.  The regular one
    # gives way, because the end of the period is the more useful of the two.
    if count > 1:
        if wanted and (count - 1 - wanted[-1]) <= max(1, every // 2):
            wanted.pop()
        wanted.append(count - 1)
    # The first and last labels are anchored to their edges rather than
    # centered on their points, which sit on the frame: a centered label there
    # hangs half of itself off the side of the chart and gets clipped.
    labels = []
    ordered = sorted(set(wanted))
    for i in ordered:
        if i == 0:
            anchor = "start"
        elif i == count - 1:
            anchor = "end"
        else:
            anchor = "middle"
        labels.append({"x": round(x_at(i), 1), "anchor": anchor,
                       "text": points[i]["day"].strftime("%d %b")})

    marks = [{"x": round(x_at(i), 1), "y": round(y_at(totals[i]), 1),
              "day": points[i]["day"], "total": totals[i],
              "reconstructed": points[i].get("source") == "reconstructed"}
             for i in range(count)]

    return {
        "empty": False, "width": width, "height": height,
        "pad_left": pad_left, "pad_top": pad_top,
        "plot_w": plot_w, "plot_h": plot_h,
        "top": top, "areas": areas, "grid": grid, "labels": labels,
        "marks": marks,
        "first": points[0], "last": points[-1],
        "change": totals[-1] - totals[0],
    }


def heat_levels(rows: list, key: str = "total") -> list:
    """Add a 0 to 4 shade to each row, by where it sits against the busiest.

    Shaded against the largest row rather than against an absolute scale, so
    the picture is about which of these is worst rather than about how the
    estate compares to some other estate.  An absolute scale would make every
    cell the same color on a tidy estate and on a terrible one.
    """
    if not rows:
        return []
    biggest = max(row.get(key, 0) for row in rows) or 1
    out = []
    for row in rows:
        share = row.get(key, 0) / float(biggest)
        row = dict(row)
        row["level"] = 0 if not row.get(key) else min(4, int(share * 4) + 1)
        out.append(row)
    return out
