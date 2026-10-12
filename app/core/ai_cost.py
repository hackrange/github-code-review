"""What the AI has cost, and what it is on course to cost.

Read off the usage table, which has one row for every question that went out,
priced with whatever the AI page's cost tab says a million tokens cost.  A
price left empty counts as nothing, so tokens still add up before anybody has
typed a price in.

The forecast is plain arithmetic, said on the page as such: the average day
in the window, carried forward.  The average is over the days since usage was
first recorded, when that is inside the window, so a new install is not
dragged down by days before it asked anything.
"""

from __future__ import annotations

import calendar
from datetime import datetime, timedelta, timezone
from decimal import Decimal, InvalidOperation

from app.core.models import AIUsage, FindingAnalysis, RepoDiagram

KINDS = ("input", "output", "cache_read", "cache_write")
FORECAST_DAYS = 30


def prices(cfg: dict) -> dict:
    """Price per million tokens for each kind.  -> {kind: Decimal or None}"""
    out = {}
    for kind in KINDS:
        raw = str(cfg.get(f"ai.price_{kind}") or "").strip()
        try:
            out[kind] = Decimal(raw) if raw else None
        except InvalidOperation:
            out[kind] = None
    return out


def _cost(tokens: dict, rate: dict) -> Decimal:
    total = Decimal(0)
    for kind in KINDS:
        if rate[kind] is not None and tokens[kind]:
            total += Decimal(tokens[kind]) * rate[kind] / Decimal(1_000_000)
    return total


def _blank() -> dict:
    return {"calls": 0, "failed": 0, "cut_off": 0,
            "input": 0, "output": 0, "cache_read": 0, "cache_write": 0}


def _add(bucket: dict, row) -> None:
    bucket["calls"] += 1
    bucket["failed"] += 0 if row.ok else 1
    bucket["cut_off"] += 1 if (row.finish or "").lower() in ("length", "max_tokens") else 0
    bucket["input"] += row.input_tokens or 0
    bucket["output"] += row.output_tokens or 0
    bucket["cache_read"] += row.cache_read_tokens or 0
    bucket["cache_write"] += row.cache_write_tokens or 0


def _aware(value: datetime) -> datetime:
    # SQLite hands back naive datetimes; every one stored here is UTC.
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def summary(session, cfg: dict, days: int, now: datetime | None = None) -> dict:
    """Usage and cost over the last `days` days, by day and by purpose."""
    now = now or datetime.now(timezone.utc)
    today = now.replace(hour=0, minute=0, second=0, microsecond=0)
    start = today - timedelta(days=days - 1)
    rate = prices(cfg)

    rows = (session.query(AIUsage)
            .filter(AIUsage.at >= start)
            .order_by(AIUsage.at).all())
    first = session.query(AIUsage.at).order_by(AIUsage.at).limit(1).scalar()

    by_day = {(start + timedelta(days=i)).date(): _blank() for i in range(days)}
    by_purpose, total = {}, _blank()
    for row in rows:
        day = _aware(row.at).date()
        if day in by_day:
            _add(by_day[day], row)
        _add(by_purpose.setdefault(row.purpose or "other", _blank()), row)
        _add(total, row)

    def finish(bucket):
        bucket["tokens"] = sum(bucket[k] for k in KINDS)
        bucket["cost"] = _cost(bucket, rate)
        return bucket

    daily = [{"day": day, **finish(bucket)} for day, bucket in by_day.items()]
    purposes = sorted(({"purpose": name, **finish(bucket)}
                       for name, bucket in by_purpose.items()),
                      key=lambda p: (-p["cost"], -p["tokens"], p["purpose"]))
    finish(total)

    # Days the average is taken over: the whole window, or only the part of it
    # since the first call ever recorded.  Never fewer than one.
    span = days
    if first is not None:
        since_first = (today.date() - _aware(first).date()).days + 1
        span = max(1, min(days, since_first))
    per_day_cost = total["cost"] / span
    per_day_tokens = total["tokens"] / span

    month_days = calendar.monthrange(today.year, today.month)[1]
    month_start = today.replace(day=1)
    month_rows = (session.query(AIUsage)
                  .filter(AIUsage.at >= month_start).all())
    month = _blank()
    for row in month_rows:
        _add(month, row)
    finish(month)
    left = month_days - today.day

    return {
        "days": days,
        "start": start.date(),
        "end": today.date(),
        "first": _aware(first).date() if first is not None else None,
        "span": span,
        "priced": any(value is not None for value in rate.values()),
        "rates": rate,
        "currency": cfg.get("ai.price_currency") or "",
        "daily": daily,
        "purposes": purposes,
        "total": total,
        "forecast": {
            "days": FORECAST_DAYS,
            "per_day_cost": per_day_cost,
            "per_day_tokens": per_day_tokens,
            "cost": per_day_cost * FORECAST_DAYS,
            "tokens": per_day_tokens * FORECAST_DAYS,
            "month_name": today.strftime("%B"),
            "month_so_far": month["cost"],
            "month_tokens_so_far": month["tokens"],
            "month_cost": month["cost"] + per_day_cost * left,
            "month_tokens": month["tokens"] + per_day_tokens * left,
        },
    }


def chart(daily: list, priced: bool) -> dict:
    """Bars for the daily chart: cost when there are prices, tokens when not."""
    width, height = 720, 200
    pad_left, pad_top, pad_bottom = 56, 12, 26
    plot_w, plot_h = width - pad_left - 12, height - pad_top - pad_bottom
    key = "cost" if priced else "tokens"
    values = [float(d[key]) for d in daily]
    top = max(values) if values and max(values) > 0 else 1.0
    step = plot_w / max(1, len(daily))
    gap = 2 if step > 6 else 0
    bars = []
    for i, (d, value) in enumerate(zip(daily, values)):
        h = plot_h * value / top
        bars.append({"x": round(pad_left + i * step + gap / 2, 1),
                     "y": round(pad_top + plot_h - h, 1),
                     "w": round(max(1.0, step - gap), 1),
                     "h": round(h, 1),
                     "day": d["day"], "row": d})
    grid = [{"y": round(pad_top + plot_h * (1 - f), 1), "value": top * f}
            for f in (0, 0.5, 1)]
    every = max(1, len(daily) // 6)
    labels = [{"x": round(pad_left + i * step + step / 2, 1),
               "text": d["day"].strftime("%d %b")}
              for i, d in enumerate(daily) if i % every == 0]
    return {"width": width, "height": height, "pad_left": pad_left,
            "pad_top": pad_top, "plot_h": plot_h, "key": key,
            "bars": bars, "grid": grid, "labels": labels,
            "empty": not any(values)}


def backfill(session) -> int:
    """Usage already recorded elsewhere, copied in once when the table is new.

    Validations and diagrams kept their own token counts before this table
    existed.  Only answers that worked were kept there, so the history this
    gives is a floor, and only the newest diagram per repository survives.
    """
    if session.query(AIUsage.id).limit(1).first() is not None:
        return 0
    # Only the columns needed: an analysis row also holds the whole answer.
    A, D = FindingAnalysis, RepoDiagram
    found = [("validation", r) for r in session.query(
        A.created_at, A.provider, A.model, A.input_tokens, A.output_tokens,
        A.duration_ms).all()]
    found += [("diagram", r) for r in session.query(
        D.created_at, D.provider, D.model, D.input_tokens, D.output_tokens
        ).filter(D.created_at.isnot(None)).all()
        if r.input_tokens or r.output_tokens]
    for purpose, r in found:
        session.add(AIUsage(at=r.created_at, purpose=purpose,
                            provider=r.provider or "", model=r.model or "",
                            ok=True, input_tokens=r.input_tokens or 0,
                            output_tokens=r.output_tokens or 0,
                            duration_ms=getattr(r, "duration_ms", 0) or 0))
    return len(found)
