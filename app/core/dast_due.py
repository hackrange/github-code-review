"""Which web applications are due for a dynamic scan or penetration test.

The tests happen elsewhere, by another system or another company.  This says
which sites should be next: never tested, code changed since the last test,
or the last test is too old.  A commit is not a deployment, so every message
says the code changed rather than that the site did.
"""

from __future__ import annotations

import logging

from app.core import settings_store as store
from app.core import tagging, webapps

log = logging.getLogger("gcr.dast_due")


def applications(session, base=None) -> list:
    """Every web application, judged.  `base` narrows it to what somebody can see."""
    apps = webapps.inventory(session, base=base)
    max_age = int(store.get(session, "dast.max_age_days") or 0)
    return webapps.judge(apps, webapps.tests_by_key(session), max_age)


def message(due: list, new: list) -> tuple:
    """-> (title, lines) naming what became due, then how many are due in all."""
    title = (f"{len(new)} web application{'s' if len(new) != 1 else ''} "
             f"due for testing")
    lines = []
    for app in new[:40]:
        urls = ", ".join(app["urls"][:3])
        lines.append(f"{app['name']}"
                     + (f" ({urls})" if urls else "")
                     + f": {'; '.join(app['due']['reasons'])}")
    if len(new) > 40:
        lines.append(f"and {len(new) - 40} more")
    lines.append(f"{len(due)} due in all.  Changed means a commit on the default "
                 f"branch, not a deployment.")
    return title, lines


def weekly() -> None:
    """The scheduled message.  Quiet unless switched on and something became due."""
    from app.core import notify
    from app.core.audit import record
    from app.core.db import session_scope

    with session_scope() as db:
        if not store.get(db, "notify.dast_due_enabled"):
            return
        try:
            apps = applications(db)
        except Exception as exc:  # a background job must not take the scheduler down
            log.warning("web application check failed: %s", exc)
            return
        due = [a for a in apps if a["due"]["is_due"]]
        told = set(store.get(db, "notify.dast_due_last") or [])
        new = [a for a in due if a["key"] not in told]
        # Remembered either way, so an application that was tested and then
        # became due again is new again.
        store.set_value(db, "notify.dast_due_last", [a["key"] for a in due],
                        "scheduler")
        if not new:
            return
        title, lines = message(due, new)
        root = notify.base_url(db)
        link = f"{root}/blast-radius/web-apps?due=1" if root else ""
        sent = notify._fan_out(db, title, lines, link,
                               {"kind": "dast_due",
                                "applications": [
                                    {"name": a["name"], "urls": a["urls"],
                                     "reasons": a["due"]["reasons"]}
                                    for a in new]})
        if store.get(db, "notify.dast_due_owners"):
            # One message per application, to its own owners, leaving out
            # anybody who already got the full list.
            already = set(notify.recipients(db))
            for app in new:
                to = [x for x in app["owners"] + app["technical"]
                      if tagging.ADDRESS.match(x) and x not in already]
                if not to:
                    continue
                lines = [f"{app['name']} is due for a dynamic scan or "
                         f"penetration test: {'; '.join(app['due']['reasons'])}."]
                if app["urls"]:
                    lines.append("Served at " + ", ".join(app["urls"][:5]) + ".")
                lines.append("Changed means a commit on the default branch, "
                             "not a deployment.")
                result = notify._mail(db, f"{app['name']} is due for testing",
                                      lines, link, None, to)
                sent[f"owners of {app['name']}"] = all(result.values())
        record(db, "notifications.dast_due", actor="scheduler",
               detail="%d newly due, %d due; %s" % (
                   len(new), len(due),
                   ", ".join(f"{k}: {'ok' if v else 'failed'}"
                             for k, v in sorted(sent.items())) or "nothing sent"),
               outcome="ok" if not sent or all(sent.values()) else "warn")
