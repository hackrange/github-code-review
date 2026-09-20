"""The app itself.

Boots the database, wires the routes, and starts the scheduler.  Keep this
file thin.  Anything with real logic in it belongs in app/core or app/web.
"""

from __future__ import annotations

import logging
import os
import sys

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles

from app.config import APP_NAME, VERSION, settings
from app.core import live
from app.core.db import init_db

log = logging.getLogger("gcr")


def _configure_logging() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s %(name)s  %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%SZ",
        stream=sys.stdout,
    )
    # The scheduler logs every run of every job at INFO.  With the utilization
    # sample every five seconds that was two lines every five seconds, tens of
    # thousands a day, burying the lines anybody reads the log for.  A job that
    # fails is still logged, at ERROR, and a schedule firing is logged by
    # gcr.scheduler itself.
    logging.getLogger("apscheduler.executors").setLevel(logging.WARNING)
    logging.getLogger("apscheduler.scheduler").setLevel(logging.WARNING)


def create_app() -> FastAPI:
    _configure_logging()

    problems = settings.auth.problems()
    if problems:
        # This is the environment, checked before there is a database to ask.
        # Better to refuse to start than to come up with an auth mode that
        # cannot actually let anybody in.
        for line in problems:
            log.error("configuration: %s", line)
        raise SystemExit(2)

    app = FastAPI(
        title=APP_NAME,
        version=VERSION,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    from app.web.security import (ImpersonationIsReadOnlyMiddleware,
                                  RateLimitMiddleware,
                                  SecurityHeadersMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    # Before the routes and after the rate limiter: a borrowed view may read
    # anything the borrowed account can read, and write nothing at all.
    app.add_middleware(ImpersonationIsReadOnlyMiddleware)
    app.add_middleware(RateLimitMiddleware,
                       general=settings.rate_limit_general,
                       auth=settings.rate_limit_auth,
                       window=settings.rate_limit_window)

    @app.on_event("startup")
    def _startup() -> None:
        init_db()

        # Now there is a database, so the sign in settings may come from it
        # rather than from the environment.  A bad one here gets a loud warning
        # and not an exit, because an admin who saves something wrong on the
        # Settings page should still be able to get back in and fix it.
        live.invalidate()
        for line in live.auth_config().problems():
            log.warning("sign in settings: %s", line)

        # A restart kills whatever was scanning, and a row left saying
        # "running" makes the Scans page lie and blocks the next scan.
        from app.core.db import session_scope as _scope
        from app.core.models import ScanRun, utcnow as _now
        with _scope() as db:
            stale = db.query(ScanRun).filter(ScanRun.status == "running").all()
            for run in stale:
                run.status = "interrupted"
                run.finished_at = _now()
            if stale:
                log.warning("%d scan(s) were running when this last stopped, "
                            "marked interrupted", len(stale))

        # Whatever those runs had already finished.  The findings are on disk,
        # one file per repository, written as each one completed; a container
        # recreated mid scan runs none of the in process handlers, so this is
        # the only thing standing between ninety minutes of work and nothing.
        # Before the sweep below, because that clears the work area.
        try:
            from app.core import scanner as _scanner
            from app.core.db import session_scope as _s
            from app.core import settings_store as _store
            with _s() as db:
                _scanner.set_concurrency(_store.get(db, "scan.max_concurrent") or 1)
        except Exception:            # noqa: BLE001
            log.warning("could not read the scan limit", exc_info=True)

        try:
            from app.core.scanner import salvage_interrupted
            salvage_interrupted()
        except Exception:            # noqa: BLE001 - never stop the app booting
            log.warning("could not salvage interrupted scans", exc_info=True)

        # And the clones that scan was holding.  A killed process never gets to
        # the end of the block that would have removed them, so they sit in the
        # work area until something clears them.  Nothing can be using them
        # here: no scan runs in a process that has not finished starting.
        try:
            from app.core.scanner import sweep_orphans
            orphaned = sweep_orphans()
            if orphaned:
                log.warning("cleared %d leftover scan work director%s",
                            orphaned, "y" if orphaned == 1 else "ies")
        except Exception as exc:
            log.warning("could not sweep leftover scan directories: %s", exc)

        # An install that predates connections has one credential in the
        # settings.  Turn it into the first connection so nothing stops working.
        try:
            from app.core import connections as connection_store
            with _scope() as db:
                if connection_store.adopt_settings(db):
                    log.info("made the first connection from the existing settings")
        except Exception as exc:
            log.warning("could not adopt the existing credential: %s", exc)

        from app.auth.service import ensure_bootstrap_admin
        from app.core.db import session_scope
        with session_scope() as db:
            created = ensure_bootstrap_admin(db)
        if created:
            # The password is not written here, and the comment that used to
            # say it was printed once and stored nowhere else was wrong: a log
            # is somewhere else, and a worse one than the file.
            #
            # ensure_bootstrap_admin writes it to first-admin.txt at mode 600
            # and the application deletes that file the moment the account
            # changes its password.  The log has none of those properties.  It
            # is kept for the life of the container, it survives the password
            # being changed, and anybody who can read container logs can read
            # it, which on most installations is more people than can read the
            # data directory.
            #
            # Found by this scanner, on this file.  The rule was right.
            log.warning("")
            log.warning("  FIRST ADMIN")
            log.warning("    username: %s", created["username"])
            log.warning("    password: written to %s, mode 600",
                        created.get("path") or "first-admin.txt in the data directory")
            log.warning("    Change it at first sign in.  That deletes the file.")
            log.warning("")

        # Cron for scans and for refreshing the vulnerability feeds.  Off
        # when GCR_SCHEDULER is set to anything falsy, which the tests use.
        if os.environ.get("GCR_SCHEDULER", "1").lower() not in {"0", "false", "no"}:
            try:
                from app.core import scheduler
                scheduler.start()
            except Exception as exc:
                log.error("could not start the scheduler: %s", exc)

        log.info("%s %s ready, auth mode %s", APP_NAME, VERSION,
                 live.auth_config().mode)
        from app.core.scanner import _report_directory, reports_writable
        ok, problem = reports_writable()
        if ok:
            log.info("reports go to %s", _report_directory())
        else:
            log.warning("")
            log.warning("  THE REPORTS DIRECTORY IS NOT WRITABLE")
            log.warning("    %s", problem)
            log.warning("    Scans will still run and findings will still be")
            log.warning("    saved, but the two report files cannot be written.")
            log.warning("")

    @app.on_event("shutdown")
    def _shutdown() -> None:
        try:
            from app.core import scheduler
            scheduler.shutdown()
        except Exception:
            pass

    @app.get("/healthz", include_in_schema=False)
    def healthz() -> PlainTextResponse:
        """Used by the container health check.  No auth, no database."""
        return PlainTextResponse("ok")

    @app.get("/readyz", include_in_schema=False)
    def readyz() -> JSONResponse:
        """Deeper than healthz.  Says whether the database answers.

        Neither of these asks who is calling, because a balancer cannot sign
        in, so what they say back goes to anybody who can reach the port.  The
        status is the whole answer.  The version used to ride along in it,
        which told a stranger what this is and which release it is running
        before they had done anything at all, and the failure used to carry the
        exception text, which is where the driver, the host and the schema name
        live.  Both now go to the log, where the person running this can read
        them and nobody else can.
        """
        from sqlalchemy import text
        from app.core.db import session_scope
        try:
            with session_scope() as session:
                session.execute(text("SELECT 1"))
            return JSONResponse({"status": "ready"})
        except Exception as exc:
            log.warning("readiness check failed: %s", exc)
            return JSONResponse({"status": "degraded"}, status_code=503)

    try:
        from pathlib import Path
        web_static = Path(__file__).resolve().parent / "web" / "static"
        if web_static.is_dir():
            app.mount(f"{settings.base_path}/static",
                      StaticFiles(directory=str(web_static)), name="static")
    except Exception as exc:
        log.warning("static files not mounted: %s", exc)

    from fastapi.responses import RedirectResponse
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.exception_handler(StarletteHTTPException)
    async def _errors(request, exc):
        """Say what went wrong, on the page they were already looking at.

        A form that answers with a plain 400 loses everything somebody typed
        and tells them nothing they can act on.  For a browser posting a form
        we send them back where they came from with the reason in the banner
        at the top.  Anything else still gets the status and the text.
        """
        from urllib.parse import quote

        location = (exc.headers or {}).get("Location") if exc.headers else None
        if exc.status_code == 307 and location:
            return RedirectResponse(location, status_code=303)

        wants_html = "text/html" in (request.headers.get("accept") or "")
        came_from = request.headers.get("referer") or ""
        if (request.method == "POST" and wants_html and came_from
                and exc.status_code in (400, 403, 404, 409)):
            detail = str(exc.detail or "That did not work.")
            joiner = "&" if "?" in came_from else "?"
            return RedirectResponse(
                f"{came_from}{joiner}msg={quote(detail[:300])}&kind=error",
                status_code=303)

        if exc.status_code == 404:
            return PlainTextResponse("Not found.\n", status_code=404)
        return PlainTextResponse(f"{exc.detail}\n", status_code=exc.status_code)

    _attach_routes(app)
    return app


def _attach_routes(app: FastAPI) -> None:
    """Bring in the page and API routers once they are present.

    They are being built out.  Until a router exists the app still boots and
    answers the health checks, which is what the container needs.
    """
    attached = 0
    for module_name, attr in (
        ("app.web.routes_auth", "router"),
        ("app.web.routes_pages", "router"),
        ("app.web.routes_api", "router"),
        ("app.web.routes_api_v1", "router"),
    ):
        try:
            module = __import__(module_name, fromlist=[attr])
        except ModuleNotFoundError:
            continue
        router = getattr(module, attr, None)
        if router is not None:
            app.include_router(router)
            attached += 1

    if attached == 0:
        @app.get("/", include_in_schema=False)
        def _placeholder(request: Request) -> PlainTextResponse:
            return PlainTextResponse(
                f"{APP_NAME} {VERSION} is running.  The web interface is not "
                "installed in this build.\n",
                status_code=503,
            )
    log.info("attached %d router(s)", attached)


app = create_app()
