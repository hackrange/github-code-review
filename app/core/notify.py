"""Telling somebody, without waiting for them to log in.

Scans run overnight and the results sit in a web page.  The most urgent thing
this tool produces is a credential the issuing provider has confirmed still
works, and the response time to it is however long it takes somebody to visit
the site.

Four ways out, which between them cover nearly every installation: a Slack
incoming webhook, a Teams incoming webhook, an SMTP sender, and a plain
outbound webhook for everyone else.

Three rules decide what actually gets sent, and they matter more than the
transports:

  New findings only.  Every finding carries `first_found_at`, so this is
  already answerable.  A nightly message about the standing backlog trains
  people to filter the sender, which is strictly worse than sending nothing.

  Routed by severity, not by volume.  A verified credential and a critical on
  the KEV list go out on their own because somebody should stop what they are
  doing.  Everything else is one digest at the end of the scan.

  Never the secret.  A message leaves this system and lands somewhere with a
  different set of readers than the web page has.  What goes in it is the
  redacted preview and a link, the same as the report files.

Worth being explicit, because it looks like it cuts across the read only
promise and does not: that promise is about the repositories being scanned.
Every provider call is a GET and nothing here can change a customer's code.
Sending a message outward is not a write to a repository.
"""

from __future__ import annotations

import json
import logging
import smtplib
import ssl
import urllib.error
import urllib.request
from datetime import datetime, timezone
from email.message import EmailMessage

from app.core import settings_store as store

log = logging.getLogger("gcr.notify")

# How long any one send gets.  A webhook nobody is listening to must not hold a
# scan open.
TIMEOUT = 15

# What counts as worth interrupting somebody for.
URGENT_REASONS = (
    ("verified", "a credential the provider confirmed still works"),
    ("known_exploited", "on the CISA list of vulnerabilities being exploited"),
    ("malicious", "a package that is itself the attack"),
)


def _enum(value):
    return getattr(value, "value", value) or ""


def enabled(session) -> bool:
    return bool(store.get(session, "notify.enabled"))


def _targets(session) -> dict:
    return {
        "slack": (store.get(session, "notify.slack_webhook") or "").strip(),
        "teams": (store.get(session, "notify.teams_webhook") or "").strip(),
        "webhook": (store.get(session, "notify.webhook_url") or "").strip(),
        "email": (store.get(session, "notify.email_to") or "").strip(),
    }


def _min_rank(session) -> int:
    order = ["info", "low", "medium", "high", "critical"]
    wanted = (store.get(session, "notify.min_severity") or "high").lower()
    return order.index(wanted) if wanted in order else 3


def _rank(severity) -> int:
    order = ["info", "low", "medium", "high", "critical"]
    value = _enum(severity).lower()
    return order.index(value) if value in order else 0


def is_urgent(finding) -> str:
    """-> why this one should not wait for the digest, or "" if it can."""
    for attribute, why in URGENT_REASONS:
        if getattr(finding, attribute, False):
            return why
    return ""


def base_url(session) -> str:
    return (store.get(session, "notify.base_url") or "").strip().rstrip("/")


def _link(session, finding) -> str:
    root = base_url(session)
    return f"{root}/findings/{finding.id}" if root else ""


def describe(finding) -> str:
    """One line, and never the secret itself."""
    what = (finding.rule or finding.vulnerability_id or "a finding").strip()
    where = (finding.repository or "").strip()
    at = (finding.file_path or "").strip()
    line = f"{_enum(finding.severity).upper()}  {what}  in {where}"
    if at:
        line += f" at {at}"
        if finding.line:
            line += f":{finding.line}"
    if finding.secret_preview:
        # The mask, which is what the report files carry.  The value itself
        # never leaves the scan and must not start here.
        line += f"  [{finding.secret_preview}]"
    return line


# --- the transports ---------------------------------------------------------
class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Follow nothing.

    The address is checked when it is saved: https, and not the link-local
    range where the cloud metadata service lives.  A redirect would walk
    straight around that check, and there is no legitimate incoming webhook
    that needs one.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def _post_json(url: str, payload: dict) -> bool:
    body = json.dumps(payload).encode()
    request = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json",
                 "User-Agent": "git-code-review"})
    try:
        with _OPENER.open(request, timeout=TIMEOUT) as response:
            return 200 <= response.status < 300
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("could not post to %s: %s", _safe(url), exc)
        return False


def _safe(url: str) -> str:
    """A webhook URL is a credential.  Never log the whole thing."""
    if "://" not in url:
        return "the configured endpoint"
    scheme, rest = url.split("://", 1)
    host = rest.split("/", 1)[0]
    return f"{scheme}://{host}/..."


def send_slack(url: str, title: str, lines: list, link: str = "") -> bool:
    text = f"*{title}*\n" + "\n".join(f"• {line}" for line in lines[:20])
    if len(lines) > 20:
        text += f"\n_and {len(lines) - 20} more_"
    if link:
        text += f"\n{link}"
    return _post_json(url, {"text": text})


def send_teams(url: str, title: str, lines: list, link: str = "") -> bool:
    # The legacy MessageCard, on purpose.  Every Teams incoming webhook
    # accepts it, including the ones created years ago, and an Adaptive Card
    # posted to one of those is rejected with a 400 nobody can read.
    body = "\n\n".join(lines[:20])
    if len(lines) > 20:
        body += f"\n\nand {len(lines) - 20} more"
    payload = {
        "@type": "MessageCard",
        "@context": "https://schema.org/extensions",
        "summary": title,
        "themeColor": "D93F0B",
        "title": title,
        "text": body,
    }
    if link:
        payload["potentialAction"] = [{
            "@type": "OpenUri", "name": "Open it",
            "targets": [{"os": "default", "uri": link}]}]
    return _post_json(url, payload)


def send_webhook(url: str, title: str, lines: list, extra: dict = None) -> bool:
    payload = {"title": title, "lines": lines,
               "generated_at": datetime.now(timezone.utc).strftime(
                   "%Y-%m-%dT%H:%M:%SZ")}
    payload.update(extra or {})
    return _post_json(url, payload)


# Microsoft's own endpoints, not anything a person types.  That matters: every
# other address this server fetches goes through clean_remote_url, and these
# are constants here precisely so there is nothing to check.
GRAPH_LOGIN = "https://login.microsoftonline.com"
GRAPH_API = "https://graph.microsoft.com/v1.0"


def _graph_token(tenant: str, client_id: str, secret: str) -> str:
    """A token for the app registration.  -> the token, or "" with a reason logged.

    Client credentials, which is the flow for an application acting as itself
    rather than on behalf of a person.  There is no refresh token and no user
    interaction; the secret is the credential.
    """
    import urllib.parse

    body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": secret,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    request = urllib.request.Request(
        f"{GRAPH_LOGIN}/{urllib.parse.quote(tenant)}/oauth2/v2.0/token",
        data=body, method="POST",
        headers={"Content-Type": "application/x-www-form-urlencoded"})
    try:
        with _OPENER.open(request, timeout=TIMEOUT) as response:
            payload = json.loads(response.read().decode("utf-8", "replace"))
        return payload.get("access_token") or ""
    except urllib.error.HTTPError as exc:
        # The body says which of the three fields is wrong, and that is the
        # whole question when this does not work.  It carries no secret.
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8", "replace")).get(
                "error_description", "")[:300]
        except Exception:            # noqa: BLE001
            pass
        log.warning("Microsoft refused the app registration: %s %s",
                    exc.code, detail)
        return ""
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("could not reach Microsoft to get a token: %s", exc)
        return ""


def send_graph(session, subject: str, body: str) -> bool:
    """Send through Microsoft 365, as the mailbox the app registration owns.

    For tenants with basic authentication switched off, which have no SMTP to
    offer at all.  saveToSentItems is false: this is a notification, and
    filling somebody's Sent Items with them helps nobody.
    """
    import urllib.parse

    tenant = (store.get(session, "notify.graph_tenant") or "").strip()
    client = (store.get(session, "notify.graph_client_id") or "").strip()
    secret = store.get(session, "notify.graph_secret") or ""
    sender = (store.get(session, "notify.graph_sender") or "").strip()
    to = (store.get(session, "notify.email_to") or "").strip()

    if not (tenant and client and secret and sender and to):
        log.warning("Microsoft 365 mail is selected but not fully configured")
        return False

    token = _graph_token(tenant, client, secret)
    if not token:
        return False

    recipients = [{"emailAddress": {"address": part.strip()}}
                  for part in to.split(",") if part.strip()]
    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "Text", "content": body},
            "toRecipients": recipients,
        },
        "saveToSentItems": False,
    }
    request = urllib.request.Request(
        f"{GRAPH_API}/users/{urllib.parse.quote(sender)}/sendMail",
        data=json.dumps(payload).encode(), method="POST",
        headers={"Content-Type": "application/json",
                 "Authorization": f"Bearer {token}"})
    try:
        with _OPENER.open(request, timeout=TIMEOUT) as response:
            # sendMail answers 202 with no body when it has accepted it.
            return 200 <= response.status < 300
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = json.loads(exc.read().decode("utf-8", "replace")).get(
                "error", {}).get("message", "")[:300]
        except Exception:            # noqa: BLE001
            pass
        log.warning("Microsoft would not send the message: %s %s", exc.code, detail)
        return False
    except (urllib.error.URLError, OSError, ValueError) as exc:
        log.warning("could not reach Microsoft to send: %s", exc)
        return False


def send_email(session, subject: str, body: str) -> bool:
    host = (store.get(session, "notify.smtp_host") or "").strip()
    to = (store.get(session, "notify.email_to") or "").strip()
    if not host or not to:
        return False

    try:
        port = int(store.get(session, "notify.smtp_port") or 587)
    except (TypeError, ValueError):
        port = 587
    sender = (store.get(session, "notify.email_from") or "").strip() or to.split(",")[0].strip()
    username = (store.get(session, "notify.smtp_user") or "").strip()
    password = store.get(session, "notify.smtp_password") or ""
    mode = (store.get(session, "notify.smtp_security") or "starttls").lower()

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = sender
    message["To"] = ", ".join(part.strip() for part in to.split(",") if part.strip())
    message.set_content(body)

    try:
        if mode == "ssl":
            server = smtplib.SMTP_SSL(host, port, timeout=TIMEOUT,
                                      context=ssl.create_default_context())
        else:
            server = smtplib.SMTP(host, port, timeout=TIMEOUT)
        with server:
            server.ehlo()
            if mode == "starttls":
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
            if username:
                server.login(username, password)
            server.send_message(message)
        return True
    except (smtplib.SMTPException, OSError, ssl.SSLError) as exc:
        log.warning("could not send mail through %s: %s", host, exc)
        return False


# --- what to send -----------------------------------------------------------
def _fan_out(session, title: str, lines: list, link: str = "",
             extra: dict = None) -> dict:
    """Every configured way out, and which of them worked.

    One failing transport never stops the others: an expired Slack webhook must
    not be the reason nobody got the email.
    """
    targets = _targets(session)
    sent = {}
    if targets["slack"]:
        sent["slack"] = send_slack(targets["slack"], title, lines, link)
    if targets["teams"]:
        sent["teams"] = send_teams(targets["teams"], title, lines, link)
    if targets["webhook"]:
        sent["webhook"] = send_webhook(targets["webhook"], title, lines, extra)
    if targets["email"]:
        body = title + "\n\n" + "\n".join(lines)
        if link:
            body += f"\n\n{link}\n"
        transport = (store.get(session, "notify.mail_transport") or "smtp").lower()
        if transport == "graph":
            sent["microsoft 365"] = send_graph(session, title, body)
        else:
            sent["email"] = send_email(session, title, body)
    return sent


def notify_urgent(session, finding, why: str) -> dict:
    """One finding somebody should stop what they are doing for."""
    if not enabled(session):
        return {}
    title = f"{_enum(finding.severity).upper()}: {why}"
    return _fan_out(session, title, [describe(finding)],
                    _link(session, finding),
                    {"kind": "urgent", "vuln_id": finding.vuln_id or "",
                     "reason": why})


def notify_digest(session, findings: list, scan_label: str = "") -> dict:
    """Everything else this scan found that was not there before."""
    if not enabled(session) or not findings:
        return {}
    counts = {}
    for finding in findings:
        key = _enum(finding.severity)
        counts[key] = counts.get(key, 0) + 1
    summary = ", ".join(f"{count} {name}" for name, count in
                        sorted(counts.items(), key=lambda kv: -_rank(kv[0])))
    title = f"{len(findings)} new finding(s): {summary}"
    if scan_label:
        title += f" ({scan_label})"

    ordered = sorted(findings, key=lambda f: -_rank(f.severity))
    lines = [describe(finding) for finding in ordered]
    root = base_url(session)
    return _fan_out(session, title, lines,
                    f"{root}/findings" if root else "",
                    {"kind": "digest", "counts": counts})


def announce(session, findings: list, scan_label: str = "") -> dict:
    """What a finished scan sends, in the order it should arrive.

    Urgent items go on their own so they are not buried in a list, and are then
    left out of the digest so nobody reads the same finding twice and assumes
    there were two.
    """
    if not enabled(session):
        return {"sent": False, "reason": "notifications are off"}

    floor = _min_rank(session)
    urgent, rest = [], []
    for finding in findings:
        why = is_urgent(finding)
        if why:
            urgent.append((finding, why))
        elif _rank(finding.severity) >= floor:
            rest.append(finding)

    results = {"urgent": 0, "digest": 0}
    for finding, why in urgent[:25]:
        notify_urgent(session, finding, why)
        results["urgent"] += 1
    if rest:
        notify_digest(session, rest, scan_label)
        results["digest"] = len(rest)
    return results


def test_message(session) -> dict:
    """Prove the wiring, from the page, before anybody relies on it."""
    return _fan_out(
        session, "Git Code Review: a test message",
        ["This confirms the notification settings work.",
         "No findings are attached to it."],
        base_url(session))
