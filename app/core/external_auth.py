"""Signing in to a site for a dynamic scan.

Three ways, set per site and stored encrypted:

    header   one header on every request, usually Authorization: Bearer ...
    cookie   a session cookie copied from a browser that is signed in, which
             is the way through single sign on
    form     a login page, a user name and a password

For a form, this signs in once before the engines start: it reads the login
page, keeps the hidden fields such as a CSRF token, posts the credentials,
and hands the session cookie it gets back to every engine.  wapiti is also
given the form itself so it can sign in again if the session drops.

The secrets never leave this module in the clear except into an engine's
command line and the login request.  Everything a scan stores goes through
redact() first, so a session cookie an engine echoed back in its evidence is
not kept in the findings, the JSON, the PDF or the log.
"""

from __future__ import annotations

import base64
import json
import re
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

KINDS = {"": "Not signed in", "header": "Header", "cookie": "Session cookie",
         "form": "Form login", "recorded": "Recorded in a browser"}
# The kinds a person can type into the site's form.  A recorded sign in only
# comes from Record a session, so the form can keep it but never make one.
FORM_KINDS = {k: v for k, v in KINDS.items() if k != "recorded"}
_HEADER_NAME = re.compile(r"^[A-Za-z0-9!#$%&'*+.^_`|~-]{1,100}$")
_FIELD_NAME = re.compile(r"^[A-Za-z0-9_.\[\]:-]{1,100}$")


# ------------------------------------------------------------------ storage

def _encrypt(data: dict) -> str:
    from app.core import settings_store as store

    return store._encrypt(json.dumps(data)) if data else ""


# The two sign in slots: a is the main account, b is the second account used by
# the checks that compare what one account can reach against another.
_SLOTS = {"a": ("auth_kind", "auth_data", "auth_set_by", "auth_set_at"),
          "b": ("auth_kind_b", "auth_data_b", "auth_set_by_b", "auth_set_at_b")}


def load(asset, slot: str = "a") -> dict:
    """A site's sign in, decrypted.  {} when there is none or it cannot be read."""
    from app.core import settings_store as store

    kind_attr, data_attr = _SLOTS[slot][0], _SLOTS[slot][1]
    kind, blob = getattr(asset, kind_attr, ""), getattr(asset, data_attr, "")
    if not kind or not blob:
        return {}
    try:
        data = json.loads(store._decrypt(blob) or "{}")
    except Exception:  # noqa: BLE001 - a key change makes it unreadable, not fatal
        return {}
    data["kind"] = kind
    # Which site this is, so a sign in can check the certificate it sends the
    # credentials over.  Never saved: load() adds them each time.
    data["_asset_id"] = getattr(asset, "id", None)
    data["_host"] = getattr(asset, "host", "") or ""
    return data


def load_b(asset) -> dict:
    """The second account's sign in, decrypted."""
    return load(asset, "b")


def describe(asset, slot: str = "a") -> dict:
    """What the page and the API may show: never a secret.  {} when none."""
    data = load(asset, slot)
    if not data:
        return {}
    by_attr, at_attr = _SLOTS[slot][2], _SLOTS[slot][3]
    set_at = getattr(asset, at_attr, None)
    out = {"kind": data["kind"], "kind_name": KINDS.get(data["kind"], data["kind"]),
           "set_by": getattr(asset, by_attr, "") or "",
           "set_at": set_at.isoformat() if set_at else None,
           "intent": data.get("intent", "")}
    if data["kind"] == "header":
        out["header_name"] = data.get("header_name", "")
    elif data["kind"] == "cookie":
        out["cookie_names"] = [p.split("=", 1)[0].strip()
                               for p in data.get("cookie", "").split(";") if "=" in p]
    elif data["kind"] == "form":
        out.update(login_url=data.get("login_url", ""), username=data.get("username", ""),
                   username_field=data.get("username_field", ""),
                   password_field=data.get("password_field", ""))
    elif data["kind"] == "recorded":
        from app.core import session_recorder

        steps = data.get("steps") or []
        out.update(cookie_names=[p.split("=", 1)[0].strip()
                                 for p in data.get("cookie", "").split(";") if "=" in p],
                   recorded_at=data.get("recorded_at", ""),
                   steps=session_recorder.public_steps(steps),
                   replayable=bool(steps) and not any(s.get("human") for s in steps),
                   has_totp=bool(data.get("totp_secret")))
    return out


def _clean_line(value: str, what: str, limit: int = 8000) -> str:
    text = str(value or "").strip()
    if "\r" in text or "\n" in text or "\x00" in text:
        raise ValueError(f"{what} has to be one line.")
    if len(text) > limit:
        raise ValueError(f"{what} is too long.")
    return text


def save(asset, kind: str, values: dict, actor: str, parent_domain: str = "",
         slot: str = "a") -> None:
    """Set or clear a site's sign in.  A secret left empty keeps the saved one.

    slot a is the main account, slot b the second account for the compare
    checks.  Raises ValueError with a sentence when something will not do.
    """
    from app.core.models import utcnow

    kind_attr, data_attr, by_attr, at_attr = _SLOTS[slot]
    kind = (kind or "").strip().lower()
    if kind not in KINDS:
        raise ValueError("Sign in is none, header, cookie or form.")
    if not kind:
        setattr(asset, kind_attr, "")
        setattr(asset, data_attr, "")
        setattr(asset, by_attr, (actor or "")[:120])
        setattr(asset, at_attr, utcnow())
        return
    old = load(asset, slot) if getattr(asset, kind_attr) == kind else {}
    data = {}
    if kind == "recorded":
        # Only Record a session makes one.  The site's form keeps it as it is,
        # so saving the form for another reason does not lose the recording.
        if not old:
            raise ValueError("Use Record a session to sign in through a browser.")
        data = {k: v for k, v in old.items() if not k.startswith("_") and k != "kind"}
    elif kind == "header":
        name = _clean_line(values.get("header_name") or old.get("header_name") or "", "Header name", 100)
        if not _HEADER_NAME.fullmatch(name):
            raise ValueError("Give the header's name, such as Authorization.")
        if name.lower() in ("host", "content-length", "transfer-encoding", "connection"):
            raise ValueError(f"{name} cannot be set for a scan.")
        value = _clean_line(values.get("header_value") or "", "Header value") or old.get("header_value", "")
        if not value:
            raise ValueError("Give the header's value, such as Bearer and the token.")
        data = {"header_name": name, "header_value": value}
    elif kind == "cookie":
        cookie = _clean_line(values.get("cookie") or "", "Cookie") or old.get("cookie", "")
        cookie = re.sub(r"^cookie:\s*", "", cookie, flags=re.I)
        parts = [p.strip() for p in cookie.split(";") if p.strip()]
        if not parts or not all("=" in p and p.split("=", 1)[0].strip() for p in parts):
            raise ValueError("Paste the cookie as name=value, separated by semicolons.")
        data = {"cookie": "; ".join(parts)}
    elif kind == "form":
        login_url = _clean_line(values.get("login_url") or old.get("login_url") or "", "Login page", 1000)
        parsed = urlparse(login_url)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username:
            raise ValueError("The login page has to be an http or https address.")
        host = parsed.hostname.lower()
        if parent_domain and not (host == parent_domain or host.endswith("." + parent_domain)):
            raise ValueError(f"The login page has to be on {parent_domain}, so the password is "
                             "only ever sent to the site itself.  For single sign on, use a "
                             "session cookie.")
        username = _clean_line(values.get("username") or old.get("username") or "", "User name", 300)
        password = _clean_line(values.get("password") or "", "Password", 1000) or old.get("password", "")
        if not username or not password:
            raise ValueError("A form login needs a user name and a password.")
        data = {"login_url": login_url, "username": username, "password": password}
        for key, what in (("username_field", "User name field"), ("password_field", "Password field")):
            field = _clean_line(values.get(key) or "", what, 100)
            if field and not _FIELD_NAME.fullmatch(field):
                raise ValueError(f"{what} is the name of the form field, such as email.")
            if field:
                data[key] = field
    # What this login is meant to be able to do, and not do.  Free text, not a
    # secret: it is the intended authorization policy for the account, which the
    # compare checks and the review weigh a cross account read against.  Kept
    # across a change of sign in kind, since it describes the account, not how
    # it signs in.
    prior = load(asset, slot)
    new_intent = str(values.get("intent") or "").strip()[:2000]
    intent = new_intent or prior.get("intent", "")
    if intent:
        data["intent"] = intent
    setattr(asset, kind_attr, kind)
    setattr(asset, data_attr, _encrypt(data))
    setattr(asset, by_attr, (actor or "")[:120])
    setattr(asset, at_attr, utcnow())


def save_recorded(asset, recording: dict, actor: str, start_url: str,
                  slot: str = "a") -> None:
    """Keep what Record a session captured as the site's sign in."""
    from app.core import session_recorder
    from app.core.models import utcnow

    kind_attr, data_attr, by_attr, at_attr = _SLOTS[slot]
    steps = recording.get("steps") or []
    data = {"cookie": session_recorder.cookie_header(recording.get("cookies") or []),
            "user_agent": str(recording.get("user_agent") or "")[:500],
            "steps": steps, "start_url": start_url[:1000],
            "final_url": str(recording.get("final_url") or "")[:1000],
            "recorded_at": utcnow().isoformat()}
    if recording.get("totp_secret"):
        data["totp_secret"] = recording["totp_secret"]
    prior = load(asset, slot)
    if prior.get("intent"):
        data["intent"] = prior["intent"]
    setattr(asset, kind_attr, "recorded")
    setattr(asset, data_attr, _encrypt(data))
    setattr(asset, by_attr, (actor or "")[:120])
    setattr(asset, at_attr, utcnow())


def check_live(data: dict, cookie: str, allow_private: bool = False) -> tuple:
    """Whether a recorded session still gets past the site's front door.
    -> (ok, a sentence).  A bot check answering, or the sign in page coming
    back, means the scan would see only that, so it is said plainly."""
    from app.core import external_probe

    # The page the recording ended on, when it is the site's own: a sign in
    # start page can show its form whether or not the session is good.
    final = data.get("final_url") or ""
    host = (data.get("_host") or "").lower()
    final_host = (urlparse(final).hostname or "").lower()
    url = (final if final_host and host and (final_host == host or final_host.endswith("." + host))
           else data.get("start_url") or (f"https://{host}/" if host else ""))
    if not url:
        return True, ""
    headers = {"Cookie": cookie}
    if data.get("user_agent"):
        headers["User-Agent"] = data["user_agent"]
    got = external_probe.fetch(url, headers=headers, allow_private=allow_private)
    if got.get("error") and not got.get("status"):
        return False, f"the site did not answer: {str(got['error'])[:100]}"
    body = got.get("body") or ""
    check = external_probe.bot_check(body, got.get("status") or 0)
    if check:
        return False, (f"{check}'s bot check answers instead of the site, so the recorded "
                       "pass has expired or is tied to something the scan cannot repeat")
    if _login_form(body) is not None and (data.get("final_url") or "") != (got.get("final_url") or ""):
        return False, "the sign in page comes back, so the recorded session has ended"
    return True, ""


# ------------------------------------------------------------------ secrets

def secrets_of(data: dict, session_cookie: str = "") -> list:
    """Every value that must not be stored, longest first."""
    out = []
    if data.get("header_value"):
        value = data["header_value"]
        out.append(value)
        # The token without its scheme, as an engine might print it.
        if " " in value:
            out.append(value.split(" ", 1)[1])
    for cookie in (data.get("cookie", ""), session_cookie):
        for part in (cookie or "").split(";"):
            if "=" in part:
                value = part.split("=", 1)[1].strip()
                if value:
                    out.append(value)
    if data.get("password"):
        out.append(data["password"])
    for step in data.get("steps") or []:
        if step.get("secret") and step.get("text"):
            out.append(step["text"])
    if data.get("totp_secret"):
        out.append(data["totp_secret"])
    if data.get("kind") == "header" and data.get("header_value", "").lower().startswith("basic "):
        try:
            pair = base64.b64decode(data["header_value"].split(" ", 1)[1]).decode()
            out.append(pair.split(":", 1)[-1])
        except Exception:  # noqa: BLE001
            pass
    return sorted({s for s in out if len(s) >= 4}, key=len, reverse=True)


def redact(value, secrets: list):
    """The same value with every secret replaced, through lists and dicts."""
    if not secrets:
        return value
    if isinstance(value, str):
        for secret in secrets:
            if secret in value:
                value = value.replace(secret, "[redacted]")
        return value
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, dict):
        return {k: redact(v, secrets) for k, v in value.items()}
    return value


# ------------------------------------------------------------------ form login

class _Forms(HTMLParser):
    def __init__(self):
        super().__init__()
        self.forms, self._form = [], None

    def handle_starttag(self, tag, attrs):
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(),
                          "inputs": []}
            self.forms.append(self._form)
        elif tag == "input" and self._form is not None and a.get("name"):
            self._form["inputs"].append({"name": a["name"], "type": (a.get("type") or "text").lower(),
                                         "value": a.get("value", "")})

    def handle_endtag(self, tag):
        if tag == "form":
            self._form = None


def _login_form(html: str):
    parser = _Forms()
    try:
        parser.feed(html or "")
    except Exception:  # noqa: BLE001 - broken markup is common
        pass
    for form in parser.forms:
        if any(i["type"] == "password" for i in form["inputs"]):
            return form
    return None


def login(data: dict, allow_private: bool = False) -> dict:
    """Sign in through the login form.  -> {ok, cookie, detail}

    The cookie is every cookie the site set, as one Cookie header value.  ok is
    False with a sentence when the page had no form, the post was refused, or
    the login form came straight back, which is what a wrong password does.
    """
    import httpx

    from app.core import external_probe

    out = {"ok": False, "cookie": "", "detail": ""}
    url = data.get("login_url", "")
    headers = {"User-Agent": external_probe.user_agent(),
               "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}
    try:
        proxy = external_probe.current_proxy()
        checked = {(urlparse(url).hostname or "")}
        # Certificates are not checked by the client: a site's own self signed
        # one is common.  tls_trust has checked or pinned each host instead,
        # in session_for for the first and in go() for any other.
        with httpx.Client(verify=False, timeout=20, follow_redirects=False,  # noqa: S501
                          proxy=proxy or None, trust_env=not proxy) as client:
            def go(method, target, **kw):
                for _hop in range(6):
                    host = urlparse(target).hostname or ""
                    if not allow_private and not external_probe._host_is_public(host):
                        raise ValueError(f"{host} is a private address")
                    # A redirect to another host is checked as the first one was.
                    if host not in checked:
                        from app.core import tls_trust
                        gate = tls_trust.allow(data.get("_asset_id"), target, allow_private)
                        if not gate["ok"]:
                            raise ValueError(gate["detail"])
                        checked.add(host)
                    resp = client.request(method, target, headers=headers, **kw)
                    location = resp.headers.get("location")
                    if 300 <= resp.status_code < 400 and location:
                        target, method, kw = urljoin(target, location), "GET", {}
                        continue
                    return resp, target
                raise ValueError("too many redirects")

            page, page_url = go("GET", url)
            form = _login_form(page.text)
            if form is None:
                out["detail"] = "the login page has no form with a password field"
                return out
            fields = {i["name"]: i["value"] for i in form["inputs"]
                      if i["type"] not in ("submit", "button", "image", "checkbox", "radio")}
            user_field = data.get("username_field") or next(
                (i["name"] for i in form["inputs"]
                 if i["type"] in ("text", "email") and re.search(r"user|mail|login|name|id", i["name"], re.I)),
                next((i["name"] for i in form["inputs"] if i["type"] in ("text", "email")), ""))
            pass_field = data.get("password_field") or next(
                i["name"] for i in form["inputs"] if i["type"] == "password")
            if not user_field:
                out["detail"] = "the login form has no user name field; name it in the sign in settings"
                return out
            fields[user_field] = data.get("username", "")
            fields[pass_field] = data.get("password", "")
            action = urljoin(page_url, form["action"] or page_url)
            from app.core.diagram import registrable

            if registrable(urlparse(action).hostname or "") != registrable(urlparse(url).hostname or ""):
                out["detail"] = "the login form posts to another domain, so the password was not sent"
                return out
            # A form that submits by GET, or names no method, would put the
            # password in the address, where access logs, proxies and history
            # keep it.  The password is not sent that way.
            if form["method"] != "post":
                out["detail"] = ("the login form submits by GET, which would put the "
                                 "password in the address and in every log that keeps "
                                 "one, so the password was not sent")
                return out
            before = {(c.name, c.value) for c in client.cookies.jar}
            result, _final = go("POST", action, data=fields)
            after = {(c.name, c.value) for c in client.cookies.jar}
            jar = "; ".join(f"{c.name}={c.value}" for c in client.cookies.jar)
            # A login that works sets a new session cookie, or changes the one
            # it had.  A wrong password sets nothing new and shows the form
            # again.  Some sites show a login box on every page, so the form
            # coming back alone does not mean it failed.
            fresh = after - before
            if result.status_code >= 400:
                out["detail"] = f"the login was refused with HTTP {result.status_code}"
            elif not fresh and _login_form(result.text) is not None:
                out["detail"] = "the login form came back, so the user name or password is likely wrong"
            elif not jar:
                out["detail"] = "the site set no session cookie"
            elif not fresh:
                out["detail"] = "the site set no new cookie after the login, so it is not clear it worked"
            else:
                out.update(ok=True, cookie=jar, detail="signed in")
    except Exception as exc:  # noqa: BLE001 - a failed login is a result
        out["detail"] = f"the login failed: {type(exc).__name__}: {str(exc)[:120]}"
    return out


# ------------------------------------------------------------------ engines

def session_for(data: dict, allow_private: bool = False) -> dict:
    """What a scan signs in with.  -> {kind, headers: [(name, value)], cookie,
    form: data or None, ok, detail}"""
    out = {"kind": data.get("kind", ""), "headers": [], "cookie": "", "form": None,
           "ok": True, "detail": ""}
    kind = out["kind"]
    # Every credential a scan uses comes through here, for the engines, the
    # scan proxy and the screenshots alike.  A certificate that changed since
    # it was first trusted gets none of them.  See app.core.tls_trust.
    if kind:
        from app.core import tls_trust
        targets = [f"https://{data['_host']}/"] if data.get("_host") else []
        if kind == "form" and data.get("login_url"):
            targets.append(data["login_url"])
        for target in dict.fromkeys(targets):
            gate = tls_trust.allow(data.get("_asset_id"), target, allow_private)
            if not gate["ok"]:
                out.update(ok=False, detail=gate["detail"])
                return out
    if kind == "header":
        out["headers"] = [(data["header_name"], data["header_value"])]
        out["detail"] = f"the {data['header_name']} header"
    elif kind == "cookie":
        out["cookie"] = data["cookie"]
        out["detail"] = "the session cookie"
    elif kind == "form":
        out["form"] = data
        got = login(data, allow_private)
        out["ok"], out["cookie"] = got["ok"], got["cookie"]
        out["detail"] = got["detail"]
    elif kind == "recorded":
        out.update(_recorded_session(data, allow_private))
    return out


def _recorded_session(data: dict, allow_private: bool) -> dict:
    """A recorded sign in for a scan: the steps replayed when they can be,
    else the cookies the recording kept, and either way checked against the
    site before the engines lean on it."""
    from app.core import external_probe, session_recorder

    cookie, how = data.get("cookie", ""), "the recorded session"
    steps = data.get("steps") or []
    if steps and not any(s.get("human") for s in steps):
        from app.core import settings_store
        from app.core.db import session_scope

        with session_scope() as db:
            domains = settings_store.get(db, "web.company_domains") or []
        got = session_recorder.replay(data, allow_private, external_probe.current_proxy(),
                                      domains)
        if got["ok"]:
            cookie, how = got["cookie"], "signed in again by replaying the recorded steps"
        else:
            how = f"the recorded session (replaying the steps failed: {got['detail']})"
    headers = [("User-Agent", data["user_agent"])] if data.get("user_agent") else []
    ok, why = check_live(data, cookie, allow_private)
    return {"cookie": cookie, "headers": headers, "ok": ok,
            "detail": how if ok else f"{why}.  Record the session again from the site page"}


def test_signin(slots: dict, allow_private: bool = False) -> list:
    """Sign in now with each configured account, so an administrator can
    confirm it works before a scan leans on it.  slots is {"a": data, "b":
    data} from load().  -> a list of {slot, label, kind, kind_name,
    configured, live, ok, detail}, in order.

    A form login is signed in for real against the site.  A header or cookie
    is reported as saved, since there is nothing here to sign into; it is sent
    to the engines as given.  The second account's result is here too, which a
    scan runs silently and never shows.
    """
    labels = {"a": "Account A", "b": "Account B (compare account)"}
    out = []
    for slot in ("a", "b"):
        data = slots.get(slot) or {}
        kind = data.get("kind", "")
        row = {"slot": slot, "label": labels[slot], "kind": kind,
               "kind_name": KINDS.get(kind, kind), "configured": bool(kind),
               "live": kind == "form", "ok": False, "detail": ""}
        if not kind:
            out.append(row)
            continue
        if kind in ("form", "recorded"):
            row["live"] = True
            sess = session_for(data, allow_private)
            row["ok"], row["detail"] = sess["ok"], sess["detail"]
        else:
            row["ok"] = True
            row["detail"] = ("saved and sent to the engines as given; there is "
                             "nothing to sign into from here, so it is not tested live")
        out.append(row)
    return out


def engine_args(tool: str, session: dict) -> list:
    """The command line options that sign an engine in.  [] when it cannot."""
    if not session or not session.get("kind"):
        return []
    headers = list(session.get("headers") or [])
    cookie = session.get("cookie") or ""
    args = []
    if tool in ("nuclei", "ffuf", "dalfox", "sqlmap", "wapiti"):
        for name, value in headers:
            args += ["-H", f"{name}: {value}"]
    if tool == "nikto":
        for name, value in headers:
            args += ["-Add-header", f"{name}: {value}"]
        if cookie:
            args += ["-Add-header", f"Cookie: {cookie}"]
    if cookie:
        if tool == "nuclei":
            args += ["-H", f"Cookie: {cookie}"]
        elif tool == "ffuf":
            args += ["-b", cookie]
        elif tool == "dalfox":
            args += ["--cookies", cookie]
        elif tool == "sqlmap":
            args += ["--cookie", cookie]
        elif tool == "wapiti":
            args += ["-C", cookie]
    form = session.get("form")
    if tool == "wapiti" and form:
        args += ["--form-user", form["username"], "--form-password", form["password"],
                 "--form-url", form["login_url"]]
    return args


SIGNS_IN = {"nuclei", "ffuf", "dalfox", "sqlmap", "wapiti", "nikto"}


def for_nextgen(data: dict) -> dict:
    """What nextgen-dast's scan API can take.  Raises ValueError when the
    site signs in some way its API has no field for."""
    kind = data.get("kind")
    if kind == "form":
        return {"creds_username": data["username"], "creds_password": data["password"],
                "login_url": data["login_url"]}
    if kind == "header" and data.get("header_name", "").lower() == "authorization" \
            and data.get("header_value", "").lower().startswith("basic "):
        try:
            user, password = base64.b64decode(data["header_value"].split(" ", 1)[1]).decode().split(":", 1)
        except Exception:  # noqa: BLE001
            raise ValueError("The Basic authorization header could not be read.")
        # No login page: nextgen-dast uses HTTP Basic then.
        return {"creds_username": user, "creds_password": password}
    raise ValueError("nextgen-dast's API takes a form login or HTTP Basic only, so a "
                     f"{KINDS.get(kind, kind).lower()} cannot be passed to it.  Run this scan on "
                     "this server, or start it without signing in.")
