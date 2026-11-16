"""What a page hands to whoever holds its link.

Some pages are opened by a link alone: a document to sign, an invoice, a
shared file.  The link is the key, and that is fine as far as it goes.  What
goes wrong is what the page's own requests bring back with it: the whole
record, with other people's addresses, an IP address, staff names, and the
other people's own links, so one holder can act as another.

Nothing here sends a request.  The scan loads the link in a browser with no
sign in, keeps the JSON the page's own requests got back, and this reads it.
What it reports is only ever what the answer itself contains, and the
evidence names fields and counts, never the values.
"""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import parse_qsl, urlparse

MAX_LEAVES = 20000
MAX_LINKS = 5

_EMAIL = re.compile(r"^[\w.+\-]+@([\w\-]+(?:\.[\w\-]+)+)$")
_GUID = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
_RANDOM = re.compile(r"^[A-Za-z0-9_\-]{20,}$")
_PHONE = re.compile(r"^\+?[\d\s().\-]{7,20}$")

# Keys whose value opens something: a link, a share, a signature.
KEY_FIELDS = re.compile(r"identif|token|secret|access|share|invite|link|sign(ing)?key|"
                        r"api[_\-]?key|^key$|magic|otp|code$|hash$|uuid|guid", re.I)
IP_FIELDS = re.compile(r"(^|[_\-])ip($|[_\-])|ipaddr|ip_?address|remoteaddr|clientip|"
                       r"userip", re.I)
PHONE_FIELDS = re.compile(r"phone|mobile|cell|fax|^tel", re.I)
STAFF_FIELDS = re.compile(r"(created|modified|updated|sent|submitted|approved|owner|"
                          r"assigned|requested)_?(by|user)|sender|author|agent|rep$|"
                          r"salesperson|employee", re.I)
COUNTING_ID = re.compile(r"(^id$|id$|_id$|number$|no$)", re.I)


def link_secrets(link: str) -> set:
    """The parts of a link that are its key: long random path segments and
    query values.  Lower case, for comparing."""
    parsed = urlparse(link or "")
    parts = [s for s in parsed.path.split("/") if s]
    parts += [v for _k, v in parse_qsl(parsed.query)]
    out = set()
    for part in parts:
        for guid in _GUID.findall(part):
            out.add(guid.lower())
        if _RANDOM.match(part) and not part.isalpha():
            out.add(part.lower())
    return out


def mask_link(link: str) -> str:
    """A link fit to show: its key replaced, so a report never carries it."""
    text = link or ""
    for secret in sorted(link_secrets(text), key=len, reverse=True):
        text = re.sub(re.escape(secret), "[key]", text, flags=re.I)
    return text


def _leaves(value, path="", out=None):
    """(key path, last key, value) for every scalar, depth first."""
    if out is None:
        out = []
    if len(out) >= MAX_LEAVES:
        return out
    if isinstance(value, dict):
        for k, v in value.items():
            _leaves(v, f"{path}.{k}" if path else str(k), out)
    elif isinstance(value, list):
        for v in value[:500]:
            _leaves(v, f"{path}[]", out)
    elif value is not None and not isinstance(value, bool):
        last = re.split(r"[.\[\]]+", path.rstrip("[]"))[-1] if path else ""
        out.append((path, last, value))
    return out


def _is_ip(text: str) -> bool:
    try:
        ip = ipaddress.ip_address(text.strip())
    except ValueError:
        return False
    return not (ip.is_unspecified or ip.is_loopback)


def read(answers: list, link: str, company_domains=()) -> dict:
    """What the page's answers carry.  answers are the captured JSON
    responses, already parsed: [{"url", "data", "signed"}].

    -> {"emails": {address: [fields]}, "company_emails": set, "ips": {fields},
        "phones": {fields}, "other_keys": {field: n}, "own_key_seen": bool,
        "staff": {fields}, "counting": {field: example}, "answers": n}
    """
    own = link_secrets(link)
    company = {d.lower().lstrip(".") for d in company_domains or () if d}
    found = {"emails": {}, "company_emails": set(), "ips": set(), "phones": set(),
             "other_keys": {}, "own_key_seen": False, "staff": set(), "counting": {},
             "answers": 0}
    for answer in answers or []:
        if answer.get("signed"):
            # The page sent a sign in with this one; not what the link alone opens.
            continue
        found["answers"] += 1
        for path, key, value in _leaves(answer.get("data")):
            field = re.sub(r"\[\]", "", path)
            if isinstance(value, (int, float)):
                if COUNTING_ID.search(key) and isinstance(value, int) and value >= 1000 \
                        and not KEY_FIELDS.search(key):
                    found["counting"].setdefault(field, value)
                continue
            text = str(value).strip()
            if not text or len(text) > 2000:
                continue
            mail = _EMAIL.match(text)
            if mail:
                found["emails"].setdefault(text.lower(), set()).add(field)
                domain = mail.group(1).lower()
                if any(domain == d or domain.endswith("." + d) for d in company):
                    found["company_emails"].add(text.lower())
                if STAFF_FIELDS.search(key):
                    found["staff"].add(field)
                continue
            if IP_FIELDS.search(key) and _is_ip(text):
                found["ips"].add(field)
                continue
            if PHONE_FIELDS.search(key) and _PHONE.match(text) and sum(c.isdigit() for c in text) >= 7:
                found["phones"].add(field)
                continue
            if KEY_FIELDS.search(key):
                keys = {g.lower() for g in _GUID.findall(text)}
                if not keys and _RANDOM.match(text) and not text.isalpha() and not text.isdigit():
                    keys = {text.lower()}
                for k in keys:
                    if k in own:
                        found["own_key_seen"] = True
                    else:
                        found["other_keys"][field] = found["other_keys"].get(field, 0) + 1
                continue
            if STAFF_FIELDS.search(key) and re.fullmatch(r"[A-Za-z][\w.\-]{2,40}", text):
                found["staff"].add(field)
    return found


def _fields(names, limit=5) -> str:
    names = sorted(names)
    shown = ", ".join(names[:limit])
    return shown + (f" and {len(names) - limit} more" if len(names) > limit else "")


def findings(found: dict, link: str, make) -> list:
    """Turn what read() found into findings.

    make(title, severity, evidence, fix, cwe) builds one in the scan's shape.
    """
    shown = mask_link(link)
    out = []
    lead = f"With no sign in, the page at {shown} fetched data that "
    if found["other_keys"]:
        n = sum(found["other_keys"].values())
        out.append(make(
            "A link hands out the keys of other links",
            "high",
            lead + f"carries {n} key{'s' if n != 1 else ''} other than this link's own, in "
                   f"{_fields(found['other_keys'])}.  Each one is somebody else's way in: "
                   "whoever holds this link can open, and act as, theirs.",
            "Return only what the page needs for the person whose link this is.  Never "
            "send another person's identifier, token or link to the browser.",
            "CWE-200"))
    others = [m for m in found["emails"] if m not in found["company_emails"]]
    personal = []
    if len(others) > 1:
        personal.append(f"{len(others)} email addresses outside the company")
    if found["ips"]:
        personal.append(f"an IP address ({_fields(found['ips'], 3)})")
    if found["phones"]:
        personal.append(f"a phone number ({_fields(found['phones'], 3)})")
    if personal:
        out.append(make(
            "A link returns personal data beyond what its holder needs",
            "medium",
            lead + "includes " + "; ".join(personal) + ".  A link gets forwarded, sits in "
                   "mailboxes and browser history, and anyone who has it gets all of this.",
            "Send the browser only the fields the page shows.  Leave out other people's "
            "addresses, IP addresses and phone numbers, or show them masked.",
            "CWE-359"))
    if found["company_emails"] or found["staff"]:
        bits = []
        if found["company_emails"]:
            n = len(found["company_emails"])
            bits.append(f"{n} company email address{'es' if n != 1 else ''}")
        if found["staff"]:
            bits.append(f"staff and account names ({_fields(found['staff'], 4)})")
        out.append(make(
            "A link exposes staff names and internal details",
            "low",
            lead + "names " + " and ".join(bits) + ".  Useful to anyone writing a "
                   "convincing phishing email to the people involved.",
            "Leave internal user names, staff addresses and audit fields out of what a "
            "customer link returns.",
            "CWE-200"))
    if found["counting"]:
        example = next(iter(sorted(found["counting"])))
        out.append(make(
            "A link's data carries counting record numbers",
            "info",
            lead + f"carries record numbers that count up ({_fields(found['counting'], 4)}).  "
                   "Not a problem alone, but any route that takes one of these without the "
                   "link's key opens every record by counting.  Worth checking the routes "
                   f"that accept {example.split('.')[-1]}.",
            "Make every route that takes a record number check that the caller holds that "
            "record's link, or use the link's key in its place.",
            "CWE-639"))
    return out
