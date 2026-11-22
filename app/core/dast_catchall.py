"""Catch-all awareness: tell a real file from the page a site gives for anything.

Many sites answer every address with the same page.  A single page app sends
its index for any path so the browser router can take over; a CMS sends its
home page for "/.anything"; a gateway sends one JSON error for all of it.  A
scanner that asks for "/.bash_history" and gets HTTP 200 reports a shell
history, when the site only sent its front page again.  That is the biggest
source of false alarms in the path findings, and each one costs a person a
look and costs the platform some trust.

Two checks settle most of them, with no model and no guess:

1. A control of the same shape.  The site is asked for an address that cannot
   exist but looks like the one reported: a leading dot stays a leading dot,
   ".zip" stays ".zip", and the folder depth is kept.  Sites route by shape
   (AEM serves its home page for "/.x" but a real 404 for "/x/y.html"), so a
   fixed control misses them.  A reported page that matches its control is the
   catch-all answer, not a file.

2. What the file must look like.  A shell history is lines of commands, not
   HTML.  An .htpasswd is "user:hash" lines.  A zip starts with "PK\\x03\\x04".
   For a file name we know, the answer has to carry that file's signature to be
   called found, and an answer without it is not that file.  That makes a
   confirmed finding a fact: the file is there and it is what its name says.

Every request here is a GET for a fixed address.  Nothing is sent that could
change anything on the site.
"""

from __future__ import annotations

import re
import secrets
from urllib.parse import unquote, urljoin, urlparse

# ------------------------------------------------------------------ shapes

_EXT = re.compile(r"((?:\.[A-Za-z0-9]{1,8}){1,2})$")


def shape(path: str) -> tuple:
    """The shape of an address: (depth, leading dot, extension, trailing slash).

    "/.git/config" is (2, False, "", False) at its last part, with the dot on
    the folder kept by control_path().  Only what a router could key on is
    kept.
    """
    path = urlparse(path).path or "/"
    trailing = path.endswith("/") and path != "/"
    parts = [p for p in path.split("/") if p]
    if not parts:
        return (0, False, "", False, ())
    name = unquote(parts[-1])
    dot = name.startswith(".")
    core = name.lstrip(".")
    m = _EXT.search(core)
    ext = m.group(1).lower() if m and m.start() > 0 else ""
    dotted_dirs = tuple(i for i, p in enumerate(parts[:-1]) if p.startswith("."))
    return (len(parts), dot, ext, trailing, dotted_dirs)


def control_path(path: str) -> str:
    """An address that cannot exist, with the same shape as path."""
    depth, dot, ext, trailing, dotted_dirs = shape(path)
    if depth == 0:
        return f"/gcr-{secrets.token_hex(6)}"
    parts = []
    for i in range(depth - 1):
        parts.append(("." if i in dotted_dirs else "") + f"gcr-{secrets.token_hex(4)}")
    parts.append(("." if dot else "") + f"gcr-{secrets.token_hex(6)}" + ext)
    return "/" + "/".join(parts) + ("/" if trailing else "")


# ------------------------------------------------------------------ comparing

_TAG = re.compile(r"<\s*([a-zA-Z][a-zA-Z0-9-]*)")
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
_VOLATILE = [
    re.compile(r"gcr-[0-9a-f]+"),
    re.compile(r"[0-9a-fA-F]{16,}"),
    # Nonces, CSRF and request ids that change on every answer.
    re.compile(r"(nonce|csrf[\w-]*|_token|requestid|request-id|traceid|x-amzn[\w-]*)"
               r"""(["'\s:=]+)[^"'\s<>]{6,}""", re.I),
    re.compile(r"\b\d{9,13}\b"),  # epoch timestamps
]


def _norm(body: str, *echoed: str) -> str:
    body = body or ""
    for rx in _VOLATILE:
        body = rx.sub("", body)
    for word in echoed:
        if word and len(word) >= 3:
            body = body.replace(word, "")
    return re.sub(r"\s+", " ", body).strip()


def _skeleton(body: str) -> tuple:
    """The sequence of tag names: the same template filled with a different
    address, token or date has the same skeleton."""
    return tuple(_TAG.findall((body or "")[:200_000]))


def _title(body: str) -> str:
    m = _TITLE.search((body or "")[:20_000])
    return re.sub(r"\s+", " ", m.group(1)).strip().lower() if m else ""


def looks_html(resp: dict) -> bool:
    """The answer is an HTML document, by its type or by how it starts."""
    ctype = ((resp or {}).get("headers") or {}).get("content-type", "").lower()
    head = ((resp or {}).get("body") or "")[:512].lstrip().lower()
    return ("html" in ctype or head.startswith("<!doctype html") or head.startswith("<html")
            or (head.startswith("<") and "<head" in head[:400]))


def same_page(a: dict, b: dict, echoed: tuple = ()) -> bool:
    """Two answers are the same page, allowing for what changes per request.

    Same status, and then the same normalized body, or for HTML the same tag
    skeleton and title with lengths within 3 percent.  The skeleton test is
    what catches a single page app whose index carries a fresh nonce or build
    stamp on every load.
    """
    if not a or not b or a.get("status") != b.get("status"):
        return False
    ba, bb = a.get("body") or "", b.get("body") or ""
    if _norm(ba, *echoed) == _norm(bb, *echoed):
        return True
    if looks_html(a) and looks_html(b):
        la, lb = len(ba), len(bb)
        close = abs(la - lb) <= max(64, 0.03 * max(la, lb))
        if close and _title(ba) == _title(bb) and _skeleton(ba) == _skeleton(bb):
            return True
    return False


# ------------------------------------------------------------------ file types
#
# A file name we know, and what its content must look like.  Each check reads
# the text body and the first bytes as hex.  It is strict on purpose: a file
# that fails is not reported as that file, so a weak check would hide a real
# one, and a loose one would cry wolf.  Every pattern here is the format's own
# fixed marker, not a guess.

def _lines(body: str, limit: int = 200) -> list:
    return [ln for ln in (body or "").splitlines()[:limit] if ln.strip()]


def _share(lines: list, rx) -> float:
    return (sum(1 for ln in lines if rx.search(ln)) / len(lines)) if lines else 0.0


_SHELL = re.compile(
    r"^\s*(sudo|cd|ls|ll|cat|less|more|tail|head|grep|find|git|ssh|scp|rsync|vi|vim|nano|"
    r"export|source|docker|kubectl|helm|mysql|psql|mongo|redis-cli|cp|mv|rm|mkdir|touch|"
    r"echo|curl|wget|chmod|chown|apt|apt-get|yum|dnf|pip|pip3|npm|yarn|node|python|python3|"
    r"php|java|mvn|exit|history|systemctl|service|journalctl|ps|top|kill|df|du|free|tar|"
    r"unzip|zip|crontab|passwd|su|whoami|id|ping|nc|netstat|ss|make|clear|pwd|\./)(\s|$)")
_SQL_LINE = re.compile(
    r"^\s*(select|insert|update|delete|create|drop|alter|show|use|describe|desc|grant|"
    r"explain|truncate|set|begin|commit|\\[a-z?]+)\b", re.I)
_HTPASSWD = re.compile(r"^[^:\s<>\"']{1,64}:(\$apr1\$|\$2[abxy]?\$|\{SHA\}|\$[156]\$|"
                       r"[./0-9A-Za-z]{13}$)")
_HTACCESS = re.compile(r"^\s*(RewriteEngine|RewriteRule|RewriteCond|RewriteBase|Order\s|"
                       r"Deny\s|Allow\s|AuthType|AuthName|AuthUserFile|Require\s|Options\s|"
                       r"DirectoryIndex|ErrorDocument|Header\s|php_(value|flag)|"
                       r"<IfModule|<Files|<FilesMatch|SetEnv|AddType|AddHandler|Redirect)",
                       re.I)
_ENV_LINE = re.compile(r"^\s*(export\s+)?[A-Za-z_][A-Za-z0-9_.]*\s*=")
_SQL_DUMP = re.compile(r"(-- MySQL dump|-- MariaDB dump|PostgreSQL database dump|"
                       r"^\s*CREATE TABLE\b|^\s*INSERT INTO\b|^\s*DROP TABLE\b|"
                       r"^\s*LOCK TABLES\b|^\s*COPY [\w.\"]+ \()", re.I | re.M)
_PRIVATE_KEY = re.compile(r"-----BEGIN (RSA |OPENSSH |EC |DSA |ENCRYPTED )?PRIVATE KEY-----")
_PHP_SOURCE = re.compile(r"<\?php|<\?=")
_SOURCE_CODE = re.compile(r"<\?php|<%@|<%=|^\s*(import|package|using|namespace|def|class|"
                          r"function|const|var|let|require\(|module\.exports)\b", re.M)


def _not_html_and(rx_ok):
    """A text file that is not HTML and whose lines are mostly of one kind."""
    def check(resp):
        if looks_html(resp):
            return False
        return rx_ok(resp.get("body") or "")
    return check


def _shell_history(body: str) -> bool:
    lines = _lines(body)
    return len(lines) >= 2 and _share(lines, _SHELL) >= 0.5 and \
        all(len(ln) < 2000 for ln in lines)


def _sql_history(body: str) -> bool:
    lines = _lines(body.replace("\\040", " "))
    return len(lines) >= 1 and _share(lines, _SQL_LINE) >= 0.5


def _htpasswd(body: str) -> bool:
    lines = _lines(body)
    return len(lines) >= 1 and _share(lines, _HTPASSWD) >= 0.8


def _htaccess(body: str) -> bool:
    lines = [ln for ln in _lines(body) if not ln.lstrip().startswith("#")]
    return len(lines) >= 1 and _share(lines, _HTACCESS) >= 0.5


def _env(body: str) -> bool:
    lines = [ln for ln in _lines(body) if not ln.lstrip().startswith("#")]
    return len(lines) >= 2 and _share(lines, _ENV_LINE) >= 0.8


def _magic(*prefixes: str, at: int = 0):
    """The raw bytes start (at an offset) with one of these hex prefixes."""
    def check(resp):
        head = (resp.get("head_hex") or "").lower()
        return any(head[at * 2:].startswith(p) for p in prefixes)
    return check


def _contains(rx, html_ok: bool = False):
    def check(resp):
        if not html_ok and looks_html(resp):
            return False
        return bool(rx.search((resp.get("body") or "")[:200_000]))
    return check


def _source_backup(resp) -> bool:
    """A backup copy of source code: served as text (not rendered), and it reads
    as code.  A backup of an HTML page is not judged here."""
    if looks_html(resp) and not _PHP_SOURCE.search(resp.get("body") or ""):
        return False
    return bool(_SOURCE_CODE.search((resp.get("body") or "")[:200_000]))


ZIP = ("504b0304", "504b0506", "504b0708")
GZIP = ("1f8b",)

# (name pattern on the last part or the path, label, check)
FILE_TYPES = [
    (re.compile(r"(^|/)\.(bash|zsh|sh|ash|ksh|fish)_history$"), "shell history",
     _not_html_and(_shell_history)),
    (re.compile(r"(^|/)\.(mysql|psql|sqlite|mongo|dbshell|rediscli)_history$|"
                r"(^|/)\.mongorc\.js$"), "database client history",
     _not_html_and(_sql_history)),
    (re.compile(r"(^|/)\.htpasswd$|(^|/)\.passwd$"), "password file (htpasswd)",
     _not_html_and(_htpasswd)),
    (re.compile(r"(^|/)\.htaccess$"), "Apache .htaccess", _not_html_and(_htaccess)),
    (re.compile(r"(^|/)\.env(\.[A-Za-z0-9_-]+)?$"), "environment file (.env)",
     _not_html_and(_env)),
    (re.compile(r"(^|/)\.git/config$"), "Git config",
     _contains(re.compile(r"^\s*\[core\]", re.M))),
    (re.compile(r"(^|/)\.git/HEAD$"), "Git HEAD",
     _contains(re.compile(r"^(ref: refs/|[0-9a-f]{40}\s*$)"))),
    (re.compile(r"(^|/)\.git/index$"), "Git index", _magic("44495243")),  # DIRC
    (re.compile(r"(^|/)\.svn/wc\.db$"), "Subversion database",
     _magic("53514c69746520666f726d6174203300")),  # SQLite format 3\0
    (re.compile(r"(^|/)\.svn/entries$"), "Subversion entries",
     _contains(re.compile(r"^(8|9|10|12)\s*$|^dir\s*$", re.M))),
    (re.compile(r"(^|/)\.DS_Store$"), "macOS .DS_Store", _magic("0000000142756431")),
    (re.compile(r"\.sw[a-p]$"), "Vim swap file", _magic("623056494d")),
    (re.compile(r"\.(zip|jar|war|ear)$", re.I), "zip archive", _magic(*ZIP)),
    (re.compile(r"\.(tar\.gz|tgz|gz)$", re.I), "gzip archive", _magic(*GZIP)),
    (re.compile(r"\.tar$", re.I), "tar archive", _magic("7573746172", at=257)),
    (re.compile(r"\.7z$", re.I), "7-Zip archive", _magic("377abcaf271c")),
    (re.compile(r"\.rar$", re.I), "RAR archive", _magic("526172211a07")),
    (re.compile(r"\.(sqlite|sqlite3|db)$", re.I), "SQLite database",
     _magic("53514c69746520666f726d6174203300")),
    (re.compile(r"\.(sql|dump)$", re.I), "SQL dump", _contains(_SQL_DUMP)),
    (re.compile(r"(^|/)(id_rsa|id_dsa|id_ecdsa|id_ed25519)$|\.(pem|key)$", re.I),
     "private key", _contains(_PRIVATE_KEY)),
    (re.compile(r"(^|/)\.npmrc$"), "npm config",
     _contains(re.compile(r"(_authToken|_auth|registry)\s*=", re.I))),
    (re.compile(r"(^|/)\.aws/credentials$"), "AWS credentials",
     _contains(re.compile(r"aws_access_key_id\s*=", re.I))),
    (re.compile(r"(^|/)web\.config(\.(bak|old|orig|save|txt))?$", re.I), "web.config",
     _contains(re.compile(r"<configuration[\s>]", re.I))),
    (re.compile(r"(^|/)WEB-INF/web\.xml$", re.I), "WEB-INF/web.xml",
     _contains(re.compile(r"<web-app[\s>]", re.I))),
    (re.compile(r"(^|/)wp-config\.php[._~-]?\w*$", re.I), "wp-config backup",
     _contains(re.compile(r"DB_(PASSWORD|NAME|USER)", re.I), html_ok=True)),
    (re.compile(r"\.php(\.|~|_)(bak|old|orig|save|swp|txt|backup|copy|1)?$|"
                r"\.php~$", re.I), "PHP source backup", _source_backup),
    (re.compile(r"(^|/)(composer|package-lock|yarn)\.(lock|json)$", re.I), "dependency lock file",
     _contains(re.compile(r"\"(packages|lockfileVersion|dependencies)\"|^# yarn lockfile",
                          re.M))),
    (re.compile(r"(^|/)docker-compose\.ya?ml$", re.I), "docker-compose file",
     _contains(re.compile(r"^\s*services\s*:", re.M))),
    (re.compile(r"(^|/)(\.travis|\.gitlab-ci)\.ya?ml$|(^|/)\.circleci/config\.ya?ml$", re.I),
     "CI config", _contains(re.compile(r"^\s*(script|stages|jobs|version|before_script)\s*:",
                                       re.M))),
    (re.compile(r"(^|/)terraform\.tfstate(\.backup)?$", re.I), "Terraform state",
     _contains(re.compile(r"\"terraform_version\""))),
]

# A backup suffix on any other name.  Its content cannot be checked against a
# format, so it is only held to not being the catch-all page, and to not being
# an HTML page when the original is not HTML either.
_BACKUP_SUFFIX = re.compile(r"\.(bak|old|orig|save|backup|copy|tmp|swo|~)$|~$", re.I)

# Extensions that are never an HTML page.  An HTML document served for one of
# these, or for a dot file, is the site's page for anything, not the file.
_NOT_HTML_EXT = {".bak", ".old", ".orig", ".save", ".backup", ".zip", ".gz", ".tgz", ".tar",
                 ".7z", ".rar", ".sql", ".dump", ".db", ".sqlite", ".sqlite3", ".log",
                 ".key", ".pem", ".swp", ".swo", ".tar.gz", ".yml", ".yaml", ".ini", ".conf",
                 ".cfg", ".env", ".json", ".xml", ".txt", ".lock", ".tfstate", ".war", ".jar",
                 ".ear", ".properties", ".toml"}


def file_type(path: str):
    """-> (label, check) for a path whose file format we know, or None."""
    p = unquote(urlparse(path).path or "")
    for rx, label, check in FILE_TYPES:
        if rx.search(p):
            return label, check
    return None


def expects_non_html(path: str) -> bool:
    """A real answer for this path would not be an HTML page."""
    depth, dot, ext, trailing, dotted_dirs = shape(path)
    if trailing or depth == 0:
        return False
    if dot or dotted_dirs:
        return True
    return ext in _NOT_HTML_EXT or bool(_BACKUP_SUFFIX.search(urlparse(path).path or ""))


# ------------------------------------------------------------------ the site

class Site:
    """What one site answers for addresses that cannot exist, by shape.

    fetch is external_probe.fetch (or a stand in for tests).  Controls are
    asked once per shape and kept, so verifying many findings costs one extra
    request per shape, not per finding.
    """

    def __init__(self, base_url: str, fetch=None, allow_private: bool = False,
                 body_limit: int = 65536, headers: dict = None):
        if fetch is None:
            from app.core import external_probe
            fetch = external_probe.fetch
        self.base_url = base_url
        self._fetch = fetch
        self.allow_private = allow_private
        self.body_limit = body_limit
        self.headers = dict(headers or {})
        self._controls = {}
        self.requests = 0

    def get(self, url: str, follow: bool = False) -> dict:
        self.requests += 1
        return self._fetch(url, allow_private=self.allow_private, follow=follow,
                           body_limit=self.body_limit, **({"headers": self.headers}
                                                          if self.headers else {}))

    def control(self, path: str) -> dict:
        key = shape(path)
        if key not in self._controls:
            self._controls[key] = self.get(urljoin(self.base_url, control_path(path)))
        return self._controls[key]

    def catch_all(self, path: str) -> bool:
        """This shape of address answers 200 even when nothing is there."""
        return (self.control(path) or {}).get("status") == 200

    def verify(self, url: str, resp: dict = None) -> dict:
        """Check one reported address.

        -> {"result": "confirmed" | "absent" | "unknown", "why": ..., "label": ...,
            "response": the answer}

        confirmed: the answer carries the signature of the file its name says.
        absent: the answer is the catch-all page, or an HTML page where a
                file was named, or misses the file's signature.
        unknown: nothing here can say either way, so the finding is left as is.
        """
        path = urlparse(url).path or "/"
        if resp is None:
            resp = self.get(url)
        out = {"result": "unknown", "why": "", "label": "", "response": resp}
        status = resp.get("status") or 0
        if status != 200:
            return out  # 404, 401/403 and redirects are judged by the caller
        name = unquote(path.rstrip("/").rsplit("/", 1)[-1])
        ctl = self.control(path)
        if same_page(resp, ctl, (name.lstrip("."),)):
            out.update(result="absent",
                       why=("the site gives the same page for an address of the same "
                            "shape that cannot exist (" + control_path(path) + ")"))
            return out
        known = file_type(path)
        if known:
            label, check = known
            out["label"] = label
            if check(resp):
                out.update(result="confirmed",
                           why=f"the answer has the format of a {label}, and differs from "
                               "the site's answer for an address that cannot exist")
            else:
                out.update(result="absent",
                           why=f"the answer is not a {label}: it lacks that format's fixed "
                               "markers" + (" and is an HTML page" if looks_html(resp) else ""))
            return out
        if expects_non_html(path) and looks_html(resp):
            out.update(result="absent",
                       why="an HTML page was served where a file was named, which is the "
                           "site's page, not the file")
        return out
