"""Read a shipped image for the problems that only exist in the image.

lib/image_fetch.py lays the image out; this reads it.  Every rule here reports
a fact about the files and the run configuration, never a guess about intent,
and stays quiet when the fact cannot be established from the image alone.

  image.sudo-root-grant
      A sudoers rule that lets an account other than root run, without a
      password, something that hands over root: every command, a shell or an
      interpreter with any arguments, or a tool that writes a file as root.
      Graded by what the tool can reach: writing a file root later executes
      or parses for privileges (cron, sudoers, passwd, init and profile
      scripts, a script root runs) is root, any other root-owned file is
      tampering with that file.  Fixed-argument commands like
      `apachectl graceful` are not reported.  sudo ignores files in
      sudoers.d whose name contains a dot or ends in ~, so those are too.

  image.root-runs-writable-code
      Something that runs as root (the image's own entrypoint when the image
      runs as root, a root cron job, a supervisor program with no user) runs a
      file that a different account owns.  Whoever controls that account
      controls what root runs next.  Commands after a privilege drop (gosu,
      su-exec, runuser, setpriv, s6-setuidgid, chpst, su, sudo -u) are not
      counted, and neither is a file on a volume the image does not contain.

  image.archive-with-credential-files
      An archive in the application's files whose entries are named like
      credentials (.my.cnf, .pgpass, .env, private keys, keystores, .netrc,
      .git-credentials ...).  Legacy ZIP encryption is said to be breakable
      offline, because it is.

  image.git-directory-in-web-root
      A .git directory inside a web root, which hands out the source and its
      history to anyone the server will serve it to.

  image.source-not-in-repository
      Source files the image ships that have no counterpart anywhere in the
      repository the image is built from.  Informational: nobody reviewed
      them, because the review reads the repository.

Usage:
  image_check.py image <outdir> <repo dir> <repository> <image ref>
  image_check.py repo  <repo dir> <repository> <branch> <web> <link JSON>
  image_check.py refs  <repo dir> [cap]       images the repository publishes
  image_check.py prune <outdir> <repo dir>    drop image files already read

Prints a JSON array of findings in the misconfiguration shape.  The repo mode
runs only the archive rule, over a checkout.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import sys
import tarfile
import zipfile

# --- shared ---------------------------------------------------------------

CREDENTIAL_NAMES = re.compile(
    r"(^|/)(\.my\.cnf|\.mylogin\.cnf|\.pgpass|\.netrc|_netrc|\.git-credentials|"
    r"\.env(\.(local|prod|production|live|staging))?|\.htpasswd|\.npmrc|\.pypirc|"
    r"\.dockercfg|id_(rsa|dsa|ecdsa|ed25519)|credentials(\.json|\.csv)?|"
    r"service[-_]account[^/]*\.json|[^/]+\.(pem|key|p12|pfx|jks|keystore|kdbx|ovpn|ppk))$",
    re.I)
NOT_SECRET_PEM = re.compile(r"(cert|chain|ca[-_.]|fullchain|public|\.pub$|bundle)", re.I)
ARCHIVE = re.compile(r"\.(zip|tar|tgz|tar\.gz|tar\.bz2|tar\.xz)$", re.I)
TEST_PATH = re.compile(r"(^|/)(tests?|spec|fixtures?|testdata|__tests__|examples?|samples?|"
                       r"docs?|node_modules|vendor|third_party)/", re.I)


def finding(rule, severity, title, message, resolution, file, line=0, image="",
            resource="", repository="", cwe="", url=""):
    org, _, name = repository.partition("/")
    return {
        "organization": org, "repository": repository, "repository_name": name,
        "source": "image-check" if image else "archive-check",
        "category": "misconfiguration",
        "finding_type": "container_image" if image else "infrastructure_as_code",
        "configuration_kind": "image" if image else "archive",
        "rule_id": rule, "rule_name": rule, "title": title, "message": message,
        "description": message, "resolution": resolution,
        "resource": resource or file, "provider": "", "service": "",
        "file": file, "start_line": line, "end_line": line,
        "start_column": 0, "end_column": 0, "severity": severity,
        "engine_severity": severity, "confidence": "high",
        "references": [f"https://cwe.mitre.org/data/definitions/{cwe}.html"] if cwe else [],
        "cwe": [f"CWE-{cwe}"] if cwe else [],
        "url": url, "help_url": "", "image": image,
        "triage": "review", "triage_reason": "", "state": "open",
    }


def read_text(path: str, limit: int = 2_000_000) -> str:
    try:
        if os.path.islink(path) or not os.path.isfile(path):
            return ""
        with open(path, "rb") as handle:
            data = handle.read(limit)
    except OSError:
        return ""
    return data.decode("utf-8", "replace")


# --- archives -------------------------------------------------------------

def archive_entries(path: str):
    """-> (entry names, legacy_zip_encryption) or None when unreadable."""
    try:
        if path.lower().endswith(".zip"):
            with zipfile.ZipFile(path) as archive:
                infos = archive.infolist()[:5000]
                names = [i.filename for i in infos]
                # Bit 0 is "encrypted"; method 99 is the AES extension.
                legacy = any(i.flag_bits & 1 and i.compress_type != 99 for i in infos)
                return names, legacy
        with tarfile.open(path, "r:*") as archive:
            names = []
            for member in archive:
                names.append(member.name)
                if len(names) >= 5000:
                    break
            return names, False
    except (OSError, zipfile.BadZipFile, tarfile.TarError, EOFError, ValueError,
            NotImplementedError, RuntimeError):
        return None


def credential_entries(names):
    hits = []
    for name in names:
        clean = name.rstrip("/")
        if not CREDENTIAL_NAMES.search(clean):
            continue
        base = clean.rsplit("/", 1)[-1]
        # A certificate or a public key is not a credential.
        if base.lower().endswith((".pem", ".key")) and NOT_SECRET_PEM.search(base):
            continue
        hits.append(clean)
    return hits


def archive_findings(root: str, rel_paths, display, image="", repository="",
                     url_for=None):
    out = []
    for rel in rel_paths:
        if not ARCHIVE.search(rel) or (not image and TEST_PATH.search(rel)):
            continue
        listed = archive_entries(os.path.join(root, rel))
        if not listed:
            continue
        names, legacy = listed
        hits = credential_entries(names)
        if not hits:
            continue
        shown = ", ".join(hits[:6]) + (f" and {len(hits) - 6} more" if len(hits) > 6 else "")
        where = "the image" if image else "the repository"
        msg = (f"The archive {display(rel)} in {where} contains files named like "
               f"credentials: {shown}.  Anyone who can read {where} can unpack them.")
        if legacy:
            msg += ("  The archive uses the legacy ZIP password scheme, which can be "
                    "broken offline, especially when some file names inside are known.")
        out.append(finding(
            "image.archive-with-credential-files" if image else "repo.archive-with-credential-files",
            "medium",
            "An archive containing credential files ships with the "
            + ("image" if image else "repository"),
            msg,
            "Remove the archive, keep backups out of the build context and the "
            "repository, and change any credential that was in it.",
            display(rel), 0, image, resource=rel, repository=repository, cwe="538",
            url=url_for(rel) if url_for else ""))
    return out


# --- sudoers --------------------------------------------------------------

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "csh", "tcsh", "fish", "ash",
          "busybox", "su", "sudo", "doas", "script", "expect", "screen", "tmux"}
INTERPRETERS = re.compile(
    r"^(python[\d.]*|perl[\d.]*|ruby[\d.]*|php[\d.]*|node(js)?|lua[\d.]*|"
    r"awk|gawk|mawk|nawk|env|xargs|find|vi|vim|nvim|nano|ed|emacs|less|more|"
    r"man|git|tar|zip|rsync|docker|podman|kubectl|ssh|scp|gdb|strace|nsenter|"
    r"chroot|unshare|capsh|setarch|taskset|nice|ionice|timeout|stdbuf|watch|"
    r"systemd-run|crontab|at|make|pip[\d.]*|npm|npx|composer|apt|apt-get|dpkg|"
    r"rpm|yum|dnf|apk|mount|openssl|wget|curl)$")
WRITERS = {"tee", "cp", "mv", "dd", "install", "ln", "chmod", "chown", "chgrp",
           "sed", "truncate", "touch", "rm", "mkdir", "rmdir", "cat", "unzip", "patch"}
# Files root executes or reads to decide who may do what.
EXEC_SIGNIFICANT = re.compile(
    r"^/(etc/(cron[^/]*|crontab|sudoers(\.d)?|passwd|shadow|group|gshadow|"
    r"ld\.so[^/]*|profile(\.d)?|bash\.bashrc|environment|rc[^/]*|init\.d|init|"
    r"systemd|supervisor[^/]*|security|pam\.d|update-motd\.d|logrotate[^/]*)|"
    r"var/spool/cron|root|usr/(local/)?s?bin|s?bin|lib/systemd|usr/lib/systemd)(/|$)")
DROP = re.compile(r"\b(gosu|su-exec|runuser|setpriv|s6-setuidgid|chpst|setuidgid|"
                  r"capsh\s+--user)\b|\bsu\s+(-\s+|-[lsc]\s+)?[a-z_][\w-]*\b|\bsudo\s+-u\b")


def _sudoers_lines(text: str):
    """Logical lines with their first physical line number."""
    buf, start = "", 0
    for number, raw in enumerate(text.splitlines(), 1):
        line = raw
        # A comment, but #123 is a uid and #include is a directive.
        cut = re.search(r"(^|\s)#(?!\d)(?!include)", line)
        if cut:
            line = line[:cut.start()]
        if not buf:
            start = number
        if line.rstrip().endswith("\\"):
            buf += line.rstrip()[:-1] + " "
            continue
        buf += line
        if buf.strip():
            yield start, buf.strip()
        buf = ""


def _parse_sudoers(text: str):
    """-> list of (line, users, runas, [(cmd, nopasswd)])"""
    aliases = {}
    rules = []
    for number, line in _sudoers_lines(text):
        head = line.split(None, 1)[0]
        if head.startswith(("Defaults", "@include", "#include")):
            continue
        if head in ("Cmnd_Alias", "Cmd_Alias"):
            for part in line.split(None, 1)[1].split(":"):
                if "=" in part:
                    name, value = part.split("=", 1)
                    aliases[name.strip()] = [c.strip() for c in value.split(",") if c.strip()]
            continue
        if head in ("User_Alias", "Runas_Alias", "Host_Alias"):
            continue
        if "=" not in line:
            continue
        left, right = line.split("=", 1)
        users = [u.strip() for u in left.split()[0].split(",") if u.strip()] if left.split() else []
        # The tags also use ':', and they are a fixed vocabulary, so they are
        # taken off each command rather than split on.
        runas = "root"
        body = right.strip()
        m = re.match(r"\(([^)]*)\)\s*", body)
        if m:
            runas = m.group(1).split(":")[0].strip() or "root"
            body = body[m.end():]
        cmds = []
        nopasswd = False
        for piece in body.split(","):
            piece = piece.strip()
            while True:
                t = re.match(r"(NOPASSWD|PASSWD|NOEXEC|EXEC|SETENV|NOSETENV|LOG_INPUT|"
                             r"NOLOG_INPUT|LOG_OUTPUT|NOLOG_OUTPUT|MAIL|NOMAIL|FOLLOW|"
                             r"NOFOLLOW|INTERCEPT|NOINTERCEPT)\s*:\s*", piece)
                if not t:
                    break
                if t.group(1) == "NOPASSWD":
                    nopasswd = True
                elif t.group(1) == "PASSWD":
                    nopasswd = False
                piece = piece[t.end():]
            if not piece:
                continue
            for cmd in aliases.get(piece, [piece]):
                cmds.append((cmd, nopasswd))
        rules.append((number, users, runas, cmds))
    return rules


def _classify(cmd: str, owner_of):
    """-> (severity, reason) or None for a sudo command that is safe enough."""
    cmd = cmd.strip()
    if cmd.startswith("!"):
        return None
    if cmd in ("ALL", "(ALL) ALL"):
        return "high", "every command"
    try:
        argv = shlex.split(cmd)
    except ValueError:
        argv = cmd.split()
    if not argv:
        return None
    prog = argv[0]
    name = prog.rsplit("/", 1)[-1]
    args = argv[1:]
    wild = (not args) or any("*" in a or "?" in a or "[" in a for a in args)
    if name in SHELLS:
        return "high", f"{prog}, a shell"
    if INTERPRETERS.match(name):
        if wild:
            return "high", f"{prog} with any arguments, which runs arbitrary commands"
        scripts = [a for a in args if a.startswith("/")]
        for script in scripts:
            owner = owner_of(script)
            if owner not in (None, 0):
                return "high", f"{prog} {script}, and {script} belongs to uid {owner}"
        return None
    if name in WRITERS:
        if wild:
            return "high", f"{prog} with any arguments, which writes any file as root"
        targets = [a for a in args if a.startswith("/")]
        if not targets:
            return None
        exec_hit = [t for t in targets if EXEC_SIGNIFICANT.match(t)]
        if exec_hit:
            return "high", (f"{prog} {' '.join(args)}, which lets the content of "
                            f"{exec_hit[0]} be chosen, and root acts on that file")
        if name in ("tee", "cp", "mv", "dd", "install", "sed", "truncate", "cat",
                    "ln", "unzip", "patch"):
            return "medium", (f"{prog} {' '.join(args)}, which lets the content of "
                              f"{targets[-1]} be replaced as root")
        return None
    # A fixed command line to any other program, such as a service reload, is
    # the narrow grant sudo exists for.
    return None


def sudo_findings(fs: str, meta: dict, repository: str, image: str):
    files = []
    if os.path.isfile(os.path.join(fs, "etc/sudoers")):
        files.append("etc/sudoers")
    sd = os.path.join(fs, "etc/sudoers.d")
    if os.path.isdir(sd):
        for name in sorted(os.listdir(sd)):
            # sudo skips these, so a rule in one is not in force.
            if "." in name or name.endswith("~"):
                continue
            files.append("etc/sudoers.d/" + name)

    def owner_of(path):
        entry = meta.get("files", {}).get(path.lstrip("/"))
        return entry[0] if entry else None

    out = []
    for rel in files:
        text = read_text(os.path.join(fs, rel))
        grants = {}
        for number, users, runas, cmds in _parse_sudoers(text):
            if runas not in ("root", "ALL", "#0", "0"):
                continue
            for user in users:
                if user in ("root", "#0"):
                    continue
                for cmd, nopasswd in cmds:
                    if not nopasswd:
                        continue
                    verdict = _classify(cmd, owner_of)
                    if verdict:
                        grants.setdefault(user, []).append((number, verdict))
        for user, hits in grants.items():
            rank = {"high": 0, "medium": 1}
            hits.sort(key=lambda h: (rank[h[1][0]], h[0]))
            severity = hits[0][1][0]
            reasons = []
            for _, (_, reason) in hits:
                if reason not in reasons:
                    reasons.append(reason)
            shown = "; ".join(reasons[:5]) + (f"; and {len(reasons) - 5} more" if len(reasons) > 5 else "")
            who = f"members of the group {user[1:]}" if user.startswith("%") else f"the account {user}"
            effect = ("Anything that runs as that account, such as code an attacker gets to "
                      "run through the application, becomes root." if severity == "high" else
                      "Anything that runs as that account can rewrite those root-owned "
                      "files, for example to switch a security control off.")
            out.append(finding(
                "image.sudo-root-grant", severity,
                f"sudo lets {who} act as root without a password",
                f"/{rel} lets {who} run, as root and without a password: {shown}.  {effect}",
                "Remove the rule.  If the application must change something only root "
                "may change, give it a narrow helper that takes no free-form input, or "
                "make the change at build time.",
                "/" + rel, hits[0][0], image, resource=f"{rel}#{user}",
                repository=repository, cwe="269"))
    return out


# --- what root runs -------------------------------------------------------

RUNNERS = re.compile(
    r"(?:^|[\s;&|(`$'\"])(?:(?:/usr(?:/local)?)?/bin/)?"
    r"(?:php[\d.]*|python[\d.]*|perl|ruby|node|bash|sh|dash|source|\.)"
    r"(?:\s+-[-\w=]+(?:\s+[-\w=.]+)?)*\s+['\"]?(/[\w.@+/-]+)")
REQUIRES = re.compile(r"\b(?:require|require_once|include|include_once|source|load)\b"
                      r"\s*\(?\s*['\"](/[\w.@+/-]+)['\"]")
BARE_EXEC = re.compile(r"^\s*(?:exec\s+)?(/[\w.@+/-]+\.(?:sh|php|py|pl|rb|js))\b")


def _executed_paths(text: str):
    """(line number, path) for each file a script hands to an interpreter,
    up to the first line that drops privileges for good."""
    out = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if DROP.search(stripped):
            if re.match(r"^\s*exec\b", stripped):
                break               # everything after runs as someone else
            continue                # this one line runs as someone else
        for regex in (RUNNERS, REQUIRES, BARE_EXEC):
            for m in regex.finditer(line):
                out.append((number, m.group(1)))
    return out


def _root_cron_jobs(fs: str):
    """(file, line number, command) for every job root runs from cron."""
    out = []
    candidates = ["etc/crontab"]
    cd = os.path.join(fs, "etc/cron.d")
    if os.path.isdir(cd):
        candidates += ["etc/cron.d/" + n for n in sorted(os.listdir(cd))
                       if "." not in n and not n.endswith("~")]
    for rel in candidates:
        for number, line in enumerate(read_text(os.path.join(fs, rel)).splitlines(), 1):
            s = line.strip()
            if not s or s.startswith("#") or re.match(r"^[A-Z_]+\s*=", s):
                continue
            parts = s.split(None, 6) if not s.startswith("@") else s.split(None, 2)
            if s.startswith("@") and len(parts) == 3:
                user, cmd = parts[1], parts[2]
            elif len(parts) == 7:
                user, cmd = parts[5], parts[6]
            else:
                continue
            if user == "root":
                out.append((rel, number, cmd))
    spool = "var/spool/cron/crontabs/root"
    for number, line in enumerate(read_text(os.path.join(fs, spool)).splitlines(), 1):
        s = line.strip()
        if s and not s.startswith("#") and not re.match(r"^[A-Z_]+\s*=", s):
            parts = s.split(None, 5) if not s.startswith("@") else s.split(None, 1)
            if len(parts) >= 2:
                out.append((spool, number, parts[-1]))
    return out


def _supervisor_programs(fs: str):
    out = []
    for base in ("etc/supervisor/conf.d", "etc/supervisord.d", "etc/supervisor"):
        d = os.path.join(fs, base)
        if not os.path.isdir(d):
            continue
        for name in sorted(os.listdir(d)):
            if not name.endswith((".conf", ".ini")):
                continue
            rel = f"{base}/{name}"
            section, user, command, cline = None, "", "", 0
            lines = read_text(os.path.join(fs, rel)).splitlines() + ["[end]"]
            for number, line in enumerate(lines, 1):
                s = line.strip()
                if s.startswith("["):
                    if section and command and user in ("", "root"):
                        out.append((rel, cline, command))
                    section = s if s.startswith("[program:") else None
                    user, command = "", ""
                elif section and "=" in s:
                    key, value = [x.strip() for x in s.split("=", 1)]
                    if key == "user":
                        user = value
                    elif key == "command":
                        command, cline = value, number
    return out


def service_accounts(fs: str, meta: dict) -> set:
    """Accounts something in the image actually runs as, apart from root.

    A file owned by an account nothing runs as, such as nobody, or a uid left
    over from a tarball, cannot be rewritten by anyone who has broken in, so
    root running it is not a way up.  The accounts that matter are the ones a
    web server, a PHP pool, a cron job, a supervisor program or the start
    script after it drops privileges run as.
    """
    names = set()
    envvars = read_text(os.path.join(fs, "etc/apache2/envvars"))
    if envvars:
        m = re.search(r"APACHE_RUN_USER[:=]-?\$?\{?[A-Z_]*:?-?([a-z_][\w-]*)", envvars)
        names.add(m.group(1) if m else "www-data")
    for conf in ("etc/nginx/nginx.conf", "usr/local/apache2/conf/httpd.conf",
                 "etc/httpd/conf/httpd.conf", "etc/apache2/apache2.conf"):
        text = read_text(os.path.join(fs, conf))
        for m in re.finditer(r"^\s*(?:user|User)\s+([a-z_][\w-]*)", text, re.M):
            names.add(m.group(1))
    for base in ("usr/local/etc/php-fpm.d", "etc/php-fpm.d"):
        d = os.path.join(fs, base)
        if os.path.isdir(d):
            for name in os.listdir(d):
                for m in re.finditer(r"^\s*user\s*=\s*([a-z_][\w-]*)",
                                     read_text(os.path.join(d, name)), re.M):
                    names.add(m.group(1))
    php = os.path.join(fs, "etc/php")
    if os.path.isdir(php):
        for base, _, files in os.walk(php):
            if base.endswith("pool.d"):
                for name in files:
                    for m in re.finditer(r"^\s*user\s*=\s*([a-z_][\w-]*)",
                                         read_text(os.path.join(base, name)), re.M):
                        names.add(m.group(1))
    for candidate in ["etc/crontab"] + ["etc/cron.d/" + n for n in
                                         (os.listdir(os.path.join(fs, "etc/cron.d"))
                                          if os.path.isdir(os.path.join(fs, "etc/cron.d")) else [])]:
        for line in read_text(os.path.join(fs, candidate)).splitlines():
            parts = line.split(None, 6)
            if len(parts) == 7 and not line.lstrip().startswith("#") and \
                    re.match(r"^[\d*/,@-]", parts[0]):
                names.add(parts[5])
    for base in ("etc/supervisor/conf.d", "etc/supervisord.d", "etc/supervisor"):
        d = os.path.join(fs, base)
        if os.path.isdir(d):
            for name in os.listdir(d):
                for m in re.finditer(r"^\s*user\s*=\s*([a-z_][\w-]*)",
                                     read_text(os.path.join(d, name)), re.M):
                    names.add(m.group(1))
    user = str(meta.get("user") or "").split(":")[0]
    if user and user not in ("root", "0"):
        names.add(user)
    for arg in list(meta.get("entrypoint") or []) + list(meta.get("cmd") or []):
        if arg.startswith("/"):
            text = read_text(os.path.join(fs, arg.lstrip("/")))
            for m in re.finditer(r"\b(?:gosu|su-exec|runuser\s+-u|s6-setuidgid|chpst\s+-u|"
                                 r"sudo\s+-u|setuidgid)\s+['\"]?([a-z_][\w-]*)", text):
                names.add(m.group(1))
    names.discard("root")
    names.discard("nobody")
    return names


def root_runs_findings(fs: str, meta: dict, repository: str, image: str):
    files = meta.get("files", {})
    passwd = {}
    for line in read_text(os.path.join(fs, "etc/passwd")).splitlines():
        parts = line.split(":")
        if len(parts) > 3 and parts[2].isdigit():
            passwd.setdefault(int(parts[2]), parts[0])
    running = service_accounts(fs, meta)

    def owner(path):
        entry = files.get(path.lstrip("/"))
        if not entry or entry[5] != "f":
            return None
        return entry[0]

    def name(uid):
        return passwd.get(uid, f"uid {uid}")

    sources = []          # (what, where, line, [(line, path)])
    start = "The image starts as root and its start command"
    user = str(meta.get("user") or "").split(":")[0]
    if user in ("", "root", "0"):
        argv = list(meta.get("entrypoint") or []) + list(meta.get("cmd") or [])
        if argv and argv[0].rsplit("/", 1)[-1] in ("sh", "bash", "dash") and "-c" in argv:
            at = argv.index("-c") + 1
            text = argv[at] if at < len(argv) else ""
            sources.append((start, "the image's start command", 0,
                            [(0, p) for _, p in _executed_paths(text)]))
        else:
            for arg in argv[:2]:
                if not arg.startswith("/") or owner(arg) is None:
                    continue
                hits = [(0, arg)]
                hits += _executed_paths(read_text(os.path.join(fs, arg.lstrip("/"))))
                sources.append((start, arg, 0, hits))
    for rel, number, cmd in _root_cron_jobs(fs):
        sources.append(("A cron job that runs as root", "/" + rel, number,
                        [(number, p) for _, p in _executed_paths(cmd)]))
    for rel, number, cmd in _supervisor_programs(fs):
        if DROP.search(cmd):
            continue
        sources.append(("A supervisor program that runs as root", "/" + rel, number,
                        [(number, p) for _, p in _executed_paths(cmd)]))

    out = []
    for what, where, number, hits in sources:
        risky, seen = [], set()
        for line, path in hits:
            uid = owner(path)
            if uid in (None, 0) or path in seen or passwd.get(uid) not in running:
                continue
            seen.add(path)
            risky.append((line, path, uid))
        if not risky:
            continue
        accounts = sorted({name(uid) for _, _, uid in risky})
        shown = ", ".join(f"{p} ({name(u)})" for _, p, u in risky[:6])
        if len(risky) > 6:
            shown += f" and {len(risky) - 6} more"
        out.append(finding(
            "image.root-runs-writable-code", "medium",
            f"Root runs code that {', '.join(accounts)} can change",
            f"{what} ({where}) runs files that belong to {', '.join(accounts)}: {shown}.  "
            f"The owner of a file can rewrite it, so anything running as "
            f"{' or '.join(accounts)}, such as code an attacker gets to run through the "
            f"application, can choose what root runs the next time this starts.",
            "Make the files root runs owned by root and not writable by the service "
            "account, or drop privileges before running them.",
            where, risky[0][0] or number, image, resource=where,
            repository=repository, cwe="250"))
    return out


# --- web roots and unreviewed source -------------------------------------

WEB_ROOTS = re.compile(r"^(var/www/[^/]+|var/www|usr/share/nginx/html|srv/www|srv/http|"
                       r"app/public|public_html|usr/local/apache2/htdocs)/")
APP_ROOTS = re.compile(r"^(var/www|srv|app|home/[^/]+|usr/src/app|workspace|code)/")
SOURCE_EXT = re.compile(r"\.(php|phtml|inc|py|rb|pl|cgi|jsp|aspx?|cfm|sh)$", re.I)
NOT_SOURCE_DIRS = re.compile(
    r"(^|/)(vendor|node_modules|site-packages|dist-packages|__pycache__|cache|\.cache|"
    r"tmp|logs?|storage|uploads?|sessions?|generated|dist|build|\.git|bootstrap/cache|"
    r"\.composer|\.npm|\.local|\.config|venv|\.venv|env|lib/python[\d.]+)/", re.I)


def git_dir_findings(meta: dict, repository: str, image: str):
    roots = set()
    for path in meta.get("files", {}):
        # A repository is a .git directory with a HEAD in it, anywhere under
        # a web root.
        if path.endswith("/.git/HEAD") and WEB_ROOTS.match(path):
            roots.add(path[: -len("/HEAD")])
    out = []
    for git in sorted(roots)[:5]:
        out.append(finding(
            "image.git-directory-in-web-root", "low",
            "A .git directory ships inside a web root",
            f"/{git} is inside a directory a web server serves.  If the server hands "
            "it out, anyone can download the source code and its full history, "
            "including anything ever committed and later removed.",
            "Leave .git out of the image (.dockerignore), or deny it in the web "
            "server's configuration.",
            "/" + git, 0, image, resource=git, repository=repository, cwe="527"))
    return out


def repo_basenames(repo_dir: str):
    names = set()
    for base, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d != ".git"]
        names.update(files)
    return names


def unreviewed_source_findings(meta: dict, repo_dir: str, repository: str, image: str):
    if not repo_dir or not os.path.isdir(repo_dir):
        return []
    known = repo_basenames(repo_dir)
    only = []
    for path, entry in meta.get("files", {}).items():
        if entry[5] != "f" or not APP_ROOTS.match(path) or NOT_SOURCE_DIRS.search(path):
            continue
        if not SOURCE_EXT.search(path):
            continue
        if path.rsplit("/", 1)[-1] in known:
            continue
        only.append(path)
    if not only:
        return []
    only.sort()
    shown = ", ".join("/" + p for p in only[:10]) + \
        (f" and {len(only) - 10} more" if len(only) > 10 else "")
    return [finding(
        "image.source-not-in-repository", "info",
        f"The image ships {len(only)} source file(s) that are not in this repository",
        f"These files are in the published image, and no file of the same name is "
        f"anywhere in the repository it is built from: {shown}.  A review of the "
        "repository never read them.",
        "Build the image only from reviewed source, or bring these files into the "
        "repository so they are reviewed.",
        "/" + only[0], 0, image, resource="source-not-in-repository",
        repository=repository, cwe="1357")]


# --- entry points ---------------------------------------------------------

def run_image(outdir, repo_dir, repository, image):
    with open(os.path.join(outdir, "meta.json"), encoding="utf-8") as handle:
        meta = json.load(handle)
    fs = os.path.join(outdir, "scan", "fs")
    out = []
    out += sudo_findings(fs, meta, repository, image)
    out += root_runs_findings(fs, meta, repository, image)
    kept = []
    for base, dirs, files in os.walk(fs):
        for name in files:
            kept.append(os.path.relpath(os.path.join(base, name), fs))
    out += archive_findings(fs, kept, lambda rel: "/" + rel, image, repository)
    out += git_dir_findings(meta, repository, image)
    out += unreviewed_source_findings(meta, repo_dir, repository, image)
    return out


def run_repo(repo_dir, repository, branch, web, link):
    rels = []
    for base, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor")]
        for name in files:
            if ARCHIVE.search(name):
                rels.append(os.path.relpath(os.path.join(base, name), repo_dir))

    def url_for(rel):
        if not (web and branch):
            return ""
        return f"{web}/{repository}/{link.get('blob', 'blob')}/{branch}/{rel}"

    rows = archive_findings(repo_dir, rels, lambda rel: rel, "", repository, url_for)
    for row in rows:
        row["branch"] = branch
    return rows


# --- which images a repository publishes ---------------------------------

COMPOSE = re.compile(r"^(docker-)?compose(\.[\w-]+)?\.ya?ml$", re.I)
UNRESOLVED = re.compile(r"[$]|\{\{|<<|%\(")


def _clean_ref(value) -> str:
    ref = str(value or "").strip().strip("'\"")
    if not ref or UNRESOLVED.search(ref) or " " in ref or len(ref) > 300:
        return ""
    return ref


def shipped_refs(repo_dir: str, cap: int = 3):
    """Images this repository builds and publishes, by literal reference.

    Only where the repository itself says so: a compose service that both
    builds from the repository and names the image it tags, or a workflow
    step that pushes a named tag.  A reference with a variable in it is left
    out rather than guessed, and so is anything under tests or examples.
    """
    try:
        import yaml                     # the scanner venv has it
    except ImportError:
        yaml = None
    found = []

    def add(ref, source):
        ref = _clean_ref(ref)
        if ref and ref not in [f["ref"] for f in found]:
            found.append({"ref": ref, "source": source})

    for base, dirs, files in os.walk(repo_dir):
        dirs[:] = [d for d in dirs if d not in (".git", "node_modules", "vendor")
                   and not TEST_PATH.search(d + "/")]
        rel_base = os.path.relpath(base, repo_dir)
        for name in files:
            rel = os.path.normpath(os.path.join(rel_base, name))
            path = os.path.join(base, name)
            if COMPOSE.match(name) and yaml is not None:
                try:
                    doc = yaml.safe_load(read_text(path, 512_000)) or {}
                except yaml.YAMLError:
                    continue
                services = doc.get("services") if isinstance(doc, dict) else None
                for svc in (services or {}).values():
                    if isinstance(svc, dict) and svc.get("build") and svc.get("image"):
                        add(svc["image"], rel)
            elif rel.startswith(".github/workflows/") and name.endswith((".yml", ".yaml")) \
                    and yaml is not None:
                try:
                    doc = yaml.safe_load(read_text(path, 512_000)) or {}
                except yaml.YAMLError:
                    continue
                for job in (doc.get("jobs") or {}).values() if isinstance(doc, dict) else []:
                    for step in (job or {}).get("steps") or []:
                        if not isinstance(step, dict):
                            continue
                        uses = str(step.get("uses") or "")
                        args = step.get("with") or {}
                        if uses.startswith("docker/build-push-action") and \
                                str(args.get("push")).lower() == "true":
                            tags = args.get("tags") or ""
                            for tag in re.split(r"[\s,]+", str(tags)):
                                add(tag, rel)
                        for line in str(step.get("run") or "").splitlines():
                            m = re.match(r"\s*docker\s+push\s+(\S+)\s*$", line)
                            if m:
                                add(m.group(1), rel)
            if len(found) >= cap:
                return found
    return found


# --- before the credential pass ------------------------------------------

def prune(outdir: str, repo_dir: str) -> int:
    """Delete the image files the credential pass need not read again.

    A file identical to one in the repository was read there.  A copy a
    later layer replaced with the same bytes, or the same file staged in
    two places, is one file.  What is left is what only the image has.
    """
    import hashlib

    def digest(path):
        h = hashlib.sha256()
        try:
            with open(path, "rb") as handle:
                for block in iter(lambda: handle.read(1 << 16), b""):
                    h.update(block)
        except OSError:
            return None
        return h.hexdigest()

    seen = set()
    if repo_dir and os.path.isdir(repo_dir):
        for base, dirs, files in os.walk(repo_dir):
            dirs[:] = [d for d in dirs if d != ".git"]
            for name in files:
                path = os.path.join(base, name)
                try:
                    if os.path.islink(path) or os.path.getsize(path) > 2 * 1024 * 1024:
                        continue
                except OSError:
                    continue
                d = digest(path)
                if d:
                    seen.add(d)
    removed = 0
    scan = os.path.join(outdir, "scan")
    # The final image first, so a deleted copy of a file that still ships is
    # the one dropped.
    for top in ("fs", "deleted"):
        for base, dirs, files in os.walk(os.path.join(scan, top)):
            dirs.sort()
            for name in sorted(files):
                path = os.path.join(base, name)
                d = digest(path)
                if d is None:
                    continue
                if d in seen:
                    os.unlink(path)
                    removed += 1
                else:
                    seen.add(d)
    return removed


def main(argv) -> int:
    if len(argv) >= 6 and argv[1] == "image":
        rows = run_image(argv[2], argv[3], argv[4], argv[5])
    elif len(argv) >= 7 and argv[1] == "repo":
        rows = run_repo(argv[2], argv[3], argv[4], argv[5], json.loads(argv[6] or "{}"))
    elif len(argv) >= 3 and argv[1] == "refs":
        rows = shipped_refs(argv[2], int(argv[3]) if len(argv) > 3 else 3)
    elif len(argv) >= 4 and argv[1] == "prune":
        rows = {"removed": prune(argv[2], argv[3])}
    else:
        print(__doc__, file=sys.stderr)
        return 2
    json.dump(rows, sys.stdout)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
