"""Verified real world precedent for a weakness class.

The point is factual grounding.  A language model asked for a real world
example of a weakness will happily invent a CVE number, a company and a breach
size.  So the examples do not come from the model: they live here, vetted, each
one a well documented public incident with a reference a reader can check.  The
triage prompt is handed the matching entry as a fact to reason from, and the
report renders it straight from this table, so what a reader sees is sourced
here, not from the model's memory.

Each entry is one weakness class: how an attacker abuses it, a documented real
world case, and a checkable reference.  A class is only listed when there is a
genuinely well documented public incident for it; a low or informational
finding with no real precedent gets none, rather than an inflated one.

Match order matters: the most specific, highest impact classes come first, so
an injection that leads to code execution is read as code execution, not as a
generic injection.
"""

from __future__ import annotations

import re

# Each: a matcher over the finding's text, the OWASP and CWE anchors, how the
# class is abused, and a documented real world case with a reference.  Keep the
# facts conservative and checkable; never add a case that is not well sourced.
PRECEDENTS = [
    {
        "key": "rce",
        "match": re.compile(r"remote code|command inj|\brce\b|code exec|os command|"
                            r"deserial|CWE-?(?:78|94|77|502)\b", re.I),
        "ref": "CVE-2017-5638; OWASP A03:2021",
        "abuse": "The attacker sends crafted input that the server runs as code, "
                 "takes control of the host, then reaches the data and systems "
                 "behind it.",
        "precedent": "The 2017 Equifax breach, which exposed data on about 147 "
                     "million people, began with an unpatched remote code "
                     "execution flaw in Apache Struts (CVE-2017-5638).",
    },
    {
        "key": "ssrf",
        "match": re.compile(r"\bssrf\b|server.side request|CWE-?918\b", re.I),
        "ref": "OWASP A10:2021; CWE-918",
        "abuse": "The attacker makes the server fetch a URL of their choosing, "
                 "reaching internal services the outside cannot, such as a cloud "
                 "metadata endpoint, and reading back what it returns.",
        "precedent": "The 2019 Capital One breach, which affected about 100 "
                     "million people, used server side request forgery to reach "
                     "the cloud metadata service and take credentials from it.",
    },
    {
        "key": "sqli",
        "match": re.compile(r"sql\s*inj|\bsqli\b|CWE-?89\b", re.I),
        "ref": "OWASP A03:2021; CWE-89",
        "abuse": "The attacker puts database syntax into a parameter to read or "
                 "change data the query never meant to expose, often dumping whole "
                 "tables of accounts or payment records.",
        "precedent": "SQL injection was the entry point for the 2008 Heartland "
                     "Payment Systems breach, about 130 million card numbers, and "
                     "the 2015 TalkTalk breach, for which the UK regulator fined "
                     "the company.",
    },
    {
        "key": "xss",
        "match": re.compile(r"\bxss\b|cross.site.script|CWE-?79\b", re.I),
        "ref": "OWASP A03:2021; CWE-79",
        "abuse": "The attacker gets script to run in another user's session, so it "
                 "acts as that user: stealing the session, changing their account, "
                 "or spreading to everyone who views the page.",
        "precedent": "The 2005 Samy worm used a stored cross site script to add "
                     "over a million MySpace friends in under a day, by running in "
                     "the session of everyone who viewed an infected profile.",
    },
    {
        "key": "bola",
        "match": re.compile(r"\bidor\b|\bbola\b|broken object|object level auth|"
                            r"insecure direct object|CWE-?639\b", re.I),
        "ref": "OWASP API1:2023; CWE-639",
        "abuse": "The attacker changes an id in a URL or request and reads or edits "
                 "records that belong to other users, walking the ids to reach many "
                 "accounts at once.",
        "precedent": "The 2019 First American Financial exposure, about 885 million "
                     "documents, and the 2018 USPS Informed Visibility API both let "
                     "anyone read other people's records by changing an id, each "
                     "documented publicly at the time.",
    },
    {
        "key": "secret",
        "match": re.compile(r"api.?key|secret|hardcoded|private key|credential|"
                            r"access.key|\.htpasswd|\.npmrc|id_rsa|CWE-?798\b", re.I),
        "ref": "CWE-798; OWASP A05:2021",
        "abuse": "The attacker reads the exposed key or password and uses it to sign "
                 "in to the service it belongs to, with whatever access that key "
                 "was granted, no guessing required.",
        "precedent": "The 2016 Uber breach, about 57 million riders and drivers, "
                     "happened because a cloud access key sat in a code repository "
                     "the attackers were able to reach.",
    },
    {
        "key": "graphql-amplification",
        "match": re.compile(r"amplif|aliased|batch|rate limit|CWE-?770\b|"
                            r"API4:2023", re.I),
        "ref": "OWASP API4:2023; CWE-770",
        "abuse": "The attacker packs many operations into one request, so a single "
                 "call becomes many login or one time code attempts, and the per "
                 "request rate limit and edge counting never see the real volume.",
        "precedent": "Bypassing login and one time code rate limits by batching or "
                     "aliasing GraphQL operations is a documented technique, "
                     "recognised in the OWASP API Security Top 10 as unrestricted "
                     "resource consumption.",
    },
    {
        "key": "credential-stuffing",
        "match": re.compile(r"brute.?forc|credential stuff|weak password|"
                            r"password spray|CWE-?307\b", re.I),
        "ref": "OWASP A07:2021; CWE-307",
        "abuse": "The attacker tries large lists of guessed or reused passwords "
                 "against the login, and every account whose password is weak or "
                 "reused is taken over.",
        "precedent": "Credential stuffing against Nintendo in 2020 compromised "
                     "about 300,000 accounts by reusing passwords leaked from other "
                     "sites.",
    },
    {
        "key": "cors",
        "match": re.compile(r"\bcors\b|cross.origin resource sharing|"
                            r"access-control-allow-origin|CWE-?942\b", re.I),
        "ref": "CWE-942; OWASP A05:2021",
        "abuse": "A malicious site that a signed-in user visits makes a credentialed "
                 "cross-origin request to this site and reads the authenticated "
                 "response, taking the user's own data.",
        "precedent": "A permissive CORS policy that reflects any origin with "
                     "credentials is a well documented cause of cross-origin data "
                     "theft, recognised in OWASP guidance and reported in many "
                     "public disclosures.",
    },
    {
        "key": "open-redirect",
        "match": re.compile(r"open redirect|unvalidated redirect|CWE-?601\b", re.I),
        "ref": "CWE-601; OWASP A01:2021",
        "abuse": "The attacker crafts a link on this trusted site that bounces the "
                 "visitor to a site they control, for phishing or to capture an "
                 "OAuth token from a sign-in response.",
        "precedent": "Open redirects are a standard phishing and OAuth token theft "
                     "technique, documented in the OWASP Top 10 and used repeatedly "
                     "against sign-in flows.",
    },
    {
        "key": "host-header-injection",
        "match": re.compile(r"host header|host injection|password reset poison|"
                            r"cache poison|CWE-?644\b", re.I),
        "ref": "CWE-644",
        "abuse": "The attacker sets the Host header so the site builds a password "
                 "reset link, or a cached page, that points at the attacker's "
                 "server, then waits for a victim to use it.",
        "precedent": "Host header injection that poisons password reset emails and "
                     "web caches is a documented technique, described by security "
                     "researchers and in OWASP guidance.",
    },
    {
        "key": "data-exposure",
        "match": re.compile(r"directory listing|directory index|exposed backup|"
                            r"\.bak\b|\.sql\b|open to the world|publicly readable|"
                            r"exposed .*(database|dump|backup)|CWE-?(?:538|548)\b", re.I),
        "ref": "OWASP A05:2021; CWE-200",
        "abuse": "The attacker reads files or listings the site left open, taking "
                 "backups, database dumps or source that were never meant to be "
                 "public.",
        "precedent": "Misconfigured, publicly readable cloud storage has exposed "
                     "data repeatedly, such as the 2017 exposure of about 14 "
                     "million Verizon customer records left open on a storage "
                     "bucket.",
    },
]


def match(f: dict):
    """The precedent for a finding's weakness class, or None.

    Matched on the finding's own text, most specific class first, so nothing is
    attached unless the finding clearly belongs to a class with a documented
    real world case."""
    text = " ".join(str(f.get(k) or "") for k in ("title", "cwe", "evidence", "url"))
    for p in PRECEDENTS:
        if p["match"].search(text):
            return {"class": p["key"], "abuse": p["abuse"],
                    "precedent": p["precedent"], "reference": p["ref"]}
    return None


def annotate(findings: list) -> list:
    """Add the verified abuse description, real world precedent and reference to
    each finding that belongs to a documented class, in place.  Findings with no
    documented precedent are left untouched, never given an inflated one."""
    for f in findings:
        p = match(f)
        if p:
            f["abuse"] = p["abuse"]
            f["precedent"] = p["precedent"]
            f["precedent_ref"] = p["reference"]
            f["weakness_class"] = p["class"]
    return findings
