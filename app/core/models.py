"""Tables.

Findings are keyed by a fingerprint, not a row id.  The same secret or the same
CVE shows up on every scan, and we want one row that gets updated rather than a
new one each night.  That is also what makes last_found mean anything.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean, Column, DateTime, Enum, Float, ForeignKey, Index, Integer,
    String, Table, Text, UniqueConstraint,
)
from sqlalchemy.dialects.mysql import MEDIUMTEXT
from sqlalchemy.orm import declarative_base, relationship

# MySQL TEXT stops at 65,535 bytes, which sounds like plenty until one finding
# turns out to be reachable from every branch of a repository that has
# thousands of them.  SQLite does not care either way, so this only changes
# what MariaDB is asked for.
LONG_JSON = Text().with_variant(MEDIUMTEXT, "mysql")

Base = declarative_base()


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def vuln_id_for(fingerprint: str) -> str:
    """The readable id for a fingerprint.

    Same input, same id, every time.  Twelve hex characters is 48 bits, so two
    different findings landing on the same id is not something that happens to
    a real estate of repositories.
    """
    import hashlib

    digest = hashlib.sha256((fingerprint or "").encode()).hexdigest()
    return "GCR-" + digest[:12].upper()


class UserRole(str, enum.Enum):
    """Three roles, and the gap between them is on purpose.

    admin runs the place.  developer sees only what they have been given.
    reader sees everything but cannot change anything.
    """

    ADMIN = "admin"
    DEVELOPER = "developer"
    READER = "reader"


class AuthSource(str, enum.Enum):
    LOCAL = "local"
    OIDC = "oidc"


class FindingKind(str, enum.Enum):
    CREDENTIAL = "credential"
    CODE = "code"
    DEPENDENCY = "dependency"
    # The files that decide where the application runs, rather than what it
    # does.  Filing these as CODE would make that word mean two things.
    MISCONFIGURATION = "misconfiguration"


class Severity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


class FindingState(str, enum.Enum):
    OPEN = "open"
    WAIVED = "waived"
    FIXED = "fixed"


class WaiverStatus(str, enum.Enum):
    """A waiver starts as a request and only an admin can approve it.

    Only APPROVED takes a finding out of the report files.  A developer asking
    for one changes nothing on disk until somebody signs off.
    """

    REQUESTED = "requested"
    APPROVED = "approved"
    REJECTED = "rejected"
    REVOKED = "revoked"


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(120), nullable=False, unique=True, index=True)
    email = Column(String(255), default="")
    display_name = Column(String(255), default="")

    # Who this person is on the host being scanned.
    #
    # An administrator sets it, because nothing else can be trusted to work it
    # out: a sign in name here and a login there are two different things and
    # matching them by guessing would hand somebody the wrong repositories.
    #
    # Once it is set, whatever that login can reach is what this account can
    # see.  Access granted on the host shows up here on the next scan without
    # anybody maintaining a second list of it.
    github_login = Column(String(255), default="", index=True)

    role = Column(Enum(UserRole), nullable=False, default=UserRole.READER)
    source = Column(Enum(AuthSource), nullable=False, default=AuthSource.LOCAL)

    # Hold the role against the provider.
    #
    # The provider owns the role, which is right while it sends group names.
    # When it will not, every sign in rewrites the role to whatever the
    # fallback says, and an administrator cannot give one named person a
    # different one that lasts.  This says leave this account's role alone.
    #
    # It holds the role, not the account.  The provider still decides whether
    # somebody gets in at all, so taking their access away there still works.
    role_pinned = Column(Boolean, default=False, nullable=False)

    password_hash = Column(String(255), default="")
    totp_secret = Column(String(255), default="")
    totp_confirmed = Column(Boolean, default=False, nullable=False)
    recovery_hashes = Column(Text, default="")

    must_change_password = Column(Boolean, default=False, nullable=False)
    disabled = Column(Boolean, default=False, nullable=False)

    failed_logins = Column(Integer, default=0, nullable=False)
    locked_until = Column(DateTime(timezone=True))
    last_login_at = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    scopes = relationship("UserScope", back_populates="user",
                          cascade="all, delete-orphan")
    groups = relationship("ScanGroup", secondary="user_groups",
                          back_populates="members")
    # Which sessions belong to this person.  Named explicitly because a
    # session now points at users twice: whose it is, and whose view it is
    # borrowing.  Without this SQLAlchemy cannot tell which one this means.
    sessions = relationship("Session", back_populates="user",
                            foreign_keys="Session.user_id",
                            cascade="all, delete-orphan")

    @property
    def is_admin(self) -> bool:
        return self.role == UserRole.ADMIN

    @property
    def needs_totp_setup(self) -> bool:
        """Local accounts have to finish TOTP before they can do anything.

        OIDC accounts do not, since the identity provider owns that.
        """
        return self.source == AuthSource.LOCAL and not self.totp_confirmed


# Which groups somebody is in.  A plain association table: the interesting
# part is the group, not the membership.
user_groups = Table(
    "user_groups", Base.metadata,
    Column("user_id", Integer, ForeignKey("users.id", ondelete="CASCADE"),
           primary_key=True),
    Column("group_id", Integer, ForeignKey("scan_groups.id", ondelete="CASCADE"),
           primary_key=True),
)


class ScanGroup(Base):
    """A named set of repositories somebody can be given all at once.

    Project abc has eleven repositories and four people work on it.  Without
    this, that list gets pasted onto four accounts and then drifts: somebody
    adds a repository to the project and three of the four never hear about it.
    Put the list in one place and give people the group.
    """

    __tablename__ = "scan_groups"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False, unique=True, index=True)
    description = Column(Text, default="")

    # One per line, either an organization on its own or organization/repo.
    entries = Column(Text, default="")

    created_by = Column(String(120), default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    members = relationship("User", secondary=user_groups,
                           back_populates="groups")

    def pairs(self) -> list:
        """The organization and repository pairs this group covers."""
        out = []
        for line in (self.entries or "").replace(",", "\n").splitlines():
            entry = line.strip()
            if not entry:
                continue
            organization, _, repository = entry.partition("/")
            out.append((organization.strip(), repository.strip()))
        return out


class UserScope(Base):
    """What a developer is allowed to see.

    An org scope covers every repo under it.  A repo scope is one repo.  Admin
    and reader ignore this table completely.
    """

    __tablename__ = "user_scopes"
    __table_args__ = (
        UniqueConstraint("user_id", "organization", "repository",
                         name="uq_scope"),
    )

    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    organization = Column(String(255), nullable=False)
    # Empty repository means the whole org.
    repository = Column(String(255), default="", nullable=False)
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    user = relationship("User", back_populates="scopes")

    def covers(self, organization: str, repository: str) -> bool:
        if (self.organization or "").lower() != (organization or "").lower():
            return False
        if not self.repository:
            return True
        return (self.repository or "").lower() == (repository or "").lower()


class Session(Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(128), nullable=False, unique=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)

    # A half session is one that got past the password but not TOTP yet.  It
    # cannot reach anything.
    half_auth = Column(Boolean, default=False, nullable=False)

    source_ip = Column(String(64), default="")
    user_agent = Column(String(255), default="")

    # An administrator looking at the product as somebody else, to see the
    # findings and the scope that person sees.  The session still belongs to
    # the administrator: user_id never changes, so the audit log keeps naming
    # the person who is actually at the keyboard.  This only says whose view
    # they are borrowing, and it is read only while it is set.
    impersonating_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"),
                              index=True)
    impersonating_since = Column(DateTime(timezone=True))

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True))
    revoked_reason = Column(String(255), default="")

    user = relationship("User", back_populates="sessions",
                        foreign_keys=[user_id])


class Repository(Base):
    """One row per repo we have seen.  Scans update it, they do not replace it."""

    __tablename__ = "repositories"
    __table_args__ = (
        UniqueConstraint("organization", "name", name="uq_repo"),
    )

    id = Column(Integer, primary_key=True)
    connection_id = Column(Integer, ForeignKey("connections.id",
                                               ondelete="SET NULL"),
                           nullable=True, index=True)
    connection = Column(String(120), default="", index=True)

    organization = Column(String(255), nullable=False, index=True)
    name = Column(String(255), nullable=False, index=True)
    full_name = Column(String(320), nullable=False, index=True)

    visibility = Column(String(32), default="")
    default_branch = Column(String(255), default="")
    archived = Column(Boolean, default=False, nullable=False)
    size_kb = Column(Integer, default=0)
    html_url = Column(String(1024), default="")

    first_seen_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_scanned_at = Column(DateTime(timezone=True))

    # Whether the default branch has any protection rule on it.  The branch
    # list says so for free; the detail of who may push past it needs a call
    # per branch and stays off unless somebody asks for it.
    default_branch_protected = Column(Boolean, default=False, nullable=False)

    # How far back through this repository's history the credential engines
    # have walked, and whether they reached the beginning.
    #
    # A repository whose history is too large to walk inside one time limit
    # used to restart from the newest commit every run and never reach the far
    # end, so the oldest commits - where a credential somebody thought they had
    # deleted actually lives - were never examined at all.  The walk is
    # windowed and this is the marker it resumes from.  Empty means nothing has
    # been walked yet.
    history_from = Column(String(32), default="")
    history_complete = Column(Boolean, default=False, nullable=False)

    # Every branch the last scan actually walked here, as a list of names.
    #
    # The scanner knows this and used to throw it away with the report.  Keeping
    # it means the branch box on a connection can offer what is really there
    # rather than asking somebody to type a name from memory, and it is also the
    # only record afterwards of what a scan covered.
    branch_names = Column(LONG_JSON, default="[]")
    # Branch name to the commit it was on at the last scan.
    #
    # What lets a security sign off know it is out of date.  Names alone say
    # a branch still exists; they cannot say whether anybody pushed to it,
    # and a commit that introduced no finding is still a commit nobody
    # reviewed.
    branch_heads = Column(LONG_JSON, default="{}")
    # Whether a dynamic pass could run against this repository, and why not
    # when it could not.  Read only: nothing is built and nothing is started.
    dast_verdict = Column(String(16), default="")
    dast_reason = Column(String(500), default="")

    # What this particular repository is, who answers for it and what it holds.
    #
    # The connection says these for a whole account, which is right until it is
    # not: one organization routinely holds a cardholder system and a brochure
    # site, owned by different people.  Anything set here wins for this
    # repository; anything left empty falls back to the connection, so tagging
    # is only needed where the account level answer is wrong.
    application_name = Column(String(200), default="")
    application_owner = Column(String(200), default="")
    technical_owner = Column(String(200), default="")
    sensitivity = Column(String(400), default="")
    tagged_by = Column(String(120), default="")
    tagged_at = Column(DateTime(timezone=True))

    # What this repository is, in somebody's own words.
    #
    # The tagging fields above answer fixed questions.  This one is for the
    # sentence that decides what to do and fits none of them: that it is the
    # payment gateway, that it is being retired in March, that the owner left.
    # Read by a person, never matched on.
    note = Column(Text, default="")
    note_by = Column(String(120), default="")
    note_at = Column(DateTime(timezone=True))

    findings = relationship("Finding", back_populates="repo",
                            cascade="all, delete-orphan")


class Baseline(Base):
    """A line drawn on a date, per organization.

    The first scan of a repository with ten years in it comes back with
    thousands of findings, and a team that cannot triage thousands stops
    looking at any of them.  A baseline says: what was already here is the
    backlog, and what turns up after is the work.

    Nothing is deleted or hidden by this.  It decides which of the two lists a
    finding lands in, and both lists stay on the page.  An organization with no
    row here has no line drawn, and every one of its findings counts as new,
    which is what everybody got before this existed.
    """

    __tablename__ = "baselines"
    __table_args__ = (
        UniqueConstraint("organization", name="uq_baseline_org"),
    )

    id = Column(Integer, primary_key=True)
    organization = Column(String(255), nullable=False, index=True)

    # Findings first seen before this are the backlog.  It is the finding's own
    # first_found_at that decides, not the scan it turned up in, so rescanning
    # never moves anything across the line.
    baseline_at = Column(DateTime(timezone=True), nullable=False)

    set_by = Column(String(120), default="")
    set_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    note = Column(Text, default="")


class Finding(Base):
    """A credential, a code weakness or a vulnerable package.

    fingerprint is what makes a finding the same finding across scans.  For a
    secret it comes from the scanner.  For code and dependencies we build one
    from the parts that do not move.
    """

    __tablename__ = "findings"
    __table_args__ = (
        UniqueConstraint("fingerprint", name="uq_finding_fingerprint"),
        Index("ix_finding_lookup", "organization", "repository", "state"),
        Index("ix_finding_sev", "severity", "state"),
    )

    id = Column(Integer, primary_key=True)
    fingerprint = Column(String(128), nullable=False, index=True)

    # The id people use.  GCR- and twelve characters worked out from the
    # fingerprint, so the same finding gets the same id on every install and
    # after every rebuild.  Row ids are not that: they depend on the order
    # things happened to be inserted, and an exception written against one
    # would point at something else on the next machine.
    # Worked out from the fingerprint on the way in, so anything that makes a
    # Finding gets one without having to remember to.
    vuln_id = Column(String(32), nullable=False, unique=True, index=True,
                     default=lambda ctx: vuln_id_for(
                         (ctx.get_current_parameters() or {}).get("fingerprint", "")))

    # One flag, and it is the whole answer to "is this reported".  Set it and
    # the finding leaves vulnerabilities.json and vulnerabilities.csv.  An
    # approved waiver sets it, and so does an exclusion rule that matches at
    # ingest time.  Nothing is deleted: the row and the reason stay.
    excepted = Column(Boolean, default=False, nullable=False, index=True)
    exception_reason = Column(Text, default="")
    exception_by = Column(String(120), default="")
    exception_at = Column(DateTime(timezone=True))
    exception_expires_at = Column(DateTime(timezone=True))

    kind = Column(Enum(FindingKind), nullable=False, index=True)
    severity = Column(Enum(Severity), nullable=False, default=Severity.UNKNOWN)
    state = Column(Enum(FindingState), nullable=False, default=FindingState.OPEN,
                   index=True)

    repo_id = Column(Integer, ForeignKey("repositories.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    # Which account this came from.  Two organizations in different accounts
    # can share a repository name, and a finding has to say which one it means.
    connection_id = Column(Integer, ForeignKey("connections.id",
                                               ondelete="SET NULL"),
                           nullable=True, index=True)
    connection = Column(String(120), default="", index=True)

    organization = Column(String(255), nullable=False, index=True)
    repository = Column(String(320), nullable=False, index=True)
    branch = Column(String(255), default="")
    branches = Column(LONG_JSON, default="[]")

    file_path = Column(String(1024), default="")
    line = Column(Integer, default=0)
    # Where on the line.  An editor underlines a range; a line number alone
    # underlines the whole line and looks broken next to any other linter.
    # Zero means the engine did not say, which trufflehog and the GitHub alerts
    # never do.
    start_column = Column(Integer, default=0)
    end_column = Column(Integer, default=0)

    rule = Column(String(255), default="", index=True)
    title = Column(Text, default="")
    description = Column(Text, default="")

    # Credentials only.  Never the value itself, just the mask and a hash.
    secret_preview = Column(String(255), default="")
    verified = Column(Boolean, default=False, nullable=False)
    exposure = Column(String(64), default="")

    # Dependencies only.
    package_name = Column(String(255), default="")
    package_version = Column(String(128), default="")
    # The package this one was built from, where a distribution says so.
    #
    # One source package ships as many binaries, and a flaw in the source is
    # reported against every binary that came out of it.  A single problem in
    # util-linux arrives as eight findings, against eight package names, with
    # one apt upgrade answering all of them.  Grouping on the binary name
    # cannot see that; grouping on this can.
    #
    # Blank for anything that is not a distribution package, which is most of
    # what gets scanned: an npm or PyPI package is its own source.  The
    # grouping falls back to the package name there, which is correct rather
    # than a compromise, because for those two the name is the thing you
    # upgrade.
    package_source = Column(String(255), default="", index=True)
    ecosystem = Column(String(64), default="")
    vulnerability_id = Column(String(128), default="", index=True)
    cvss_score = Column(Float)
    fixed_in = Column(String(255), default="")
    known_exploited = Column(Boolean, default=False, nullable=False)
    epss_score = Column(Float)

    # Whether the application can actually reach the vulnerable package.
    # Shaped like the triage verdict on a code finding: a value, the reason for
    # it, and nothing removed.  Blank on anything scanned before there was one,
    # and `unknown` wherever the tree could not be read, because a wrong
    # `unlikely` is somebody not looking at the one that mattered.
    # What an administrator says this one finding is worth, when the rule
    # level override is the wrong instrument.  severity_rules regrades a rule
    # everywhere at once, which cannot say anything about one line in one file.
    #
    # `severity` stays the effective grade so every filter, sort and report
    # reads it without knowing this exists.  This column is what makes the
    # decision survive a rescan: ingest reapplies it after the engine and the
    # rule level overrides have had their say.
    custom_severity = Column(Enum(Severity))
    custom_severity_reason = Column(Text, default="")
    custom_severity_by = Column(String(120), default="")
    custom_severity_at = Column(DateTime(timezone=True))

    # The package is the attack, rather than the package having a hole in it.
    # A typosquat, a dependency confusion package or a compromised release has
    # no CVE until well after it has run, so nothing about upgrading helps and
    # the finding has to read differently.
    # Which engines produced this.  Two pointing at the same line is the
    # strongest signal either of them makes, and it is worth keeping rather
    # than blending into one number.
    engines = Column(String(120), default="")
    corroborated = Column(Boolean, default=False, nullable=False)

    # What a leaked token turned out to say about itself.
    #
    # Two of the three parts of a JSON web token are base64 of plain JSON, so
    # anybody holding one can read them without the signing key.  A scanner
    # that reports a token as an unidentified high entropy string is throwing
    # away the only evidence available about how much it matters, and a rule
    # firing ten thousand times is unusable while every long string with a dot
    # in it is still in the count.
    #
    # These are what the value said, not what anybody concluded from it.  The
    # conclusion is impact and likelihood, worked out from these in risk.py.
    #
    # Blank token_kind means it did not decode, which is the useful half: the
    # detector called it a token and it is not one.
    token_kind = Column(String(16), default="", index=True)
    token_alg = Column(String(32), default="")
    token_issuer = Column(String(500), default="")
    token_audience = Column(String(500), default="")
    token_expires_at = Column(DateTime, nullable=True)
    token_issued_at = Column(DateTime, nullable=True)
    # Deliberately nullable, and the nullability is the point.  A token with
    # no expiry at all is not an unexpired token: it is the worse case, one
    # that never stops working, and collapsing that into False would file the
    # most dangerous kind under the same heading as the safest.
    token_expired = Column(Boolean, nullable=True, index=True)
    # Claim names, never claim values.  Answering "this token carries an
    # employee address" by writing that address into this table would make a
    # second copy of the disclosure being reported.
    token_claims = Column(String(1000), default="")
    token_identity_claims = Column(String(500), default="", index=True)
    token_privilege_claims = Column(String(500), default="")

    malicious = Column(Boolean, default=False, nullable=False, index=True)
    malicious_signal = Column(String(32), default="")
    malicious_reason = Column(String(500), default="")
    malicious_evidence = Column(String(500), default="")

    # Which container image this came out of, when it did not come out of a
    # manifest.  Blank for everything found in a checkout.
    image_ref = Column(String(500), default="")
    # Whether the build patches that image after pulling it.
    #
    # A base image is scanned as its registry publishes it, because nothing
    # here builds anything, so a Dockerfile that upgrades three lines below its
    # FROM produces findings about packages the shipped image does not have.
    # This does not remove them: the advisory is true of the image that was
    # read, and an upgrade only moves packages as far as the archive had got on
    # the day of the build.  It moves the finding down the queue and says why.
    base_upgraded = Column(Boolean, default=False, nullable=False)

    reachability = Column(String(16), default="", index=True)
    reachability_reason = Column(String(500), default="")
    # Asked for by name in a manifest, or pulled in by something else.
    dependency_direct = Column(String(16), default="")
    # Whether it ships.  A test framework is a real vulnerability in nothing.
    dependency_scope = Column(String(16), default="")

    # Code findings only.
    # What the engine thought of its own rule.
    #
    # Semgrep tags every rule with these, and a great many of its rules are
    # audit grade: p/security-audit exists to say "a person should look at
    # this", not "this is a bug".  The scanner has always extracted them and
    # the database used to drop them on the floor, so every finding arrived
    # looking equally certain and each one needed its own exception.
    # What the fidelity pass made of it: review, third_party, advisory or
    # not_applicable.  Blank for anything scanned before there was one.
    # What the engine graded it, kept when this organization says otherwise.
    engine_severity = Column(String(16), default="")

    triage = Column(String(16), default="", index=True)
    triage_reason = Column(String(500), default="")

    confidence = Column(String(16), default="", index=True)

    # The two halves of what a severity is standing in for.
    #
    # A severity says both that this would hurt and that somebody could do it,
    # and a rule matching a line is only entitled to an opinion about the
    # first.  These are worked out per finding by `risk.py`: impact from what
    # the system holds, likelihood from the evidence there is.  Indexed because
    # "high impact and happening now" is the shortest useful list in the
    # product and somebody will want to filter on it.
    #
    # Nothing here changes `severity`.  A grade is a decision, and where these
    # two disagree with it the recommendation says so and waits to be accepted.
    impact = Column(String(16), default="", index=True)
    likelihood = Column(String(16), default="", index=True)
    # Why each reads the way it does.  A grade with nothing behind it asks to
    # be trusted and offers nothing to check, which is the failure this file
    # already avoids everywhere else.
    impact_reason = Column(String(500), default="")
    likelihood_reason = Column(String(500), default="")

    # What the engine said about its own rule, kept the way `engine_severity`
    # keeps the grade.  semgrep publishes an impact and a likelihood per rule;
    # both are statements about the rule in the abstract rather than about this
    # system, which is exactly why the columns above exist.  Kept so somebody
    # can see that the rule claimed one thing and the system said another.
    engine_impact = Column(String(16), default="")
    engine_likelihood = Column(String(16), default="")

    # Where this sits in the queue, 1 to 100.  Stored because sorting four
    # thousand findings by it is a job for the database, and worked out from
    # the two columns above plus whatever is genuinely numeric about this one.
    #
    # The band it sits in is the grade those two axes come to, so the number
    # and the word can never disagree.  Nothing sorts below its band because
    # nobody has looked at it yet: an unexamined finding sits in the middle of
    # its band, never at the bottom.
    risk_score = Column(Integer, default=0, index=True)
    # Whether the number is backed by somebody proving this finding, or worked
    # out from the rule and the advisory data.  Beside the score rather than
    # inside it: two findings can deserve the same place in the queue while one
    # is proved and one is guessed, and that difference is the reader's to make
    # use of, not ours to average away.
    risk_evidence = Column(String(16), default="", index=True)

    cwe = Column(String(255), default="")
    owasp = Column(String(255), default="")

    url = Column(String(2048), default="")
    commit_sha = Column(String(64), default="")
    commit_url = Column(String(2048), default="")
    author_name = Column(String(255), default="")
    author_email = Column(String(255), default="")
    author_login = Column(String(255), default="")
    committed_at = Column(DateTime(timezone=True))

    first_found_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    last_found_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    resolved_at = Column(DateTime(timezone=True))

    repo = relationship("Repository", back_populates="findings")
    waiver = relationship("Waiver", back_populates="finding", uselist=False,
                          cascade="all, delete-orphan")


class Certification(Base):
    """A security review of one branch of one repository, and when it lapses.

    Somebody in security reads a codebase, finds nothing they consider unsafe,
    and says so.  That is a real and useful statement, and until now there was
    nowhere to put it: the reviewer's conclusion lived in a ticket somewhere
    and the tool went on showing the same list to the next person.

    It is also the most dangerous thing in this schema, because a green badge
    is read as "this is fine" by everybody who sees it and almost nobody will
    check what it was based on.  So it is deliberately narrow.

    It certifies a branch, not a repository.  The same code on main and on a
    six month old release branch are different code, and a review of one says
    nothing about the other.

    It certifies a moment, not a state.  The commit that was reviewed is
    recorded, so a certification can be shown as describing code that has since
    moved on rather than quietly continuing to vouch for whatever was pushed
    after it.

    It expires, and the date is required.  A review with no end date is a claim
    that nothing will ever change, which is not a claim anybody means to make.

    And it is never a filter.  Nothing here removes a finding, changes a grade
    or keeps anything out of a report: a certified repository that starts
    producing criticals shows exactly the criticals it produces, next to a
    badge that says the review is now out of date.  A certification that could
    hide a finding would be a way of turning one person's confidence into
    everybody else's blind spot.
    """

    __tablename__ = "certifications"
    __table_args__ = (
        UniqueConstraint("repository", "branch", name="uq_certification"),
    )

    id = Column(Integer, primary_key=True)
    repository = Column(String(320), nullable=False, index=True)
    branch = Column(String(255), nullable=False, default="")

    # What was reviewed and what the reviewer concluded.  Required, because a
    # badge whose only content is that somebody clicked a button cannot be
    # argued with by the next person who has to rely on it.
    note = Column(Text, default="")
    # The head this was reviewed at.  What makes staleness detectable rather
    # than assumed.
    commit_sha = Column(String(64), default="")

    certified_by = Column(String(120), default="")
    certified_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)

    # Withdrawing one is not deleting it.  The record that somebody certified
    # this in March, and that somebody else took it back in June, is the part
    # an auditor asks about.
    revoked_at = Column(DateTime(timezone=True))
    revoked_by = Column(String(120), default="")
    revoked_reason = Column(Text, default="")

    def live(self, now: datetime = None) -> bool:
        now = now or utcnow()
        if self.revoked_at is not None:
            return False
        expires = self.expires_at
        # SQLite returns these naive whatever the column says.
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return bool(expires and expires > now)


class Waiver(Base):
    """An exception on a finding.

    Developers can ask for one on a repo they own.  Only an admin can approve
    it.  Once approved, the finding drops out of vulnerabilities.json and
    vulnerabilities.csv completely, because the whole point is that another
    tool reads those files.  A request on its own changes nothing on disk.
    """

    __tablename__ = "waivers"

    id = Column(Integer, primary_key=True)
    finding_id = Column(Integer, ForeignKey("findings.id", ondelete="CASCADE"),
                        nullable=False, unique=True, index=True)

    status = Column(Enum(WaiverStatus), nullable=False,
                    default=WaiverStatus.REQUESTED, index=True)

    reason = Column(Text, nullable=False)
    ticket = Column(String(120), default="")

    requested_by = Column(String(120), nullable=False)
    requested_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    # No open ended exceptions.  When this passes the finding comes back.
    expires_at = Column(DateTime(timezone=True), nullable=False, index=True)

    decided_by = Column(String(120), default="")
    decided_at = Column(DateTime(timezone=True))
    decision_note = Column(Text, default="")

    finding = relationship("Finding", back_populates="waiver")

    def active(self, now: datetime = None) -> bool:
        """True only when an admin approved it and it has not run out."""
        if self.status != WaiverStatus.APPROVED:
            return False
        now = now or utcnow()
        expires = self.expires_at
        if expires is not None and expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires > now

    @property
    def pending(self) -> bool:
        return self.status == WaiverStatus.REQUESTED


class ScanRun(Base):
    __tablename__ = "scan_runs"

    id = Column(Integer, primary_key=True)
    started_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    finished_at = Column(DateTime(timezone=True))
    status = Column(String(32), default="running", index=True)

    triggered_by = Column(String(120), default="")
    trigger = Column(String(32), default="manual")
    scope = Column(Text, default="")
    connection = Column(String(120), default="")

    repositories = Column(Integer, default=0)
    # Scanned is not the same as in scope.  A repository that failed or was
    # skipped used to disappear without trace, and a scan that quietly covered
    # nine of ten repositories reads exactly like one that covered all ten.
    repositories_failed = Column(Integer, default=0)
    repositories_skipped = Column(Integer, default=0)
    # Stopped part way, with what it had already found kept.  Its own count
    # because it is not the same claim as either of the two above: some of the
    # repository was examined and the rest was not, and the report says which
    # passes finished.
    repositories_partial = Column(Integer, default=0)
    branches = Column(Integer, default=0)
    findings_new = Column(Integer, default=0)
    findings_updated = Column(Integer, default=0)
    findings_resolved = Column(Integer, default=0)

    exit_code = Column(Integer)
    log_excerpt = Column(Text, default="")
    # One sentence saying what went wrong, for the Scans page.  The excerpt
    # underneath it is forty lines of scanner output, which answers the
    # question eventually; this answers it at a glance.
    failure_reason = Column(String(400), default="")


class Schedule(Base):
    """Cron entries.  One for scans, one for refreshing the vulnerability feeds."""

    __tablename__ = "schedules"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False, unique=True)
    kind = Column(String(32), nullable=False, default="scan")
    cron = Column(String(120), nullable=False)
    enabled = Column(Boolean, default=True, nullable=False)

    scope_orgs = Column(Text, default="")
    scope_repos = Column(Text, default="")

    last_run_at = Column(DateTime(timezone=True))
    last_status = Column(String(32), default="")
    next_run_at = Column(DateTime(timezone=True))

    created_by = Column(String(120), default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)


class SeverityRule(Base):
    """What a finding is worth here, rather than what the engine guessed.

    A scanner grades a rule once, for everybody.  plaintext-http-link is a
    medium in the abstract; a plain HTTP link to an image on a marketing page
    is not a medium in most places, and an organization that says so is not
    wrong.  Severity is a statement about your risk, so you get to make it.

    Matches a rule by name, or a CWE the finding carries.  The engine's own
    grade is kept beside the new one: an override is a decision somebody made,
    and decisions are worth being able to read back.
    """

    __tablename__ = "severity_rules"

    id = Column(Integer, primary_key=True)
    # "rule" or "cwe"
    match_type = Column(String(8), default="rule", nullable=False)
    pattern = Column(String(200), nullable=False, index=True)
    severity = Column(Enum(Severity), nullable=False)
    reason = Column(Text, default="")

    # Where this override stops applying.
    #
    # Saying "a plain HTTP link is low here" is reasonable for a brochure site
    # and wrong for the system holding cardholder data.  Naming the tags it
    # does not cover means the exception can be broad without being careless:
    # the finding keeps its real severity exactly where it matters.
    unless_sensitivity = Column(String(400), default="")

    created_by = Column(String(120), default="")
    created_at = Column(DateTime, default=utcnow)


class ApiToken(Base):
    """A credential for something that is not a browser.

    Everything else here signs in with a password, a second factor and a
    cookie.  An editor plugin cannot do any of that, so it gets one of these.

    Only the hash is kept, the same way a password is, so the table is worth
    nothing to somebody who reads it.  The first few characters are stored in
    the clear as well, purely so the page can show which token a row is without
    being able to reconstruct it.

    Scopes are deliberately thin.  A token can ask for a review and read the
    rules, and that is all.  Nothing here can change a setting, approve an
    exception or read a finding from another team's repository, because a
    credential that lives on a laptop is the one most likely to walk.
    """

    __tablename__ = "api_tokens"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False)
    token_hash = Column(String(128), nullable=False, unique=True, index=True)
    # Enough to recognize a row by, not enough to use.
    prefix = Column(String(16), default="")

    # Whose it is.  A token is that person, with less of them: a request made
    # with it sees the repositories they were given and nothing else, so a
    # developer's token cannot read another team's work even though the
    # endpoint it calls is the same one.
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"),
                     nullable=False, index=True)

    # Comma separated.  "review" posts code to be looked at, "rules" reads the
    # triage rules and exclusions so a client can cache them.
    scopes = Column(String(200), default="review,rules")

    created_by = Column(String(120), default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    expires_at = Column(DateTime(timezone=True))
    revoked_at = Column(DateTime(timezone=True))
    last_used_at = Column(DateTime(timezone=True))
    last_used_ip = Column(String(64), default="")
    uses = Column(Integer, default=0)

    def live(self, now=None) -> bool:
        if self.revoked_at is not None:
            return False
        if self.expires_at is None:
            return True
        moment = now or utcnow()
        # SQLite hands these back without a zone whatever the column says, and
        # comparing one of those to an aware datetime raises rather than
        # returning false.  The same fix Exclusion.live carries.
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires >= moment

    def may(self, scope: str) -> bool:
        return scope in {s.strip() for s in (self.scopes or "").split(",")}

    def __repr__(self) -> str:
        return f"<ApiToken {self.name}>"


class RepoAccess(Base):
    """Who can reach a repository, and what that lets them do.

    One row per person per repository.  The permission is the effective one:
    GitHub works out the highest of whatever the organization grants everybody,
    whatever a team the person is on grants, and anything granted to them
    directly, and reports the answer.  We keep the answer and the route.

    This is the blast radius.  If somebody's account is taken, this table says
    what the person holding it can now reach, which is a different and more
    useful question than what any one repository allows.
    """

    __tablename__ = "repo_access"

    id = Column(Integer, primary_key=True)
    organization = Column(String(255), nullable=False, index=True)
    repository = Column(String(320), nullable=False, index=True)
    login = Column(String(255), nullable=False, index=True)

    # read, triage, write, maintain or admin.
    permission = Column(String(16), default="read", nullable=False)
    # "direct" if granted to them by name, "inherited" through the org or a team.
    affiliation = Column(String(16), default="inherited")

    # A person from outside the organization, given access to this one
    # repository.  Worth its own column because it is the shortest question an
    # auditor asks.
    outside_collaborator = Column(Boolean, default=False, nullable=False)
    # "User" or "Bot".  A service account is a User with nobody reading its
    # mail, so the report separates them by name as well as by type.
    account_type = Column(String(16), default="User")
    site_admin = Column(Boolean, default=False, nullable=False)
    html_url = Column(String(500), default="")

    connection = Column(String(120), default="", index=True)
    seen_at = Column(DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        UniqueConstraint("repository", "login", name="uq_repo_access"),
        Index("ix_access_org_login", "organization", "login"),
    )

    def __repr__(self) -> str:
        return f"<RepoAccess {self.login}@{self.repository}={self.permission}>"


class Component(Base):
    """Every piece of software in the estate, and where it sits.

    One row per package per branch per repository, read straight out of the
    SBOM a scan produces.  This is deliberately not the findings table.  A
    finding exists because somebody published an advisory; a component exists
    because it is there.  The question this answers is the one that gets asked
    at nine in the morning after a package is announced as compromised: is that
    version anywhere in our code, and which team has to move.

    A compromised release usually has no CVE for days, so a table built from
    advisories cannot answer it at all.  This one can, because it never asked
    whether the package was interesting.

    The branch matters as much as the repository.  A release branch routinely
    pins a version the default branch has already moved off, so "we upgraded
    that" is only true of the branch somebody checked.
    """

    __tablename__ = "components"

    id = Column(Integer, primary_key=True)

    organization = Column(String(255), default="", index=True)
    repository = Column(String(320), nullable=False, index=True)
    branch = Column(String(255), default="", index=True)
    connection = Column(String(120), default="", index=True)

    # The package as the SBOM names it.  `name` is what somebody types into
    # the search box, so it is indexed and it is the unqualified name: an npm
    # scope stays on the front of it because that is how people say it.
    name = Column(String(512), nullable=False, index=True)
    version = Column(String(128), default="", index=True)
    # npm, pypi, maven, nuget, golang, gem and so on, taken from the purl type
    # so there is one spelling rather than the four the engines each use.
    ecosystem = Column(String(64), default="", index=True)
    # The whole package URL, which is the identifier anything else will quote
    # at us.  Long, because a maven coordinate with qualifiers is long.
    purl = Column(String(1024), default="")
    # library, application, framework, operating-system, file.
    kind = Column(String(32), default="library")
    # Comma separated, because a package can be dual licensed and picking one
    # would be inventing the answer.  Empty means the SBOM did not say, which
    # is not the same as public domain.
    licenses = Column(String(500), default="", index=True)
    cpe = Column(String(500), default="")

    # A hash of the purl.  The purl itself is far too long for a unique key
    # and MySQL will not have it, so the key is over the hash.
    purl_key = Column(String(64), nullable=False, default="")

    first_seen_at = Column(DateTime, default=utcnow, nullable=False)
    last_seen_at = Column(DateTime, default=utcnow, nullable=False, index=True)

    __table_args__ = (
        # One row per package per place.  A rescan updates rather than
        # doubling, and a purl is what makes two rows the same package: it
        # carries the type, the namespace, the name and the version at once.
        UniqueConstraint("repository", "branch", "purl_key",
                         name="uq_component_place"),
        Index("ix_component_name", "name", "version"),
        Index("ix_component_where", "organization", "repository"),
    )

    def __repr__(self) -> str:
        return f"<Component {self.name}@{self.version} in {self.repository}>"


class TriageRule(Base):
    """What the scanner treats as a placeholder rather than a credential.

    Triage is the step between finding a candidate and reporting it: a value
    that matches one of these is an example somebody wrote down, not a key
    somebody leaked, and it never reaches the report.

    Two kinds.  A `value` rule is matched against the credential itself, which
    is why nothing here can be shown against what is already in the database:
    cleartext exists only inside a scan run, and by the time a finding lands it
    is a hash and a redacted preview.  A `path` rule is matched against the
    file, which is stored, so that one can be.

    The rules this tool ships are not in this table.  They are the tool's
    opinion and they live in scanner_defaults, the same way the seeded rule
    mutes do; a row here is a decision somebody made, which is either a rule of
    their own or a shipped one they turned off.  That is what makes restoring
    the defaults a matter of deleting rows rather than trying to remember what
    the defaults were.
    """

    __tablename__ = "triage_rules"

    id = Column(Integer, primary_key=True)
    # "value" for the credential itself, "path" for the file it sits in.
    target = Column(String(8), default="value", nullable=False)
    # A regular expression, read by the scanner, which is jq.  Not every
    # pattern jq accepts is one python accepts, so these are never compiled
    # here: \x{2026} is valid Oniguruma and a syntax error in python's re.
    pattern = Column(String(500), nullable=False)
    reason = Column(Text, default="")
    enabled = Column(Boolean, default=True, nullable=False)
    # A row standing in for one of the shipped rules, so it can be turned off
    # without anybody having to edit the source to do it.
    shipped = Column(Boolean, default=False, nullable=False)
    created_by = Column(String(120), default="")
    created_at = Column(DateTime, default=utcnow)

    __table_args__ = (
        UniqueConstraint("target", "pattern", name="uq_triage_rule"),
    )

    def __repr__(self) -> str:
        return f"<TriageRule {self.target}:{self.pattern}>"


class RuleMute(Base):
    """A request to set a rule aside, and who agreed to it.

    Muting a rule is the same kind of decision as approving an exception: it
    stops a class of finding reaching anybody.  The difference is that an
    exception covers one finding and this covers every one the rule will ever
    produce, which is precisely why it should not be one person's quiet
    decision on a Friday afternoon.

    So it is asked for and then approved, by somebody else, and both halves are
    on the record.  Unmuting needs no approval at all: showing more findings is
    never the dangerous direction.
    """

    __tablename__ = "rule_mutes"

    id = Column(Integer, primary_key=True)
    rule = Column(String(200), nullable=False, index=True)
    reason = Column(Text, default="")

    # requested, approved, rejected, revoked
    status = Column(String(16), default="requested", nullable=False, index=True)

    requested_by = Column(String(120), default="")
    requested_at = Column(DateTime, default=utcnow)
    decided_by = Column(String(120), default="")
    decided_at = Column(DateTime)


class Connection(Base):
    """One hosting account, with its own credential.

    A fine grained GitHub token only ever reaches one resource owner, so an
    estate spread across several organizations needs a token for each.  One row
    per token, each with a name somebody chose, and every finding records which
    one it came from.  A GitLab token is usually the other way round and covers
    a whole instance, so one row is often all it takes.

    The credential is encrypted the same way the settings are.  Nothing here is
    written to a file, ever.
    """

    __tablename__ = "connections"

    id = Column(Integer, primary_key=True)
    name = Column(String(120), nullable=False, unique=True, index=True)
    enabled = Column(Boolean, default=True, nullable=False)

    # github, gitlab or bitbucket.  Everything that predates this column is
    # GitHub, which is why that is the default rather than something empty.
    provider = Column(String(16), default="github", nullable=False)

    # Who owns the thing being scanned, and what it holds.
    #
    # A finding's risk is not a property of the code alone.  A plain HTTP link
    # on a brochure site and the same link on a system holding cardholder data
    # are the same rule and different problems, and the only place that
    # difference is known is here.
    application_name = Column(String(200), default="")
    application_owner = Column(String(200), default="")
    technical_owner = Column(String(200), default="")
    # Comma separated: PCI, HIPAA, SOX, Customer Data, CUI, Login, and whatever
    # else an organization needs to say.
    sensitivity = Column(String(400), default="")

    api_url = Column(String(300), default="https://api.github.com")
    web_url = Column(String(300), default="https://github.com")

    auth_method = Column(String(16), default="pat")
    token = Column(Text, default="")
    app_id = Column(String(60), default="")
    app_installation = Column(String(60), default="")
    app_key = Column(Text, default="")

    # Organizations this one covers.  Empty means everything the credential can
    # reach, which for a fine grained token is its one resource owner anyway.
    organizations = Column(Text, default="")
    repositories = Column(Text, default="")

    # Which branches to walk in this account's repositories, one per line.
    #
    # The global branch setting is one rule for the whole estate, which is the
    # wrong shape when one account is a handful of release repositories and the
    # next is thousands of feature branches nobody has touched in a year.  Names
    # or globs, so main, master and release/* all work.  Empty, or a star, means
    # every branch, which is what the setting on the Settings page then decides.
    branches = Column(Text, default="")

    last_checked_at = Column(DateTime(timezone=True))
    last_status = Column(String(32), default="")
    last_detail = Column(Text, default="")

    created_by = Column(String(120), default="")
    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)

    def scope_orgs(self) -> list:
        return [item.strip() for item in (self.organizations or "").split(",")
                if item.strip()]

    def scope_repos(self) -> list:
        return [item.strip() for item in (self.repositories or "").split(",")
                if item.strip()]

    def scope_branches(self) -> list:
        """The branch names and globs this account is limited to.

        Stored one per line because that is how the box is typed into, but a
        comma separated line is what somebody who used the fields above will
        write, so both are read.  An empty list means no limit of its own.
        """
        raw = (self.branches or "").replace("\r", "\n").replace(",", "\n")
        return [item.strip() for item in raw.split("\n") if item.strip()]


class Setting(Base):
    """Everything an admin can change from the Settings page.

    This is where the scan configuration lives.  It used to be a JSON file on
    disk, which meant the name of whatever organization you scan sat in the
    source tree, and anybody who cloned the repo got it.  Now the file is
    generated from these rows at scan time and thrown away afterward.

    Values are JSON so a setting can be a list or a number without a second
    column saying which.  Anything marked secret is encrypted with the app key.
    """

    __tablename__ = "settings"

    id = Column(Integer, primary_key=True)
    key = Column(String(120), nullable=False, unique=True, index=True)
    value = Column(Text, default="")
    is_secret = Column(Boolean, default=False, nullable=False)

    updated_by = Column(String(120), default="")
    updated_at = Column(DateTime(timezone=True), default=utcnow, onupdate=utcnow)


class Exclusion(Base):
    """A finding somebody reviewed and accepted, kept in the database.

    This used to be a CSV you edited by hand.  It is a table now for the same
    reason the settings are: the file had real repository names in it, and
    those do not belong in a source tree.  The scanner still wants a CSV, so we
    write one into a temp directory when a scan starts.

    Nothing is deleted by an exclusion.  The finding moves to an excluded list
    with the reason and who signed it off, so the decision stays auditable.
    """

    __tablename__ = "exclusions"

    id = Column(Integer, primary_key=True)

    # secret, code, vuln, or any
    kind = Column(String(16), default="any", nullable=False, index=True)
    organization = Column(String(255), default="*")
    repository = Column(String(320), default="*")
    path = Column(String(1024), default="*")
    rule = Column(String(255), default="*")
    fingerprint = Column(String(128), default="")

    # Where this exclusion stops applying.
    #
    # An exclusion hides a finding outright, which is a fair decision about a
    # brochure site and a careless one about the system holding cardholder
    # data.  Naming the tags it does not cover lets an exception be broad
    # without being blind: on a system carrying any of them the finding comes
    # back, with the reason it was let through elsewhere still on the record.
    unless_sensitivity = Column(String(400), default="")
    # Set when the rule came from waiving one particular finding.  It matches
    # that finding and nothing else, which is what somebody means when they
    # waive a single thing rather than writing a rule.
    vuln_id = Column(String(32), default="", index=True)

    reason = Column(Text, default="")
    ticket = Column(String(120), default="")

    reviewed_by = Column(String(120), default="")
    reviewed_date = Column(DateTime(timezone=True), default=utcnow)
    # Past this the rule stops working and the finding comes back.  Empty is
    # forever, which is what you want for a fixture directory and not much else.
    expires_at = Column(DateTime(timezone=True), nullable=True)
    active = Column(Boolean, default=True, nullable=False)

    created_at = Column(DateTime(timezone=True), default=utcnow, nullable=False)

    __table_args__ = (
        Index("ix_exclusions_scope", "organization", "repository"),
    )

    def live(self, now: datetime = None) -> bool:
        """Still in force.  An expired rule is kept for the record only."""
        if not self.active:
            return False
        if self.expires_at is None:
            return True
        moment = now or utcnow()
        expires = self.expires_at
        if expires.tzinfo is None:
            expires = expires.replace(tzinfo=timezone.utc)
        return expires >= moment


class AuditEvent(Base):
    """Who did what.  Append only, nothing in the app deletes from here."""

    __tablename__ = "audit_events"

    id = Column(Integer, primary_key=True)
    at = Column(DateTime(timezone=True), default=utcnow, nullable=False, index=True)
    actor = Column(String(120), default="", index=True)
    action = Column(String(120), nullable=False, index=True)
    target = Column(String(512), default="")
    detail = Column(Text, default="")
    source_ip = Column(String(64), default="")
    outcome = Column(String(32), default="ok")
