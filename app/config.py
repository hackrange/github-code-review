"""Settings.  Everything comes from the environment so the image stays generic.

Nothing here reaches out to the network or the database.  Import it from
anywhere without worrying about order.
"""

from __future__ import annotations

import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

APP_NAME = "Git Code Review"
APP_SLUG = "gcr"
VERSION = "1.0.1"


def _bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, "").strip())
    except (TypeError, ValueError):
        return default


def _list(name: str, default=None) -> list:
    raw = os.environ.get(name, "")
    items = [x.strip() for x in raw.replace(",", " ").split() if x.strip()]
    return items or (default or [])


@dataclass(frozen=True)
class AuthConfig:
    """Which sign in methods are live.

    Three shapes are supported.  "local" is username, password and TOTP.
    "oidc" is your identity provider only, and nobody signs in with a local
    password.  "both" leaves both doors open, which is the one you want while
    you are migrating.
    """

    mode: str = "local"

    oidc_issuer: str = ""
    oidc_client_id: str = ""
    oidc_client_secret: str = ""
    oidc_scopes: str = "openid profile email groups"
    oidc_redirect_url: str = ""
    oidc_group_claim: str = "groups"

    # Group name to role.  Anyone in none of these gets no account at all,
    # which is the safe way round.
    oidc_admin_groups: list = field(default_factory=list)
    oidc_developer_groups: list = field(default_factory=list)
    oidc_reader_groups: list = field(default_factory=list)

    # What to do with somebody the provider vouched for who is in none of the
    # mapped groups.  Empty keeps the safe behavior and refuses them.  Setting
    # a role here hands that decision to the provider's app assignment instead,
    # so only turn it on when the provider will not send group names and the
    # application is restricted to the right people on its side.
    oidc_default_role: str = ""

    @property
    def local_enabled(self) -> bool:
        return self.mode in {"local", "both"}

    @property
    def oidc_enabled(self) -> bool:
        return self.mode in {"oidc", "both"}

    def problems(self) -> list:
        """What is missing.  Checked at startup so it fails loudly, early."""
        out = []
        if self.mode not in {"local", "oidc", "both"}:
            out.append(f"GCR_AUTH_MODE must be local, oidc or both, got {self.mode!r}")
        if self.oidc_enabled:
            for name, value in (
                ("GCR_OIDC_ISSUER", self.oidc_issuer),
                ("GCR_OIDC_CLIENT_ID", self.oidc_client_id),
                ("GCR_OIDC_CLIENT_SECRET", self.oidc_client_secret),
            ):
                if not value:
                    out.append(f"{name} is required when OIDC is on")
            if not (self.oidc_admin_groups or self.oidc_developer_groups
                    or self.oidc_reader_groups):
                out.append(
                    "map at least one group to a role, or nobody can sign in "
                    "through OIDC"
                )
        return out


@dataclass(frozen=True)
class Settings:
    data_dir: Path
    reports_dir: Path
    work_dir: Path
    db_path: Path
    database_url: str

    bind_address: str
    port: int
    base_path: str
    secret_key: str
    encryption_key: str

    auth: AuthConfig

    session_hours: int
    idle_minutes: int
    login_attempt_limit: int
    login_lockout_minutes: int

    # Requests per minute per address, before anybody has signed in.  Separate
    # from the account lockout above: that counts wrong passwords for one
    # account, this counts requests from one address.
    rate_limit_general: int
    rate_limit_auth: int
    rate_limit_window: int

    trusted_proxies: list
    force_https: bool

    scanner_bin: Path

    @property
    def uses_sqlite(self) -> bool:
        return self.database_url.startswith("sqlite")

    @property
    def report_json(self) -> Path:
        return self.reports_dir / "vulnerabilities.json"

    @property
    def report_csv(self) -> Path:
        return self.reports_dir / "vulnerabilities.csv"


def _secret_key(data_dir: Path) -> str:
    """Signing key for sessions.

    Set GCR_SECRET_KEY yourself in production.  If you do not, we make one and
    keep it next to the database so restarts do not sign everyone out.
    """
    from_env = os.environ.get("GCR_SECRET_KEY", "").strip()
    if from_env:
        return from_env

    keyfile = data_dir / "secret_key"
    try:
        if keyfile.exists():
            value = keyfile.read_text(encoding="utf-8").strip()
            if value:
                return value
        data_dir.mkdir(parents=True, exist_ok=True)
        value = secrets.token_urlsafe(48)
        keyfile.write_text(value, encoding="utf-8")
        keyfile.chmod(0o600)
        return value
    except OSError:
        # Read only volume.  Fall back to a key that lives for this process,
        # which means sessions end when the container restarts.
        return secrets.token_urlsafe(48)


def _database_url(db_path: Path) -> str:
    """Where the database is.

    SQLite is the default and it is enough for this: one process writes, WAL
    keeps readers out of its way, and the whole thing is one file in a volume.
    Point GCR_DATABASE_URL at MariaDB when you would rather run a server, for
    example mysql+pymysql://gcr:secret@mariadb:3306/gcr?charset=utf8mb4.
    """
    raw = os.environ.get("GCR_DATABASE_URL", "").strip()
    if raw:
        # A bare mysql:// URL needs a driver name or SQLAlchemy reaches for
        # MySQLdb, which is not installed.
        if raw.startswith("mysql://"):
            raw = "mysql+pymysql://" + raw[len("mysql://"):]
        if raw.startswith("mariadb://"):
            raw = "mysql+pymysql://" + raw[len("mariadb://"):]
        return raw

    host = os.environ.get("GCR_DB_HOST", "").strip()
    if host:
        from urllib.parse import quote_plus
        user = quote_plus(os.environ.get("GCR_DB_USER", "gcr"))
        password = quote_plus(os.environ.get("GCR_DB_PASSWORD", ""))
        name = os.environ.get("GCR_DB_NAME", "gcr")
        port = _int("GCR_DB_PORT", 3306)
        return (f"mysql+pymysql://{user}:{password}@{host}:{port}/{name}"
                "?charset=utf8mb4")

    return f"sqlite:///{db_path}"


def load() -> Settings:
    data_dir = Path(os.environ.get("GCR_DATA_DIR", "/data"))
    # The reports land here and something else picks them up, so this is a
    # volume, not a directory inside the container.
    reports_dir = Path(os.environ.get("GCR_REPORTS_DIR", "/out"))
    work_dir = Path(os.environ.get("GCR_WORK_DIR", "/var/tmp/gcr-work"))
    db_path = Path(os.environ.get("GCR_DB_PATH", str(data_dir / "db" / "gcr.sqlite3")))
    database_url = _database_url(db_path)

    auth = AuthConfig(
        mode=os.environ.get("GCR_AUTH_MODE", "local").strip().lower(),
        oidc_issuer=os.environ.get("GCR_OIDC_ISSUER", "").strip(),
        oidc_client_id=os.environ.get("GCR_OIDC_CLIENT_ID", "").strip(),
        oidc_client_secret=os.environ.get("GCR_OIDC_CLIENT_SECRET", "").strip(),
        oidc_scopes=os.environ.get("GCR_OIDC_SCOPES", "openid profile email groups"),
        oidc_redirect_url=os.environ.get("GCR_OIDC_REDIRECT_URL", "").strip(),
        oidc_group_claim=os.environ.get("GCR_OIDC_GROUP_CLAIM", "groups").strip(),
        oidc_admin_groups=_list("GCR_OIDC_ADMIN_GROUPS"),
        oidc_developer_groups=_list("GCR_OIDC_DEVELOPER_GROUPS"),
        oidc_reader_groups=_list("GCR_OIDC_READER_GROUPS"),
        oidc_default_role=os.environ.get("GCR_OIDC_DEFAULT_ROLE", "").strip().lower(),
    )

    return Settings(
        data_dir=data_dir,
        reports_dir=reports_dir,
        work_dir=work_dir,
        db_path=db_path,
        database_url=database_url,
        bind_address=os.environ.get("GCR_BIND_ADDRESS", "0.0.0.0"),
        port=_int("GCR_PORT", 8080),
        base_path=os.environ.get("GCR_BASE_PATH", "").rstrip("/"),
        secret_key=_secret_key(data_dir),
        # What encrypts the GitHub token, the App key and the OIDC client
        # secret in the database.  Kept apart from the session key so rotating
        # one does not invalidate the other.
        encryption_key=(os.environ.get("GCR_ENCRYPTION_KEY", "").strip()
                        or _secret_key(data_dir)),
        auth=auth,
        session_hours=_int("GCR_SESSION_HOURS", 12),
        idle_minutes=_int("GCR_IDLE_MINUTES", 60),
        login_attempt_limit=_int("GCR_LOGIN_ATTEMPT_LIMIT", 5),
        login_lockout_minutes=_int("GCR_LOGIN_LOCKOUT_MINUTES", 15),
        rate_limit_general=_int("GCR_RATE_LIMIT_GENERAL", 300),
        rate_limit_auth=_int("GCR_RATE_LIMIT_AUTH", 12),
        rate_limit_window=_int("GCR_RATE_LIMIT_WINDOW", 60),
        trusted_proxies=_list("GCR_TRUSTED_PROXIES"),
        force_https=_bool("GCR_FORCE_HTTPS", True),
        scanner_bin=Path(os.environ.get("GCR_SCANNER_BIN", "/opt/gcr/bin/ghscan")),
    )


settings = load()
