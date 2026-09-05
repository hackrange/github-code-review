# Git Code Review
#
# One image.  It holds the web app, the scanner and every engine the scanner
# drives.  Nothing gets downloaded on first run except the vulnerability feeds,
# and those go in a volume so they survive a restart.
#
# Two stages.  The builder compiles the python wheels, because a couple of
# these packages have C in them.  The image you actually run has no compiler,
# which is what you want on something that clones untrusted repositories.

# ==============================================================================
# Stage 1, build the wheels
# ==============================================================================
FROM ubuntu:26.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-dev python3-pip python3-venv \
        build-essential libffi-dev libssl-dev pkg-config \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /wheels
COPY requirements.txt requirements-scanner.txt ./
# Two sets, built separately, because they resolve separately.
RUN python3 -m pip wheel --wheel-dir /wheels/app -r requirements.txt \
 && python3 -m pip wheel --wheel-dir /wheels/scanner -r requirements-scanner.txt

# ==============================================================================
# Stage 2, the image that runs
# ==============================================================================
FROM ubuntu:26.04

LABEL org.opencontainers.image.title="Git Code Review" \
      org.opencontainers.image.description="Finds secrets, code weaknesses and vulnerable packages across every repository and branch in a GitHub organization" \
      org.opencontainers.image.version="1.0.1" \
      org.opencontainers.image.authors="Tim Rice <tim.j.rice@hackrange.com>" \
      org.opencontainers.image.licenses="MIT"

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Runtime only.  git and jq do the heavy lifting for the scanner, openssl signs
# the GitHub App tokens, and util-linux gives us flock for the rate limiter.
RUN apt-get update && apt-get install -y --no-install-recommends \
        python3 python3-venv \
        bash git jq curl openssl ca-certificates \
        coreutils findutils util-linux tzdata \
        subversion \
    && rm -rf /var/lib/apt/lists/*

# The clients the other two version control systems need are deliberately not
# here.  p4 is not in Debian and ships as a vendor binary; the AWS and Google
# command line tools are large and only one installation in a hundred wants
# them.  Each of those providers checks for its tool and refuses with a clear
# message rather than reporting an estate with nothing in it, so an operator
# who needs one installs it and the rest carry no weight for it.

# The scanning engines.  Pinned, because a scanner that changes its mind
# between runs makes every report argue with the last one.
ARG GITLEAKS_VERSION=8.30.1
ARG SYFT_VERSION=1.51.0
ARG GRYPE_VERSION=0.117.0
ARG OSV_VERSION=v2.5.1
ARG TRIVY_VERSION=0.74.0
ARG ZIZMOR_VERSION=1.29.0
# The one second engine that adds real depth rather than corroboration:
# gosec analyses a Go package rather than a file at a time, which is exactly
# the boundary semgrep's free rules stop at.
ARG GOSEC_VERSION=2.22.9
# gosec reads types through go/packages, which shells out to `go list`.  With
# no toolchain it exits zero having analysed nothing, so the compiler comes
# with it or the engine is worse than absent.
ARG GO_VERSION=1.25.1

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) gl_arch=x64;  go_arch=amd64; tv_arch=64bit; zz_arch=x86_64 ;; \
      arm64) gl_arch=arm64; go_arch=arm64; tv_arch=ARM64; zz_arch=aarch64 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks; \
    curl -fsSL "https://raw.githubusercontent.com/anchore/syft/main/install.sh" \
      | sh -s -- -b /usr/local/bin "v${SYFT_VERSION}"; \
    curl -fsSL "https://raw.githubusercontent.com/anchore/grype/main/install.sh" \
      | sh -s -- -b /usr/local/bin "v${GRYPE_VERSION}"; \
    curl -fsSL "https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh" \
      | sh -s -- -b /usr/local/bin; \
    curl -fsSL "https://github.com/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_linux_${go_arch}" \
      -o /usr/local/bin/osv-scanner; \
    chmod 0755 /usr/local/bin/osv-scanner; \
    curl -fsSL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tv_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin trivy; \
    curl -fsSL "https://github.com/zizmorcore/zizmor/releases/download/v${ZIZMOR_VERSION}/zizmor-${zz_arch}-unknown-linux-gnu.tar.gz" \
      | tar -xz -C /usr/local/bin zizmor; \
    curl -fsSL "https://github.com/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${go_arch}.tar.gz" \
      | tar -xz -C /usr/local/bin gosec; \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" \
      | tar -xz -C /usr/local; \
    ln -sf /usr/local/go/bin/go /usr/local/bin/go; \
    gitleaks version; syft version; grype version; trivy --version; zizmor --version; \
    gosec --version; go version; \
    trufflehog --version || true

# Python packages go in their own venv.  Ubuntu marks the system python as
# externally managed, and arguing with that just breaks later apt upgrades.
COPY --from=builder /wheels /wheels
COPY requirements.txt requirements-scanner.txt /tmp/
RUN python3 -m venv /opt/gcr/venv \
    && /opt/gcr/venv/bin/pip install --no-index --find-links=/wheels/app \
           -r /tmp/requirements.txt \
    && python3 -m venv /opt/gcr/scanner-venv \
    && /opt/gcr/scanner-venv/bin/pip install --no-index --find-links=/wheels/scanner \
           -r /tmp/requirements-scanner.txt \
    && rm -rf /wheels /tmp/requirements.txt /tmp/requirements-scanner.txt

# It runs as a normal user.  Nothing here needs root, and this thing clones
# code it did not write.
RUN useradd --create-home --uid 10001 --shell /usr/sbin/nologin gcr

WORKDIR /opt/gcr
COPY --chown=root:root app/       /opt/gcr/app/
COPY --chown=root:root bin/       /opt/gcr/bin/
COPY --chown=root:root lib/       /opt/gcr/lib/
COPY --chown=root:root config/    /opt/gcr/config/
COPY --chown=root:root schema/    /opt/gcr/schema/
COPY --chown=root:root LICENSE README.md /opt/gcr/
RUN chmod +x /opt/gcr/bin/ghscan

# The mount points.  /data holds the session key and the SQLite file if you
# run without MariaDB, /out holds the two report files, and the cache holds the
# grype database and the CISA and EPSS feeds.
RUN mkdir -p /data/db /out /var/tmp/gcr-work /home/gcr/.cache \
    && chown -R gcr:gcr /data /out /var/tmp/gcr-work /home/gcr

ENV GCR_DATA_DIR=/data \
    GCR_REPORTS_DIR=/out \
    GCR_DB_PATH=/data/db/gcr.sqlite3 \
    GCR_WORK_DIR=/var/tmp/gcr-work \
    GCR_SCANNER_BIN=/opt/gcr/bin/ghscan \
    GCR_SCANNER_VENV=/opt/gcr/scanner-venv \
    GCR_PORT=8080 \
    PATH="/opt/gcr/venv/bin:/opt/gcr/scanner-venv/bin:/opt/gcr/bin:${PATH}"

USER gcr
EXPOSE 8080
VOLUME ["/data", "/out", "/home/gcr/.cache"]

HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD curl -fsS "http://127.0.0.1:${GCR_PORT}/healthz" || exit 1

CMD ["/opt/gcr/venv/bin/python", "-m", "uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8080", "--proxy-headers", \
     "--forwarded-allow-ips", "*"]
