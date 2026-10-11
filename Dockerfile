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

# Upgraded here too.  Nothing from this stage is scanned, because only the
# wheels it builds are carried forward, but those wheels are compiled against
# whatever openssl and libffi are present when they are built.  Building them
# against a library that is known broken and then copying them into a patched
# image would leave the report clean and the binary not.
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
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
#
# The upgrade is not decoration.  apt-get install only moves the packages it is
# given and whatever they depend on; everything else stays at whatever version
# the base layer happened to ship with.  Scanning this image found around eighty
# advisories against packages nothing here asks for by name, openssl and zlib
# and the util-linux family among them, all of them fixed in Ubuntu weeks
# earlier and none of them reached because nothing ever asked for the upgrade.
#
# A scanner that ships a base nobody patched is not in a position to report on
# anybody else's.
RUN apt-get update && apt-get -y upgrade && apt-get install -y --no-install-recommends \
        python3 python3-venv \
        bash git jq curl openssl ca-certificates \
        coreutils findutils util-linux tzdata \
        subversion \
        # Typesetting, for the generated reports.
        #
        # The reports are laid out as HTML and turned into PDF, which is what
        # lets them use the same design as the rest of the product instead of
        # being assembled shape by shape into something that looks like a
        # different piece of software.  These are what does the text layout:
        # glib and pango for shaping and line breaking, harfbuzz for the font
        # itself, cairo for drawing, and one font so a report rendered on a
        # machine with no fonts installed is still typeset rather than blank.
        libglib2.0-0t64 libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz0b \
        libfontconfig1 libcairo2 libgdk-pixbuf-2.0-0 \
        fonts-dejavu-core \
    && rm -rf /var/lib/apt/lists/*

# The clients the other two version control systems need are deliberately not
# here.  p4 is not in Debian and ships as a vendor binary; the AWS and Google
# command line tools are large and only one installation in a hundred wants
# them.  Each of those providers checks for its tool and refuses with a clear
# message rather than reporting an estate with nothing in it, so an operator
# who needs one installs it and the rest carry no weight for it.

# The scanning engines.  Pinned, because a scanner that changes its mind
# between runs makes every report argue with the last one.  Each download is
# also checked against the sha256 its project published for that release, so
# a build never runs a binary nobody looked at.  A version bump means new
# sums too: take them from the release's own checksums file.
ARG GITLEAKS_VERSION=8.30.1
ARG GITLEAKS_SHA256_AMD64=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
ARG GITLEAKS_SHA256_ARM64=e4a487ee7ccd7d3a7f7ec08657610aa3606637dab924210b3aee62570fb4b080
ARG SYFT_VERSION=1.54.1
ARG SYFT_SHA256_AMD64=c069905b391cc4c20a5ba65ad5c10be2a7ba074f8ea6ad203e24d14e303dad47
ARG SYFT_SHA256_ARM64=dfdf0537610113edbefe1f1fc6548bc957b2d77439636ec824fcf0e10d46d054
ARG GRYPE_VERSION=0.120.1
ARG GRYPE_SHA256_AMD64=0a9ee97ef5ae2ee953b0a80098105052e846cdbe319a57d808b519c33cd1343d
ARG GRYPE_SHA256_ARM64=29f47391dc283aa79fcc38e65224cd61f64dec0ecfd0db7074128ebf8ff23514
ARG TRUFFLEHOG_VERSION=3.99.2
ARG TRUFFLEHOG_SHA256_AMD64=3c7b0d1dc4278294269bfdd7594bca8bb28c78da0a4a06ad202ded37b48deca4
ARG TRUFFLEHOG_SHA256_ARM64=929b81efffca752eafd58bf6f17bf725d354f338636a7bbbee65c086d2f9ddf3
ARG OSV_VERSION=v2.6.0
ARG OSV_SHA256_AMD64=ca69b3d3cd08f889a49dc0a383122f71cc528b83803671df5fd874d97485b108
ARG OSV_SHA256_ARM64=2c71403eb443d05891c4f268c3ad771cf4f16e5443463fd7851ef8f454d3c7e4
ARG TRIVY_VERSION=0.75.0
ARG TRIVY_SHA256_AMD64=c6e65abddb348e25f10549df887045629cf28cc72453cd1c63acb717316b3f3f
ARG TRIVY_SHA256_ARM64=a1ee9f6ffb7d112b64ff726a2a0717c21175c1114361391f4a132956751a13b3
ARG ZIZMOR_VERSION=1.29.0
ARG ZIZMOR_SHA256_AMD64=dd96df044a6e8538d5f423790f453bdd03d49e5b2bcc38214acc41a2f1297839
ARG ZIZMOR_SHA256_ARM64=415eaa7c0a06479a701b8e44a3e812c1047decc848ec4bede7bd6bbf49f22d20
# The one second engine that adds real depth rather than corroboration:
# gosec analyses a Go package rather than a file at a time, which is exactly
# the boundary semgrep's free rules stop at.
ARG GOSEC_VERSION=2.29.0
ARG GOSEC_SHA256_AMD64=6431b119741c1f4a50fdfcf94e782e16b9e642afc8c7fa9b5d39d48bf3003095
ARG GOSEC_SHA256_ARM64=c71244ec8d37488fd479d0d26990968fee03ece48b305d8224ac0c1ebd66e87c
# gosec reads types through go/packages, which shells out to `go list`.  With
# no toolchain it exits zero having analysed nothing, so the compiler comes
# with it or the engine is worse than absent.
ARG GO_VERSION=1.27.2
ARG GO_SHA256_AMD64=ecbadb99091a3f46e31f5f934b068b1864eafa7995211b39eaddf76996045fe5
ARG GO_SHA256_ARM64=94f3e30b8e374bc285e7dadc11e0865726b9bc6e85b841ccceaabc0214c6b7c8

RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) gl_arch=x64;  go_arch=amd64; tv_arch=64bit; zz_arch=x86_64; \
             gl_sum=$GITLEAKS_SHA256_AMD64; sy_sum=$SYFT_SHA256_AMD64; \
             gr_sum=$GRYPE_SHA256_AMD64; th_sum=$TRUFFLEHOG_SHA256_AMD64; \
             os_sum=$OSV_SHA256_AMD64; tv_sum=$TRIVY_SHA256_AMD64; \
             zz_sum=$ZIZMOR_SHA256_AMD64; gs_sum=$GOSEC_SHA256_AMD64; \
             go_sum=$GO_SHA256_AMD64 ;; \
      arm64) gl_arch=arm64; go_arch=arm64; tv_arch=ARM64; zz_arch=aarch64; \
             gl_sum=$GITLEAKS_SHA256_ARM64; sy_sum=$SYFT_SHA256_ARM64; \
             gr_sum=$GRYPE_SHA256_ARM64; th_sum=$TRUFFLEHOG_SHA256_ARM64; \
             os_sum=$OSV_SHA256_ARM64; tv_sum=$TRIVY_SHA256_ARM64; \
             zz_sum=$ZIZMOR_SHA256_ARM64; gs_sum=$GOSEC_SHA256_ARM64; \
             go_sum=$GO_SHA256_ARM64 ;; \
      *) echo "unsupported architecture: $arch" >&2; exit 1 ;; \
    esac; \
    dl=/tmp/tools; mkdir -p "$dl"; \
    fetch() { curl -fsSL "$1" -o "$dl/$2"; echo "$3  $dl/$2" | sha256sum -c -; }; \
    gh=https://github.com; \
    fetch "$gh/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${gl_arch}.tar.gz" gitleaks.tgz "$gl_sum"; \
    fetch "$gh/anchore/syft/releases/download/v${SYFT_VERSION}/syft_${SYFT_VERSION}_linux_${go_arch}.tar.gz" syft.tgz "$sy_sum"; \
    fetch "$gh/anchore/grype/releases/download/v${GRYPE_VERSION}/grype_${GRYPE_VERSION}_linux_${go_arch}.tar.gz" grype.tgz "$gr_sum"; \
    fetch "$gh/trufflesecurity/trufflehog/releases/download/v${TRUFFLEHOG_VERSION}/trufflehog_${TRUFFLEHOG_VERSION}_linux_${go_arch}.tar.gz" trufflehog.tgz "$th_sum"; \
    fetch "$gh/google/osv-scanner/releases/download/${OSV_VERSION}/osv-scanner_linux_${go_arch}" osv-scanner "$os_sum"; \
    fetch "$gh/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-${tv_arch}.tar.gz" trivy.tgz "$tv_sum"; \
    fetch "$gh/zizmorcore/zizmor/releases/download/v${ZIZMOR_VERSION}/zizmor-${zz_arch}-unknown-linux-gnu.tar.gz" zizmor.tgz "$zz_sum"; \
    fetch "$gh/securego/gosec/releases/download/v${GOSEC_VERSION}/gosec_${GOSEC_VERSION}_linux_${go_arch}.tar.gz" gosec.tgz "$gs_sum"; \
    fetch "https://go.dev/dl/go${GO_VERSION}.linux-${go_arch}.tar.gz" go.tgz "$go_sum"; \
    tar -xzf "$dl/gitleaks.tgz" -C /usr/local/bin gitleaks; \
    tar -xzf "$dl/syft.tgz" -C /usr/local/bin syft; \
    tar -xzf "$dl/grype.tgz" -C /usr/local/bin grype; \
    tar -xzf "$dl/trufflehog.tgz" -C /usr/local/bin trufflehog; \
    install -m 0755 "$dl/osv-scanner" /usr/local/bin/osv-scanner; \
    tar -xzf "$dl/trivy.tgz" -C /usr/local/bin trivy; \
    tar -xzf "$dl/zizmor.tgz" -C /usr/local/bin zizmor; \
    tar -xzf "$dl/gosec.tgz" -C /usr/local/bin gosec; \
    tar -xzf "$dl/go.tgz" -C /usr/local; \
    ln -sf /usr/local/go/bin/go /usr/local/bin/go; \
    rm -rf "$dl"; \
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
# The editor packages are built from this on request, so the source has to
# be in the image.  It is a few files of JavaScript and no dependencies.
COPY --chown=root:root ide/       /opt/gcr/ide/
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

# No proxy headers at this layer.  With them on and every address trusted,
# uvicorn copied whatever X-Forwarded-For a caller sent into the client address
# before the app saw the request, so the app's own check against
# GCR_TRUSTED_PROXIES was reading a value the caller had already chosen.  The
# rate limits and the audit log both stood on it.  client_ip() is the one place
# that decides whose forwarding header to believe.
CMD ["/opt/gcr/venv/bin/python", "-m", "uvicorn", "app.main:app", \
     "--host", "0.0.0.0", "--port", "8080", "--no-proxy-headers"]
