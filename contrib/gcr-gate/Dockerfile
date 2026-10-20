# The gcr-gate client: bash, curl, jq, git and gitleaks, and nothing that
# scans.  The scanning happens on the server.
#
# gitleaks comes out of the Git Code Review image itself rather than a second
# download, so the fallback check runs the same build the server does.
#
#   docker build -f contrib/gcr-gate/Dockerfile -t gcr-gate:1.0.1 .
ARG GCR_IMAGE=github-code-review:1.0.1
FROM ${GCR_IMAGE} AS tools

FROM ubuntu:26.04
RUN apt-get update \
 && apt-get install -y --no-install-recommends bash ca-certificates curl git jq \
 && rm -rf /var/lib/apt/lists/*
COPY --from=tools /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY contrib/gcr-gate/gcr-gate /usr/local/bin/gcr-gate
# A checkout mounted by a CI runner belongs to another user, and git refuses
# to read a repository it does not own unless told this one is fine.
RUN git config --system --add safe.directory '*'
ENTRYPOINT []
CMD ["gcr-gate", "--help"]
