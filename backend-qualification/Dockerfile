# P01/P02/P03-CACHE qualification overlay for the Plane community backend image.
#
# The base image is pinned by tag and manifest-list digest resolved from the
# public registry on 2026-10-26 for Plane 1.4.2.
# Source commit: 5f7d92784c403f76284f0f16718f320221dc7fec.
# Only backend.patch is applied; no other upstream file is modified.
#
# Publication is gated: build this image only after the package review, and use
# the same image digest for api, worker, beat and migrator. The base manifest
# offers linux/amd64 and linux/arm64; a build targets the selected platform.

ARG PLANE_BACKEND_IMAGE=makeplane/plane-backend:v1.4.2@sha256:90032ce088708889b60c00d491897916f4deb882facda27db59fd10fb68729ef
FROM ${PLANE_BACKEND_IMAGE}

LABEL org.opencontainers.image.title="plane-backend-qualified" \
      org.opencontainers.image.description="Independent Plane 1.4.2 backend with Redis TLS, notification recovery and scoped startup cache handling" \
      org.opencontainers.image.source="https://github.com/makeplane/plane" \
      org.opencontainers.image.revision="5f7d92784c403f76284f0f16718f320221dc7fec" \
      ch.df.patch.licenses="AGPL-3.0-only" \
      org.opencontainers.image.base.digest="sha256:90032ce088708889b60c00d491897916f4deb882facda27db59fd10fb68729ef" \
      ch.df.patch="P01,P02,P03-CACHE"

# The upstream image keeps the Django project at /code (Dockerfile.api copies
# plane/ there), so apps/api/... in the patch maps to /code/... and patch -p3
# strips the a/, apps/ and api/ components. Expectation hashes make a partial or
# fuzzed application fail the build instead of shipping silently.
COPY backend.patch /tmp/p01/backend.patch

RUN set -eu; \
    apk add --no-cache --virtual .p01-patch patch; \
    cd /code; \
    printf '%s  %s\n' \
        '8a605a93b13b756ab0560a1e731de319edf54b26c170517797f1246604d668db' plane/settings/redis.py \
        'd4e8e3751b187bcec17cce767419757b8ef06011c1e98c6dafbe2c1f926506ee' plane/settings/common.py \
        '1d1ac43f063d1a917dbab539faa33bacbeebe9308ef66d00e2f98e97c39fb87f' plane/bgtasks/email_notification_task.py \
        '35904e9c48fe5a00fb8f392f16df90bed9d9bb02bccadfa80f9e6b676d580187' plane/bgtasks/issue_activities_task.py \
        'b0db5e03c2d755bf95c70696235834a81d6abc079dd56ebb5a1e8fb9d7d73dcd' plane/db/management/commands/clear_cache.py \
        > /tmp/p01/original.sha256; \
    sha256sum -c /tmp/p01/original.sha256; \
    patch -p3 --batch --fuzz=0 --no-backup-if-mismatch < /tmp/p01/backend.patch; \
    printf '%s  %s\n' \
        'db39fe6eb4631de938c2cd0e04e8731174976dd8789d637e8d38bbce4958fe2c' plane/settings/redis.py \
        '7cc81f2531afadedd8f68c45b1f34873db4c98b0aaf8edd57223d1940d67a842' plane/settings/common.py \
        '591057e29e5621b31e42a511d1d4e42026242161cacd706389a4b19bd9bf9ad1' plane/bgtasks/email_notification_task.py \
        '90dab98c403fed70f5f7ce985f3a1d357f0c3ea947cdfe15fed3c05919b43ef2' plane/bgtasks/issue_activities_task.py \
        'fddeaba3c2a2fadb6b2d77f8ff538356e7d77d7f5c1cbf18f803390456753cdd' plane/db/management/commands/clear_cache.py \
        > /tmp/p01/expected.sha256; \
    sha256sum -c /tmp/p01/expected.sha256; \
    python -c 'import ast; from pathlib import Path; [ast.parse(Path(path).read_text()) for path in ("plane/settings/redis.py", "plane/settings/common.py", "plane/bgtasks/email_notification_task.py", "plane/bgtasks/issue_activities_task.py", "plane/db/management/commands/clear_cache.py")]'; \
    apk del .p01-patch; \
    rm -rf /tmp/p01 /var/cache/apk/*

# REDIS_SSL_CA_CERTS must point at a mounted CA bundle when the Redis endpoint
# uses a private CA; the system trust store applies when it is unset.
