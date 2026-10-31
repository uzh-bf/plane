# Qualified Plane v1.4.2 backend

This branch preserves Plane v1.4.2 at
`5f7d92784c403f76284f0f16718f320221dc7fec` and changes five backend files.
The patch fixes Redis TLS trust and encoded URL handling, notification retry
eligibility after cache/send failures, and shared-cache preservation at startup.
The complete upstream tree and its existing licences/notices remain in this
repository. Licence labels on the patch do not relicense the upstream base.

## Build the derivative image

Run from a clean checkout of the accepted derivative source revision. Use a
Linux ARM64 builder. The Dockerfile checks the original and patched hashes,
applies the patch without fuzz and parses the five changed modules. It overlays
`makeplane/plane-backend:v1.4.2@sha256:90032ce088708889b60c00d491897916f4deb882facda27db59fd10fb68729ef`.
The backend files in this source tree already contain the same patch; the
Dockerfile applies its copy to the pinned upstream image, not to these files.

```sh
release_revision=$(git rev-parse HEAD)
test -z "$(git status --porcelain)"
docker build --platform linux/arm64 \
  --label org.opencontainers.image.source=https://github.com/uzh-bf/plane \
  --label "org.opencontainers.image.revision=$release_revision" \
  --label "org.opencontainers.image.url=https://github.com/uzh-bf/plane/tree/$release_revision" \
  --label ch.df.upstream.revision=5f7d92784c403f76284f0f16718f320221dc7fec \
  --tag plane-backend:qualified \
  backend-qualification
```

Docker build labels override the Dockerfile's original upstream metadata.
Inspect the resulting labels before any release. Bind the accepted source SHA,
Dockerfile and patch SHA-256, base digest, build run and registry digest in the
release record. API, worker, beat and migrator must all use that registry digest.
Build and source preparation do not imply publication or deployment. The complete
source at the immutable derivative SHA must be downloadable by every image user;
retain this directory, upstream source, build inputs and licences/notices.

The dedicated workflow runs only when this release branch is pushed. That push
publishes source and starts its ARM64 qualification/build/publication sequence;
it requires explicit release authority. It uses the standard
`ubuntu-24.04-arm` runner, a 60-minute job limit and repository-scoped package
write permission. It does not trigger on the upstream default branches or pull
requests. It accepts only a first run attempt; a source correction requires a
new reviewed commit. Each successful run uses a unique image tag containing
its source SHA and run ID. Package visibility and anonymous digest/source
download still require acceptance before users are admitted.

## Replay the behavior contracts

The tests apply the patch to an original source snapshot and verify both sets of
hashes. Export the original baseline separately; pointing tests at the patched
checkout would fail the intentional original-hash checks.

```sh
qualification_baseline=$(mktemp -d)
git archive 5f7d92784c403f76284f0f16718f320221dc7fec | tar -x -C "$qualification_baseline"
```

Use a Python3.12 Linux container with uv, OpenSSL, GNU patch and redis-server.
Mount `backend-qualification` as the working directory and the exported baseline
read-only at `/upstream`. Keep its environment/cache in temporary storage:

```sh
export PLANE_SOURCE_DIR=/upstream
export UV_PROJECT_ENVIRONMENT=/tmp/qualification-venv
export UV_CACHE_DIR=/tmp/qualification-cache
export PYTHONDONTWRITEBYTECODE=1
uv sync --locked
uv lock --check
uv run --locked pytest -p no:cacheprovider -q
```

The accepted harness passes35contracts using real TLS Redis and test-owned
SQLite/mail adapters. It does not prove a deployed service. Local Linux ARM64
qualification separately started the actual migrator, API, worker and beat
against synthetic PostgreSQL, TLS Redis, RabbitMQ and SeaweedFS. Migrations,
HTTP health, cache round-trips and direct plus scheduled worker task completion
passed. Signed attachment upload, SMTP delivery, browser authentication and
collaboration remain outside that proof. amd64 remains unqualified.

Keep each patch only until an upstream version passes its corresponding behavior
contracts. A later upstream sync requires comparing behavior and replaying tests;
do not replay this patch blindly onto a different baseline.
