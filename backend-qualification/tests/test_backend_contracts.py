"""Contracts for P01 TLS, P02 notification recovery and P03-CACHE startup safety.

Executable source hashes check fixture provenance; behavior is exercised below.
The patch applies to disposable copies of the pinned public files. Settings are
imported normally; task bodies run with test-owned database and I/O adapters.
All TLS checks use an actual Redis server and generated certificates.
"""

from __future__ import annotations

import ast
import hashlib
import importlib
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock
from urllib.parse import quote

import pytest
import redis

QUALIFICATION_DIR = Path(__file__).resolve().parents[1]
PATCH_FILE = QUALIFICATION_DIR / "backend.patch"

# Public source snapshot qualified by this package: makeplane/plane at
# 5f7d92784c403f76284f0f16718f320221dc7fec (release 1.4.2).
# These are source-fixture integrity checks, separate from behavioral contracts.
UPSTREAM_COMMIT = "5f7d92784c403f76284f0f16718f320221dc7fec"
ORIGINAL_SHA256 = {
    "apps/api/plane/settings/redis.py": "8a605a93b13b756ab0560a1e731de319edf54b26c170517797f1246604d668db",
    "apps/api/plane/settings/common.py": "d4e8e3751b187bcec17cce767419757b8ef06011c1e98c6dafbe2c1f926506ee",
    "apps/api/plane/bgtasks/email_notification_task.py": "1d1ac43f063d1a917dbab539faa33bacbeebe9308ef66d00e2f98e97c39fb87f",
    "apps/api/plane/bgtasks/issue_activities_task.py": "35904e9c48fe5a00fb8f392f16df90bed9d9bb02bccadfa80f9e6b676d580187",
    "apps/api/plane/db/management/commands/clear_cache.py": "b0db5e03c2d755bf95c70696235834a81d6abc079dd56ebb5a1e8fb9d7d73dcd",
}
PATCHED_SHA256 = {
    "apps/api/plane/settings/redis.py": "db39fe6eb4631de938c2cd0e04e8731174976dd8789d637e8d38bbce4958fe2c",
    "apps/api/plane/settings/common.py": "7cc81f2531afadedd8f68c45b1f34873db4c98b0aaf8edd57223d1940d67a842",
    "apps/api/plane/bgtasks/email_notification_task.py": "591057e29e5621b31e42a511d1d4e42026242161cacd706389a4b19bd9bf9ad1",
    "apps/api/plane/bgtasks/issue_activities_task.py": "90dab98c403fed70f5f7ce985f3a1d357f0c3ea947cdfe15fed3c05919b43ef2",
    "apps/api/plane/db/management/commands/clear_cache.py": "fddeaba3c2a2fadb6b2d77f8ff538356e7d77d7f5c1cbf18f803390456753cdd",
}

SUPPORT_FILES = (
    "apps/api/plane/settings/__init__.py",
    "apps/api/plane/utils/__init__.py",
    "apps/api/plane/utils/url.py",
)
PACKAGE_BOOTSTRAP = "apps/api/plane/__init__.py"
PACKAGE_BOOTSTRAP_CONTENT = (
    "# Qualification harness placeholder. The upstream module only re-exports a"
    " Celery app, which these settings contracts do not exercise.\n"
)
TARGET_FILES = tuple(ORIGINAL_SHA256)

ACL_USER = "plane-ops"
ACL_PASSWORD = uuid.uuid4().hex + ":/=@+"


def _sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.fixture(scope="session", autouse=True)
def django_settings():
    """Configure a minimal Django settings object; no application is booted."""
    from django.conf import settings as django_settings

    if not django_settings.configured:
        django_settings.configure(
            DEBUG=False,
            SECRET_KEY=uuid.uuid4().hex,
            CACHES={},
            DATABASES={
                "default": {"ENGINE": "django.db.backends.sqlite3", "NAME": ":memory:"}
            },
            INSTALLED_APPS=[],
            USE_TZ=False,
            WEB_URL="https://plane.example.test",
        )
        import django

        django.setup()
    yield


@pytest.fixture(scope="session")
def upstream_source() -> Path:
    source = Path(os.environ.get("PLANE_SOURCE_DIR", "/private/tmp/plane-v142"))
    if not (source / "apps/api/plane/settings/redis.py").is_file():
        pytest.skip(
            f"pinned Plane source not found at {source}; set PLANE_SOURCE_DIR to the "
            f"unpacked {UPSTREAM_COMMIT} tree"
        )
    return source


@pytest.fixture(scope="session")
def patched_tree(tmp_path_factory, upstream_source) -> Path:
    """Copy the pinned modules, apply backend.patch, and check both hashes."""
    if shutil.which("patch") is None:
        pytest.fail("patch is required to apply backend.patch strictly")

    root = tmp_path_factory.mktemp("plane-p01-patched")
    for relative in SUPPORT_FILES + TARGET_FILES:
        destination = root / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(upstream_source / relative, destination)

    (root / PACKAGE_BOOTSTRAP).write_text(PACKAGE_BOOTSTRAP_CONTENT)

    for relative, expected in ORIGINAL_SHA256.items():
        actual = _sha256(root / relative)
        assert actual == expected, (
            f"{relative} is not the {UPSTREAM_COMMIT} baseline: {actual} != {expected}"
        )

    applied = subprocess.run(
        [
            "patch",
            "-p1",
            "--batch",
            "--fuzz=0",
            "--no-backup-if-mismatch",
            "-i",
            str(PATCH_FILE),
        ],
        cwd=root,
        capture_output=True,
        text=True,
    )
    assert applied.returncode == 0, f"patch failed:\n{applied.stdout}\n{applied.stderr}"

    for relative, expected in PATCHED_SHA256.items():
        actual = _sha256(root / relative)
        assert actual == expected, (
            f"patched {relative} hash drifted: {actual} != {expected}"
        )

    return root


@pytest.fixture
def load_plane_module(patched_tree):
    """Import a module from the patched tree with fresh Plane module state."""

    def load(module_name: str):
        for name in [
            name for name in sys.modules if name == "plane" or name.startswith("plane.")
        ]:
            del sys.modules[name]
        api_path = str(patched_tree / "apps/api")
        sys.path.insert(0, api_path)
        try:
            return importlib.import_module(module_name)
        finally:
            sys.path.remove(api_path)

    return load


def _client(module, url: str, ca_certs: str | None = None):
    """Build the patched redis_instance() for one URL without leaking settings."""
    from django.test import override_settings

    overrides = {"REDIS_URL": url, "REDIS_SSL": module.redis_url_is_tls(url)}
    if ca_certs is not None:
        overrides["REDIS_SSL_CA_CERTS"] = ca_certs
    with override_settings(**overrides):
        return module.redis_instance()


def _pool(module, url: str, ca_certs: str | None = None) -> dict:
    return _client(module, url, ca_certs).connection_pool.connection_kwargs


REDISS_URL = "rediss://plane%40ops:p%40ss%3Aword@redis.internal:6380/2"
PLAIN_URL = "redis://plane%40ops:p%40ss%3Aword@redis.internal:6380/3"


def test_plain_url_decodes_credentials_and_database(load_plane_module):
    module = load_plane_module("plane.settings.redis")
    client = _client(module, PLAIN_URL)
    kwargs = client.connection_pool.connection_kwargs

    assert client.connection_pool.connection_class is redis.Connection
    assert kwargs["host"] == "redis.internal"
    assert kwargs["port"] == 6380
    assert kwargs["db"] == 3
    assert kwargs["username"] == "plane@ops"
    assert kwargs["password"] == "p@ss:word"
    assert "ssl_cert_reqs" not in kwargs


def test_rediss_enforces_required_verification_and_hostname(load_plane_module):
    module = load_plane_module("plane.settings.redis")
    pool = _client(module, REDISS_URL).connection_pool

    assert pool.connection_class is redis.SSLConnection
    kwargs = pool.connection_kwargs
    assert kwargs["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert kwargs["ssl_check_hostname"] is True
    assert kwargs.get("ssl_ca_certs") is None, (
        "a CA file is used only when explicitly configured"
    )
    assert kwargs["username"] == "plane@ops"
    assert kwargs["password"] == "p@ss:word"
    assert kwargs["db"] == 2

    # redis-py stores the flags on the connection; instantiation is lazy and
    # performs no I/O, so this asserts the effective handshake configuration.
    connection = redis.SSLConnection(**kwargs)
    assert connection.cert_reqs == ssl.CERT_REQUIRED
    assert connection.check_hostname is True


def test_url_query_cannot_weaken_tls_validation(load_plane_module):
    module = load_plane_module("plane.settings.redis")
    hostile = (
        "rediss://plane%40ops:p%40ss%3Aword@redis.internal:6380/2"
        "?ssl_cert_reqs=none&ssl_check_hostname=false&ssl_ca_certs=/tmp/untrusted-ca.pem"
        "&socket_timeout=7"
    )
    kwargs = _pool(module, hostile)

    assert kwargs["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert kwargs["ssl_check_hostname"] is True
    assert kwargs.get("ssl_ca_certs") is None
    assert kwargs["socket_timeout"] == 7, (
        "non-TLS URL options must still reach the client"
    )


def test_ca_bundle_is_used_only_when_explicit(load_plane_module):
    module = load_plane_module("plane.settings.redis")
    ca_path = "/var/run/plane/tls/redis-ca.crt"
    kwargs = _pool(module, REDISS_URL, ca_certs=ca_path)
    assert kwargs["ssl_ca_certs"] == ca_path


def test_plaintext_url_mentioning_rediss_is_not_treated_as_tls(
    load_plane_module, monkeypatch
):
    monkeypatch.setenv("REDIS_URL", "redis://redis.internal:6379/0?label=rediss")
    monkeypatch.delenv("REDIS_SSL_CA_CERTS", raising=False)
    module = load_plane_module("plane.settings.common")

    assert module.REDIS_SSL is False
    assert "CONNECTION_POOL_KWARGS" not in module.CACHES["default"]["OPTIONS"]


def test_django_cache_matches_backend_tls_validation(load_plane_module, monkeypatch):
    ca_path = "/etc/plane/tls/redis-ca.pem"
    monkeypatch.setenv(
        "REDIS_URL",
        "rediss://plane%40ops:p%40ss%3Aword@redis.internal:6380/2"
        "?ssl_cert_reqs=none&ssl_check_hostname=false&ssl_ca_certs=/tmp/untrusted-ca.pem",
    )
    monkeypatch.setenv("REDIS_SSL_CA_CERTS", ca_path)
    common = load_plane_module("plane.settings.common")
    redis_module = importlib.import_module("plane.settings.redis")

    cache = common.CACHES["default"]
    options = cache["OPTIONS"]
    expected = {
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
        "ssl_check_hostname": True,
        "ssl_ca_certs": ca_path,
    }

    assert common.REDIS_SSL is True
    assert cache["BACKEND"] == "django_redis.cache.RedisCache"
    assert options["CLIENT_CLASS"] == "django_redis.client.DefaultClient"
    assert options["CONNECTION_POOL_KWARGS"] == expected
    assert options["CONNECTION_POOL_KWARGS"] == redis_module.redis_tls_kwargs(ca_path)
    assert "ssl_" not in cache["LOCATION"]
    assert cache["LOCATION"].startswith("rediss://")

    # Rebuild the pool the way django-redis does (URL parsed last) to prove the
    # cache path cannot regress through redis-py query overrides keyword merge.
    pool = redis.ConnectionPool.from_url(
        cache["LOCATION"], **options["CONNECTION_POOL_KWARGS"]
    )
    assert pool.connection_class is redis.SSLConnection
    assert pool.connection_kwargs["ssl_cert_reqs"] == ssl.CERT_REQUIRED
    assert pool.connection_kwargs["ssl_check_hostname"] is True
    assert pool.connection_kwargs["ssl_ca_certs"] == ca_path
    assert pool.connection_kwargs["db"] == 2
    assert pool.connection_kwargs["username"] == "plane@ops"
    assert pool.connection_kwargs["password"] == "p@ss:word"


class TlsRedis:
    def __init__(self, port: int, ca_cert: Path, wrong_ca_cert: Path):
        self.port = port
        self.ca_cert = ca_cert
        self.wrong_ca_cert = wrong_ca_cert

    def url(self, host: str, password: str = ACL_PASSWORD, db: int = 0) -> str:
        user = quote(ACL_USER, safe="")
        secret = quote(password, safe="")
        return f"rediss://{user}:{secret}@{host}:{self.port}/{db}"


def _run(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True)


def _write(path: Path, content: str) -> None:
    path.write_text(content)
    path.chmod(0o644)


def _generate_certificates(directory: Path) -> tuple[Path, Path]:
    ca_config = directory / "ca.cnf"
    _write(
        ca_config,
        "\n".join(
            [
                "[req]",
                "distinguished_name = dn",
                "prompt = no",
                "x509_extensions = ca_ext",
                "",
                "[dn]",
                "CN = Plane P01 Test CA",
                "",
                "[ca_ext]",
                "basicConstraints = critical,CA:TRUE",
                "keyUsage = critical,keyCertSign,cRLSign",
                "subjectKeyIdentifier = hash",
                "",
            ]
        ),
    )
    server_config = directory / "server.cnf"
    _write(
        server_config,
        "\n".join(
            [
                "[req]",
                "distinguished_name = dn",
                "prompt = no",
                "",
                "[dn]",
                "CN = localhost",
                "",
            ]
        ),
    )
    server_extensions = directory / "server_ext.cnf"
    _write(
        server_extensions,
        "\n".join(
            [
                "basicConstraints = critical,CA:FALSE",
                "keyUsage = critical,digitalSignature,keyEncipherment",
                "extendedKeyUsage = serverAuth",
                "subjectAltName = DNS:localhost",
                "",
            ]
        ),
    )

    for ca_name in ("ca", "wrong-ca"):
        generated = _run(
            [
                "openssl",
                "req",
                "-x509",
                "-newkey",
                "rsa:2048",
                "-nodes",
                "-sha256",
                "-days",
                "2",
                "-keyout",
                str(directory / f"{ca_name}.key"),
                "-out",
                str(directory / f"{ca_name}.crt"),
                "-config",
                str(ca_config),
            ]
        )
        assert generated.returncode == 0, generated.stderr

    request = _run(
        [
            "openssl",
            "req",
            "-newkey",
            "rsa:2048",
            "-nodes",
            "-sha256",
            "-keyout",
            str(directory / "server.key"),
            "-out",
            str(directory / "server.csr"),
            "-config",
            str(server_config),
        ]
    )
    assert request.returncode == 0, request.stderr

    signing = _run(
        [
            "openssl",
            "x509",
            "-req",
            "-in",
            str(directory / "server.csr"),
            "-CA",
            str(directory / "ca.crt"),
            "-CAkey",
            str(directory / "ca.key"),
            "-CAcreateserial",
            "-out",
            str(directory / "server.crt"),
            "-days",
            "2",
            "-sha256",
            "-extfile",
            str(server_extensions),
        ]
    )
    assert signing.returncode == 0, signing.stderr

    for file_name in ("ca.crt", "server.crt", "server.key", "wrong-ca.crt"):
        (directory / file_name).chmod(0o644)

    return directory / "ca.crt", directory / "wrong-ca.crt"


@pytest.fixture(scope="session")
def tls_redis():
    """Real Redis over TLS with a private CA and a non-default ACL user."""
    local_server = shutil.which("redis-server")
    for tool in ("redis-server", "openssl"):
        if shutil.which(tool) is None:
            pytest.skip(f"{tool} is unavailable; the TLS fixture cannot run")

    directory = Path(tempfile.mkdtemp(prefix="plane-qualification-tls-"))
    directory.chmod(0o755)
    ca_cert, wrong_ca_cert = _generate_certificates(directory)

    import socket

    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        local_port = reservation.getsockname()[1]

    _write(
        directory / "redis.conf",
        "\n".join(
            [
                "port 0",
                f"tls-port {local_port}",
                f"tls-cert-file {directory}/server.crt",
                f"tls-key-file {directory}/server.key",
                f"tls-ca-cert-file {directory}/ca.crt",
                "tls-auth-clients no",
                "protected-mode no",
                'save ""',
                "appendonly no",
                "dir /tmp",
                "user default off",
                f"user {ACL_USER} on >{ACL_PASSWORD} ~* allchannels +@all",
                "",
            ]
        ),
    )

    server = subprocess.Popen(
        [local_server, str(directory / "redis.conf")],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        client = redis.Redis(
            host="localhost",
            port=local_port,
            username=ACL_USER,
            password=ACL_PASSWORD,
            ssl=True,
            ssl_ca_certs=str(ca_cert),
            ssl_cert_reqs=ssl.CERT_REQUIRED,
            ssl_check_hostname=True,
            socket_connect_timeout=2,
            socket_timeout=2,
        )
        deadline = time.monotonic() + 10
        while True:
            try:
                assert client.ping()
                break
            except redis.ConnectionError:
                if server.poll() is not None or time.monotonic() > deadline:
                    raise
                time.sleep(0.05)
        yield TlsRedis(local_port, ca_cert, wrong_ca_cert)
    finally:
        server.terminate()
        server.wait(timeout=5)
        shutil.rmtree(directory)


@pytest.mark.integration
def test_backend_client_authenticates_over_tls(tls_redis, load_plane_module):
    module = load_plane_module("plane.settings.redis")
    client = _client(
        module, tls_redis.url("localhost"), ca_certs=str(tls_redis.ca_cert)
    )

    assert client.ping() is True
    # Pub/Sub travels the same TLS connection pool; subscribing must not fail.
    pubsub = client.pubsub()
    try:
        pubsub.subscribe("p01-contracts")
        message = pubsub.get_message(timeout=1.0)
        assert message is None or message["type"] == "subscribe"
    finally:
        pubsub.close()


@pytest.mark.integration
def test_backend_client_rejects_wrong_hostname(tls_redis, load_plane_module):
    module = load_plane_module("plane.settings.redis")
    client = _client(
        module, tls_redis.url("127.0.0.1"), ca_certs=str(tls_redis.ca_cert)
    )

    with pytest.raises(redis.exceptions.ConnectionError) as excinfo:
        client.ping()
    message = str(excinfo.value).lower()
    assert "hostname" in message or "certificate" in message, message


def _task_definitions(path, namespace):
    """Execute unmodified function/class ASTs from the patched public modules.

    Imports are replaced at external seams only: test-owned database models,
    Celery's real decorator, Django's locmem mail backend and real Redis. This
    avoids booting Plane or loading its unrelated Commercial email helper.
    """
    # Celery caches tasks by qualified name; each harness owns a fresh module.
    namespace["__name__"] = f"qualification_{uuid.uuid4().hex}"
    source = ast.parse(path.read_text(), filename=str(path))
    definitions = ast.Module(
        body=[
            node
            for node in source.body
            if isinstance(node, (ast.FunctionDef, ast.ClassDef))
        ],
        type_ignores=[],
    )
    exec(compile(definitions, str(path), "exec"), namespace)
    return SimpleNamespace(**namespace)


@pytest.fixture(scope="session")
def email_log_model():
    """A real SQLite table with the fields used at the notification seam."""
    from django.db import connection, models

    class ActiveLogs(models.Manager):
        def get_queryset(self):
            return super().get_queryset().filter(deleted_at__isnull=True)

    class EmailLog(models.Model):
        receiver_id = models.CharField(max_length=40)
        triggered_by_id = models.CharField(max_length=40)
        entity_identifier = models.CharField(max_length=40)
        data = models.JSONField()
        processed_at = models.DateTimeField(null=True)
        sent_at = models.DateTimeField(null=True)
        deleted_at = models.DateTimeField(null=True)
        objects = ActiveLogs()
        all_objects = models.Manager()

        class Meta:
            app_label = "qualification"

    # order_by("receiver") is an upstream query contract; use a real FK-like
    # field name on this small test-owned model.
    EmailLog.add_to_class(
        "receiver", models.CharField(max_length=40, default="receiver")
    )
    with connection.schema_editor() as schema:
        schema.create_model(EmailLog)
    try:
        yield EmailLog
    finally:
        with connection.schema_editor() as schema:
            schema.delete_model(EmailLog)


@pytest.fixture
def notification_harness(
    patched_tree, tls_redis, load_plane_module, monkeypatch, email_log_model
):
    import logging
    import re
    from datetime import datetime, timedelta
    from smtplib import SMTPDataError, SMTPRecipientsRefused
    from urllib.parse import urlsplit

    from celery import shared_task
    from django.conf import settings
    from django.core import mail
    from django.core.mail import EmailMultiAlternatives, get_connection
    from django.test import override_settings
    from django.utils import timezone

    redis_module = load_plane_module("plane.settings.redis")
    client = _client(redis_module, tls_redis.url("localhost"), str(tls_redis.ca_cert))
    receiver = SimpleNamespace(email="receiver@example.test")
    project = SimpleNamespace(
        identifier="Q",
        id="project-1",
        name="Synthetic",
        workspace=SimpleNamespace(slug="qualification"),
    )
    issue = SimpleNamespace(
        id="issue-1", project=project, sequence_id=1, name="Synthetic issue"
    )

    class MissingRecord(Exception):
        pass

    contexts = []
    errors = []

    def render(template, context):
        contexts.append(context)
        return f'<a href="{context["issue_url"]}">Issue</a>'

    namespace = {
        "logging": logging,
        "re": re,
        "datetime": datetime,
        "timedelta": timedelta,
        "SMTPDataError": SMTPDataError,
        "SMTPRecipientsRefused": SMTPRecipientsRefused,
        "urlsplit": urlsplit,
        "shared_task": shared_task,
        "settings": settings,
        "timezone": timezone,
        "redis_instance": lambda: client,
        "EmailNotificationLog": email_log_model,
        "User": SimpleNamespace(
            objects=SimpleNamespace(get=lambda **kwargs: receiver),
            DoesNotExist=MissingRecord,
        ),
        "Issue": SimpleNamespace(
            objects=SimpleNamespace(get=lambda **kwargs: issue),
            DoesNotExist=MissingRecord,
        ),
        "EmailMultiAlternatives": EmailMultiAlternatives,
        "get_connection": get_connection,
        "render_to_string": render,
        # This adapter is test-owned: the upstream imported helper has a
        # Commercial notice and is outside this AGPL-only patch.
        "generate_plain_text_from_html": lambda html: "Synthetic email",
        "get_email_configuration": lambda: (
            "unused",
            "",
            "",
            "25",
            "0",
            "0",
            "sender@example.test",
        ),
        "log_exception": errors.append,
    }
    path = patched_tree / "apps/api/plane/bgtasks/email_notification_task.py"
    email_log_model.all_objects.all().delete()
    with override_settings(
        WEB_URL="https://plane.example.test",
        EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    ):
        get_connection()
        mail.outbox.clear()
        module = _task_definitions(path, namespace)
        pending = email_log_model.objects.create(
            receiver_id="receiver-1",
            triggered_by_id="actor-1",
            entity_identifier="issue-1",
            data={},
            processed_at=timezone.now(),
        )

        def send(ids=None):
            module.send_email_notification.run(
                issue_id="issue-1",
                notification_data={},
                receiver_id="receiver-1",
                email_notification_ids=[pending.pk] if ids is None else ids,
            )

        try:
            yield SimpleNamespace(
                module=module,
                namespace=namespace,
                redis=client,
                log=pending,
                logs=email_log_model,
                contexts=contexts,
                outbox=mail.outbox,
                errors=errors,
                send=send,
                settings=settings,
                monkeypatch=monkeypatch,
            )
        finally:
            client.delete("issue-1")
            client.connection_pool.disconnect()


@pytest.mark.integration
@pytest.mark.parametrize(
    "cached, expected",
    [
        (None, "https://plane.example.test"),
        (b"https://app.example.test/subpath/", "https://app.example.test/subpath"),
        (b"javascript:alert(1)", "https://plane.example.test"),
        (b"https://user:secret@example.test", "https://plane.example.test"),
        (b"//attacker.example.test", "https://plane.example.test"),
        (b"https://example.test/\r\nbad", "https://plane.example.test"),
        (b"\xff", "https://plane.example.test"),
        (b"https://example.test?redirect=unsafe", "https://plane.example.test"),
    ],
)
def test_notification_origin_loss_or_invalid_value_uses_canonical_url(
    notification_harness, cached, expected
):
    harness = notification_harness
    if cached is None:
        harness.redis.delete("issue-1")
    else:
        harness.redis.set("issue-1", cached)

    harness.send()

    assert len(harness.outbox) == 1
    assert harness.contexts[0]["issue_url"].startswith(
        expected + "/qualification/projects/"
    )
    harness.log.refresh_from_db()
    assert harness.log.sent_at is not None
    # A sequential redelivery after success must not send a duplicate.
    harness.send()
    assert len(harness.outbox) == 1


@pytest.mark.integration
def test_cache_get_failure_preserves_eligibility_and_retry_sends(
    notification_harness, monkeypatch
):
    harness = notification_harness
    get = harness.redis.get
    failed_get = Mock(side_effect=redis.ConnectionError("synthetic cache outage"))
    monkeypatch.setattr(harness.redis, "get", failed_get)

    with pytest.raises(redis.ConnectionError):
        harness.send()

    failed_get.assert_called_once_with("issue-1")
    harness.log.refresh_from_db()
    assert harness.log.processed_at is None
    assert harness.log.sent_at is None
    assert harness.outbox == []
    assert not harness.redis.exists(
        f"send_email_notif_issue-1_receiver-1_{harness.log.pk}"
    )

    monkeypatch.setattr(harness.redis, "get", get)
    # Exercise the actual stacker and sender synchronously at the publish seam.
    monkeypatch.setattr(
        harness.module.send_email_notification,
        "delay",
        lambda **kwargs: harness.module.send_email_notification.run(**kwargs),
    )
    harness.module.stack_email_notification.run()
    harness.log.refresh_from_db()
    assert harness.log.sent_at is not None
    assert len(harness.outbox) == 1


@pytest.mark.integration
@pytest.mark.parametrize(
    "failure",
    ["smtp", "zero-send", "invalid-web-url", "recipient-450", "data-450", "auth-535"],
)
def test_failed_notification_returns_to_pending(
    notification_harness, monkeypatch, failure
):
    harness = notification_harness
    if failure in ("smtp", "recipient-450", "data-450", "auth-535"):
        from smtplib import (
            SMTPAuthenticationError,
            SMTPDataError,
            SMTPRecipientsRefused,
        )

        errors = {
            "smtp": OSError("synthetic SMTP outage"),
            "recipient-450": SMTPRecipientsRefused(
                {"receiver@example.test": (450, b"try later")}
            ),
            "data-450": SMTPDataError(450, b"try later"),
            "auth-535": SMTPAuthenticationError(535, b"repair configuration"),
        }
        monkeypatch.setitem(
            harness.namespace,
            "get_connection",
            Mock(side_effect=errors[failure]),
        )
    elif failure == "zero-send":
        monkeypatch.setattr(
            harness.module.EmailMultiAlternatives, "send", lambda self: 0
        )
    else:
        monkeypatch.setattr(harness.settings, "WEB_URL", "file:///unsafe")
    with pytest.raises((OSError, RuntimeError, ValueError)):
        harness.send()
    harness.log.refresh_from_db()
    assert harness.log.processed_at is None
    assert harness.log.sent_at is None
    assert harness.outbox == []


@pytest.mark.integration
@pytest.mark.parametrize(
    "failure", ["missing-issue", "missing-user", "recipient-550", "data-550"]
)
def test_terminal_notification_is_retained_but_not_republished(
    notification_harness, monkeypatch, failure
):
    from datetime import timedelta
    from smtplib import SMTPDataError, SMTPRecipientsRefused
    from django.utils import timezone

    harness = notification_harness
    if failure.startswith("missing-"):
        model = harness.namespace["Issue" if failure == "missing-issue" else "User"]
        monkeypatch.setattr(model.objects, "get", Mock(side_effect=model.DoesNotExist))
    else:
        error = (
            SMTPRecipientsRefused(
                {"receiver@example.test": (550, b"recipient refused")}
            )
            if failure == "recipient-550"
            else SMTPDataError(550, b"message refused")
        )
        monkeypatch.setattr(
            harness.module.EmailMultiAlternatives, "send", Mock(side_effect=error)
        )
    harness.send()
    harness.log.refresh_from_db()
    assert harness.log.deleted_at is not None
    assert harness.log.sent_at is None
    assert not harness.logs.objects.filter(pk=harness.log.pk).exists()
    assert harness.logs.all_objects.filter(pk=harness.log.pk).exists()
    harness.logs.all_objects.filter(pk=harness.log.pk).update(
        processed_at=timezone.now() - timedelta(minutes=20)
    )
    publish = Mock()
    monkeypatch.setattr(harness.module.send_email_notification, "delay", publish)
    harness.module.stack_email_notification.run()
    publish.assert_not_called()


@pytest.mark.integration
def test_stacker_scopes_each_issue_and_reverts_publication_failure(
    notification_harness, monkeypatch
):
    from django.utils import timezone

    harness = notification_harness
    harness.logs.objects.update(processed_at=None)
    other = harness.logs.objects.create(
        receiver_id="receiver-1",
        triggered_by_id="actor-1",
        entity_identifier="issue-2",
        data={},
    )
    already_sent = harness.logs.objects.create(
        receiver_id="receiver-1",
        triggered_by_id="actor-1",
        entity_identifier="issue-sent",
        data={},
        sent_at=timezone.now(),
    )
    published = []
    monkeypatch.setattr(
        harness.module.send_email_notification,
        "delay",
        lambda **kwargs: published.append(kwargs),
    )
    harness.module.stack_email_notification.run()
    ids_by_issue = {
        message["issue_id"]: message["email_notification_ids"] for message in published
    }
    assert ids_by_issue == {"issue-1": [harness.log.pk], "issue-2": [other.pk]}

    harness.logs.objects.update(processed_at=None)
    monkeypatch.setattr(
        harness.module.send_email_notification,
        "delay",
        Mock(side_effect=ConnectionError("synthetic broker outage")),
    )
    with pytest.raises(ConnectionError):
        harness.module.stack_email_notification.run()
    assert (
        harness.logs.objects.filter(
            processed_at__isnull=True, sent_at__isnull=True
        ).count()
        == 2
    )
    already_sent.refresh_from_db()
    assert already_sent.processed_at is None
    assert already_sent.sent_at is not None


@pytest.mark.integration
def test_stale_claim_and_lock_contention_remain_recoverable(
    notification_harness, monkeypatch
):
    from datetime import timedelta
    from django.utils import timezone

    harness = notification_harness
    lock_id = f"send_email_notif_issue-1_receiver-1_{harness.log.pk}"
    assert harness.module.acquire_lock(lock_id=lock_id)
    try:
        harness.send()
    finally:
        harness.module.release_lock(lock_id=lock_id)
    harness.log.refresh_from_db()
    assert harness.log.sent_at is None

    # Time passing after lock contention or a crashed sender must make the row
    # eligible again; a fresh claim and a sent row must not be reclaimed.
    expired = timezone.now() - timedelta(minutes=11)
    harness.logs.objects.filter(pk=harness.log.pk).update(processed_at=expired)
    fresh = harness.logs.objects.create(
        receiver_id="receiver-1",
        triggered_by_id="actor-1",
        entity_identifier="issue-fresh",
        data={},
        processed_at=timezone.now(),
    )
    sent = harness.logs.objects.create(
        receiver_id="receiver-1",
        triggered_by_id="actor-1",
        entity_identifier="issue-sent",
        data={},
        processed_at=expired,
        sent_at=timezone.now(),
    )
    published = []

    def deliver(**kwargs):
        published.append(kwargs["email_notification_ids"])
        harness.module.send_email_notification.run(**kwargs)

    monkeypatch.setattr(harness.module.send_email_notification, "delay", deliver)
    harness.module.stack_email_notification.run()
    assert published == [[harness.log.pk]]
    harness.log.refresh_from_db()
    fresh.refresh_from_db()
    sent.refresh_from_db()
    assert harness.log.sent_at is not None
    assert len(harness.outbox) == 1
    assert fresh.processed_at is not None and fresh.sent_at is None
    assert sent.processed_at == expired and sent.sent_at is not None


def test_issue_activity_cache_write_failure_still_dispatches_notification(patched_tree):
    import json
    from celery import shared_task
    from django.core.serializers.json import DjangoJSONEncoder
    from django.utils import timezone

    failed_redis = SimpleNamespace(
        set=Mock(side_effect=redis.ConnectionError("synthetic cache write outage"))
    )
    notifications = SimpleNamespace(delay=Mock())
    activity_store = SimpleNamespace(bulk_create=Mock(return_value=[]))
    errors = []
    namespace = {
        "json": json,
        "shared_task": shared_task,
        "DjangoJSONEncoder": DjangoJSONEncoder,
        "timezone": timezone,
        "is_valid_uuid": lambda value: True,
        "Project": SimpleNamespace(
            objects=SimpleNamespace(
                get=lambda **kwargs: SimpleNamespace(workspace_id="workspace")
            )
        ),
        "Issue": SimpleNamespace(
            objects=SimpleNamespace(
                filter=lambda **kwargs: SimpleNamespace(first=lambda: None)
            )
        ),
        "IssueActivity": SimpleNamespace(objects=activity_store),
        "IssueActivitySerializer": lambda *args, **kwargs: SimpleNamespace(data=[]),
        "notifications": notifications,
        "redis_instance": lambda: failed_redis,
        "log_exception": errors.append,
    }
    path = patched_tree / "apps/api/plane/bgtasks/issue_activities_task.py"
    definitions = _task_definitions(path, namespace)
    definitions.issue_activity.run(
        type="issue.activity.updated",
        requested_data="{}",
        current_instance="{}",
        issue_id="issue",
        actor_id="actor",
        project_id="project",
        epoch=0,
        notification=True,
        origin="https://plane.example.test",
    )
    notifications.delay.assert_called_once()
    activity_store.bulk_create.assert_called_once()
    assert len(errors) == 1


@pytest.mark.integration
def test_startup_clear_preserves_live_state_and_explicit_key_is_scoped(
    patched_tree, tls_redis, load_plane_module, monkeypatch
):
    from django.core.cache import caches
    from django.core.management.base import BaseCommand
    from django.test import override_settings

    monkeypatch.setenv("REDIS_URL", tls_redis.url("localhost"))
    monkeypatch.setenv("REDIS_SSL_CA_CERTS", str(tls_redis.ca_cert))
    common = load_plane_module("plane.settings.common")
    redis_module = importlib.import_module("plane.settings.redis")
    client = _client(redis_module, tls_redis.url("localhost"), str(tls_redis.ca_cert))
    path = patched_tree / "apps/api/plane/db/management/commands/clear_cache.py"
    with override_settings(CACHES=common.CACHES):
        cache = caches["default"]
        namespace = {"cache": cache, "BaseCommand": BaseCommand}
        command = _task_definitions(path, namespace).Command()
        client.set("live:synthetic-session", "coordination")
        cache.set("synthetic-cache", "preserved", timeout=30)
        try:
            # Default args match both upstream startup entrypoints.
            options = vars(
                command.create_parser("manage.py", "clear_cache").parse_args([])
            )
            command.handle(**options)
            assert client.get("live:synthetic-session") == b"coordination"
            assert cache.get("synthetic-cache") == "preserved"
            command.handle(key="synthetic-cache")
            assert cache.get("synthetic-cache") is None
            assert client.get("live:synthetic-session") == b"coordination"
        finally:
            client.delete("live:synthetic-session")
            cache.delete("synthetic-cache")
            client.connection_pool.disconnect()


@pytest.mark.integration
def test_backend_client_rejects_untrusted_ca(tls_redis, load_plane_module):
    module = load_plane_module("plane.settings.redis")
    client = _client(
        module, tls_redis.url("localhost"), ca_certs=str(tls_redis.wrong_ca_cert)
    )

    with pytest.raises(redis.exceptions.ConnectionError) as excinfo:
        client.ping()
    message = str(excinfo.value).lower()
    assert "certificate" in message or "verify" in message, message


@pytest.mark.integration
def test_backend_client_rejects_wrong_password(tls_redis, load_plane_module):
    module = load_plane_module("plane.settings.redis")
    client = _client(
        module,
        tls_redis.url("localhost", password="wrong-password"),
        ca_certs=str(tls_redis.ca_cert),
    )

    with pytest.raises(redis.exceptions.AuthenticationError):
        client.ping()


@pytest.mark.integration
def test_django_cache_reads_over_tls(tls_redis, load_plane_module, monkeypatch):
    from django.core.cache import caches
    from django.test import override_settings

    monkeypatch.setenv("REDIS_URL", tls_redis.url("localhost"))
    monkeypatch.setenv("REDIS_SSL_CA_CERTS", str(tls_redis.ca_cert))
    common = load_plane_module("plane.settings.common")

    key = f"p01-contracts:{uuid.uuid4().hex}"
    with override_settings(CACHES=common.CACHES):
        cache = caches["default"]
        assert cache.set(key, "tls-roundtrip", timeout=30) is True
        assert cache.get(key) == "tls-roundtrip"
        cache.delete(key)


@pytest.mark.integration
def test_django_cache_rejects_wrong_hostname(tls_redis, load_plane_module, monkeypatch):
    from django.core.cache import caches
    from django.test import override_settings

    monkeypatch.setenv("REDIS_URL", tls_redis.url("127.0.0.1"))
    monkeypatch.setenv("REDIS_SSL_CA_CERTS", str(tls_redis.ca_cert))
    common = load_plane_module("plane.settings.common")

    with override_settings(CACHES=common.CACHES):
        cache = caches["default"]
        with pytest.raises(redis.exceptions.ConnectionError) as excinfo:
            cache.get(f"p01-contracts:{uuid.uuid4().hex}")
    message = str(excinfo.value).lower()
    assert "hostname" in message or "certificate" in message, message
