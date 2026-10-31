# Copyright (c) 2023-present Plane Software, Inc. and contributors
# SPDX-License-Identifier: AGPL-3.0-only
# See the LICENSE file for details.

import logging
import ssl
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import redis
from django.conf import settings

_logger = logging.getLogger("plane")

TLS_SCHEME = "rediss"
TLS_QUERY_PREFIX = "ssl_"


def redis_url_is_tls(url):
    """Return True only for an explicit rediss:// URL.

    Substring matching would also treat a query value that happens to contain
    "rediss" as TLS and change which validation rules apply to the client.
    """
    return bool(url) and urlsplit(url).scheme == TLS_SCHEME


def redis_url_for_client(url):
    """Strip ssl_* query parameters before a URL reaches redis-py.

    redis-py lets URL query parameters override keyword arguments, so
    ``?ssl_cert_reqs=none`` would disable certificate verification even when
    the caller asks for it. TLS behaviour is set by the settings below and by
    ``redis_tls_kwargs`` only; values carried in the URL are ignored.
    """
    parsed = urlsplit(url)
    if not parsed.query:
        return url

    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    kept = [(key, value) for key, value in pairs if not key.lower().startswith(TLS_QUERY_PREFIX)]
    if len(kept) == len(pairs):
        return url

    ignored = sorted({key for key, _ in pairs if key.lower().startswith(TLS_QUERY_PREFIX)})
    _logger.warning(
        "Ignoring TLS query parameters %s in REDIS_URL; rediss:// connections always verify the certificate chain and hostname.",
        ", ".join(ignored),
    )
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, urlencode(kept), parsed.fragment))


def redis_tls_kwargs(ca_certs=None):
    """Return the TLS validation kwargs required for every rediss:// client.

    redis-py defaults ``ssl_check_hostname`` to False, so hostname
    verification has to be requested explicitly. A CA file is used only when
    one is configured; otherwise the system trust store applies.
    """
    kwargs = {
        "ssl_cert_reqs": ssl.CERT_REQUIRED,
        "ssl_check_hostname": True,
    }
    if ca_certs:
        kwargs["ssl_ca_certs"] = ca_certs
    return kwargs


def redis_instance():
    # connect to redis
    url = settings.REDIS_URL
    if redis_url_is_tls(url):
        kwargs = redis_tls_kwargs(getattr(settings, "REDIS_SSL_CA_CERTS", None))
    else:
        kwargs = {}
    # Let redis-py decode credentials and select the URL database for both schemes.
    return redis.Redis.from_url(redis_url_for_client(url), **kwargs)
