"""Optional barcode lookup — the application's only outbound request.

Everywhere else, DOOM refuses to fetch anything a user supplied (D-13): the
``doc_links`` feature stores URLs and renders them but never requests them,
because a server-side fetch of a user-controlled address is a request-forgery
primitive aimed at an internal network where ``db`` and ``cache`` resolve by
hostname.

This module is the deliberate exception, and the distinction is the whole
reason it is allowed to exist:

    D-13 forbids fetching **a URL the user supplied**.
    This calls **a fixed URL template belonging to a provider chosen from a
    dict in code**, with a validated numeric barcode substituted in.

The user supplies a *parameter*. They never supply a *destination*. That is the
difference between an API client and an SSRF hole (CWE-918, T-40).

It is off unless ``BARCODE_LOOKUP_PROVIDER`` is set, and the interface says
plainly that enabling it sends product codes to a third party (T-42).
"""

from __future__ import annotations

import ipaddress
import logging
import socket
from dataclasses import dataclass
from urllib.parse import quote, urlparse

import requests

from .. import validation as v

logger = logging.getLogger(__name__)


class LookupUnavailable(RuntimeError):
    """Lookup could not be completed. Never fatal to the caller."""


@dataclass(frozen=True)
class ProductSuggestion:
    """A *suggestion*, never an assignment.

    The name lands in an editable field the user confirms. Nothing arriving
    from a third party is written to the database unreviewed.
    """

    name: str
    brand: str | None
    provider: str


def _assert_public_address(hostname: str) -> None:
    """Refuse hosts that resolve anywhere internal.

    Even with the destination pinned in code, DNS is not ours. A provider whose
    domain is hijacked — or simply misconfigured — could resolve to
    169.254.169.254 (cloud metadata), 127.0.0.1, or an address on the Docker
    network where ``db`` and ``cache`` live.

    Every returned address must be public; one bad answer fails the whole
    lookup rather than being skipped.

    KNOWN LIMITATION: this resolves and then lets requests connect, which
    leaves a DNS-rebinding window between the two. Closing it fully needs a
    transport adapter pinned to the validated IP. Recorded rather than hidden.
    """
    try:
        infos = socket.getaddrinfo(hostname, 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror as exc:
        raise LookupUnavailable(f"could not resolve {hostname}") from exc

    if not infos:
        raise LookupUnavailable(f"no address for {hostname}")

    for info in infos:
        address = ipaddress.ip_address(info[4][0])
        if (
            address.is_private
            or address.is_loopback
            or address.is_link_local
            or address.is_reserved
            or address.is_multicast
            or address.is_unspecified
        ):
            logger.error(
                "lookup_blocked_internal_address",
                extra={"extra_fields": {"host": hostname, "resolved": str(address)}},
            )
            raise LookupUnavailable(
                "the lookup provider resolved to an internal address"
            )


def _read_capped(response: requests.Response) -> bytes:
    """Read a bounded amount of the response body.

    An upstream that streams forever, or returns a gigabyte, must not be able
    to exhaust a worker (T-41). Content-Length is a claim, so the stream is
    capped as it is read rather than trusted in advance.
    """
    chunks, total = [], 0
    for chunk in response.iter_content(8192):
        total += len(chunk)
        if total > v.LOOKUP_MAX_BYTES:
            raise LookupUnavailable("the lookup response was too large")
        chunks.append(chunk)
    return b"".join(chunks)


def _clean(value, limit: int) -> str | None:
    """Bound and sanitise a value that came off the network.

    Third-party data gets the same treatment as anything a user typed:
    truncated to our own limit, control characters removed. Autoescaping
    handles rendering; this stops a hostile upstream putting newlines into logs
    or a megabyte into a column.
    """
    if not isinstance(value, str):
        return None
    text = "".join(c for c in value if c.isprintable()).strip()
    return text[:limit] or None


def lookup_barcode(barcode: str, provider_key: str) -> ProductSuggestion:
    """Ask a pinned provider what a barcode is.

    Raises LookupUnavailable for every failure mode. The caller treats that as
    "no suggestion" and saves the item anyway — a lookup must never be able to
    block capture.
    """
    # Re-validated here even though the form already did it. This function is
    # the boundary that matters, and a control at the boundary should not
    # depend on every caller having remembered (T-43).
    if not v.BARCODE_RE.match(barcode or ""):
        raise LookupUnavailable("not a valid barcode")

    provider = v.BARCODE_PROVIDERS.get(provider_key)
    if provider is None:
        # An unknown key means misconfiguration, not user input — there is no
        # request path that can set this.
        raise LookupUnavailable(f"unknown lookup provider {provider_key!r}")

    # quote() is belt and braces: the value is already digits-only, so there is
    # nothing to escape. Both together mean the barcode cannot leave its path
    # segment even if the regex above were ever loosened.
    url = provider["url"].format(barcode=quote(barcode, safe=""))
    hostname = urlparse(url).hostname
    _assert_public_address(hostname)

    try:
        response = requests.get(
            url,
            timeout=(v.LOOKUP_CONNECT_TIMEOUT, v.LOOKUP_READ_TIMEOUT),
            # THE critical flag. A redirect is exactly how a pinned host turns
            # into an arbitrary one: follow 302s and the allowlist above is
            # decorative, because the provider (or anyone who can spoof it)
            # chooses the real destination.
            allow_redirects=False,
            stream=True,
            headers={"Accept": "application/json", "User-Agent": "DOOM-inventory/1.0"},
        )
    except requests.RequestException as exc:
        raise LookupUnavailable("the lookup provider did not respond") from exc

    try:
        if response.is_redirect or response.status_code in (301, 302, 303, 307, 308):
            logger.warning(
                "lookup_refused_redirect",
                extra={"extra_fields": {"provider": provider_key,
                                        "status": response.status_code}},
            )
            raise LookupUnavailable("the lookup provider tried to redirect us")

        if response.status_code != 200:
            raise LookupUnavailable(
                f"the lookup provider returned {response.status_code}"
            )

        body = _read_capped(response)
    finally:
        response.close()

    try:
        import json

        data = json.loads(body.decode("utf-8", errors="replace"))
    except (ValueError, UnicodeDecodeError) as exc:
        raise LookupUnavailable("the lookup response was not valid JSON") from exc

    suggestion = _extract(data, provider_key)
    if suggestion is None:
        raise LookupUnavailable("that barcode was not found")
    return suggestion


def _extract(data, provider_key: str) -> ProductSuggestion | None:
    """Pull the few fields we want out of an untrusted document.

    Only expected keys are read, and only expected types are accepted. The rest
    of the response — however large or strangely shaped — is discarded.
    """
    if not isinstance(data, dict):
        return None

    if provider_key == "openfoodfacts":
        product = data.get("product")
        if not isinstance(product, dict):
            return None
        name = _clean(product.get("product_name"), v.ITEM_NAME_MAX)
        brand = _clean(product.get("brands"), 80)
    elif provider_key == "upcitemdb":
        items = data.get("items")
        if not isinstance(items, list) or not items:
            return None
        first = items[0]
        if not isinstance(first, dict):
            return None
        name = _clean(first.get("title"), v.ITEM_NAME_MAX)
        brand = _clean(first.get("brand"), 80)
    else:
        return None

    if not name:
        return None
    return ProductSuggestion(
        name=name, brand=brand, provider=v.BARCODE_PROVIDERS[provider_key]["label"]
    )
