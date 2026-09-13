"""
IOC Normalization, Refanging, and IP/Domain Classification.
Enforces RFC compliance and strict security shielding for internal indicators.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any
import urllib.parse

import idna

from backend.app.models.threat_intel_result import IOCType
from threat_intel.models import IPClassification, NormalizedObservable


# Common internal / non-public domain suffixes (RFC 6761, RFC 6762, RFC 8375, and enterprise conventions)
INTERNAL_DOMAIN_SUFFIXES = (
    ".local",
    ".internal",
    ".corp",
    ".lan",
    ".arpa",
    ".home",
    ".intranet",
    ".priv",
    ".test",
    ".example",
    ".invalid",
    ".localhost",
)

# Valid file hash lengths (hex digits)
HASH_LENGTHS = {32: "md5", 40: "sha1", 64: "sha256"}


def refang(value: str) -> str:
    """
    Converts security-defanged indicator representations to standard RFC format.
    Handles:
      - hxxps:// -> https://
      - hxxp:// -> http://
      - fxp://, fxps:// -> ftp://, ftps://
      - [.] or (.) or [dot] -> .
      - [:] or (:) -> :
      - [@] or (@) or [at] -> @
      - [/] -> /
      - backslash escapes: [\\.] -> .
    """
    if not value or not isinstance(value, str):
        return ""

    s = value.strip()

    # Refang schemes
    s = re.sub(r"^hxxps://", "https://", s, flags=re.IGNORECASE)
    s = re.sub(r"^hxxp://", "http://", s, flags=re.IGNORECASE)
    s = re.sub(r"^fxps://", "ftps://", s, flags=re.IGNORECASE)
    s = re.sub(r"^fxp://", "ftp://", s, flags=re.IGNORECASE)

    # Refang brackets/parentheses around dots, colons, slashes, at signs
    s = re.sub(r"\[\.\]|\(\.\)|\[dot\]|\{\.\}|\[\\\.\]", ".", s, flags=re.IGNORECASE)
    s = re.sub(r"\[:\]|\(:\)|\[colon\]", ":", s, flags=re.IGNORECASE)
    s = re.sub(r"\[@\]|\(@\)|\[at\]", "@", s, flags=re.IGNORECASE)
    s = re.sub(r"\[/\]|\(/slash\)", "/", s, flags=re.IGNORECASE)

    return s


def classify_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> tuple[IPClassification, bool]:
    """
    Classifies an IP address into its RFC boundary.
    Returns (IPClassification, is_routable_external).
    Private, loopback, link-local, multicast, and reserved IPs MUST NEVER be sent externally.
    """
    if ip.is_loopback:
        return IPClassification.LOOPBACK, False
    if ip.is_link_local:
        return IPClassification.LINK_LOCAL, False
    if ip.is_multicast:
        return IPClassification.MULTICAST, False
    if ip.is_reserved or ip.is_unspecified:
        return IPClassification.RESERVED, False
    if ip.is_private:
        return IPClassification.PRIVATE, False

    # Additional RFC checks: carrier-grade NAT (100.64.0.0/10) is private/non-global
    if not ip.is_global:
        return IPClassification.PRIVATE, False

    return IPClassification.PUBLIC, True


def normalize_ip(value: str, source_field: str | None = None) -> NormalizedObservable | None:
    """Normalizes and validates an IPv4 or IPv6 address."""
    raw = value.strip()
    refanged = refang(raw)

    try:
        ip = ipaddress.ip_address(refanged)
    except ValueError:
        return None

    canonical = str(ip)
    classification, is_routable = classify_ip(ip)

    return NormalizedObservable(
        ioc_type=IOCType.IP,
        raw_value=raw,
        canonical_value=canonical,
        ip_classification=classification,
        is_routable_external=is_routable,
        source_field=source_field,
    )


def is_internal_domain(domain: str) -> bool:
    """Checks whether a domain is a non-routable internal or reserved domain."""
    d = domain.lower()
    if d == "localhost":
        return True
    return any(d.endswith(suffix) for suffix in INTERNAL_DOMAIN_SUFFIXES)


def normalize_domain(value: str, source_field: str | None = None) -> NormalizedObservable | None:
    """
    Normalizes a domain name:
      - Refangs
      - Lowercases
      - Strips trailing dots
      - Converts IDN to Punycode (RFC 5891)
      - Validates RFC 1035 / RFC 1123 label constraints
      - Flags internal domains (.local, .internal, etc.) as not routable externally
    """
    raw = value.strip()
    refanged = refang(raw).lower().rstrip(".")

    if not refanged or len(refanged) > 253:
        return None

    if "://" in refanged:
        try:
            parsed = urllib.parse.urlsplit(refanged)
            if parsed.hostname:
                refanged = parsed.hostname.lower().rstrip(".")
        except Exception:
            pass

    # Strip port if accidentally attached to a domain (e.g. example.com:8080)
    if ":" in refanged and not refanged.startswith("["):
        # Check if it's an IPv6 address; if so, this isn't a domain
        try:
            ipaddress.IPv6Address(refanged)
            return None
        except ValueError:
            pass
        parts = refanged.rsplit(":", 1)
        if len(parts) == 2 and parts[1].isdigit():
            refanged = parts[0]

    # Punycode / IDN encoding
    try:
        ascii_domain = idna.encode(refanged).decode("ascii").lower()
    except Exception:
        # Fallback to standard ascii if already ascii or idna error
        ascii_domain = refanged

    # Label validation
    labels = ascii_domain.split(".")
    if len(labels) < 2 and ascii_domain != "localhost":
        return None

    label_regex = re.compile(r"^[a-z0-9]([a-z0-9-_]{0,61}[a-z0-9])?$", re.IGNORECASE)
    for label in labels:
        if not label or len(label) > 63:
            return None
        if not label_regex.match(label):
            return None

    # TLD validation: last label must not be all-numeric (RFC 1123)
    tld = labels[-1]
    if tld.isdigit() and len(labels) == 4:
        # Looks like an IPv4 address, not a domain
        return None

    is_routable = not is_internal_domain(ascii_domain)

    return NormalizedObservable(
        ioc_type=IOCType.DOMAIN,
        raw_value=raw,
        canonical_value=ascii_domain,
        ip_classification=None,
        is_routable_external=is_routable,
        source_field=source_field,
    )


def normalize_url(value: str, source_field: str | None = None) -> NormalizedObservable | None:
    """
    Normalizes a URL:
      - Refangs
      - Validates scheme (http, https)
      - Lowercases scheme and hostname
      - Removes default ports (80 for http, 443 for https)
      - Removes fragments (#...)
      - Evaluates hostname routability
    """
    raw = value.strip().rstrip(".,;:!?)'\"")
    refanged = refang(raw).rstrip(".,;:!?)'\"")

    try:
        parsed = urllib.parse.urlsplit(refanged)
    except Exception:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None

    if not parsed.hostname:
        return None

    # Check hostname: can be IP or domain
    host = parsed.hostname.lower()
    is_routable = True
    ip_class: IPClassification | None = None

    try:
        # Host is an IP
        ip_obj = ipaddress.ip_address(host)
        ip_class, is_routable = classify_ip(ip_obj)
        canonical_host = str(ip_obj)
    except ValueError:
        # Host is a domain
        norm_dom = normalize_domain(host)
        if not norm_dom:
            return None
        canonical_host = norm_dom.canonical_value
        is_routable = norm_dom.is_routable_external

    # Strip default port
    port = parsed.port
    if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
        netloc = canonical_host
    elif port:
        netloc = f"{canonical_host}:{port}"
    else:
        netloc = canonical_host

    # Path normalization
    path = parsed.path if parsed.path else "/"

    # Reconstruct canonical URL without fragment
    canonical_url = urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, ""))

    return NormalizedObservable(
        ioc_type=IOCType.URL,
        raw_value=raw,
        canonical_value=canonical_url,
        ip_classification=ip_class,
        is_routable_external=is_routable,
        source_field=source_field,
    )


def normalize_hash(value: str, source_field: str | None = None) -> NormalizedObservable | None:
    """Normalizes and validates a cryptographic file hash (MD5, SHA1, SHA256)."""
    raw = value.strip()
    canonical = raw.lower()

    if len(canonical) not in HASH_LENGTHS:
        return None

    # Must be valid hex characters
    if not all(c in "0123456789abcdef" for c in canonical):
        return None

    return NormalizedObservable(
        ioc_type=IOCType.FILE_HASH,
        raw_value=raw,
        canonical_value=canonical,
        ip_classification=None,
        is_routable_external=True,
        source_field=source_field,
    )


def normalize_email(value: str, source_field: str | None = None) -> NormalizedObservable | None:
    """Normalizes and validates an email address."""
    raw = value.strip()
    refanged = refang(raw).lower()

    if "@" not in refanged:
        return None

    parts = refanged.split("@", 1)
    user_part, domain_part = parts[0], parts[1]

    if not user_part or not domain_part:
        return None

    # Basic user-part characters check
    if not re.match(r"^[a-z0-9._%+-]+$", user_part):
        return None

    norm_dom = normalize_domain(domain_part)
    if not norm_dom:
        return None

    canonical = f"{user_part}@{norm_dom.canonical_value}"
    is_routable = norm_dom.is_routable_external

    return NormalizedObservable(
        ioc_type=IOCType.EMAIL,
        raw_value=raw,
        canonical_value=canonical,
        ip_classification=None,
        is_routable_external=is_routable,
        source_field=source_field,
    )


def normalize_observable(
    value: str,
    ioc_type: IOCType | None = None,
    source_field: str | None = None,
) -> NormalizedObservable | None:
    """
    Normalizes a candidate indicator. If ioc_type is not provided,
    attempts type inference in order of specificity.
    """
    if not value or not isinstance(value, str):
        return None

    s = value.strip()
    if not s:
        return None

    if ioc_type == IOCType.IP:
        return normalize_ip(s, source_field=source_field)
    if ioc_type == IOCType.DOMAIN:
        return normalize_domain(s, source_field=source_field)
    if ioc_type == IOCType.URL:
        return normalize_url(s, source_field=source_field)
    if ioc_type == IOCType.FILE_HASH:
        return normalize_hash(s, source_field=source_field)
    if ioc_type == IOCType.EMAIL:
        return normalize_email(s, source_field=source_field)

    # Inferred normalization:
    # 1. Check URL (scheme http/https or hxxp/hxxps)
    if re.match(r"^(?:https?|hxxps?)://", s, flags=re.IGNORECASE):
        norm = normalize_url(s, source_field=source_field)
        if norm:
            return norm

    # 2. Check File Hash (32, 40, 64 hex characters)
    if len(s) in HASH_LENGTHS and re.match(r"^[a-fA-F0-9]+$", s):
        norm = normalize_hash(s, source_field=source_field)
        if norm:
            return norm

    # 3. Check IP address
    norm = normalize_ip(s, source_field=source_field)
    if norm:
        return norm

    # 4. Check Email (contains @)
    if "@" in s:
        norm = normalize_email(s, source_field=source_field)
        if norm:
            return norm

    # 5. Check Domain
    norm = normalize_domain(s, source_field=source_field)
    if norm:
        return norm

    return None
