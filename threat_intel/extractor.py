"""
IOC Extractor: Extracts and validates observables from structured events,
incident context, dictionary payloads, and unstructured text.
"""

from __future__ import annotations

import re
from typing import Any, Iterable

from backend.app.models.incident import Incident
from backend.app.models.normalized_event import NormalizedEvent
from backend.app.models.threat_intel_result import IOCType
from threat_intel.models import NormalizedObservable
from threat_intel.normalizer import (
    normalize_domain,
    normalize_email,
    normalize_hash,
    normalize_ip,
    normalize_observable,
    normalize_url,
)


# Strict regex patterns for unstructured text extraction
RE_URL = re.compile(
    r"\b(?:https?|hxxps?|ftp|fxp)://[a-zA-Z0-9.\-\[\]_]+(?::\d+)?(?:/[^\s<>'\"`{}|\^]*)?",
    re.IGNORECASE,
)
RE_EMAIL = re.compile(
    r"\b[A-Za-z0-9._%+-]+(?:@|\[@\]|\(@\))[A-Za-z0-9.-]+(?:\.|\[\.\]|\(\.\))[A-Za-z]{2,}\b",
    re.IGNORECASE,
)
RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(?:\.|\[\.\]|\(\.\))){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)
RE_IPV6 = re.compile(
    r"\b(?:[0-9a-fA-F]{1,4}:){1,7}:?(?:[0-9a-fA-F]{1,4})?\b|"
    r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|"
    r"\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b"
)
RE_HASH_SHA256 = re.compile(r"\b[a-fA-F0-9]{64}\b")
RE_HASH_SHA1 = re.compile(r"\b[a-fA-F0-9]{40}\b")
RE_HASH_MD5 = re.compile(r"\b[a-fA-F0-9]{32}\b")
RE_DOMAIN = re.compile(
    r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.|\[\.\]|\(\.\)))+[a-zA-Z]{2,}\b",
    re.IGNORECASE,
)

# File extensions to ignore when scanning text for domains to prevent false positives
IGNORED_EXTENSIONS = {
    "py", "js", "ts", "json", "xml", "html", "htm", "css", "yaml", "yml",
    "txt", "log", "md", "csv", "sql", "sh", "bash", "exe", "dll", "so",
    "bin", "gz", "tar", "zip", "7z", "conf", "ini", "cfg", "bak", "tmp",
}


class IOCExtractor:
    """Extracts, validates, and deduplicates security observables."""

    @staticmethod
    def _deduplicate(observables: Iterable[NormalizedObservable | None]) -> list[NormalizedObservable]:
        seen: set[tuple[IOCType, str]] = set()
        unique: list[NormalizedObservable] = []

        for obs in observables:
            if not obs:
                continue
            key = (obs.ioc_type, obs.canonical_value)
            if key not in seen:
                seen.add(key)
                unique.append(obs)

        return unique

    @classmethod
    def extract_from_text(cls, text: str, source_field: str | None = None) -> list[NormalizedObservable]:
        """Extracts observables from unstructured text."""
        if not text or not isinstance(text, str):
            return []

        results: list[NormalizedObservable | None] = []
        matched_spans: list[tuple[int, int]] = []

        # 1. URLs
        for m in RE_URL.finditer(text):
            norm_u = normalize_url(m.group(0), source_field=source_field or "text.url")
            if norm_u:
                results.append(norm_u)
                matched_spans.append(m.span())

        # 2. Emails
        for m in RE_EMAIL.finditer(text):
            norm_e = normalize_email(m.group(0), source_field=source_field or "text.email")
            if norm_e:
                results.append(norm_e)
                matched_spans.append(m.span())

        # 3. Hashes (order by SHA256 -> SHA1 -> MD5 to prevent substring mis-classification)
        matched_hash_spans: list[tuple[int, int]] = []
        for m in RE_HASH_SHA256.finditer(text):
            results.append(normalize_hash(m.group(0), source_field=source_field or "text.file_hash"))
            matched_hash_spans.append(m.span())

        for m in RE_HASH_SHA1.finditer(text):
            if not any(s <= m.start() and m.end() <= e for s, e in matched_hash_spans):
                results.append(normalize_hash(m.group(0), source_field=source_field or "text.file_hash"))
                matched_hash_spans.append(m.span())

        for m in RE_HASH_MD5.finditer(text):
            if not any(s <= m.start() and m.end() <= e for s, e in matched_hash_spans):
                results.append(normalize_hash(m.group(0), source_field=source_field or "text.file_hash"))
                matched_hash_spans.append(m.span())

        # 4. IPv4
        for m in RE_IPV4.finditer(text):
            results.append(normalize_ip(m.group(0), source_field=source_field or "text.ip"))

        # 5. IPv6 (check colon presence and avoid single colons)
        for m in RE_IPV6.finditer(text):
            val = m.group(0)
            if val.count(":") >= 2:
                results.append(normalize_ip(val, source_field=source_field or "text.ipv6"))

        # 6. Domains (with filtering to prevent file extension false positives)
        for m in RE_DOMAIN.finditer(text):
            val = m.group(0)
            # Check TLD
            parts = val.replace("[.]", ".").replace("(.)", ".").split(".")
            tld = parts[-1].lower()
            if tld in IGNORED_EXTENSIONS:
                continue
            # If parts look like an IPv4 address, skip
            if all(p.isdigit() for p in parts):
                continue
            results.append(normalize_domain(val, source_field=source_field or "text.domain"))

        return cls._deduplicate(results)

    @classmethod
    def extract_from_dict(cls, data: dict[str, Any], prefix: str = "") -> list[NormalizedObservable]:
        """Recursively inspects a dictionary for structured indicators and free text."""
        if not data or not isinstance(data, dict):
            return []

        results: list[NormalizedObservable | None] = []

        for key, value in data.items():
            field_name = f"{prefix}.{key}" if prefix else key

            if isinstance(value, str):
                s_val = value.strip()
                if not s_val:
                    continue

                # Specific field semantic mapping
                k_low = key.lower()
                if any(x in k_low for x in ("ip", "src_ip", "dst_ip", "client_ip", "server_ip")):
                    norm = normalize_ip(s_val, source_field=field_name)
                    if norm:
                        results.append(norm)
                        continue

                if any(x in k_low for x in ("domain", "hostname", "dns_question", "query_name")):
                    norm = normalize_domain(s_val, source_field=field_name)
                    if norm:
                        results.append(norm)
                        continue

                if any(x in k_low for x in ("url", "referrer", "uri")):
                    norm = normalize_url(s_val, source_field=field_name)
                    if norm:
                        results.append(norm)
                        continue

                if any(x in k_low for x in ("hash", "md5", "sha1", "sha256")):
                    norm = normalize_hash(s_val, source_field=field_name)
                    if norm:
                        results.append(norm)
                        continue

                if any(x in k_low for x in ("email", "mail_from", "mail_to", "recipient")):
                    norm = normalize_email(s_val, source_field=field_name)
                    if norm:
                        results.append(norm)
                        continue

                # Generic text extraction on string value
                results.extend(cls.extract_from_text(s_val, source_field=field_name))

            elif isinstance(value, dict):
                results.extend(cls.extract_from_dict(value, prefix=field_name))
            elif isinstance(value, list):
                for idx, item in enumerate(value):
                    item_field = f"{field_name}[{idx}]"
                    if isinstance(item, str):
                        results.extend(cls.extract_from_text(item, source_field=item_field))
                    elif isinstance(item, dict):
                        results.extend(cls.extract_from_dict(item, prefix=item_field))

        return cls._deduplicate(results)

    @classmethod
    def extract_from_event(cls, event: NormalizedEvent) -> list[NormalizedObservable]:
        """
        Extracts observables from a Phase 2 NormalizedEvent:
        - Structured fields: src_ip, dst_ip, file_hash, file_path
        - JSONB extra_fields
        - raw_payload text if present
        """
        results: list[NormalizedObservable | None] = []

        # 1. Structured fields
        if event.src_ip:
            results.append(normalize_ip(event.src_ip, source_field="normalized_event.src_ip"))

        if event.dst_ip:
            results.append(normalize_ip(event.dst_ip, source_field="normalized_event.dst_ip"))

        if event.file_hash:
            results.append(normalize_hash(event.file_hash, source_field="normalized_event.file_hash"))

        # 2. extra_fields inspection
        if event.extra_fields and isinstance(event.extra_fields, dict):
            results.extend(cls.extract_from_dict(event.extra_fields, prefix="extra_fields"))

        # 3. file_path inspection (check for embedded URLs or hashes in command lines/paths)
        if event.file_path and isinstance(event.file_path, str):
            results.extend(cls.extract_from_text(event.file_path, source_field="normalized_event.file_path"))

        return cls._deduplicate(results)

    @classmethod
    def extract_from_incident(
        cls,
        incident: Incident,
        events: list[NormalizedEvent] | None = None,
    ) -> list[NormalizedObservable]:
        """
        Extracts all unique observables from an Incident:
        - entity_context JSON
        - member events if provided or linked
        """
        results: list[NormalizedObservable | None] = []

        # 1. entity_context
        if incident.entity_context and isinstance(incident.entity_context, dict):
            results.extend(cls.extract_from_dict(incident.entity_context, prefix="incident.entity_context"))

        # 2. member events
        if events:
            for ev in events:
                results.extend(cls.extract_from_event(ev))

        return cls._deduplicate(results)
