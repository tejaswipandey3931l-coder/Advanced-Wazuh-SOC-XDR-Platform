"""
Category and event type mapping for Wazuh alerts.

Maps Wazuh decoders, rule groups, and specific rule IDs to standard ECS-aligned
categories and event types deterministically.
"""

from __future__ import annotations

from typing import Any, Tuple

# Mapping of specific Wazuh rule IDs to (category, event_type, auth_action, auth_result)
RULE_ID_OVERRIDES: dict[str, tuple[str, str, str | None, str | None]] = {
    # Server / Agent lifecycle
    "502": ("system", "os_service_event", None, None),  # Wazuh server started
    "503": ("system", "os_service_event", None, None),  # Agent started
    "504": ("system", "os_service_event", None, None),  # Agent stopped
    # SSH authentication rules
    "5710": ("authentication", "user_login_failed", "logon", "failure"),  # SSHD unauthorized/failed login attempt
    "5715": ("authentication", "user_login", "logon", "success"),  # SSHD authentication success
    "5716": ("authentication", "user_login_failed", "logon", "failure"),  # SSHD authentication failed
    "5720": ("authentication", "user_login_failed", "logon", "failure"),  # Multiple failed logins
    # Syscheck (FIM) rules
    "550": ("file", "file_modification", None, None),  # Integrity checksum changed
    "554": ("file", "file_creation", None, None),  # File added to system
    "553": ("file", "file_deletion", None, None),  # File deleted
}

# Mapping of Wazuh decoder names to default (category, event_type)
DECODER_MAPPINGS: dict[str, tuple[str, str]] = {
    "sca": ("configuration_assessment", "compliance_check"),
    "syscheck": ("file", "file_modification"),
    "sshd": ("authentication", "user_login"),
    "pam": ("authentication", "user_login"),
    "windows_security": ("authentication", "user_login"),
    "firewall": ("network", "traffic_flow"),
    "iptables": ("network", "traffic_flow"),
    "pf": ("network", "traffic_flow"),
    "cisco-ios": ("network", "network_event"),
    "json": ("system", "generic_alert"),
    "syslog": ("system", "generic_alert"),
}

# Mapping of Wazuh rule groups to (category, event_type, auth_action, auth_result)
GROUP_MAPPINGS: list[tuple[set[str], str, str, str | None, str | None]] = [
    ({"sca", "ciscat"}, "configuration_assessment", "compliance_check", None, None),
    ({"syscheck", "fim"}, "file", "file_modification", None, None),
    ({"authentication_failed"}, "authentication", "user_login_failed", "logon", "failure"),
    ({"authentication_success"}, "authentication", "user_login", "logon", "success"),
    ({"sshd", "pam"}, "authentication", "user_login", "logon", None),
    ({"firewall", "ids", "network"}, "network", "traffic_flow", None, None),
    ({"rootcheck", "attack", "malware", "virus"}, "threat", "threat_detection", None, None),
    ({"ossec", "syslog"}, "system", "os_service_event", None, None),
]


def resolve_category_and_type(
    rule_id: str | None,
    decoder_name: str | None,
    groups: list[str] | None,
    rule_level: int = 0,
) -> tuple[str, str, str | None, str | None]:
    """Resolve (event_category, event_type, auth_action, auth_result) for a Wazuh alert.

    Priority:
      1. Specific rule_id override.
      2. Decoder name (e.g. sca, syscheck).
      3. Rule group matches.
      4. Fallback based on severity level.
    """
    # 1. Check exact rule_id override
    if rule_id and str(rule_id) in RULE_ID_OVERRIDES:
        return RULE_ID_OVERRIDES[str(rule_id)]

    # 2. Check decoder name override
    if decoder_name:
        dec_lower = decoder_name.lower().strip()
        if dec_lower in DECODER_MAPPINGS:
            cat, ev_type = DECODER_MAPPINGS[dec_lower]
            return cat, ev_type, None, None

    # 3. Check rule groups
    if groups:
        lower_groups = {g.lower().strip() for g in groups}
        for match_set, cat, ev_type, action, res in GROUP_MAPPINGS:
            if lower_groups & match_set:
                return cat, ev_type, action, res

    # 4. Fallback based on severity level
    if rule_level >= 10:
        return "threat", "threat_detection", None, None
    elif rule_level >= 7:
        return "threat", "generic_alert", None, None
    else:
        return "system", "generic_alert", None, None
