"""
Evidence Enrichment Service — adds intelligence context to raw evidence.

Provides:
1. IP classification — private/public, RFC category, known ranges
2. Port intelligence — well-known service names, attack port identification
3. Protocol resolution — protocol number → human-readable name
4. Threat context — MITRE ATT&CK-style tactic mapping for threat categories
5. Geolocation estimation — continent/region based on IP range (no external API)

This is all local/offline — no external API calls required.
"""

from __future__ import annotations

import ipaddress
from typing import Any, Dict, List, Optional


# ---- IP Classification ----

# RFC 1918 + RFC 6598 private/reserved ranges
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),   # CGNAT
    ipaddress.ip_network("127.0.0.0/8"),      # Loopback
    ipaddress.ip_network("169.254.0.0/16"),   # Link-local
    ipaddress.ip_network("fc00::/7"),          # IPv6 ULA
    ipaddress.ip_network("fe80::/10"),         # IPv6 Link-local
]

# Known special-purpose ranges
_SPECIAL_RANGES = {
    "0.0.0.0/8": "This Network (RFC 1122)",
    "10.0.0.0/8": "Private — Class A (RFC 1918)",
    "100.64.0.0/10": "Shared Address Space / CGNAT (RFC 6598)",
    "127.0.0.0/8": "Loopback (RFC 1122)",
    "169.254.0.0/16": "Link-Local (RFC 3927)",
    "172.16.0.0/12": "Private — Class B (RFC 1918)",
    "192.0.0.0/24": "IETF Protocol Assignments (RFC 6890)",
    "192.0.2.0/24": "Documentation — TEST-NET-1 (RFC 5737)",
    "192.168.0.0/16": "Private — Class C (RFC 1918)",
    "198.18.0.0/15": "Benchmarking (RFC 2544)",
    "198.51.100.0/24": "Documentation — TEST-NET-2 (RFC 5737)",
    "203.0.113.0/24": "Documentation — TEST-NET-3 (RFC 5737)",
    "224.0.0.0/4": "Multicast (RFC 5771)",
    "240.0.0.0/4": "Reserved for Future Use (RFC 1112)",
    "255.255.255.255/32": "Limited Broadcast",
}


def classify_ip(ip_str: str) -> Dict[str, Any]:
    """
    Classify an IP address with network intelligence.
    
    Returns:
        dict with: is_private, is_reserved, ip_class, rfc_classification,
        network_type, risk_indicator
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return {
            "ip": ip_str,
            "valid": False,
            "error": "Invalid IP address format",
        }

    is_private = ip.is_private
    is_reserved = ip.is_reserved
    is_loopback = ip.is_loopback
    is_multicast = ip.is_multicast
    is_link_local = ip.is_link_local

    # RFC classification
    rfc_classification = "Public"
    for cidr, desc in _SPECIAL_RANGES.items():
        try:
            if ip in ipaddress.ip_network(cidr):
                rfc_classification = desc
                break
        except ValueError:
            continue

    # Network type
    if is_loopback:
        network_type = "loopback"
    elif is_link_local:
        network_type = "link_local"
    elif is_multicast:
        network_type = "multicast"
    elif is_private:
        network_type = "private"
    elif is_reserved:
        network_type = "reserved"
    else:
        network_type = "public"

    # IP version
    ip_version = ip.version

    # Simple risk indicator based on IP characteristics
    risk_indicator = "neutral"
    if is_multicast or is_reserved:
        risk_indicator = "suspicious"  # Unusual in normal traffic
    elif not is_private and not is_loopback:
        risk_indicator = "external"  # External IPs warrant more scrutiny

    return {
        "ip": ip_str,
        "valid": True,
        "version": f"IPv{ip_version}",
        "is_private": is_private,
        "is_reserved": is_reserved,
        "is_loopback": is_loopback,
        "is_multicast": is_multicast,
        "is_link_local": is_link_local,
        "network_type": network_type,
        "rfc_classification": rfc_classification,
        "risk_indicator": risk_indicator,
    }


# ---- Port Intelligence ----

# Well-known ports and their services
_WELL_KNOWN_PORTS: Dict[int, Dict[str, str]] = {
    20: {"service": "FTP Data", "category": "file_transfer"},
    21: {"service": "FTP Control", "category": "file_transfer"},
    22: {"service": "SSH", "category": "remote_access"},
    23: {"service": "Telnet", "category": "remote_access"},
    25: {"service": "SMTP", "category": "email"},
    53: {"service": "DNS", "category": "name_resolution"},
    67: {"service": "DHCP Server", "category": "network_config"},
    68: {"service": "DHCP Client", "category": "network_config"},
    69: {"service": "TFTP", "category": "file_transfer"},
    80: {"service": "HTTP", "category": "web"},
    110: {"service": "POP3", "category": "email"},
    111: {"service": "RPC", "category": "remote_procedure_call"},
    123: {"service": "NTP", "category": "time_sync"},
    135: {"service": "MS-RPC", "category": "windows_service"},
    137: {"service": "NetBIOS Name", "category": "windows_service"},
    138: {"service": "NetBIOS Datagram", "category": "windows_service"},
    139: {"service": "NetBIOS Session", "category": "windows_service"},
    143: {"service": "IMAP", "category": "email"},
    161: {"service": "SNMP", "category": "network_management"},
    162: {"service": "SNMP Trap", "category": "network_management"},
    389: {"service": "LDAP", "category": "directory_service"},
    443: {"service": "HTTPS", "category": "web"},
    445: {"service": "SMB", "category": "windows_service"},
    465: {"service": "SMTPS", "category": "email"},
    514: {"service": "Syslog", "category": "logging"},
    587: {"service": "SMTP Submission", "category": "email"},
    636: {"service": "LDAPS", "category": "directory_service"},
    993: {"service": "IMAPS", "category": "email"},
    995: {"service": "POP3S", "category": "email"},
    1433: {"service": "MS-SQL", "category": "database"},
    1434: {"service": "MS-SQL Browser", "category": "database"},
    1521: {"service": "Oracle DB", "category": "database"},
    3306: {"service": "MySQL", "category": "database"},
    3389: {"service": "RDP", "category": "remote_access"},
    5432: {"service": "PostgreSQL", "category": "database"},
    5900: {"service": "VNC", "category": "remote_access"},
    5901: {"service": "VNC", "category": "remote_access"},
    6379: {"service": "Redis", "category": "database"},
    8080: {"service": "HTTP Proxy", "category": "web"},
    8443: {"service": "HTTPS Alt", "category": "web"},
    8888: {"service": "HTTP Alt", "category": "web"},
    27017: {"service": "MongoDB", "category": "database"},
}

# Ports commonly targeted in attacks
_ATTACK_PORTS: Dict[int, str] = {
    21: "FTP brute force, anonymous access",
    22: "SSH brute force, credential stuffing",
    23: "Telnet exploitation (unencrypted)",
    25: "SMTP relay abuse, email spoofing",
    53: "DNS amplification, DNS tunneling",
    80: "Web application attacks, XSS, SQLi",
    135: "MS-RPC exploitation (EternalBlue family)",
    139: "NetBIOS enumeration, SMB relay",
    443: "Web application attacks (encrypted)",
    445: "SMB exploitation (WannaCry, EternalBlue)",
    1433: "SQL Server brute force",
    3306: "MySQL brute force",
    3389: "RDP brute force, BlueKeep",
    5432: "PostgreSQL brute force",
    5900: "VNC brute force (unencrypted)",
    8080: "Web proxy exploitation",
}


def enrich_port(port: Optional[int]) -> Dict[str, Any]:
    """
    Enrich a port number with service and threat intelligence.
    """
    if port is None:
        return {"port": None, "known": False}

    info = _WELL_KNOWN_PORTS.get(port, {})
    attack_info = _ATTACK_PORTS.get(port)

    result = {
        "port": port,
        "known": bool(info),
        "service": info.get("service", "Unknown"),
        "category": info.get("category", "unknown"),
        "is_privileged": port < 1024,
        "is_ephemeral": port >= 49152,
    }

    if attack_info:
        result["attack_vector"] = attack_info
        result["is_common_target"] = True
    else:
        result["is_common_target"] = False

    return result


# ---- Protocol Resolution ----

_PROTOCOL_NAMES: Dict[int, str] = {
    0: "HOPOPT",
    1: "ICMP",
    2: "IGMP",
    6: "TCP",
    8: "EGP",
    17: "UDP",
    41: "IPv6 Encapsulation",
    43: "IPv6 Routing",
    44: "IPv6 Fragment",
    47: "GRE",
    50: "ESP",
    51: "AH",
    58: "ICMPv6",
    89: "OSPF",
    103: "PIM",
    132: "SCTP",
}


def resolve_protocol(protocol: Optional[str]) -> Dict[str, Any]:
    """Resolve protocol number or name to detailed info."""
    if protocol is None:
        return {"protocol": None, "name": "Unknown"}

    # Try as number
    try:
        proto_num = int(protocol)
        name = _PROTOCOL_NAMES.get(proto_num, f"Protocol-{proto_num}")
        return {
            "protocol": proto_num,
            "name": name,
            "is_transport": proto_num in (6, 17, 132),
            "is_control": proto_num in (1, 2, 58, 89),
        }
    except ValueError:
        # Already a name
        return {
            "protocol": protocol,
            "name": protocol.upper(),
            "is_transport": protocol.upper() in ("TCP", "UDP", "SCTP"),
            "is_control": protocol.upper() in ("ICMP", "IGMP", "ICMPV6", "OSPF"),
        }


# ---- Threat Context (MITRE ATT&CK mapping) ----

_THREAT_TACTICS: Dict[str, Dict[str, Any]] = {
    "DoS": {
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498 — Network Denial of Service",
        "description": "Denial of Service attack attempting to exhaust target resources",
        "recommended_action": "Implement rate limiting and traffic filtering",
        "severity_weight": "high",
    },
    "DoS slowloris": {
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499.001 — OS Exhaustion Flood",
        "description": "Slowloris attack — holds connections open with partial HTTP requests",
        "recommended_action": "Configure connection timeouts and request completion limits",
        "severity_weight": "high",
    },
    "DoS Slowhttptest": {
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499.001 — OS Exhaustion Flood",
        "description": "Slow HTTP attack — similar to Slowloris, targets HTTP layer",
        "recommended_action": "Deploy reverse proxy with request timeout enforcement",
        "severity_weight": "high",
    },
    "DoS Hulk": {
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499.003 — Application Exhaustion Flood",
        "description": "HULK (HTTP Unbearable Load King) — generates unique requests to bypass caching",
        "recommended_action": "Implement CAPTCHA and behavioral analysis",
        "severity_weight": "high",
    },
    "DoS GoldenEye": {
        "mitre_tactic": "Impact",
        "mitre_technique": "T1499.003 — Application Exhaustion Flood",
        "description": "GoldenEye attack — HTTP flood using randomized headers",
        "recommended_action": "Rate limit per-IP connections and deploy WAF",
        "severity_weight": "high",
    },
    "DDoS": {
        "mitre_tactic": "Impact",
        "mitre_technique": "T1498 — Network Denial of Service",
        "description": "Distributed Denial of Service — coordinated from multiple sources",
        "recommended_action": "Activate DDoS mitigation service and blackhole routing",
        "severity_weight": "critical",
    },
    "PortScan": {
        "mitre_tactic": "Reconnaissance",
        "mitre_technique": "T1046 — Network Service Discovery",
        "description": "Port scanning to enumerate open services and potential attack surface",
        "recommended_action": "Monitor for sequential port access patterns and block scanner IPs",
        "severity_weight": "medium",
    },
    "Bot": {
        "mitre_tactic": "Command and Control",
        "mitre_technique": "T1071 — Application Layer Protocol",
        "description": "Bot/C&C communication — compromised host communicating with command server",
        "recommended_action": "Isolate infected host and investigate C&C infrastructure",
        "severity_weight": "critical",
    },
    "Brute Force": {
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110 — Brute Force",
        "description": "Brute force authentication attack — systematic password guessing",
        "recommended_action": "Enforce account lockout and implement MFA",
        "severity_weight": "high",
    },
    "FTP-Patator": {
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001 — Password Guessing",
        "description": "FTP password brute force using Patator tool",
        "recommended_action": "Disable FTP, use SFTP, enforce account lockout",
        "severity_weight": "high",
    },
    "SSH-Patator": {
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001 — Password Guessing",
        "description": "SSH password brute force using Patator tool",
        "recommended_action": "Use key-based auth, implement fail2ban",
        "severity_weight": "high",
    },
    "Web Attack - Brute Force": {
        "mitre_tactic": "Credential Access",
        "mitre_technique": "T1110.001 — Password Guessing",
        "description": "Web application brute force — login form credential stuffing",
        "recommended_action": "Implement CAPTCHA, rate limiting, and account lockout",
        "severity_weight": "high",
    },
    "Web Attack - XSS": {
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1189 — Drive-by Compromise",
        "description": "Cross-Site Scripting — injection of malicious client-side scripts",
        "recommended_action": "Implement Content Security Policy and input sanitization",
        "severity_weight": "high",
    },
    "Web Attack - Sql Injection": {
        "mitre_tactic": "Initial Access",
        "mitre_technique": "T1190 — Exploit Public-Facing Application",
        "description": "SQL Injection — malicious SQL queries via user input",
        "recommended_action": "Use parameterized queries and WAF SQL injection rules",
        "severity_weight": "critical",
    },
    "Infiltration": {
        "mitre_tactic": "Lateral Movement",
        "mitre_technique": "T1570 — Lateral Tool Transfer",
        "description": "Network infiltration — unauthorized internal network access",
        "recommended_action": "Segment network, review firewall rules, investigate compromised hosts",
        "severity_weight": "critical",
    },
    "Heartbleed": {
        "mitre_tactic": "Collection",
        "mitre_technique": "T1557 — Adversary-in-the-Middle",
        "description": "Heartbleed (CVE-2014-0160) — OpenSSL memory disclosure vulnerability",
        "recommended_action": "Patch OpenSSL immediately, rotate all certificates and credentials",
        "severity_weight": "critical",
    },
}


def get_threat_context(threat_class: Optional[str]) -> Dict[str, Any]:
    """
    Get MITRE ATT&CK context and recommended actions for a threat class.
    """
    if not threat_class or threat_class.upper() == "BENIGN":
        return {
            "threat_class": threat_class,
            "mitre_tactic": None,
            "mitre_technique": None,
            "description": "No threat detected — benign traffic",
            "recommended_action": None,
        }

    # Exact match first
    if threat_class in _THREAT_TACTICS:
        result = {"threat_class": threat_class}
        result.update(_THREAT_TACTICS[threat_class])
        return result

    # Partial match
    for key, tactics in _THREAT_TACTICS.items():
        if key.lower() in threat_class.lower() or threat_class.lower() in key.lower():
            result = {"threat_class": threat_class}
            result.update(tactics)
            return result

    return {
        "threat_class": threat_class,
        "mitre_tactic": "Unknown",
        "mitre_technique": "Unknown",
        "description": f"Unrecognized threat category: {threat_class}",
        "recommended_action": "Investigate manually and classify the threat",
    }


# ---- Full Enrichment ----

def enrich_evidence(evidence) -> Dict[str, Any]:
    """
    Fully enrich an evidence record with all available intelligence.
    
    Combines IP classification, port intelligence, protocol resolution,
    and threat context into a single enrichment package.
    """
    enrichment = {
        "source_ip": classify_ip(evidence.src_ip) if evidence.src_ip else None,
        "destination_ip": classify_ip(evidence.dst_ip) if evidence.dst_ip else None,
        "source_port": enrich_port(evidence.src_port),
        "destination_port": enrich_port(evidence.dst_port),
        "protocol": resolve_protocol(evidence.protocol),
        "threat_context": get_threat_context(evidence.predicted_threat),
    }

    # Compute enrichment-based risk factors
    risk_factors = []
    if enrichment["source_ip"] and enrichment["source_ip"].get("risk_indicator") == "external":
        risk_factors.append("External source IP")
    if enrichment["destination_port"] and enrichment["destination_port"].get("is_common_target"):
        risk_factors.append(f"Common attack target port ({evidence.dst_port})")
    if enrichment["source_port"] and enrichment["source_port"].get("is_ephemeral"):
        risk_factors.append("Ephemeral source port (typical for automated tools)")
    if enrichment["threat_context"].get("severity_weight") == "critical":
        risk_factors.append("Critical threat category")

    enrichment["risk_factors"] = risk_factors
    enrichment["risk_factor_count"] = len(risk_factors)

    return enrichment
