"""
SHA-256 evidence hashing and integrity verification service.

Evidence Hashing Mechanism:
1. Serialize the canonical evidence data fields (sorted JSON).
2. Generate SHA-256 hash of the serialized data.
3. Optionally chain: current_hash = SHA-256(current_data + previous_hash).
4. Store the hash with the evidence record.

Integrity Verification:
1. Recalculate the hash from current evidence data.
2. Compare against stored hash.
3. Return VERIFIED or FAILED.

This is a cryptographic tamper-evident mechanism (NOT blockchain).
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Optional


def compute_evidence_hash(
    evidence_data: Dict[str, Any],
    previous_hash: Optional[str] = None,
) -> str:
    """
    Compute SHA-256 hash of evidence data.
    
    If previous_hash is provided, implements hash chaining:
    hash = SHA-256(canonical_data + previous_hash)
    
    This creates a tamper-evident sequence.
    """
    # Create canonical representation (sorted keys, consistent formatting)
    canonical = json.dumps(evidence_data, sort_keys=True, default=str)

    if previous_hash:
        canonical = canonical + previous_hash

    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def get_evidence_canonical_data(evidence) -> Dict[str, Any]:
    """Extract the canonical data fields from an Evidence ORM object for hashing."""
    return {
        "evidence_id": str(evidence.id),
        "case_id": str(evidence.case_id),
        "evidence_type": evidence.evidence_type,
        "predicted_threat": evidence.predicted_threat,
        "anomaly_score": evidence.anomaly_score,
        "classification_confidence": evidence.classification_confidence,
        "severity": evidence.severity,
        "risk_score": evidence.risk_score,
        "src_ip": evidence.src_ip,
        "dst_ip": evidence.dst_ip,
        "src_port": evidence.src_port,
        "dst_port": evidence.dst_port,
        "protocol": evidence.protocol,
        "source_file": evidence.source_file,
        "extraction_timestamp": str(evidence.extraction_timestamp),
    }


def verify_evidence_hash(evidence) -> Dict[str, Any]:
    """
    Verify evidence integrity by recalculating hash and comparing.
    
    Returns dict with verification result.
    """
    canonical_data = get_evidence_canonical_data(evidence)
    calculated_hash = compute_evidence_hash(
        canonical_data,
        previous_hash=evidence.previous_hash,
    )

    stored_hash = evidence.evidence_hash
    verified = calculated_hash == stored_hash

    return {
        "verified": verified,
        "stored_hash": stored_hash,
        "calculated_hash": calculated_hash,
        "message": (
            "INTEGRITY VERIFIED — Evidence hash matches stored hash."
            if verified
            else "INTEGRITY CHECK FAILED — Evidence may have been tampered with."
        ),
    }
