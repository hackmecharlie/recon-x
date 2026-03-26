# ============================================================
# RECON-X | engine/deduplicator.py
# Description: Finding deduplication - merges evidence for duplicate
#              findings on same target/port while keeping CVE findings
#              separate per target
# ============================================================

import logging
from typing import Dict, List, Optional, Tuple

from engine.findings import Finding

logger = logging.getLogger(__name__)


def _dedup_key(finding: Finding) -> Tuple[str, str, Optional[int]]:
    """Compute a deduplication key for a finding.

    Two findings are considered duplicates if they have the same:
    - title
    - target (IP or hostname)
    - port (or both None)

    CVE findings are NOT deduplicated across targets (same CVE on
    different hosts = separate findings).
    """
    return (finding.title, finding.target, finding.port)


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """Deduplicate findings, merging evidence from duplicates.

    If the same finding title + target + port appears more than once
    (e.g., from both nmap scripts and banner grabbing), the findings
    are merged: the first occurrence is kept and subsequent evidence
    strings are appended to the first.

    Same CVE on multiple targets are kept as separate findings.

    Args:
        findings: Flat list of Finding objects (may contain duplicates).

    Returns:
        Deduplicated list with merged evidence fields.
    """
    seen: Dict[Tuple, Finding] = {}
    result: List[Finding] = []
    duplicate_count = 0

    for finding in findings:
        key = _dedup_key(finding)

        if key in seen:
            existing = seen[key]
            # Append new evidence if it differs
            if finding.evidence and finding.evidence not in existing.evidence:
                existing.evidence = existing.evidence + "\n\n--- Additional Evidence ---\n" + finding.evidence
            # Merge CVE IDs
            for cve_id in finding.cve_ids:
                if cve_id not in existing.cve_ids:
                    existing.cve_ids.append(cve_id)
            # Merge references
            for ref in finding.references:
                if ref not in existing.references:
                    existing.references.append(ref)
            # Keep highest CVSS score
            if finding.cvss_score and (
                existing.cvss_score is None or finding.cvss_score > existing.cvss_score
            ):
                existing.cvss_score = finding.cvss_score
            duplicate_count += 1
            logger.debug("Deduplicated finding: %s @ %s:%s", finding.title, finding.target, finding.port)
        else:
            seen[key] = finding
            result.append(finding)

    if duplicate_count:
        logger.info("Deduplicated %d duplicate findings", duplicate_count)

    return result
