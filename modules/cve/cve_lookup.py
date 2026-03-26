# ============================================================
# RECON-X | modules/cve/cve_lookup.py
# Description: NVD API v2.0 CVE lookup with local caching,
#              rate limiting, and CVSS-based severity mapping
# ============================================================

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import requests

from engine.findings import Finding

logger = logging.getLogger(__name__)

_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_RATE_LIMIT_SECONDS = 1.0
_CACHE_TTL_HOURS = 24


@dataclass
class CVEResult:
    """A single CVE entry with CVSS score and metadata."""
    cve_id: str
    cvss_score: float
    severity: str
    description: str
    published_date: str
    references: List[str] = field(default_factory=list)


def _cvss_to_severity(score: float) -> str:
    """Map CVSS v3 score to severity string.

    Args:
        score: CVSS v3 base score (0.0–10.0).

    Returns:
        Severity level string.
    """
    if score >= 9.0:
        return "Critical"
    elif score >= 7.0:
        return "High"
    elif score >= 4.0:
        return "Medium"
    elif score > 0.0:
        return "Low"
    return "Informational"


class CVELookup:
    """Query NVD API for CVEs affecting detected products.

    Caches results locally to avoid redundant API calls.
    Respects NVD free-tier rate limit of 1 request/second.
    """

    def __init__(
        self,
        output_dir: str,
        api_key: str = "",
        rate_limit: float = _RATE_LIMIT_SECONDS,
        cache_ttl_hours: float = _CACHE_TTL_HOURS,
    ) -> None:
        """Initialize CVELookup.

        Args:
            output_dir: Directory for caching CVE results.
            api_key: NVD API key (optional, increases rate limit).
            rate_limit: Seconds between API requests.
            cache_ttl_hours: How long to keep cached results.
        """
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.cache_ttl_seconds = cache_ttl_hours * 3600
        self.cache_path = Path(output_dir) / "cve_cache.json"
        self._cache: Dict[str, dict] = self._load_cache()
        self._last_request_time: float = 0.0

    def _load_cache(self) -> Dict[str, dict]:
        """Load CVE cache from disk.

        Returns:
            Cache dict mapping query key to result data.
        """
        if not self.cache_path.exists():
            return {}
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except (OSError, json.JSONDecodeError) as exc:
            logger.debug("Failed to load CVE cache: %s", exc)
            return {}

    def _save_cache(self) -> None:
        """Save current cache to disk."""
        try:
            self.cache_path.parent.mkdir(parents=True, exist_ok=True)
            self.cache_path.write_text(
                json.dumps(self._cache, indent=2), encoding="utf-8"
            )
        except OSError as exc:
            logger.debug("Failed to save CVE cache: %s", exc)

    def _rate_limit_wait(self) -> None:
        """Wait to respect API rate limit."""
        elapsed = time.time() - self._last_request_time
        if elapsed < self.rate_limit:
            time.sleep(self.rate_limit - elapsed)

    def _query_nvd(self, keyword: str) -> List[CVEResult]:
        """Query NVD API v2 for CVEs matching a keyword.

        Args:
            keyword: Search keyword (product name + version).

        Returns:
            List of CVEResult objects.
        """
        self._rate_limit_wait()
        self._last_request_time = time.time()

        params: Dict[str, str] = {
            "keywordSearch": keyword,
            "resultsPerPage": "20",
        }
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key:
            headers["apiKey"] = self.api_key

        try:
            response = requests.get(
                _NVD_API_URL,
                params=params,
                headers=headers,
                timeout=15,
            )
            response.raise_for_status()
            data = response.json()
        except requests.RequestException as exc:
            logger.warning("NVD API request failed for %r: %s", keyword, exc)
            return []

        results: List[CVEResult] = []
        for vuln in data.get("vulnerabilities", []):
            cve_data = vuln.get("cve", {})
            cve_id = cve_data.get("id", "")
            if not cve_id:
                continue

            # Get description
            desc = ""
            for desc_entry in cve_data.get("descriptions", []):
                if desc_entry.get("lang") == "en":
                    desc = desc_entry.get("value", "")
                    break

            # Get CVSS v3 score
            cvss_score = 0.0
            metrics = cve_data.get("metrics", {})
            for version_key in ("cvssMetricV31", "cvssMetricV30"):
                metric_list = metrics.get(version_key, [])
                if metric_list:
                    cvss_score = metric_list[0].get("cvssData", {}).get("baseScore", 0.0)
                    break
            # Fallback to CVSS v2
            if cvss_score == 0.0:
                v2_list = metrics.get("cvssMetricV2", [])
                if v2_list:
                    cvss_score = v2_list[0].get("cvssData", {}).get("baseScore", 0.0)

            # Published date
            published = cve_data.get("published", "")[:10]

            # References
            refs = [
                r.get("url", "")
                for r in cve_data.get("references", [])[:5]
                if r.get("url")
            ]

            results.append(CVEResult(
                cve_id=cve_id,
                cvss_score=cvss_score,
                severity=_cvss_to_severity(cvss_score),
                description=desc[:500],
                published_date=published,
                references=refs,
            ))

        return results

    def lookup(
        self, product: str, version: str
    ) -> List[CVEResult]:
        """Look up CVEs for a product and version.

        Checks local cache first; queries NVD if not cached.

        Args:
            product: Product/software name.
            version: Version string (may be empty).

        Returns:
            List of CVEResult objects.
        """
        product = (product or "").strip()
        version = (version or "").strip()
        if not product:
            return []

        keyword = f"{product} {version}".strip() if version else product
        cache_key = keyword.lower().replace(" ", "_")

        # Check cache
        cached = self._cache.get(cache_key)
        if cached:
            cache_time = cached.get("timestamp", 0)
            if time.time() - cache_time < self.cache_ttl_seconds:
                logger.debug("CVE cache hit for %r", keyword)
                return [CVEResult(**r) for r in cached.get("results", [])]

        # Query API
        logger.info("Querying NVD for: %s", keyword)
        results = self._query_nvd(keyword)

        # Store in cache
        self._cache[cache_key] = {
            "timestamp": time.time(),
            "results": [
                {
                    "cve_id": r.cve_id,
                    "cvss_score": r.cvss_score,
                    "severity": r.severity,
                    "description": r.description,
                    "published_date": r.published_date,
                    "references": r.references,
                }
                for r in results
            ],
        }
        self._save_cache()
        return results

    def lookup_all(
        self,
        product_versions: List[Tuple[str, str]],
        target_host: str,
    ) -> List[Finding]:
        """Look up CVEs for all product+version pairs and return findings.

        Args:
            product_versions: List of (product, version) tuples.
            target_host: Target hostname/IP for finding attribution.

        Returns:
            List of Finding objects for relevant CVEs.
        """
        findings: List[Finding] = []
        seen_cves: set = set()

        for product, version in product_versions:
            if not product:
                continue
            cve_results = self.lookup(product, version)
            for cve in cve_results:
                # Avoid duplicate CVE findings for same host
                dedup_key = f"{cve.cve_id}:{target_host}"
                if dedup_key in seen_cves:
                    continue
                seen_cves.add(dedup_key)

                severity = cve.severity
                findings.append(Finding(
                    title=f"{cve.cve_id} - {product} {version}".strip(),
                    severity=severity,  # type: ignore[arg-type]
                    category="CVE",
                    target=target_host,
                    description=(
                        f"CVE {cve.cve_id} affects {product} {version}. "
                        f"CVSS Score: {cve.cvss_score}. {cve.description}"
                    ),
                    evidence=(
                        f"Product: {product}\nVersion: {version}\n"
                        f"CVE ID: {cve.cve_id}\nCVSS Score: {cve.cvss_score}\n"
                        f"Published: {cve.published_date}"
                    ),
                    remediation=(
                        f"Update {product} to the latest patched version. "
                        f"See: https://nvd.nist.gov/vuln/detail/{cve.cve_id}"
                    ),
                    cve_ids=[cve.cve_id],
                    cvss_score=cve.cvss_score,
                    references=[f"https://nvd.nist.gov/vuln/detail/{cve.cve_id}"] + cve.references,
                ))

        return findings
