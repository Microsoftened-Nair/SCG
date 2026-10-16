"""Google OSV.dev Two-Stage Batch Ingestion and Hydration Engine.

Conforms to IEEE Std 830-1998, RFC 2119, and SCG Phase 3 Specification (MODULE-ENRICH-2.1).
Queries OSV.dev in chunks up to 1,000 components, extracts unique vulnerability IDs,
hydrates them concurrently via multi-tier caching (L1 LRU + L2 Redis), normalizes CVSS signals,
and filters out withdrawn advisories unconditionally.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure repository root is in sys.path for direct script execution
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import cvss
import httpx

from scg_core.enrichment.redis_cache import ResilientCacheManager
from scg_core.schemas.base import (
    CvssSource,
    SeverityLevel,
    VulnerabilityRecord,
)

logger = logging.getLogger(__name__)


def _normalize_ecosystem(eco: str) -> str:
    """Normalizes an ecosystem name to OSV.dev standard conventions."""
    eco_clean = eco.strip()
    if eco_clean.lower() == "pypi":
        return "PyPI"
    if eco_clean.lower() == "npm":
        return "npm"
    return eco_clean


def _parse_utc_datetime(dt_str: Optional[str]) -> Optional[datetime]:
    """Parses an ISO-8601 string into a timezone-aware UTC datetime."""
    if not dt_str:
        return None
    try:
        clean_str = dt_str.replace("Z", "+00:00")
        dt = datetime.fromisoformat(clean_str)
        if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except Exception:
        return None


def _extract_component_info(comp: Dict[str, Any]) -> Tuple[str, str, str, str]:
    """Extracts (name, version, ecosystem, purl) from a component dictionary."""
    name = str(comp.get("name") or comp.get("package_name") or comp.get("package") or "").strip()
    version = str(comp.get("version") or comp.get("resolved_version") or "").strip()
    ecosystem = str(comp.get("ecosystem") or "").strip()
    purl = str(comp.get("purl") or "").strip()

    # Parse from purl if name, version, or ecosystem are missing
    if purl and (not name or not version or not ecosystem):
        if purl.startswith("pkg:"):
            rest = purl[4:]
            if "/" in rest:
                eco_part, name_ver = rest.split("/", 1)
                if not ecosystem:
                    ecosystem = eco_part
                if "@" in name_ver:
                    n_part, v_part = name_ver.rsplit("@", 1)
                    if not name:
                        name = n_part
                    if not version:
                        version = v_part
                else:
                    if not name:
                        name = name_ver

    # Synthesize purl if missing
    if not purl and name and version and ecosystem:
        purl = f"pkg:{ecosystem.lower()}/{name}@{version}"
    elif not purl and name and version:
        purl = f"pkg:generic/{name}@{version}"
    elif not purl:
        purl = name or "unknown"

    return name, version, ecosystem, purl


class OSVTwoStageClient:
    """Two-stage batch ingestion and hydration client for Google OSV.dev."""

    OSV_BATCH_URL: str = "https://api.osv.dev/v1/querybatch"
    OSV_VULN_URL: str = "https://api.osv.dev/v1/vulns"
    STAGE1_TTL: int = 21600  # 6 Hours
    STAGE2_TTL: int = 604800  # 7 Days

    def __init__(
        self,
        cache: ResilientCacheManager,
        http_client: httpx.AsyncClient,
        max_concurrent_requests: int = 16,
    ) -> None:
        """Initializes the OSV client with resilient cache and concurrency controls.

        Args:
            cache: Resilient multi-tier cache manager instance.
            http_client: Configured async HTTP client for external requests.
            max_concurrent_requests: Maximum number of concurrent outbound HTTP requests.
        """
        self.cache: ResilientCacheManager = cache
        self.http_client: httpx.AsyncClient = http_client
        self.semaphore: asyncio.Semaphore = asyncio.Semaphore(max_concurrent_requests)

    async def enrich_components(
        self,
        components: List[Dict[str, str]],
    ) -> Dict[str, List[VulnerabilityRecord]]:
        """Ingests a list of components, queries OSV in batches, hydrates advisories,
        and returns mapping from component PURL to list of vulnerability records.

        Args:
            components: List of component dictionaries (name, version, ecosystem, optional purl).

        Returns:
            Dictionary mapping canonical PURL string to affected VulnerabilityRecords.
        """
        if not components:
            return {}

        all_vuln_ids: Set[str] = set()
        purl_to_vuln_ids: Dict[str, Set[str]] = {}

        # Pre-populate all component purls
        for comp in components:
            _, _, _, purl = _extract_component_info(comp)
            if purl not in purl_to_vuln_ids:
                purl_to_vuln_ids[purl] = set()

        # Chunk incoming components up to 1,000 items per OSV batch limit
        chunk_size = 1000
        for i in range(0, len(components), chunk_size):
            chunk = components[i : i + chunk_size]
            chunk_queries: List[Dict[str, Any]] = []
            chunk_purls: List[str] = []

            for comp in chunk:
                name, version, eco, purl = _extract_component_info(comp)
                chunk_queries.append({
                    "package": {
                        "name": name,
                        "ecosystem": _normalize_ecosystem(eco),
                    },
                    "version": version,
                })
                chunk_purls.append(purl)

            payload = {"queries": chunk_queries}
            batch_data = await self._post_querybatch(payload)
            results = batch_data.get("results", [])

            for purl, res in zip(chunk_purls, results):
                for stub in res.get("vulns", []):
                    v_id = stub.get("id")
                    if v_id:
                        all_vuln_ids.add(v_id)
                        purl_to_vuln_ids[purl].add(v_id)

        # Concurrently hydrate all unique advisory IDs
        unique_vuln_ids = list(all_vuln_ids)
        hydrated_results = await asyncio.gather(
            *[self._hydrate_single_vuln(v_id) for v_id in unique_vuln_ids]
        )

        vuln_record_map: Dict[str, VulnerabilityRecord] = {}
        for v_id, record in zip(unique_vuln_ids, hydrated_results):
            if record is not None:
                vuln_record_map[v_id] = record

        # Re-associate hydrated advisories to their respective component purl
        final_enrichment: Dict[str, List[VulnerabilityRecord]] = {}
        for comp in components:
            _, _, _, purl = _extract_component_info(comp)
            target_vuln_ids = purl_to_vuln_ids.get(purl, set())
            final_enrichment[purl] = [
                vuln_record_map[v_id]
                for v_id in target_vuln_ids
                if v_id in vuln_record_map
            ]

        return final_enrichment

    async def _post_querybatch(self, payload: Dict[str, Any]) -> Dict[str, Any]:
        """Submits a batch query to OSV.dev with semaphore control and exponential backoff retry.

        Args:
            payload: JSON payload conforming to OSV querybatch schema.

        Returns:
            Decoded JSON dictionary returned from OSV.dev.
        """
        async with self.semaphore:
            for attempt in range(4):
                try:
                    resp = await self.http_client.post(self.OSV_BATCH_URL, json=payload)
                    if resp.status_code == 429:
                        retry_after = resp.headers.get("Retry-After")
                        if retry_after:
                            try:
                                backoff = float(retry_after)
                            except ValueError:
                                backoff = float(2 ** attempt)
                        else:
                            backoff = float(2 ** attempt)

                        if attempt == 3:
                            resp.raise_for_status()

                        logger.warning(
                            "OSV batch query rate limited (429), backing off for %.1fs (attempt %d/4)",
                            backoff,
                            attempt + 1,
                        )
                        await asyncio.sleep(backoff)
                        continue

                    resp.raise_for_status()
                    return resp.json()
                except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                    if attempt == 3:
                        raise
                    backoff = float(2 ** attempt)
                    logger.warning(
                        "OSV batch query failed with %s, backing off for %.1fs (attempt %d/4)",
                        exc,
                        backoff,
                        attempt + 1,
                    )
                    await asyncio.sleep(backoff)

            raise RuntimeError("Exhausted retries in _post_querybatch without response")

    async def _fetch_vuln_api(self, vuln_id: str) -> Optional[Dict[str, Any]]:
        """Fetches raw advisory data directly from OSV API under semaphore and retries."""
        async with self.semaphore:
            for attempt in range(4):
                try:
                    resp = await self.http_client.get(f"{self.OSV_VULN_URL}/{vuln_id}")
                    if resp.status_code == 404:
                        return None
                    if resp.status_code == 429:
                        retry_after = resp.headers.get("Retry-After")
                        if retry_after:
                            try:
                                backoff = float(retry_after)
                            except ValueError:
                                backoff = float(2 ** attempt)
                        else:
                            backoff = float(2 ** attempt)

                        if attempt == 3:
                            resp.raise_for_status()

                        logger.warning(
                            "OSV vuln GET %s rate limited (429), backing off for %.1fs (attempt %d/4)",
                            vuln_id,
                            backoff,
                            attempt + 1,
                        )
                        await asyncio.sleep(backoff)
                        continue

                    resp.raise_for_status()
                    return resp.json()
                except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                    if attempt == 3:
                        raise
                    backoff = float(2 ** attempt)
                    logger.warning(
                        "OSV vuln GET %s failed with %s, backing off for %.1fs (attempt %d/4)",
                        vuln_id,
                        exc,
                        backoff,
                        attempt + 1,
                    )
                    await asyncio.sleep(backoff)

            return None

    async def _hydrate_single_vuln(self, vuln_id: str) -> Optional[VulnerabilityRecord]:
        """Hydrates a single vulnerability advisory by ID using multi-tier cache and normalization.

        Args:
            vuln_id: Canonical OSV vulnerability identifier (e.g. GHSA-..., CVE-...).

        Returns:
            Normalized VulnerabilityRecord or None if 404 or withdrawn.
        """
        cache_key = f"enrich:v2:vuln:{vuln_id}"

        async def fetcher() -> Optional[Dict[str, Any]]:
            raw = await self._fetch_vuln_api(vuln_id)
            if raw is None:
                return None
            if raw.get("withdrawn"):
                return None
            return raw

        raw_advisory = await self.cache.get_or_fetch(
            key=cache_key,
            ttl_seconds=self.STAGE2_TTL,
            fetcher=fetcher,
        )

        if raw_advisory is None:
            return None

        # Unconditionally exclude withdrawn advisories
        if raw_advisory.get("withdrawn"):
            return None

        return self._normalize_advisory(raw_advisory)

    def _normalize_advisory(self, raw: Dict[str, Any]) -> VulnerabilityRecord:
        """Normalizes raw OSV advisory JSON into a canonical VulnerabilityRecord.

        Args:
            raw: Raw OSV advisory dictionary.

        Returns:
            Validated VulnerabilityRecord model instance.
        """
        vuln_id = str(raw.get("id") or "").strip()
        aliases = [str(a) for a in raw.get("aliases") or [] if a]

        # Extract summary truncated to 500 characters
        summary_raw = str(raw.get("summary") or raw.get("details") or vuln_id or "No summary available").strip()
        summary = summary_raw[:500]

        # Resolve CVSS scoring precedence
        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None
        cvss_source: CvssSource = CvssSource.ABSENT

        # 1. Search severity list for score starting with 'CVSS:' -> parse with cvss.CVSS3
        for sev in raw.get("severity") or []:
            if isinstance(sev, dict):
                score_str = sev.get("score")
                if isinstance(score_str, str) and score_str.strip().startswith("CVSS:"):
                    try:
                        parsed_cvss = cvss.CVSS3(score_str.strip())
                        cvss_score = float(parsed_cvss.base_score)
                        cvss_vector = score_str.strip()
                        cvss_source = CvssSource.PUBLISHED_VECTOR
                        break
                    except Exception as exc:
                        logger.debug("Failed parsing CVSS3 vector '%s': %s", score_str, exc)

        # 2. Fallback to numeric published score in severity or database_specific.cvss.score
        if cvss_score is None:
            for sev in raw.get("severity") or []:
                if isinstance(sev, dict):
                    score_val = sev.get("score")
                    if score_val is not None and not (isinstance(score_val, str) and score_val.strip().startswith("CVSS:")):
                        try:
                            cvss_score = float(score_val)
                            cvss_source = CvssSource.PUBLISHED_SCORE
                            break
                        except (ValueError, TypeError):
                            pass

        db_specific = raw.get("database_specific") or {}
        if cvss_score is None and isinstance(db_specific, dict):
            db_cvss = db_specific.get("cvss")
            if isinstance(db_cvss, dict):
                s = db_cvss.get("score")
                if s is not None:
                    try:
                        cvss_score = float(s)
                        cvss_source = CvssSource.PUBLISHED_SCORE
                        if "vector" in db_cvss or "vectorString" in db_cvss:
                            cvss_vector = str(db_cvss.get("vector") or db_cvss.get("vectorString"))
                    except (ValueError, TypeError):
                        pass
            elif isinstance(db_cvss, (int, float)):
                cvss_score = float(db_cvss)
                cvss_source = CvssSource.PUBLISHED_SCORE

            if cvss_score is None and "cvss_score" in db_specific:
                try:
                    cvss_score = float(db_specific["cvss_score"])
                    cvss_source = CvssSource.PUBLISHED_SCORE
                except (ValueError, TypeError):
                    pass

        # 3. Fallback to qualitative label in database_specific.severity
        if cvss_score is None and isinstance(db_specific, dict):
            raw_qual = db_specific.get("severity")
            if isinstance(raw_qual, str):
                qual_upper = raw_qual.strip().upper()
                if qual_upper == "CRITICAL":
                    cvss_score = 9.0
                    cvss_source = CvssSource.INFERRED_FROM_SEVERITY
                elif qual_upper == "HIGH":
                    cvss_score = 7.0
                    cvss_source = CvssSource.INFERRED_FROM_SEVERITY
                elif qual_upper in ("MEDIUM", "MODERATE"):
                    cvss_score = 4.0
                    cvss_source = CvssSource.INFERRED_FROM_SEVERITY
                elif qual_upper == "LOW":
                    cvss_score = 0.1
                    cvss_source = CvssSource.INFERRED_FROM_SEVERITY

        # 4. If absent: cvss_score = None, cvss_source = ABSENT
        if cvss_score is None:
            cvss_score = None
            cvss_source = CvssSource.ABSENT

        # Map to SeverityLevel
        raw_db_sev = (db_specific.get("severity") or "").strip().upper() if isinstance(db_specific, dict) else ""
        if cvss_score is not None:
            if cvss_score >= 9.0:
                severity = SeverityLevel.CRITICAL
            elif cvss_score >= 7.0:
                severity = SeverityLevel.HIGH
            elif cvss_score >= 4.0:
                severity = SeverityLevel.MEDIUM
            elif cvss_score > 0.0:
                severity = SeverityLevel.LOW
            else:
                severity = SeverityLevel.NONE
        elif raw_db_sev:
            if raw_db_sev == "CRITICAL":
                severity = SeverityLevel.CRITICAL
            elif raw_db_sev == "HIGH":
                severity = SeverityLevel.HIGH
            elif raw_db_sev in ("MEDIUM", "MODERATE"):
                severity = SeverityLevel.MEDIUM
            elif raw_db_sev == "LOW":
                severity = SeverityLevel.LOW
            else:
                severity = SeverityLevel.NONE
        else:
            severity = SeverityLevel.NONE

        # Extract fixed versions, ranges_list (f"{type}:{len(events)}"), and vulnerable symbols
        fixed_versions: List[str] = []
        vulnerable_version_ranges: List[str] = []
        vulnerable_symbols: List[str] = []

        for aff in raw.get("affected") or []:
            if not isinstance(aff, dict):
                continue

            for r in aff.get("ranges") or []:
                if not isinstance(r, dict):
                    continue
                r_type = str(r.get("type") or "UNKNOWN")
                events = r.get("events") or []
                if isinstance(events, list):
                    range_entry = f"{r_type}:{len(events)}"
                    if range_entry not in vulnerable_version_ranges:
                        vulnerable_version_ranges.append(range_entry)
                    for ev in events:
                        if isinstance(ev, dict) and "fixed" in ev and ev["fixed"]:
                            fixed_ver = str(ev["fixed"]).strip()
                            if fixed_ver and fixed_ver not in fixed_versions:
                                fixed_versions.append(fixed_ver)

            eco_spec = aff.get("ecosystem_specific")
            if isinstance(eco_spec, dict):
                symbols = (
                    eco_spec.get("symbols")
                    or eco_spec.get("vulnerable_symbols")
                    or eco_spec.get("affected_symbols")
                )
                if isinstance(symbols, list):
                    for sym in symbols:
                        sym_str = str(sym).strip()
                        if sym_str and sym_str not in vulnerable_symbols:
                            vulnerable_symbols.append(sym_str)
                elif isinstance(symbols, str) and symbols.strip():
                    sym_str = symbols.strip()
                    if sym_str not in vulnerable_symbols:
                        vulnerable_symbols.append(sym_str)

        # EPSS and KEV telemetry if present
        epss_score: Optional[float] = None
        epss_percentile: Optional[float] = None
        is_known_exploited: bool = False

        if isinstance(db_specific, dict):
            epss_data = db_specific.get("epss")
            if isinstance(epss_data, dict):
                if "score" in epss_data:
                    try:
                        epss_score = float(epss_data["score"])
                    except (ValueError, TypeError):
                        pass
                if "percentile" in epss_data:
                    try:
                        epss_percentile = float(epss_data["percentile"])
                    except (ValueError, TypeError):
                        pass
            is_known_exploited = bool(db_specific.get("cisa_kev", False))

        published_dt = _parse_utc_datetime(raw.get("published"))
        withdrawn_dt = _parse_utc_datetime(raw.get("withdrawn"))

        return VulnerabilityRecord(
            id=vuln_id,
            aliases=aliases,
            summary=summary,
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            cvss_source=cvss_source,
            severity=severity,
            epss_score=epss_score,
            epss_percentile=epss_percentile,
            is_known_exploited=is_known_exploited,
            published=published_dt,
            withdrawn=withdrawn_dt,
            fixed_versions=fixed_versions,
            vulnerable_version_ranges=vulnerable_version_ranges,
            vulnerable_symbols=vulnerable_symbols,
        )


__all__ = ["OSVTwoStageClient"]


if __name__ == "__main__":
    async def _run_self_tests() -> None:
        print("Executing verification harness for scg_core/enrichment/osv_client.py (ENRICH-TC-01)...")

        def mock_handler(request: httpx.Request) -> httpx.Response:
            url_str = str(request.url)
            if url_str == "https://api.osv.dev/v1/querybatch" and request.method == "POST":
                return httpx.Response(
                    200,
                    json={
                        "results": [
                            {
                                "vulns": [
                                    {"id": "GHSA-test-01", "modified": "2024-01-01T00:00:00Z"}
                                ]
                            }
                        ]
                    },
                )
            elif url_str == "https://api.osv.dev/v1/vulns/GHSA-test-01" and request.method == "GET":
                return httpx.Response(
                    200,
                    json={
                        "id": "GHSA-test-01",
                        "aliases": ["CVE-2024-0001"],
                        "summary": "Prototype pollution vulnerability in test-pkg",
                        "database_specific": {
                            "cvss": {"score": 9.1},
                            "severity": "CRITICAL",
                        },
                        "affected": [
                            {
                                "package": {"name": "test-pkg", "ecosystem": "npm"},
                                "ranges": [
                                    {
                                        "type": "SEMVER",
                                        "events": [
                                            {"introduced": "0"},
                                            {"fixed": "1.2.3"},
                                        ],
                                    }
                                ],
                                "ecosystem_specific": {
                                    "symbols": ["merge"]
                                },
                            }
                        ],
                    },
                )
            return httpx.Response(404, json={"message": "Not Found"})

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            cache = ResilientCacheManager()
            cache.redis_available = False

            client = OSVTwoStageClient(cache=cache, http_client=http_client)
            test_components = [
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "ecosystem": "npm",
                    "purl": "pkg:npm/test-pkg@1.0.0",
                }
            ]

            results = await client.enrich_components(test_components)

            assert "pkg:npm/test-pkg@1.0.0" in results, "Component PURL missing in enrichment results"
            advisories = results["pkg:npm/test-pkg@1.0.0"]
            assert len(advisories) == 1, f"Expected 1 advisory, got {len(advisories)}"

            adv = advisories[0]
            assert adv.cvss_score == 9.1, f"Expected cvss_score == 9.1, got {adv.cvss_score}"
            assert adv.cvss_source == CvssSource.PUBLISHED_SCORE, f"Expected PUBLISHED_SCORE, got {adv.cvss_source}"
            assert adv.severity == SeverityLevel.CRITICAL, f"Expected CRITICAL, got {adv.severity}"
            assert adv.fixed_versions == ["1.2.3"], f"Expected ['1.2.3'], got {adv.fixed_versions}"
            assert adv.vulnerable_symbols == ["merge"], f"Expected ['merge'], got {adv.vulnerable_symbols}"

            await cache.close()

        print("SUCCESS: OSV Two-Stage Client verified.")

    asyncio.run(_run_self_tests())
