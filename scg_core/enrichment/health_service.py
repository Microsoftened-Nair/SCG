"""Package health metadata scraper and OpenSSF Scorecard extractor for Supply Chain Guardian (SCG).

Conforms to IEEE Std 830-1998, RFC 2119, and SCG Phase 3 Specification (MODULE-ENRICH-2.2 & MODULE-ENRICH-2.3).
Fetches package metadata from npm and PyPI registries with deduplication per package name,
detects lifecycle install scripts, derives deprecation and release telemetry, and extracts
OpenSSF Scorecards with 24-hour negative caching for HTTP 404s.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import logging
from pathlib import Path
import re
import sys
from typing import Any, Dict, List, Optional

# Ensure repository root is in sys.path for direct script execution
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

import httpx

from scg_core.enrichment.redis_cache import ResilientCacheManager
from scg_core.schemas.base import Ecosystem, PackageHealthData
from scg_core.schemas.enrichment import (
    RegistryMetadataResponse,
    ScorecardReport,
    SignalSource,
)

logger = logging.getLogger(__name__)

# Anchored regex matching GitHub VCS repositories across HTTPS, SSH, and git protocols
_VCS_RE: re.Pattern[str] = re.compile(
    r"^(?:git\+)?(?:https?://|ssh://git@|git@)?(?P<host>github\.com)[:/](?P<org>[^/]+)/(?P<repo>[^/]+?)(?:\.git)?/?$"
)


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


class PackageHealthAggregator:
    """Aggregates registry metadata and OpenSSF Scorecards for npm and PyPI packages."""

    SCORECARD_BASE: str = "https://api.securityscorecards.dev/projects"
    NPM_REGISTRY_BASE: str = "https://registry.npmjs.org"
    NPM_DOWNLOADS_BASE: str = "https://api.npmjs.org/downloads/point/last-week"
    PYPI_BASE: str = "https://pypi.org/pypi"

    def __init__(
        self,
        cache: ResilientCacheManager,
        http_client: httpx.AsyncClient,
        max_registry_concurrency: int = 8,
        max_scorecard_concurrency: int = 4,
    ) -> None:
        """Initializes the package health aggregator with concurrency throttles.

        Args:
            cache: Resilient multi-tier cache manager instance.
            http_client: Async HTTP client for outbound API requests.
            max_registry_concurrency: Maximum concurrent registry HTTP requests.
            max_scorecard_concurrency: Maximum concurrent OpenSSF Scorecard requests.
        """
        self.cache: ResilientCacheManager = cache
        self.http_client: httpx.AsyncClient = http_client
        self.sem_reg: asyncio.Semaphore = asyncio.Semaphore(max_registry_concurrency)
        self.sem_sc: asyncio.Semaphore = asyncio.Semaphore(max_scorecard_concurrency)

    async def get_package_health(
        self,
        package_name: str,
        version: str,
        ecosystem: Ecosystem,
    ) -> PackageHealthData:
        """Assembles comprehensive package health data from upstream registry and Scorecard.

        1. Calls _fetch_registry_metadata (cached per package name with 6-hour TTL).
        2. If VCS URL found, calls _fetch_scorecard (cached for 24 hours).
           If untracked/404, caches negative sentinel and records SignalSource.UNAVAILABLE_404.
        3. Assembles and returns complete PackageHealthData with explicit provenance.

        Args:
            package_name: Canonical package name.
            version: Resolved package version string.
            ecosystem: Package ecosystem (npm or pypi).

        Returns:
            Validated PackageHealthData model instance.
        """
        meta = await self._fetch_registry_metadata(package_name, version, ecosystem)

        openssf_scorecard_score: Optional[float] = None
        if meta.vcs_url:
            scorecard_report = await self._fetch_scorecard(meta.vcs_url)
            if scorecard_report is not None:
                openssf_scorecard_score = scorecard_report.aggregate_score
                meta.signal_sources["openssf_scorecard_score"] = SignalSource.SCORECARD
            else:
                meta.signal_sources["openssf_scorecard_score"] = SignalSource.UNAVAILABLE_404
        else:
            meta.signal_sources["openssf_scorecard_score"] = SignalSource.UNAVAILABLE_404

        now_utc = datetime.now(timezone.utc)
        published_dt = meta.published_date or now_utc
        last_activity_dt = meta.last_registry_activity or now_utc

        return PackageHealthData(
            published_date=published_dt,
            last_registry_activity=last_activity_dt,
            maintainer_count=meta.maintainer_count,
            weekly_downloads=meta.weekly_downloads,
            has_install_scripts=bool(meta.has_install_scripts),
            openssf_scorecard_score=openssf_scorecard_score,
            is_deprecated=bool(meta.is_deprecated),
            signal_sources=meta.signal_sources,
        )

    async def _fetch_registry_metadata(
        self,
        package_name: str,
        version: str,
        ecosystem: Ecosystem,
    ) -> RegistryMetadataResponse:
        """Fetches and caches the upstream registry document per package name (6-hour TTL).

        Args:
            package_name: Canonical package identifier.
            version: Target version.
            ecosystem: npm or pypi ecosystem.

        Returns:
            Extracted RegistryMetadataResponse for the requested version.
        """
        cache_key = f"enrich:v2:registry:{ecosystem.value}:{package_name}"

        async def fetcher() -> Optional[Dict[str, Any]]:
            async with self.sem_reg:
                for attempt in range(4):
                    try:
                        if ecosystem == Ecosystem.NPM:
                            headers = {"Accept": "application/vnd.npm.install-v1+json"}
                            resp = await self.http_client.get(
                                f"{self.NPM_REGISTRY_BASE}/{package_name}",
                                headers=headers,
                            )
                        elif ecosystem == Ecosystem.PYPI:
                            resp = await self.http_client.get(
                                f"{self.PYPI_BASE}/{package_name}/json"
                            )
                        else:
                            return None

                        if resp.status_code == 404:
                            return None
                        if resp.status_code == 429:
                            retry_after = resp.headers.get("Retry-After")
                            backoff = float(retry_after) if retry_after else float(2 ** attempt)
                            if attempt == 3:
                                resp.raise_for_status()
                            await asyncio.sleep(backoff)
                            continue

                        resp.raise_for_status()
                        return resp.json()
                    except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                        if attempt == 3:
                            raise
                        backoff = float(2 ** attempt)
                        await asyncio.sleep(backoff)
                return None

        raw_doc = await self.cache.get_or_fetch(
            key=cache_key,
            ttl_seconds=21600,  # 6 Hours
            fetcher=fetcher,
        )

        if raw_doc is None:
            return self._create_404_metadata_response(package_name, version, ecosystem)

        return await self._extract_version_metadata(raw_doc, package_name, version, ecosystem)

    async def _fetch_npm_downloads(self, package_name: str) -> Optional[int]:
        """Fetches npm weekly downloads telemetry from api.npmjs.org."""
        cache_key = f"enrich:v2:npm_downloads:{package_name}"

        async def fetcher() -> Optional[Dict[str, Any]]:
            async with self.sem_reg:
                for attempt in range(3):
                    try:
                        resp = await self.http_client.get(f"{self.NPM_DOWNLOADS_BASE}/{package_name}")
                        if resp.status_code == 200:
                            return resp.json()
                        elif resp.status_code == 404:
                            return None
                        await asyncio.sleep(0.5 * (2 ** attempt))
                    except Exception:
                        await asyncio.sleep(0.5 * (2 ** attempt))
                return None

        data = await self.cache.get_or_fetch(cache_key, ttl_seconds=21600, fetcher=fetcher)
        if data and isinstance(data, dict) and "downloads" in data:
            try:
                return int(data["downloads"])
            except (ValueError, TypeError):
                return None
        return None

    async def _extract_version_metadata(
        self,
        raw_doc: Dict[str, Any],
        package_name: str,
        version: str,
        ecosystem: Ecosystem,
    ) -> RegistryMetadataResponse:
        """Normalizes version-specific metadata from a raw registry document.

        Args:
            raw_doc: Decoded JSON document from npm or PyPI registry.
            package_name: Package identifier.
            version: Target version string.
            ecosystem: Target ecosystem.

        Returns:
            RegistryMetadataResponse model instance.
        """
        signal_sources: Dict[str, SignalSource] = {}

        if ecosystem == Ecosystem.NPM:
            time_dict = raw_doc.get("time") or {}
            pub_date_str = time_dict.get(version)
            mod_date_str = time_dict.get("modified") or raw_doc.get("modified")

            published_date = _parse_utc_datetime(pub_date_str)
            last_activity = _parse_utc_datetime(mod_date_str)

            signal_sources["published_date"] = SignalSource.REGISTRY if published_date else SignalSource.UNAVAILABLE_404
            signal_sources["last_registry_activity"] = SignalSource.REGISTRY if last_activity else SignalSource.UNAVAILABLE_404

            versions = raw_doc.get("versions") or {}
            ver_data = versions.get(version) or {}

            # Check scripts for preinstall, install, postinstall
            scripts = ver_data.get("scripts") or {}
            has_install_scripts = bool(any(k in scripts for k in ("preinstall", "install", "postinstall")))
            signal_sources["has_install_scripts"] = SignalSource.REGISTRY

            # Check deprecated field in version object
            is_deprecated = bool(ver_data.get("deprecated"))
            signal_sources["is_deprecated"] = SignalSource.REGISTRY

            # Extract repository URL
            repo_info = ver_data.get("repository") or raw_doc.get("repository")
            vcs_url: Optional[str] = None
            if isinstance(repo_info, dict):
                vcs_url = repo_info.get("url")
            elif isinstance(repo_info, str):
                vcs_url = repo_info

            # Maintainers count
            maintainers = ver_data.get("maintainers") or raw_doc.get("maintainers")
            maintainer_count: Optional[int] = None
            if isinstance(maintainers, list) and len(maintainers) > 0:
                maintainer_count = len(maintainers)
                signal_sources["maintainer_count"] = SignalSource.REGISTRY
            else:
                signal_sources["maintainer_count"] = SignalSource.UNAVAILABLE_404

            # Weekly downloads
            weekly_downloads = await self._fetch_npm_downloads(package_name)
            if weekly_downloads is not None:
                signal_sources["weekly_downloads"] = SignalSource.REGISTRY
            else:
                signal_sources["weekly_downloads"] = SignalSource.UNAVAILABLE_404

            return RegistryMetadataResponse(
                package_name=package_name,
                ecosystem=ecosystem,
                version=version,
                published_date=published_date,
                last_registry_activity=last_activity,
                maintainer_count=maintainer_count,
                weekly_downloads=weekly_downloads,
                has_install_scripts=has_install_scripts,
                vcs_url=vcs_url,
                is_deprecated=is_deprecated,
                signal_sources=signal_sources,
            )

        elif ecosystem == Ecosystem.PYPI:
            info = raw_doc.get("info") or {}
            releases = raw_doc.get("releases") or {}
            release_files = releases.get(version) or []

            # Inspect release artifacts: if all bdist_wheel -> False; if sdist present -> True
            has_sdist = any(
                f.get("packagetype") == "sdist" or str(f.get("filename", "")).endswith((".tar.gz", ".zip"))
                for f in release_files
                if isinstance(f, dict)
            )
            all_wheels = bool(release_files) and all(
                f.get("packagetype") == "bdist_wheel"
                for f in release_files
                if isinstance(f, dict)
            )

            if has_sdist:
                has_install_scripts = True
            elif all_wheels:
                has_install_scripts = False
            else:
                has_install_scripts = False
            signal_sources["has_install_scripts"] = SignalSource.REGISTRY

            # Derive is_deprecated from yanked boolean flag on release files or info
            is_deprecated = any(
                bool(f.get("yanked")) for f in release_files if isinstance(f, dict)
            ) or bool(info.get("yanked"))
            signal_sources["is_deprecated"] = SignalSource.REGISTRY

            # Published date from upload_time_iso_8601
            published_date: Optional[datetime] = None
            for f in release_files:
                if isinstance(f, dict):
                    up_str = f.get("upload_time_iso_8601") or f.get("upload_time")
                    parsed_up = _parse_utc_datetime(up_str)
                    if parsed_up:
                        published_date = parsed_up
                        break
            signal_sources["published_date"] = SignalSource.REGISTRY if published_date else SignalSource.UNAVAILABLE_404

            # Derive last registry activity across latest release files
            last_activity: Optional[datetime] = published_date
            all_upload_times: List[datetime] = []
            for rel_version, files in releases.items():
                for f in files:
                    if isinstance(f, dict):
                        up_t = _parse_utc_datetime(f.get("upload_time_iso_8601") or f.get("upload_time"))
                        if up_t:
                            all_upload_times.append(up_t)
            if all_upload_times:
                last_activity = max(all_upload_times)
            signal_sources["last_registry_activity"] = SignalSource.REGISTRY if last_activity else SignalSource.UNAVAILABLE_404

            # For PyPI: Set weekly_downloads and maintainer_count explicitly to None with NOT_APPLICABLE
            signal_sources["weekly_downloads"] = SignalSource.NOT_APPLICABLE
            signal_sources["maintainer_count"] = SignalSource.NOT_APPLICABLE

            # Extract repository URL from project_urls or home_page
            vcs_url = None
            project_urls = info.get("project_urls") or {}
            for _, url_val in project_urls.items():
                if isinstance(url_val, str) and _VCS_RE.match(url_val.strip()):
                    vcs_url = url_val.strip()
                    break

            if not vcs_url and "home_page" in info:
                hp = str(info["home_page"]).strip()
                if _VCS_RE.match(hp):
                    vcs_url = hp

            return RegistryMetadataResponse(
                package_name=package_name,
                ecosystem=ecosystem,
                version=version,
                published_date=published_date,
                last_registry_activity=last_activity,
                maintainer_count=None,
                weekly_downloads=None,
                has_install_scripts=has_install_scripts,
                vcs_url=vcs_url,
                is_deprecated=is_deprecated,
                signal_sources=signal_sources,
            )

        return self._create_404_metadata_response(package_name, version, ecosystem)

    def _create_404_metadata_response(
        self,
        package_name: str,
        version: str,
        ecosystem: Ecosystem,
    ) -> RegistryMetadataResponse:
        """Generates a negative 404 RegistryMetadataResponse fallback."""
        signals = {
            "published_date": SignalSource.UNAVAILABLE_404,
            "last_registry_activity": SignalSource.UNAVAILABLE_404,
            "maintainer_count": SignalSource.UNAVAILABLE_404,
            "weekly_downloads": SignalSource.UNAVAILABLE_404,
            "has_install_scripts": SignalSource.UNAVAILABLE_404,
            "is_deprecated": SignalSource.UNAVAILABLE_404,
        }
        return RegistryMetadataResponse(
            package_name=package_name,
            ecosystem=ecosystem,
            version=version,
            published_date=None,
            last_registry_activity=None,
            maintainer_count=None,
            weekly_downloads=None,
            has_install_scripts=False,
            vcs_url=None,
            is_deprecated=False,
            signal_sources=signals,
        )

    async def _fetch_scorecard(self, vcs_url: str) -> Optional[ScorecardReport]:
        """Fetches OpenSSF Scorecard report from securityscorecards.dev (cached for 24h).

        Matches _VCS_RE to extract org and repo. On 404, returns None and caches negative sentinel.
        Extracts aggregate score and check mappings.

        Args:
            vcs_url: Upstream VCS repository URL.

        Returns:
            Normalized ScorecardReport or None if untracked / 404 / unsupported.
        """
        if not vcs_url:
            return None

        match = _VCS_RE.match(vcs_url.strip())
        if not match:
            return None

        org = match.group("org")
        repo = match.group("repo")
        cache_key = f"enrich:v2:scorecard:github:{org}:{repo}"

        async def fetcher() -> Optional[Dict[str, Any]]:
            async with self.sem_sc:
                for attempt in range(4):
                    try:
                        url = f"{self.SCORECARD_BASE}/github.com/{org}/{repo}"
                        resp = await self.http_client.get(url)
                        if resp.status_code == 404:
                            return None
                        if resp.status_code == 429:
                            retry_after = resp.headers.get("Retry-After")
                            backoff = float(retry_after) if retry_after else float(2 ** attempt)
                            if attempt == 3:
                                resp.raise_for_status()
                            await asyncio.sleep(backoff)
                            continue

                        resp.raise_for_status()
                        return resp.json()
                    except (httpx.TransportError, httpx.HTTPStatusError) as exc:
                        if attempt == 3:
                            raise
                        backoff = float(2 ** attempt)
                        await asyncio.sleep(backoff)
                return None

        raw_sc = await self.cache.get_or_fetch(
            key=cache_key,
            ttl_seconds=86400,  # 24 Hours
            fetcher=fetcher,
        )

        if raw_sc is None:
            return None

        # Extract aggregate score and checks
        raw_score = raw_sc.get("score")
        aggregate_score: Optional[float] = None
        if raw_score is not None:
            try:
                aggregate_score = float(raw_score)
            except (ValueError, TypeError):
                pass

        checks_map: Dict[str, int] = {}
        for chk in raw_sc.get("checks") or []:
            if isinstance(chk, dict):
                c_name = chk.get("name")
                c_score = chk.get("score")
                if c_name and c_score is not None:
                    try:
                        checks_map[str(c_name)] = int(c_score)
                    except (ValueError, TypeError):
                        pass

        repo_url = f"https://github.com/{org}/{repo}"
        date_str = str(raw_sc.get("date")) if raw_sc.get("date") else None

        return ScorecardReport(
            aggregate_score=aggregate_score,
            repo_url=repo_url,
            checks=checks_map,
            date=date_str,
        )


__all__ = ["PackageHealthAggregator", "_VCS_RE"]


if __name__ == "__main__":
    async def _run_self_tests() -> None:
        print("Executing verification harness for scg_core/enrichment/health_service.py (ENRICH-TC-02)...")

        request_counter = 0

        def mock_handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_counter
            request_counter += 1
            url_str = str(request.url)

            if "registry.npmjs.org" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "name": "express",
                        "modified": "2024-01-01T00:00:00Z",
                        "time": {
                            "modified": "2024-01-01T00:00:00Z",
                            "1.0.0": "2023-01-01T00:00:00Z",
                        },
                        "repository": {
                            "type": "git",
                            "url": "https://github.com/expressjs/express.git",
                        },
                        "versions": {
                            "1.0.0": {
                                "name": "express",
                                "version": "1.0.0",
                                "scripts": {
                                    "postinstall": "echo installed"
                                },
                                "repository": {
                                    "type": "git",
                                    "url": "https://github.com/expressjs/express.git",
                                },
                            }
                        },
                    },
                )
            elif "securityscorecards.dev" in url_str:
                return httpx.Response(
                    200,
                    json={
                        "date": "2024-02-01",
                        "score": 8.4,
                        "checks": [
                            {"name": "Branch-Protection", "score": 9},
                            {"name": "Code-Review", "score": 8},
                        ],
                    },
                )
            elif "api.npmjs.org" in url_str:
                return httpx.Response(200, json={"downloads": 30000000})

            return httpx.Response(404, json={"message": "Not Found"})

        transport = httpx.MockTransport(mock_handler)
        async with httpx.AsyncClient(transport=transport) as http_client:
            cache = ResilientCacheManager()
            cache.redis_available = False

            aggregator = PackageHealthAggregator(cache=cache, http_client=http_client)

            # First invocation
            health_1 = await aggregator.get_package_health("express", "1.0.0", Ecosystem.NPM)

            # Assertions for ENRICH-TC-02
            assert health_1.has_install_scripts is True, f"Expected has_install_scripts is True, got {health_1.has_install_scripts}"
            assert health_1.openssf_scorecard_score == 8.4, f"Expected Scorecard 8.4, got {health_1.openssf_scorecard_score}"
            assert health_1.signal_sources["has_install_scripts"] == SignalSource.REGISTRY
            assert health_1.signal_sources["openssf_scorecard_score"] == SignalSource.SCORECARD

            initial_req_count = request_counter
            assert initial_req_count > 0, "Expected requests made to mock transport"

            # Second invocation (must be served cleanly from L1 cache without new requests)
            health_2 = await aggregator.get_package_health("express", "1.0.0", Ecosystem.NPM)
            assert health_2.has_install_scripts is True
            assert health_2.openssf_scorecard_score == 8.4
            assert request_counter == initial_req_count, (
                f"Requests incremented on second call: {request_counter} != {initial_req_count}"
            )

            await cache.close()

        print("SUCCESS: Health Service and Scorecard Extractor verified.")

    asyncio.run(_run_self_tests())
