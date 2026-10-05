"""Comprehensive unit tests for OSVTwoStageClient (Phase 3 Track B - MODULE-ENRICH-2.1)."""

import asyncio
from typing import Any, Dict
import httpx
import pytest

from scg_core.enrichment.osv_client import OSVTwoStageClient
from scg_core.enrichment.redis_cache import NULL_SENTINEL, ResilientCacheManager
from scg_core.schemas.base import CvssSource, SeverityLevel


@pytest.mark.asyncio
async def test_enrich_tc_01_spec():
    """Reproduces ENRICH-TC-01 from requirements specification."""
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

        assert "pkg:npm/test-pkg@1.0.0" in results
        advisories = results["pkg:npm/test-pkg@1.0.0"]
        assert len(advisories) == 1

        adv = advisories[0]
        assert adv.cvss_score == 9.1
        assert adv.cvss_source == CvssSource.PUBLISHED_SCORE
        assert adv.severity == SeverityLevel.CRITICAL
        assert adv.fixed_versions == ["1.2.3"]
        assert adv.vulnerable_symbols == ["merge"]
        assert adv.vulnerable_version_ranges == ["SEMVER:2"]

        await cache.close()


@pytest.mark.asyncio
async def test_cvss_precedence_1_vector():
    """Validates Precedence 1: CVSS vector parsed with cvss.CVSS3 to get base score."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if url_str == "https://api.osv.dev/v1/querybatch":
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "GHSA-vector-01"}]}]},
            )
        elif url_str == "https://api.osv.dev/v1/vulns/GHSA-vector-01":
            return httpx.Response(
                200,
                json={
                    "id": "GHSA-vector-01",
                    "summary": "Vector test advisory",
                    "severity": [
                        {
                            "type": "CVSS_V3",
                            "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        }
                    ],
                    "database_specific": {
                        "cvss": {"score": 5.0},  # Precedence 1 must win over Precedence 2!
                        "severity": "LOW",
                    },
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        cache = ResilientCacheManager()
        cache.redis_available = False
        client = OSVTwoStageClient(cache=cache, http_client=http_client)

        results = await client.enrich_components([{"purl": "pkg:npm/demo@1.0.0"}])
        adv = results["pkg:npm/demo@1.0.0"][0]

        assert adv.cvss_score == 9.8
        assert adv.cvss_source == CvssSource.PUBLISHED_VECTOR
        assert adv.cvss_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        assert adv.severity == SeverityLevel.CRITICAL

        await cache.close()


@pytest.mark.asyncio
async def test_cvss_precedence_3_inferred_labels():
    """Validates Precedence 3: Qualitative label in database_specific.severity."""
    labels_to_expected = {
        "CRITICAL": (9.0, SeverityLevel.CRITICAL),
        "HIGH": (7.0, SeverityLevel.HIGH),
        "MEDIUM": (4.0, SeverityLevel.MEDIUM),
        "MODERATE": (4.0, SeverityLevel.MEDIUM),
        "LOW": (0.1, SeverityLevel.LOW),
    }

    cache = ResilientCacheManager()
    cache.redis_available = False

    for label, (expected_score, expected_sev) in labels_to_expected.items():
        raw_advisory = {
            "id": f"GHSA-infer-{label}",
            "summary": f"Inferred advisory {label}",
            "database_specific": {"severity": label},
        }

        transport = httpx.MockTransport(lambda req, d=raw_advisory: httpx.Response(200, json=d))
        async with httpx.AsyncClient(transport=transport) as http_client:
            client = OSVTwoStageClient(cache=cache, http_client=http_client)
            record = client._normalize_advisory(raw_advisory)
            assert record.cvss_score == expected_score
            assert record.cvss_source == CvssSource.INFERRED_FROM_SEVERITY
            assert record.severity == expected_sev

    await cache.close()


@pytest.mark.asyncio
async def test_cvss_precedence_4_absent():
    """Validates Precedence 4: Absent CVSS scoring defaults to None and CvssSource.ABSENT."""
    raw_advisory = {
        "id": "GHSA-absent-01",
        "summary": "Advisory with no CVSS telemetry",
    }
    cache = ResilientCacheManager()
    cache.redis_available = False
    async with httpx.AsyncClient() as http_client:
        client = OSVTwoStageClient(cache=cache, http_client=http_client)
        record = client._normalize_advisory(raw_advisory)
        assert record.cvss_score is None
        assert record.cvss_source == CvssSource.ABSENT
        assert record.severity == SeverityLevel.NONE
    await cache.close()


@pytest.mark.asyncio
async def test_withdrawn_advisory_unconditionally_excluded():
    """Validates that withdrawn advisories are filtered out unconditionally."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if url_str == "https://api.osv.dev/v1/querybatch":
            return httpx.Response(
                200,
                json={"results": [{"vulns": [{"id": "GHSA-withdrawn-01"}, {"id": "GHSA-active-02"}]}]},
            )
        elif url_str == "https://api.osv.dev/v1/vulns/GHSA-withdrawn-01":
            return httpx.Response(
                200,
                json={
                    "id": "GHSA-withdrawn-01",
                    "summary": "This advisory was retracted",
                    "withdrawn": "2024-02-15T12:00:00Z",
                    "database_specific": {"severity": "HIGH"},
                },
            )
        elif url_str == "https://api.osv.dev/v1/vulns/GHSA-active-02":
            return httpx.Response(
                200,
                json={
                    "id": "GHSA-active-02",
                    "summary": "Valid active advisory",
                    "database_specific": {"severity": "HIGH"},
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        cache = ResilientCacheManager()
        cache.redis_available = False
        client = OSVTwoStageClient(cache=cache, http_client=http_client)

        results = await client.enrich_components([{"purl": "pkg:npm/target@1.0.0"}])
        advisories = results["pkg:npm/target@1.0.0"]

        assert len(advisories) == 1
        assert advisories[0].id == "GHSA-active-02"

        # Verify that directly hydrating the withdrawn advisory returns None
        hydrated_withdrawn = await client._hydrate_single_vuln("GHSA-withdrawn-01")
        assert hydrated_withdrawn is None

        await cache.close()


@pytest.mark.asyncio
async def test_negative_404_caching_for_advisories():
    """Validates that 404 responses for advisories cache NULL_SENTINEL."""
    fetch_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal fetch_count
        fetch_count += 1
        return httpx.Response(404, json={"message": "Not Found"})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        cache = ResilientCacheManager()
        cache.redis_available = False
        client = OSVTwoStageClient(cache=cache, http_client=http_client)

        res1 = await client._hydrate_single_vuln("GHSA-missing-01")
        assert res1 is None
        assert fetch_count == 1

        # Check L1 cache contains NULL_SENTINEL
        cached_entry = await cache.l1.get("enrich:v2:vuln:GHSA-missing-01")
        assert cached_entry == NULL_SENTINEL

        # Subsequent call must not trigger HTTP request
        res2 = await client._hydrate_single_vuln("GHSA-missing-01")
        assert res2 is None
        assert fetch_count == 1

        await cache.close()


@pytest.mark.asyncio
async def test_querybatch_retry_and_429():
    """Validates retry logic and 429 Retry-After handling in _post_querybatch."""
    attempts = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            return httpx.Response(429, headers={"Retry-After": "0.01"})
        elif attempts == 2:
            return httpx.Response(502)
        return httpx.Response(200, json={"results": []})

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        cache = ResilientCacheManager()
        cache.redis_available = False
        client = OSVTwoStageClient(cache=cache, http_client=http_client)

        data = await client._post_querybatch({"queries": []})
        assert data == {"results": []}
        assert attempts == 3

        await cache.close()


@pytest.mark.asyncio
async def test_component_chunking_over_1000():
    """Validates chunking of component lists exceeding 1,000 items."""
    batch_call_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal batch_call_count
        if request.url == "https://api.osv.dev/v1/querybatch":
            batch_call_count += 1
            body = request.read()
            import json
            payload = json.loads(body)
            num_queries = len(payload.get("queries", []))
            return httpx.Response(200, json={"results": [{} for _ in range(num_queries)]})
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        cache = ResilientCacheManager()
        cache.redis_available = False
        client = OSVTwoStageClient(cache=cache, http_client=http_client)

        # Generate 1,050 components
        components = [
            {"name": f"pkg-{i}", "version": "1.0.0", "ecosystem": "npm"}
            for i in range(1050)
        ]

        results = await client.enrich_components(components)
        assert len(results) == 1050
        assert batch_call_count == 2  # 1000 in chunk 1, 50 in chunk 2

        await cache.close()
