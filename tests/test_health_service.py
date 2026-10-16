"""Comprehensive unit tests for PackageHealthAggregator (Phase 3 Track B - MODULE-ENRICH-2.2 & 2.3)."""

import asyncio
from typing import Any, Dict
import httpx
import pytest

from scg_core.enrichment.health_service import PackageHealthAggregator, _VCS_RE
from scg_core.enrichment.redis_cache import ResilientCacheManager
from scg_core.schemas.base import Ecosystem
from scg_core.schemas.enrichment import SignalSource


def test_vcs_re_matching():
    """Validates _VCS_RE against various GitHub URL patterns and non-GitHub URLs."""
    valid_urls = [
        ("https://github.com/expressjs/express", "expressjs", "express"),
        ("https://github.com/expressjs/express.git", "expressjs", "express"),
        ("git+https://github.com/expressjs/express.git", "expressjs", "express"),
        ("git@github.com:expressjs/express.git", "expressjs", "express"),
        ("ssh://git@github.com/expressjs/express.git", "expressjs", "express"),
        ("https://github.com/expressjs/express/", "expressjs", "express"),
    ]

    for url, exp_org, exp_repo in valid_urls:
        m = _VCS_RE.match(url)
        assert m is not None, f"Expected match for {url}"
        assert m.group("org") == exp_org
        assert m.group("repo") == exp_repo

    invalid_urls = [
        "https://gitlab.com/org/repo",
        "https://bitbucket.org/org/repo",
        "https://github.com/incomplete",
        "not-a-url",
    ]
    for url in invalid_urls:
        assert _VCS_RE.match(url) is None, f"Expected non-match for {url}"


@pytest.mark.asyncio
async def test_enrich_tc_02_npm_health_and_scorecard():
    """Validates ENRICH-TC-02: npm package health aggregation, Scorecard score, and L1 caching."""
    request_counter = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal request_counter
        request_counter += 1
        url_str = str(request.url)

        if "registry.npmjs.org/express" in url_str:
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

        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        cache = ResilientCacheManager()
        cache.redis_available = False

        aggregator = PackageHealthAggregator(cache=cache, http_client=http_client)

        # 1. First invocation
        health_1 = await aggregator.get_package_health("express", "1.0.0", Ecosystem.NPM)

        assert health_1.has_install_scripts is True
        assert health_1.openssf_scorecard_score == 8.4
        assert health_1.signal_sources["has_install_scripts"] == SignalSource.REGISTRY
        assert health_1.signal_sources["openssf_scorecard_score"] == SignalSource.SCORECARD
        assert health_1.signal_sources["weekly_downloads"] == SignalSource.REGISTRY

        initial_requests = request_counter
        assert initial_requests > 0

        # 2. Second invocation must hit L1 without incrementing requests
        health_2 = await aggregator.get_package_health("express", "1.0.0", Ecosystem.NPM)
        assert health_2.has_install_scripts is True
        assert health_2.openssf_scorecard_score == 8.4
        assert request_counter == initial_requests, "Request counter incremented on cached call"

        await cache.close()


@pytest.mark.asyncio
async def test_pypi_health_extraction_rules():
    """Validates PyPI extraction rules: sdist vs bdist_wheel, yanked deprecation, and NOT_APPLICABLE downloads."""
    def mock_handler(request: httpx.Request) -> httpx.Response:
        url_str = str(request.url)
        if "pypi.org/pypi/requests/json" in url_str:
            return httpx.Response(
                200,
                json={
                    "info": {
                        "name": "requests",
                        "version": "2.28.1",
                        "yanked": False,
                        "project_urls": {
                            "Source": "https://github.com/psf/requests"
                        },
                    },
                    "releases": {
                        "2.28.1": [
                            {
                                "packagetype": "bdist_wheel",
                                "filename": "requests-2.28.1-py3-none-any.whl",
                                "upload_time_iso_8601": "2022-06-29T14:41:00Z",
                                "yanked": False,
                            },
                            {
                                "packagetype": "sdist",
                                "filename": "requests-2.28.1.tar.gz",
                                "upload_time_iso_8601": "2022-06-29T14:40:00Z",
                                "yanked": False,
                            },
                        ],
                        "2.28.0": [
                            {
                                "packagetype": "bdist_wheel",
                                "filename": "requests-2.28.0-py3-none-any.whl",
                                "upload_time_iso_8601": "2022-06-01T12:00:00Z",
                                "yanked": True,
                            }
                        ],
                    },
                },
            )
        elif "securityscorecards.dev" in url_str:
            return httpx.Response(
                200,
                json={"score": 9.2, "checks": []},
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        cache = ResilientCacheManager()
        cache.redis_available = False

        aggregator = PackageHealthAggregator(cache=cache, http_client=http_client)

        # 1. requests@2.28.1 has sdist -> has_install_scripts = True, not yanked -> is_deprecated = False
        health_sdist = await aggregator.get_package_health("requests", "2.28.1", Ecosystem.PYPI)
        assert health_sdist.has_install_scripts is True
        assert health_sdist.is_deprecated is False
        assert health_sdist.weekly_downloads is None
        assert health_sdist.maintainer_count is None
        assert health_sdist.signal_sources["weekly_downloads"] == SignalSource.NOT_APPLICABLE
        assert health_sdist.signal_sources["maintainer_count"] == SignalSource.NOT_APPLICABLE
        assert health_sdist.openssf_scorecard_score == 9.2

        # 2. requests@2.28.0 has only bdist_wheel -> has_install_scripts = False, yanked -> is_deprecated = True
        health_wheel = await aggregator.get_package_health("requests", "2.28.0", Ecosystem.PYPI)
        assert health_wheel.has_install_scripts is False
        assert health_wheel.is_deprecated is True

        await cache.close()


@pytest.mark.asyncio
async def test_scorecard_404_negative_caching():
    """Validates that a 404 from Scorecard caches a negative sentinel and records UNAVAILABLE_404."""
    sc_call_count = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal sc_call_count
        url_str = str(request.url)
        if "registry.npmjs.org" in url_str:
            return httpx.Response(
                200,
                json={
                    "name": "obscure-pkg",
                    "time": {"1.0.0": "2024-01-01T00:00:00Z"},
                    "repository": {"url": "https://github.com/obscure/obscure-pkg"},
                    "versions": {"1.0.0": {}},
                },
            )
        elif "securityscorecards.dev" in url_str:
            sc_call_count += 1
            return httpx.Response(404, json={"message": "Project not analyzed"})
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        cache = ResilientCacheManager()
        cache.redis_available = False

        aggregator = PackageHealthAggregator(cache=cache, http_client=http_client)

        health_1 = await aggregator.get_package_health("obscure-pkg", "1.0.0", Ecosystem.NPM)
        assert health_1.openssf_scorecard_score is None
        assert health_1.signal_sources["openssf_scorecard_score"] == SignalSource.UNAVAILABLE_404
        assert sc_call_count == 1

        # Second call should not hit securityscorecards.dev
        health_2 = await aggregator.get_package_health("obscure-pkg", "1.0.0", Ecosystem.NPM)
        assert health_2.openssf_scorecard_score is None
        assert health_2.signal_sources["openssf_scorecard_score"] == SignalSource.UNAVAILABLE_404
        assert sc_call_count == 1

        await cache.close()


@pytest.mark.asyncio
async def test_package_deduplication_across_versions():
    """Validates that querying multiple versions of the same package shares the registry cache."""
    reg_calls = 0

    def mock_handler(request: httpx.Request) -> httpx.Response:
        nonlocal reg_calls
        if "registry.npmjs.org/multi-ver" in str(request.url):
            reg_calls += 1
            return httpx.Response(
                200,
                json={
                    "name": "multi-ver",
                    "time": {
                        "1.0.0": "2023-01-01T00:00:00Z",
                        "2.0.0": "2024-01-01T00:00:00Z",
                    },
                    "versions": {
                        "1.0.0": {"scripts": {"install": "setup"}},
                        "2.0.0": {"scripts": {}},
                    },
                },
            )
        return httpx.Response(404)

    transport = httpx.MockTransport(mock_handler)
    async with httpx.AsyncClient(transport=transport) as http_client:
        cache = ResilientCacheManager()
        cache.redis_available = False
        aggregator = PackageHealthAggregator(cache=cache, http_client=http_client)

        h1 = await aggregator.get_package_health("multi-ver", "1.0.0", Ecosystem.NPM)
        assert h1.has_install_scripts is True
        assert reg_calls == 1

        # Version 2.0.0 must reuse the cached registry document for multi-ver
        h2 = await aggregator.get_package_health("multi-ver", "2.0.0", Ecosystem.NPM)
        assert h2.has_install_scripts is False
        assert reg_calls == 1, "Registry was queried again instead of reusing cached document"

        await cache.close()
