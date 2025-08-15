from __future__ import annotations

from socket import gaierror
from unittest.mock import patch

import pytest
from httpx import AsyncClient, Request

from httpx_secure import SSRFProtectionError, httpx_ssrf_protection


class SuccessError(BaseException):
    """Raised when SSRF validation passes successfully."""


async def success_hook(_: Request):
    raise SuccessError


@pytest.fixture
async def client():
    async with httpx_ssrf_protection(AsyncClient()) as client:
        client.event_hooks["request"].append(success_hook)
        yield client


@pytest.mark.parametrize(
    "url",
    [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
    ],
)
async def test_blocks_localhost(client, url):
    with pytest.raises(SSRFProtectionError, match="not globally reachable"):
        await client.get(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.1.1/",
        "http://10.0.0.1/",
        "http://172.16.0.1/",
        "http://169.254.1.1/",
        "http://[fe80::1]/",
        "http://[fc00::1]/",
    ],
)
async def test_blocks_private_networks(client, url):
    with pytest.raises(SSRFProtectionError, match="not globally reachable"):
        await client.get(url)


@pytest.mark.parametrize(
    "url",
    [
        "http://8.8.8.8/",
        "http://1.1.1.1/",
        "http://[2001:4860:4860::8888]/",
    ],
)
async def test_allows_global_addresses(client, url):
    with pytest.raises(SuccessError):
        await client.get(url)


async def test_dns_resolution_rewrites_host_header():
    async def success_hook(request: Request):
        assert request.url.host == "1.2.3.4"
        assert request.headers["Host"] == "example.com"
        assert request.extensions["sni_hostname"] == "example.com"
        raise SuccessError

    async with httpx_ssrf_protection(AsyncClient()) as client:
        client.event_hooks["request"].append(success_hook)

        with patch("httpx_secure.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.return_value = [
                (None, None, None, None, ("1.2.3.4", 443)),
            ]
            with pytest.raises(SuccessError):
                await client.get("https://example.com/")


async def test_dns_results_are_cached():
    dns_call_count = 0

    def mock_getaddrinfo_counter(*_):
        nonlocal dns_call_count
        dns_call_count += 1
        return [(None, None, None, None, ("1.2.3.4", 443))]

    async with httpx_ssrf_protection(AsyncClient(), dns_cache_ttl=5) as client:
        client.event_hooks["request"].append(success_hook)

        with patch("httpx_secure.getaddrinfo", side_effect=mock_getaddrinfo_counter):
            with pytest.raises(SuccessError):
                await client.get("https://example.com/")
            assert dns_call_count == 1

            with pytest.raises(SuccessError):
                await client.get("https://example.com/")
            assert dns_call_count == 1

            with pytest.raises(SuccessError):
                await client.get("https://example.com/path")
            assert dns_call_count == 1

            with pytest.raises(SuccessError):
                await client.get("https://api.example.com/path")
            assert dns_call_count == 2


async def test_custom_validator_blocks_specific_ips():
    async with httpx_ssrf_protection(
        AsyncClient(),
        custom_validator=(
            lambda _, ip_addr, __: str(ip_addr) not in {"8.8.8.8", "8.8.4.4"}
        ),
    ) as client:
        client.event_hooks["request"].append(success_hook)

        with pytest.raises(SSRFProtectionError, match="failed custom validation"):
            await client.get("http://8.8.8.8/")

        with pytest.raises(SuccessError):
            await client.get("http://1.1.1.1/")


async def test_dns_resolution_failure_raises_error():
    async with httpx_ssrf_protection(AsyncClient()) as client:
        with patch("httpx_secure.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.side_effect = gaierror("Name or service not known")
            with pytest.raises(SSRFProtectionError, match="Failed to resolve hostname"):
                await client.get(
                    "http://this-hostname-definitely-does-not-exist/",
                )


async def test_skips_global_check_when_disabled():
    async with httpx_ssrf_protection(
        AsyncClient(),
        check_globally_reachable=False,
        custom_validator=lambda _, ip_addr, __: str(ip_addr) != "127.0.0.1",
    ) as client:
        client.event_hooks["request"].append(success_hook)

        with pytest.raises(SuccessError):
            await client.get("http://192.168.1.1/")

        with pytest.raises(SSRFProtectionError, match="failed custom validation"):
            await client.get("http://127.0.0.1/")


async def test_disabling_global_check_requires_custom_validator():
    with pytest.raises(
        ValueError,
        match="to ensure SSRF protection is not completely disabled",
    ):
        httpx_ssrf_protection(
            AsyncClient(),
            check_globally_reachable=False,
        )
