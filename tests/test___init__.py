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
    """Test that localhost addresses are blocked."""
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
    """Test that private network addresses are blocked."""
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
    """Test that global IP addresses are allowed and trigger success hook."""
    with pytest.raises(SuccessError):
        await client.get(url)


async def test_dns_resolution_and_validation():
    """Test real DNS resolution with success hook pattern."""

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


async def test_dns_caching():
    """Test that DNS results are cached."""
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


async def test_custom_validator():
    """Test custom validator."""

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


async def test_invalid_hostname():
    """Test that invalid hostnames raise appropriate errors."""
    async with httpx_ssrf_protection(AsyncClient()) as client:
        with patch("httpx_secure.getaddrinfo") as mock_getaddrinfo:
            mock_getaddrinfo.side_effect = gaierror("Name or service not known")
            with pytest.raises(SSRFProtectionError, match="Failed to resolve hostname"):
                await client.get(
                    "http://this-hostname-definitely-does-not-exist/",
                )
