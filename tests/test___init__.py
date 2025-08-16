from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
from unittest.mock import AsyncMock, Mock, patch

import pytest
from anyio import ConnectionFailed, getaddrinfo
from httpx import AsyncClient, Request

from httpx_secure import SSRFProtectionError, httpx_ssrf_protection

TYPE_CHECKING = False
if TYPE_CHECKING:
    from anyio.abc import IPAddressType

MOCK_DEFAULT_IP = "1.2.3.4"


class SuccessError(BaseException):
    """Raised when SSRF validation passes successfully."""


def success_hook(_: Request):
    raise SuccessError


def mock_tcp(default_ip: str = MOCK_DEFAULT_IP):
    async def connect_tcp(remote_host: IPAddressType, remote_port: int, *_, **__):
        hostname = str(remote_host)
        port = remote_port

        if "." not in hostname:
            # Resolve local hosts
            addr_info = await getaddrinfo(hostname, port)
            resolved_ip = addr_info[0][4][0]
        else:
            try:
                ip_address(hostname)
                resolved_ip = hostname
            except ValueError:
                resolved_ip = default_ip

        stream = Mock()
        stream._raw_socket = Mock()
        stream._raw_socket.getpeername.return_value = (resolved_ip, port)
        stream.__aenter__ = AsyncMock(return_value=stream)
        stream.__aexit__ = AsyncMock(return_value=None)
        return stream

    return connect_tcp


@pytest.fixture(autouse=True)
def mock_tcp_fixture():
    with patch("httpx_secure.connect_tcp", side_effect=mock_tcp()) as mock:
        yield mock


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
        assert request.url.host == MOCK_DEFAULT_IP
        assert request.headers["Host"] == "example.com"
        assert request.extensions["sni_hostname"] == "example.com"
        raise SuccessError

    async with httpx_ssrf_protection(AsyncClient()) as client:
        client.event_hooks["request"].append(success_hook)
        with pytest.raises(SuccessError):
            await client.get("https://example.com/")


async def test_dns_results_are_cached(mock_tcp_fixture):
    call_count = 0

    async def counter(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return await mock_tcp()(*args, **kwargs)

    mock_tcp_fixture.side_effect = counter

    async with httpx_ssrf_protection(AsyncClient(), dns_cache_ttl=5) as client:
        client.event_hooks["request"].append(success_hook)

        with pytest.raises(SuccessError):
            await client.get("https://example.com/")
        assert call_count == 1

        with pytest.raises(SuccessError):
            await client.get("https://example.com/path")
        assert call_count == 1

        with pytest.raises(SuccessError):
            await client.get("https://api.example.com/path")
        assert call_count == 2


async def test_custom_validator_blocks_specific_ips():
    call_count = 0

    def custom_validator(
        _: str,
        ip_addr: IPv4Address | IPv6Address,
        __: int,
    ) -> bool:
        nonlocal call_count
        call_count += 1
        return str(ip_addr) not in {"8.8.8.8", "8.8.4.4"}

    async with httpx_ssrf_protection(
        AsyncClient(),
        custom_validator=custom_validator,
    ) as client:
        client.event_hooks["request"].append(success_hook)

        with pytest.raises(SSRFProtectionError, match="failed custom validation"):
            await client.get("http://8.8.8.8/")
        assert call_count == 1

        with pytest.raises(SuccessError):
            await client.get("http://1.1.1.1/")
        assert call_count == 2

        # Another request to blocked IP should still use cache
        with pytest.raises(SSRFProtectionError, match="failed custom validation"):
            await client.get("http://8.8.8.8/different/path")
        assert call_count == 2


async def test_dns_resolution_failure_raises_error(mock_tcp_fixture):
    mock_tcp_fixture.side_effect = ConnectionFailed(["Name or service not known"])

    async with httpx_ssrf_protection(AsyncClient()) as client:
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
