from __future__ import annotations

from ipaddress import IPv4Address, IPv6Address, ip_address
from socket import AF_INET, AF_INET6, SOCK_STREAM
from unittest.mock import AsyncMock, Mock, patch

import pytest
from anyio import getaddrinfo, sleep
from httpx import AsyncClient, ConnectError, ConnectTimeout, Request, Timeout

from httpx_secure import SSRFProtectionError, httpx_ssrf_protection

MOCK_DEFAULT_IP = "1.2.3.4"


class SuccessError(BaseException):
    """Raised when SSRF validation passes successfully."""


def success_hook(_: Request):
    raise SuccessError


def mock_dns(default_ips: tuple[str, ...] = (MOCK_DEFAULT_IP,)):
    async def mock_getaddrinfo(host: str, port: int, *_, **__):
        if "." not in host:
            # Resolve local hosts
            return await getaddrinfo(host, port, type=SOCK_STREAM)

        try:
            ip_address(host)
            ips: tuple[str, ...] = (host,)
        except ValueError:
            ips = default_ips

        return [
            (AF_INET6 if ":" in ip else AF_INET, SOCK_STREAM, 6, "", (ip, port))
            for ip in ips
        ]

    return mock_getaddrinfo


@pytest.fixture(autouse=True)
def mock_dns_fixture():
    with patch("httpx_secure.getaddrinfo", side_effect=mock_dns()) as mock:
        yield mock


def mock_connect(
    refused: frozenset[str] = frozenset(),
    hanging: frozenset[str] = frozenset(),
):
    async def connect_tcp(remote_host: str, *_, **__):
        if remote_host in refused:
            raise ConnectionRefusedError(f"refused: {remote_host}")
        if remote_host in hanging:
            await sleep(60)
        stream = Mock()
        stream.aclose = AsyncMock()
        return stream

    return connect_tcp


@pytest.fixture(autouse=True)
def mock_connect_fixture():
    with patch("httpx_secure.connect_tcp", side_effect=mock_connect()) as mock:
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


async def test_dns_results_are_cached(mock_dns_fixture):
    call_count = 0

    async def counter(*args, **kwargs):
        nonlocal call_count
        call_count += 1
        return await mock_dns()(*args, **kwargs)

    mock_dns_fixture.side_effect = counter

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


async def test_dns_resolution_failure_raises_error(mock_dns_fixture):
    mock_dns_fixture.side_effect = OSError("Name or service not known")

    async with httpx_ssrf_protection(AsyncClient()) as client:
        with pytest.raises(ConnectError, match="Name or service not known"):
            await client.get(
                "http://this-hostname-definitely-does-not-exist/",
            )


async def test_dns_resolution_timeout_raises_error(mock_dns_fixture):
    async def slow_getaddrinfo(*_, **__):
        await sleep(1)

    mock_dns_fixture.side_effect = slow_getaddrinfo

    async with httpx_ssrf_protection(
        AsyncClient(timeout=Timeout(5, connect=0.01)),
    ) as client:
        with pytest.raises(ConnectTimeout):
            await client.get("https://example.com/")


async def test_empty_dns_result_raises_error(mock_dns_fixture):
    mock_dns_fixture.side_effect = mock_dns(default_ips=())

    async with httpx_ssrf_protection(AsyncClient()) as client:
        with pytest.raises(ConnectError, match="No addresses found"):
            await client.get("https://example.com/")


@pytest.mark.parametrize(
    "ips",
    [
        ("1.1.1.1", "10.0.0.1"),
        ("10.0.0.1", "1.1.1.1"),
        ("1.1.1.1", "::1"),
    ],
)
async def test_blocks_when_any_resolved_address_is_private(mock_dns_fixture, ips):
    mock_dns_fixture.side_effect = mock_dns(default_ips=ips)

    async with httpx_ssrf_protection(AsyncClient()) as client:
        client.event_hooks["request"].append(success_hook)
        with pytest.raises(SSRFProtectionError, match="not globally reachable"):
            await client.get("https://example.com/")


DUAL_STACK_IPS = ("8.8.8.8", "2001:4860:4860::8888")


def assert_selected_host(expected: str):
    async def success_hook(request: Request):
        assert request.url.host == expected
        raise SuccessError

    return success_hook


async def test_single_address_is_used_without_probing(mock_connect_fixture):
    async with httpx_ssrf_protection(AsyncClient()) as client:
        client.event_hooks["request"].append(assert_selected_host(MOCK_DEFAULT_IP))
        with pytest.raises(SuccessError):
            await client.get("https://example.com/")
    mock_connect_fixture.assert_not_called()


async def test_prefers_ipv6_when_reachable(mock_dns_fixture, mock_connect_fixture):
    mock_dns_fixture.side_effect = mock_dns(default_ips=DUAL_STACK_IPS)

    async with httpx_ssrf_protection(AsyncClient()) as client:
        client.event_hooks["request"].append(
            assert_selected_host("2001:4860:4860::8888"),
        )
        with pytest.raises(SuccessError):
            await client.get("https://example.com/")
    mock_connect_fixture.assert_called_once()


async def test_falls_back_when_address_refuses(mock_dns_fixture, mock_connect_fixture):
    mock_dns_fixture.side_effect = mock_dns(default_ips=DUAL_STACK_IPS)
    mock_connect_fixture.side_effect = mock_connect(
        refused=frozenset({"2001:4860:4860::8888"}),
    )

    async with httpx_ssrf_protection(AsyncClient()) as client:
        client.event_hooks["request"].append(assert_selected_host("8.8.8.8"))
        with pytest.raises(SuccessError):
            await client.get("https://example.com/")


async def test_falls_back_when_address_hangs(mock_dns_fixture, mock_connect_fixture):
    mock_dns_fixture.side_effect = mock_dns(default_ips=DUAL_STACK_IPS)
    mock_connect_fixture.side_effect = mock_connect(
        hanging=frozenset({"2001:4860:4860::8888"}),
    )

    async with httpx_ssrf_protection(
        AsyncClient(),
        happy_eyeballs_delay=0.01,
    ) as client:
        client.event_hooks["request"].append(assert_selected_host("8.8.8.8"))
        with pytest.raises(SuccessError):
            await client.get("https://example.com/")


async def test_all_addresses_unreachable_raises_error(
    mock_dns_fixture,
    mock_connect_fixture,
):
    mock_dns_fixture.side_effect = mock_dns(default_ips=DUAL_STACK_IPS)
    mock_connect_fixture.side_effect = mock_connect(refused=frozenset(DUAL_STACK_IPS))

    async with httpx_ssrf_protection(AsyncClient()) as client:
        with pytest.raises(ConnectError, match="All connection attempts failed"):
            await client.get("https://example.com/")


async def test_all_addresses_hanging_raises_timeout(
    mock_dns_fixture,
    mock_connect_fixture,
):
    mock_dns_fixture.side_effect = mock_dns(default_ips=DUAL_STACK_IPS)
    mock_connect_fixture.side_effect = mock_connect(hanging=frozenset(DUAL_STACK_IPS))

    async with httpx_ssrf_protection(
        AsyncClient(timeout=Timeout(5, connect=0.05)),
        happy_eyeballs_delay=0.01,
    ) as client:
        with pytest.raises(ConnectTimeout):
            await client.get("https://example.com/")


async def test_validates_every_address_before_probing(
    mock_dns_fixture,
    mock_connect_fixture,
):
    mock_dns_fixture.side_effect = mock_dns(default_ips=("8.8.8.8", "10.0.0.1"))

    async with httpx_ssrf_protection(AsyncClient()) as client:
        with pytest.raises(SSRFProtectionError, match="not globally reachable"):
            await client.get("https://example.com/")
    mock_connect_fixture.assert_not_called()


async def test_does_not_connect_before_validation():
    with patch("socket.socket.connect", side_effect=AssertionError("connected")):
        async with httpx_ssrf_protection(AsyncClient()) as client:
            with pytest.raises(SSRFProtectionError):
                await client.get("http://10.0.0.1/")


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
