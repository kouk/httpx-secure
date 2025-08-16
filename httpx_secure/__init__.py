from __future__ import annotations

from collections import OrderedDict
from inspect import isawaitable
from ipaddress import ip_address
from time import monotonic
from weakref import WeakValueDictionary

from anyio import ConnectionFailed, Lock, connect_tcp
from httpx import RequestError

TYPE_CHECKING = False
if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from ipaddress import IPv4Address, IPv6Address
    from typing import TypeVar, Union

    from httpx import AsyncClient, Request

    _IPAddress = Union[IPv4Address, IPv6Address]

    _CacheKey = tuple[str, int]  # (hostname, port)

    _AsyncClientT = TypeVar("_AsyncClientT", bound=AsyncClient)

__version__ = "1.1.0"


class SSRFProtectionError(RequestError):
    """Raised when a request would access restricted network resources."""

    def __init__(
        self,
        message: str,
        *,
        request: Request | None = None,
        hostname: str,
        ip_addr: _IPAddress | None,
        port: int,
    ) -> None:
        super().__init__(message, request=request)
        self.hostname = hostname
        self.ip_addr = ip_addr
        self.port = port


class _DNSCache:
    __slots__ = ("_cache", "_max_size", "_ttl")

    def __init__(self, max_size: int, ttl: float) -> None:
        self._cache: OrderedDict[
            _CacheKey,
            tuple[float, str | SSRFProtectionError],
        ] = OrderedDict()
        self._max_size = max_size
        self._ttl = ttl

    def get(
        self,
        key: _CacheKey,
        /,
    ) -> str | SSRFProtectionError | None:
        cached_value = self._cache.get(key)
        if cached_value is None:
            return None

        timestamp, value = cached_value

        current_time = monotonic()
        if current_time - timestamp > self._ttl:
            del self._cache[key]
            return None

        self._cache.move_to_end(key)
        return value

    def put(
        self,
        key: _CacheKey,
        value: str | SSRFProtectionError,
        /,
    ) -> None:
        current_time = monotonic()
        cache_hit = key in self._cache
        self._cache[key] = (current_time, value)

        if cache_hit:
            self._cache.move_to_end(key)
        elif len(self._cache) > self._max_size:
            self._cache.popitem(last=False)


class _SSRFProtectionHook:
    __slots__ = (
        "_cache",
        "_locks",
        "check_globally_reachable",
        "custom_validator",
        "happy_eyeballs_delay",
    )

    def __init__(
        self,
        *,
        cache: _DNSCache,
        check_globally_reachable: bool,
        custom_validator: (
            Callable[
                [str, _IPAddress, int],
                bool | Awaitable[bool],
            ]
            | None
        ),
        happy_eyeballs_delay: float,
    ):
        self._cache = cache
        self._locks: WeakValueDictionary[_CacheKey, Lock] = WeakValueDictionary()
        self.check_globally_reachable = check_globally_reachable
        self.custom_validator = custom_validator
        self.happy_eyeballs_delay = happy_eyeballs_delay

    async def _resolve(self, hostname: str, port: int) -> str:
        try:
            async with await connect_tcp(
                hostname,
                port,
                happy_eyeballs_delay=self.happy_eyeballs_delay,
            ) as stream:
                addr_info = stream._raw_socket.getpeername()
        except ConnectionFailed as e:
            raise SSRFProtectionError(
                f"Failed to resolve hostname {hostname!r}: {e}",
                hostname=hostname,
                ip_addr=None,
                port=port,
            ) from e

        return addr_info[0]

    async def _validate(
        self,
        ip_str: str,
        port: int,
        hostname: str,
    ) -> None:
        try:
            ip_addr = ip_address(ip_str)
        except ValueError as e:
            raise SSRFProtectionError(
                f"Invalid IP address format: {ip_str!r}",
                hostname=hostname,
                ip_addr=None,
                port=port,
            ) from e

        if self.check_globally_reachable and not ip_addr.is_global:
            raise SSRFProtectionError(
                f"Access denied: IP address {ip_str!r} is not globally reachable",
                hostname=hostname,
                ip_addr=ip_addr,
                port=port,
            )

        if self.custom_validator:
            result = self.custom_validator(hostname, ip_addr, port)
            if isawaitable(result):
                result = await result
            if not result:
                raise SSRFProtectionError(
                    f"Access denied: IP address {ip_str!r} failed custom validation",
                    hostname=hostname,
                    ip_addr=ip_addr,
                    port=port,
                )

    async def _process(
        self,
        hostname: str,
        port: int,
    ) -> str:
        cache_key = (hostname, port)
        result = self._cache.get(cache_key)
        if result is not None:
            if isinstance(result, SSRFProtectionError):
                raise result
            return result

        lock = self._locks.get(cache_key)
        if lock is None:
            lock = self._locks[cache_key] = Lock()

        async with lock:
            result = self._cache.get(cache_key)
            if result is not None:
                if isinstance(result, SSRFProtectionError):
                    raise result
                return result

            ip_str = await self._resolve(hostname, port)

            try:
                await self._validate(ip_str, port, hostname)
            except SSRFProtectionError as e:
                self._cache.put(cache_key, e)
                raise

            self._cache.put(cache_key, ip_str)
            return ip_str

    async def __call__(self, request: Request) -> None:
        url = request.url
        hostname = url.host
        port = url.port or (443 if url.scheme in {"https", "wss"} else 80)

        ip_str = await self._process(hostname, port)

        request.url = url.copy_with(host=ip_str)
        request.headers["Host"] = hostname
        request.extensions["sni_hostname"] = hostname


def httpx_ssrf_protection(
    client: _AsyncClientT,
    *,
    check_globally_reachable: bool = True,
    custom_validator: (
        Callable[
            [str, _IPAddress, int],
            bool | Awaitable[bool],
        ]
        | None
    ) = None,
    dns_cache_size: int = 1000,
    dns_cache_ttl: float = 600,
    happy_eyeballs_delay: float = 0.25,
) -> _AsyncClientT:
    """
    Configure SSRF protection on an httpx AsyncClient with DNS caching.

    Args:
        client: AsyncClient to configure
        check_globally_reachable: Whether to block non-global IP addresses
        custom_validator: Additional validation function(hostname, ip, port) -> bool
        dns_cache_size: Maximum number of DNS resolutions to cache
        dns_cache_ttl: Time-to-live for cached DNS resolutions in seconds
        happy_eyeballs_delay: Delay in seconds before starting the next connection attempt
    Returns:
        The same client instance with SSRF protection configured.
    """
    if not check_globally_reachable and custom_validator is None:
        raise ValueError(
            "When check_globally_reachable is False, custom_validator must be provided "
            "to ensure SSRF protection is not completely disabled",
        )

    client.event_hooks["request"].append(
        _SSRFProtectionHook(
            cache=_DNSCache(dns_cache_size, dns_cache_ttl),
            check_globally_reachable=check_globally_reachable,
            custom_validator=custom_validator,
            happy_eyeballs_delay=happy_eyeballs_delay,
        ),
    )
    return client
