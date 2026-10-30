from __future__ import annotations

from collections import OrderedDict
from inspect import isawaitable
from ipaddress import ip_address
from socket import AF_INET, AF_INET6, SOCK_STREAM
from time import monotonic
from weakref import WeakValueDictionary

from anyio import (
    Event,
    Lock,
    connect_tcp,
    create_task_group,
    fail_after,
    getaddrinfo,
    move_on_after,
)
from httpx import ConnectError, ConnectTimeout, RequestError

TYPE_CHECKING = False
if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable
    from ipaddress import IPv4Address, IPv6Address
    from typing import TypeVar, Union

    from httpx import AsyncClient, Request

    _IPAddress = Union[IPv4Address, IPv6Address]

    _CacheKey = tuple[str, int]  # (hostname, port)

    _AsyncClientT = TypeVar("_AsyncClientT", bound=AsyncClient)

__version__ = "1.2.0"


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
        "connect_timeout",
        "custom_validator",
        "happy_eyeballs_delay",
    )

    def __init__(
        self,
        *,
        cache: _DNSCache,
        check_globally_reachable: bool,
        connect_timeout: float | None,
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
        self.connect_timeout = connect_timeout
        self.custom_validator = custom_validator
        self.happy_eyeballs_delay = happy_eyeballs_delay

    async def _resolve(
        self,
        request: Request,
        hostname: str,
        port: int,
    ) -> list[str]:
        try:
            with fail_after(self.connect_timeout):
                addr_info = await getaddrinfo(hostname, port, type=SOCK_STREAM)
        except TimeoutError as e:
            raise ConnectTimeout(str(e), request=request) from e
        except OSError as e:
            raise ConnectError(str(e), request=request) from e

        # Same order as anyio.connect_tcp: first IPv6, then first IPv4, then the rest
        ip_strs: list[str] = []
        v6_found = v4_found = False
        for family, *_, sockaddr in addr_info:
            ip_str = str(sockaddr[0])
            if ip_str in ip_strs:
                continue
            if family == AF_INET6 and not v6_found:
                v6_found = True
                ip_strs.insert(0, ip_str)
            elif family == AF_INET and not v4_found and v6_found:
                v4_found = True
                ip_strs.insert(1, ip_str)
            else:
                ip_strs.append(ip_str)

        if not ip_strs:
            raise ConnectError(f"No addresses found for {hostname!r}", request=request)
        return ip_strs

    async def _select_reachable(
        self,
        request: Request,
        ip_strs: list[str],
        port: int,
    ) -> str:
        if len(ip_strs) == 1:
            return ip_strs[0]

        # Happy Eyeballs over the validated addresses only. Connecting to the IP
        # literals (not the hostname) avoids a second, unvalidated DNS lookup.
        selected: str | None = None
        errors: list[OSError] = []

        async def try_connect(ip_str: str, event: Event) -> None:
            nonlocal selected
            try:
                stream = await connect_tcp(ip_str, port)
            except OSError as e:
                errors.append(e)
                return
            else:
                await stream.aclose()
                if selected is None:
                    selected = ip_str
                    tg.cancel_scope.cancel()
            finally:
                event.set()

        try:
            with fail_after(self.connect_timeout):
                async with create_task_group() as tg:
                    for ip_str in ip_strs:
                        event = Event()
                        tg.start_soon(try_connect, ip_str, event)
                        with move_on_after(self.happy_eyeballs_delay):
                            await event.wait()
        except TimeoutError as e:
            raise ConnectTimeout(str(e), request=request) from e

        if selected is None:
            raise ConnectError(
                f"All connection attempts failed: {errors[-1]}",
                request=request,
            )
        return selected

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
        request: Request,
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

            ip_strs = await self._resolve(request, hostname, port)

            # Every address must pass, so the resolver cannot pick a blocked one later
            try:
                for ip_str in ip_strs:
                    await self._validate(ip_str, port, hostname)
            except SSRFProtectionError as e:
                self._cache.put(cache_key, e)
                raise

            ip_str = await self._select_reachable(request, ip_strs, port)
            self._cache.put(cache_key, ip_str)
            return ip_str

    async def __call__(self, request: Request) -> None:
        url = request.url
        hostname = url.host
        port = url.port or (443 if url.scheme in {"https", "wss"} else 80)

        ip_str = await self._process(request, hostname, port)

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
        happy_eyeballs_delay: Delay in seconds before starting the next connection
            attempt, when a hostname resolves to more than one address
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
            connect_timeout=client.timeout.connect,
            custom_validator=custom_validator,
            happy_eyeballs_delay=happy_eyeballs_delay,
        ),
    )
    return client
