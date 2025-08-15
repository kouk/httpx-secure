# httpx-secure

[![PyPI - Python Version](https://shields.monicz.dev/pypi/pyversions/httpx-secure)](https://pypi.org/p/httpx-secure)
[![Liberapay Patrons](https://shields.monicz.dev/liberapay/patrons/Zaczero?logo=liberapay&label=Patrons)](https://liberapay.com/Zaczero/)
[![GitHub Sponsors](https://shields.monicz.dev/github/sponsors/Zaczero?logo=github&label=Sponsors&color=%23db61a2)](https://github.com/sponsors/Zaczero)

Drop-in SSRF protection for httpx.

## Why Use This?

- **SSRF Protection**: Block requests to private/internal IP addresses
- **Custom Validation**: Extend with your own validation logic
- **Minimal Overhead**: Efficient implementation with built-in DNS caching
- **Broad Python Support**: Compatible with Python 3.9+
- [**Semantic Versioning**](https://semver.org): Predictable, reliable updates
- [**Zero-Clause BSD**](https://choosealicense.com/licenses/0bsd/): Public domain, use freely anywhere

## Installation

```bash
pip install httpx-secure
```

## Quick Start

```python
import httpx
from httpx_secure import httpx_ssrf_protection

client = httpx_ssrf_protection(
    httpx.AsyncClient(),
    dns_cache_size=1000,  # Cache up to 1000 DNS resolutions
    dns_cache_ttl=300,    # Cache for 5 minutes
)

await client.get("https://public.domain")   # Allowed
await client.get("https://private.domain")  # Blocked
```

## Custom Validation

For example, implement a simple domain whitelist to restrict requests to specific hosts:

```python
import httpx
from httpx_secure import httpx_ssrf_protection
from ipaddress import IPv4Address, IPv6Address

def custom_validator(
    hostname: str,
    ip: IPv4Address | IPv6Address,
    port: int
) -> bool:
    return hostname in {
        "whitelisted.domain",
        "webhook.partner.com",
    }

client = httpx_ssrf_protection(
    httpx.AsyncClient(),
    custom_validator=custom_validator,
)

await client.get("https://whitelisted.domain")  # Allowed
await client.get("https://unknown.domain")      # Blocked
```

## How It Works

1. **Cache Lookup**: First checks if the host has been recently validated and cached
2. **DNS Resolution**: If not cached, resolves the hostname to an IP address
3. **Validation**: Verifies the IP is globally routable, blocking private/internal addresses
4. **Custom Validation**: If provided, your custom validator is called for additional checks
5. **Request Modification**: Rewrites the request to use the validated IP directly

The DNS cache significantly reduces latency for repeated requests, while per-host locking ensures efficient concurrent resolution of parallel requests.

> [!TIP]
> The SSRF protection applies to all HTTP methods (GET, POST, PUT, DELETE, etc.) and automatically validates redirects to prevent SSRF attacks through redirect chains.
