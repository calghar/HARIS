"""Custom security checks that run without external tools.

These checks use Python's standard library and common HTTP libraries
to test for common security misconfigurations directly.
"""

from ..core.scanner import BaseScanner
from .cache_checks import CacheControlScanner
from .cookie_checks import CookieSecurityScanner
from .dns_checks import DnsRecordScanner
from .graphql_checks import GraphqlIntrospectionScanner
from .header_checks import SecurityHeaderScanner
from .info_disclosure import InfoDisclosureScanner
from .listing_checks import DirectoryListingScanner
from .method_checks import HttpMethodScanner
from .misc_checks import MiscCheckScanner
from .openapi_checks import OpenApiScanner
from .redirect_checks import OpenRedirectScanner
from .sri_checks import SriScanner
from .tls_checks import TLSCheckScanner

CHECK_REGISTRY: dict[str, type[BaseScanner]] = {
    "cache_checks": CacheControlScanner,
    "cookie_checks": CookieSecurityScanner,
    "dns_checks": DnsRecordScanner,
    "graphql_checks": GraphqlIntrospectionScanner,
    "header_checks": SecurityHeaderScanner,
    "info_disclosure": InfoDisclosureScanner,
    "listing_checks": DirectoryListingScanner,
    "method_checks": HttpMethodScanner,
    "misc_checks": MiscCheckScanner,
    "openapi_checks": OpenApiScanner,
    "redirect_checks": OpenRedirectScanner,
    "sri_checks": SriScanner,
    "tls_checks": TLSCheckScanner,
}

__all__ = [
    "CHECK_REGISTRY",
    "CacheControlScanner",
    "CookieSecurityScanner",
    "DirectoryListingScanner",
    "DnsRecordScanner",
    "GraphqlIntrospectionScanner",
    "HttpMethodScanner",
    "InfoDisclosureScanner",
    "MiscCheckScanner",
    "OpenApiScanner",
    "OpenRedirectScanner",
    "SecurityHeaderScanner",
    "SriScanner",
    "TLSCheckScanner",
]
