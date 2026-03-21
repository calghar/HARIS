"""Scanner adapters for external security tools."""

from .nikto_scanner import NiktoScanner
from .nmap_scanner import NmapScanner
from .nuclei_scanner import NucleiScanner
from .sslyze_scanner import SSLyzeScanner
from .wapiti_scanner import WapitiScanner

SCANNER_REGISTRY: dict[str, type] = {
    "wapiti": WapitiScanner,
    "sslyze": SSLyzeScanner,
    "nmap": NmapScanner,
    "nikto": NiktoScanner,
    "nuclei": NucleiScanner,
}


def get_scanner(name: str) -> type:
    """Look up a scanner class by name."""
    if name not in SCANNER_REGISTRY:
        raise KeyError(
            f"Unknown scanner {name!r}. Available: {', '.join(SCANNER_REGISTRY)}"
        )
    return SCANNER_REGISTRY[name]


__all__ = [
    "WapitiScanner",
    "SSLyzeScanner",
    "NmapScanner",
    "NiktoScanner",
    "NucleiScanner",
    "SCANNER_REGISTRY",
    "get_scanner",
]
