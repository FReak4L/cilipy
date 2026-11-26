"""Standalone Search Engine Plugin packages (Google, Yahoo, DuckDuckGo, SearXNG)."""

from plugins.duckduckgo import (
    DDGSFallbackPlugin,
    DuckDuckGoHtmlPlugin,
    DuckDuckGoLitePlugin,
)
from plugins.google import (
    GoogleBasicHtmlPlugin,
    GoogleCSECredential,
    GoogleCSEKeyPool,
    GoogleCSEPlugin,
    GoogleMobileDirectPlugin,
    GoogleMultiTierPlugin,
    GoogleSuiteConfig,
    GoogleWebDirectPlugin,
    build_google_plugins,
    register_google_plugins,
)
from plugins.searxng import SearXNGEnginePlugin, discover_local_searxng
from plugins.yahoo import YahooDirectPlugin

__all__ = [
    "DDGSFallbackPlugin",
    "DuckDuckGoHtmlPlugin",
    "DuckDuckGoLitePlugin",
    "GoogleBasicHtmlPlugin",
    "GoogleCSECredential",
    "GoogleCSEKeyPool",
    "GoogleCSEPlugin",
    "GoogleMobileDirectPlugin",
    "GoogleMultiTierPlugin",
    "GoogleSuiteConfig",
    "GoogleWebDirectPlugin",
    "SearXNGEnginePlugin",
    "YahooDirectPlugin",
    "build_google_plugins",
    "discover_local_searxng",
    "register_google_plugins",
]
