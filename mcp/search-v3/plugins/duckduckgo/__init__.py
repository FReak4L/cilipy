"""Standalone DuckDuckGo plugin package."""

from plugins.duckduckgo.plugin import (
    DDGSFallbackPlugin,
    DuckDuckGoHtmlPlugin,
    DuckDuckGoLitePlugin,
)

__all__ = [
    "DDGSFallbackPlugin",
    "DuckDuckGoHtmlPlugin",
    "DuckDuckGoLitePlugin",
]
