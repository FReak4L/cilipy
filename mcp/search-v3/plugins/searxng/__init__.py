"""Standalone SearXNG plugin package."""

from plugins.searxng.plugin import SearXNGEnginePlugin, discover_local_searxng

__all__ = ["SearXNGEnginePlugin", "discover_local_searxng"]
