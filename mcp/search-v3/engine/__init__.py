"""Engine layer exports: base contract, registry, crawler, and orchestrator."""

from engine.base import BaseSearchEngine, DirectBrowserEngineBase, _DirectBrowserPluginBase
from engine.crawler import KatanaPipeline, StructuralSchemaExtractor
from engine.orchestrator import (
    EnterpriseSearchOrchestrator,
    QueryRelaxer,
    SearchOrchestrator,
    TelemetrySink,
    export_all_engines_links_report,
    parse_difficulty_prefix,
    stream_queries_from_file,
    strip_query_line,
)
from engine.registry import EngineFactory, EngineHealthState, EngineRegistry

__all__ = [
    "BaseSearchEngine",
    "DirectBrowserEngineBase",
    "EngineFactory",
    "EngineHealthState",
    "EngineRegistry",
    "EnterpriseSearchOrchestrator",
    "KatanaPipeline",
    "QueryRelaxer",
    "SearchOrchestrator",
    "StructuralSchemaExtractor",
    "TelemetrySink",
    "_DirectBrowserPluginBase",
    "export_all_engines_links_report",
    "parse_difficulty_prefix",
    "stream_queries_from_file",
    "strip_query_line",
]
