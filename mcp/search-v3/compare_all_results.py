"""Comprehensive Cross-Version Benchmark & Result Audit (v1 vs v2 vs v2-strict vs Google vs v3)."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any

from core.exceptions import QueryParseError
from math_kernel.ast_boolean import DocumentView, compile_boolean_query
from math_kernel.deduplicator import SimHashJaccardDeduplicator
from transport.http_client import extract_root_domain, is_valid_http_url

DATASETS: list[tuple[str, Path]] = [
    ("pack_legacy (results.json)", Path("/root/ntest/pack/results.json")),
    ("pack_alt (results_alternative.json)", Path("/root/ntest/pack/results_alternative.json")),
    ("v1_pipeline (results_pipeline_source.json)", Path("/root/ntest/results_pipeline_source.json")),
    ("v2_relaxed (results_pipeline_v2.json)", Path("/root/ntest/results_pipeline_v2.json")),
    ("v2_strict (results_pipeline_strict.json)", Path("/root/ntest/results_pipeline_strict.json")),
    ("v2_google_only (results_google_only.json)", Path("/root/ntest/results_google_only.json")),
    ("v2_google_plugins (results_google_v3.json)", Path("/root/ntest/results_google_v3.json")),
    ("v3_live_docs_8q (live_docs_verification.json)", Path("/root/ntest/v3/live_docs_verification.json")),
    ("v3_federated_16q (results_v3_federated_benchmark.json)", Path("/root/ntest/v3/results_v3_federated_benchmark.json")),
    ("v3_google_live_5q (results_v3_google_live.json)", Path("/root/ntest/v3/results_v3_google_live.json")),
]


def _extract_fields(item: dict[str, Any]) -> tuple[str, str, str, str, str]:
    title = str(item.get("title") or "")
    url = str(item.get("url") or item.get("href") or item.get("link") or "")
    snippet = str(item.get("snippet") or item.get("body") or item.get("content") or "")
    query = str(item.get("query") or item.get("dork") or "")
    engine = str(item.get("engine") or item.get("source") or "unknown")
    return title, url, snippet, query, engine


def audit_dataset(label: str, path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {"label": label, "path": str(path), "missing": True}

    data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    raw_results: list[dict[str, Any]] = data.get("results", []) if isinstance(data, dict) else []

    ast_checked = 0
    ast_pass = 0
    ast_fail = 0
    ast_unparsed = 0
    bad_urls = 0
    engines_counter: Counter[str] = Counter()
    domains: set[str] = set()
    queries_covered: set[str] = set()
    fp_examples: list[dict[str, str]] = []

    deduper = SimHashJaccardDeduplicator(max_hamming=3, jaccard_threshold=0.85)
    dup_url = 0
    dup_simhash = 0
    dup_jaccard = 0

    verified_deduper = SimHashJaccardDeduplicator(max_hamming=3, jaccard_threshold=0.85)
    net_verified_unique = 0

    for item in raw_results:
        if not isinstance(item, dict):
            continue
        title, url, snippet, query, engine = _extract_fields(item)
        engines_counter[engine] += 1
        if query:
            queries_covered.add(query)

        url_ok = is_valid_http_url(url)
        if not url_ok:
            bad_urls += 1
        else:
            dom = extract_root_domain(url)
            if dom:
                domains.add(dom)

        dec = deduper.check_and_add(title=title, snippet=snippet, url=url)
        if dec.is_duplicate:
            if dec.reason == "url_exact":
                dup_url += 1
            elif dec.reason == "simhash":
                dup_simhash += 1
            elif dec.reason == "jaccard":
                dup_jaccard += 1

        passed_ast = False
        if query:
            try:
                ast_obj = compile_boolean_query(query)
                ast_checked += 1
                bit = ast_obj.evaluate(DocumentView(title=title, url=url, snippet=snippet))
                if bit == 1 and url_ok:
                    ast_pass += 1
                    passed_ast = True
                else:
                    ast_fail += 1
                    if len(fp_examples) < 5:
                        fp_examples.append({"query": query, "url": url[:100], "title": title[:60]})
            except QueryParseError:
                ast_unparsed += 1
        elif url_ok:
            passed_ast = True

        if passed_ast:
            v_dec = verified_deduper.check_and_add(title=title, snippet=snippet, url=url)
            if not v_dec.is_duplicate:
                net_verified_unique += 1

    precision_pct = round((ast_pass / ast_checked) * 100.0, 2) if ast_checked > 0 else None
    total_dups = dup_url + dup_simhash + dup_jaccard
    dup_pct = round((total_dups / len(raw_results)) * 100.0, 2) if raw_results else 0.0

    eng_metrics = data.get("engine_metrics", []) if isinstance(data, dict) else []
    total_reqs = sum(int(m.get("requests") or 0) for m in eng_metrics if m.get("engine") != "sqlite_cache")
    total_ok = sum(int(m.get("successes") or 0) for m in eng_metrics if m.get("engine") != "sqlite_cache")
    total_429 = sum(int(m.get("rate_limits") or 0) for m in eng_metrics)
    total_bot = sum(int(m.get("bot_gates") or 0) for m in eng_metrics)
    parked_engines = [m.get("engine") for m in eng_metrics if m.get("parked")]

    return {
        "label": label,
        "path": str(path),
        "raw_results": len(raw_results),
        "unique_queries_with_hits": len(queries_covered),
        "unique_domains": len(domains),
        "elapsed_seconds": data.get("elapsed_seconds") if isinstance(data, dict) else None,
        "relaxed_queries": data.get("relaxed_queries") if isinstance(data, dict) else None,
        "ast_dropped_during_run": data.get("ast_dropped_results") if isinstance(data, dict) else None,
        "bad_urls": bad_urls,
        "ast_checked": ast_checked,
        "ast_pass": ast_pass,
        "ast_fail_fp": ast_fail,
        "ast_unparsed": ast_unparsed,
        "true_ast_precision_pct": precision_pct,
        "dup_url_exact": dup_url,
        "dup_simhash": dup_simhash,
        "dup_jaccard": dup_jaccard,
        "total_duplicates": total_dups,
        "duplicate_rate_pct": dup_pct,
        "net_verified_unique": net_verified_unique,
        "upstream_requests": total_reqs,
        "upstream_successes": total_ok,
        "recorded_rate_limits": total_429,
        "recorded_bot_gates": total_bot,
        "parked_engines": parked_engines,
        "top_result_engines": engines_counter.most_common(5),
        "engine_metrics": eng_metrics,
        "fp_examples": fp_examples,
    }


def compare_shared_docs_queries(paths: dict[str, Path]) -> dict[str, Any]:
    """Apples-to-apples comparison on the 8 shared benign docs queries (source.txt L189-196)."""
    docs_queries = {
        "site:developer.paypal.com braintree hosted-fields",
        "site:developer.paypal.com braintree dropin",
        "site:developer.paypal.com braintree client_token",
        "site:developer.paypal.com braintree 3ds",
        "site:community.braintreepayments.com",
        "site:stackoverflow.com braintree hosted-fields",
        "site:stackoverflow.com braintree dropin",
        "site:stackoverflow.com braintree client_token",
    }
    summary: dict[str, Any] = {}
    for name, path in paths.items():
        if not path.is_file():
            continue
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        rows = [
            r for r in data.get("results", [])
            if isinstance(r, dict) and str(r.get("query") or "").strip() in docs_queries
        ]
        ast_pass = 0
        ast_fail = 0
        deduper = SimHashJaccardDeduplicator(max_hamming=3, jaccard_threshold=0.85)
        net_unique_valid = 0
        queries_hit: set[str] = set()
        urls: set[str] = set()
        for r in rows:
            title, url, snippet, query, _ = _extract_fields(r)
            ast_obj = compile_boolean_query(query)
            if is_valid_http_url(url) and ast_obj.evaluate(DocumentView(title=title, url=url, snippet=snippet)) == 1:
                ast_pass += 1
                queries_hit.add(query)
                urls.add(url.rstrip("/").lower())
                if not deduper.check_and_add(title=title, snippet=snippet, url=url).is_duplicate:
                    net_unique_valid += 1
            else:
                ast_fail += 1
        summary[name] = {
            "raw_hits": len(rows),
            "ast_pass": ast_pass,
            "ast_fail_fp": ast_fail,
            "precision_pct": round((ast_pass / len(rows)) * 100.0, 2) if rows else None,
            "net_unique_verified": net_unique_valid,
            "queries_with_hits": len(queries_hit),
            "urls": sorted(urls),
        }
    return summary


def main() -> None:
    audits = [audit_dataset(label, path) for label, path in DATASETS]
    shared = compare_shared_docs_queries(
        {
            "v1_source": Path("/root/ntest/results_pipeline_source.json"),
            "v2_relaxed": Path("/root/ntest/results_pipeline_v2.json"),
            "v2_strict": Path("/root/ntest/results_pipeline_strict.json"),
            "v3_docs_8q": Path("/root/ntest/v3/live_docs_verification.json"),
            "v3_federated_16q": Path("/root/ntest/v3/results_v3_federated_benchmark.json"),
        }
    )

    out_path = Path("/root/ntest/v3/full_comparison_matrix.json")
    out_path.write_text(
        json.dumps({"audits": audits, "shared_docs_8q": shared}, indent=2, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )

    print("=== FULL CROSS-VERSION AUDIT MATRIX ===")
    header = (
        f"{'Dataset':46s} | {'Raw':>4s} | {'AST OK':>6s} | {'FP':>4s} | "
        f"{'Prec%':>6s} | {'Dups':>4s} | {'NetOK':>5s} | {'Dom':>4s} | {'Time(s)':>7s}"
    )
    print(header)
    print("-" * len(header))
    for a in audits:
        if a.get("missing"):
            print(f"{a['label']:46s} | MISSING")
            continue
        prec = f"{a['true_ast_precision_pct']:.1f}%" if a["true_ast_precision_pct"] is not None else "N/A"
        el = f"{a['elapsed_seconds']:.1f}" if a["elapsed_seconds"] is not None else "N/A"
        print(
            f"{a['label']:46s} | {a['raw_results']:4d} | {a['ast_pass']:6d} | "
            f"{a['ast_fail_fp']:4d} | {prec:>6s} | {a['total_duplicates']:4d} | "
            f"{a['net_verified_unique']:5d} | {a['unique_domains']:4d} | {el:>7s}"
        )

    print("\n=== SHARED 8 DOCS QUERIES (APPLES-TO-APPLES) ===")
    for k, v in shared.items():
        print(
            f"  {k:18s} | raw={v['raw_hits']:3d} | ast_ok={v['ast_pass']:3d} | "
            f"fp={v['ast_fail_fp']:2d} | prec={v['precision_pct']}% | "
            f"net_unique={v['net_unique_verified']:3d} | q_hit={v['queries_with_hits']}/8"
        )

    print("\n=== GOOGLE-ONLY v2 vs v3 TELEMETRY COMPARISON ===")
    for a in audits:
        if "google" in a["label"].lower() and not a.get("missing"):
            print(
                f"  {a['label']:46s} | req={a['upstream_requests']} ok={a['upstream_successes']} "
                f"429={a['recorded_rate_limits']} bot={a['recorded_bot_gates']} "
                f"parked={a['parked_engines']} elapsed={a['elapsed_seconds']}s"
            )


if __name__ == "__main__":
    main()
