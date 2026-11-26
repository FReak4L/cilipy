#!/usr/bin/env python3
"""A/B parity & performance benchmark: Python agy-telegram v3 vs Rust agy-telegram-rs v4."""
from __future__ import annotations

import json
import os
import resource
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def bench_python() -> dict:
    app_dir = "/opt/agy-telegram/app"
    td = tempfile.mkdtemp(prefix="agy_ab_py_")
    try:
        env = dict(os.environ)
        env["STATE_DIR"] = td
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        code = f"""
import json, resource, sys, time
sys.path.insert(0, {app_dir!r})
t0 = time.perf_counter()
import acl, auth, agy, extensions, net, premium, render, state, webapp, widgets
t_import = (time.perf_counter() - t0) * 1000.0

sample_md = "# Report\\n\\n| Col A | Col B | Col C |\\n|---|---|---|\\n| alpha | 123 | ok |\\n| beta | 456 | warn |\\n\\n```rust\\nfn main() {{ println!(\\"hi\\"); }}\\n```\\n\\n> Quote with **bold** and `code`\\n"
t1 = time.perf_counter()
for _ in range(1000):
    h = render.md_to_html(sample_md)
    _ = render.split_html(h, 4096)
t_render = (time.perf_counter() - t1) * 1000.0

a = acl.ACLStore({td + '/acl.json'!r}, owner_id=1000000001, seed_allowed=[1000000001])
t2 = time.perf_counter()
for i in range(200):
    u = {{"id": 100000 + i, "username": f"u{{i}}", "first_name": "Test"}}
    a.record_start_attempt(u)
    if i % 2 == 0:
        a.set_status(100000 + i, "approved", by_uid=1000000001, preset="dev")
    else:
        a.toggle_select(100000 + i)
a.bulk_set_perm("selected", "skills_manage", True)
t_acl = (time.perf_counter() - t2) * 1000.0

t3 = time.perf_counter()
for k in widgets.BUILTIN_WIDGET_KINDS:
    for _ in range(100):
        sp = widgets.builtin_widget(k, initial_state={{"tab": "inst"}})
        widgets.validate_widget_spec(sp)
t_wid = (time.perf_counter() - t3) * 1000.0

rss_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
print(json.dumps({{
    "cold_startup_ms": round(t_import, 2),
    "render_1000_ms": round(t_render, 2),
    "acl_200_ops_ms": round(t_acl, 2),
    "widget_400_ops_ms": round(t_wid, 2),
    "peak_rss_kb": rss_kb,
}}))
"""
        proc = subprocess.run(
            ["/opt/agy-telegram/venv/bin/python", "-c", code],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        return json.loads(proc.stdout.strip().splitlines()[-1])
    finally:
        shutil.rmtree(td, ignore_errors=True)


def bench_rust(bin_path: str) -> dict:
    td = tempfile.mkdtemp(prefix="agy_ab_rs_")
    try:
        env = dict(os.environ)
        env["STATE_DIR"] = td
        t0 = time.perf_counter()
        subprocess.run([bin_path, "--version"], env=env, capture_output=True, check=True)
        t_cold = (time.perf_counter() - t0) * 1000.0

        proc = subprocess.run(
            [bin_path, "--bench-ab"],
            env=env,
            capture_output=True,
            text=True,
            check=True,
        )
        data = json.loads(proc.stdout.strip().splitlines()[-1])
        data["cold_cli_exec_ms"] = round(t_cold, 2)
        return data
    finally:
        shutil.rmtree(td, ignore_errors=True)


def main() -> int:
    py = bench_python()
    out = {"python": py}
    rust_bin = "/opt/agy-telegram-rs/target/release/agy-telegram"
    if len(sys.argv) > 1:
        rust_bin = sys.argv[1]
    if os.path.exists(rust_bin):
        rs = bench_rust(rust_bin)
        out["rust"] = rs
        out["speedups"] = {
            "cold_startup_x": round(py["cold_startup_ms"] / max(0.01, rs.get("cold_cli_exec_ms", rs.get("cold_startup_ms", 1.0))), 2),
            "render_1000_x": round(py["render_1000_ms"] / max(0.01, rs["render_1000_ms"]), 2),
            "acl_200_ops_x": round(py["acl_200_ops_ms"] / max(0.01, rs["acl_200_ops_ms"]), 2),
            "widget_400_ops_x": round(py["widget_400_ops_ms"] / max(0.01, rs["widget_400_ops_ms"]), 2),
            "rss_reduction_x": round(py["peak_rss_kb"] / max(1, rs["peak_rss_kb"]), 2),
        }
    print(json.dumps(out, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
