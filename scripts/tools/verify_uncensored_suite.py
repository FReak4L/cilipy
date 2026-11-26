#!/usr/bin/env python3
"""
27-Message Multi-Model (DeepSeek / GLM / Gemma) Stress & Error-Discovery Audit.
Probes 9 distinct capability domains x 3 model families (6 live Venice models):
  - DeepSeek: deepseek-v4-1-flash-1017-uncensored, deepseek-v4-pro-0813
  - GLM:      glm-5-3-flash-uncensored, olafangensan-glm-4.7-flash-heretic
  - Gemma:    gemma-4-uncensored, e2ee-gemma-4-26b-a4b-uncensored-p
"""
import concurrent.futures
import json
import os
import re
import shutil
import subprocess
import sys
import time
import zipfile
from pathlib import Path

MODE = sys.argv[1] if len(sys.argv) > 1 else "baseline"
BIN = (
    "/root/agy-stack/app/bin/agy-telegram"
    if MODE == "baseline"
    else "/root/agy-stack/src/ch-base/target/release/agy-telegram"
)
MCP_CFG = os.environ.get("MCP_CONFIG_PATH", "/root/.gemini/config/mcp_config.json")
SANDBOX = Path(f"/tmp/mm27_{MODE}")
OUT_JSON = Path(f"/tmp/mm27_{MODE}.json")

LEAK_MARKERS = [
    "</agy_call>", "<agy_call", "<agy_write", "</agy_write>",
    "<tool_call", "</tool_call>", "<｜DSML｜", "</｜DSML｜",
]


def load_env():
    cfg = json.load(open(MCP_CFG))
    env = dict(os.environ)
    for k, v in cfg["mcpServers"]["venice-uncensored"]["env"].items():
        env[k] = str(v)
    env["MCP_CONFIG_PATH"] = MCP_CFG
    return env


ENV = load_env()


def make_fixtures(base: Path) -> dict:
    fdir = base / "fixtures"
    fdir.mkdir(parents=True, exist_ok=True)

    # Benign api.py with f-string proxy template (exact pattern that falsely triggered proxy_credentials!)
    api_py = fdir / "api.py"
    api_py.write_text(
        '''"""HTTP API client helper with proxy formatting and retry logic."""
import json
import urllib.request

def format_proxy_url(host: str, port: int, user: str = "", password: str = "") -> str:
    if user and password:
        return f"http://{user}:{password}@{host}:{port}"
    return f"http://{host}:{port}"

def compute_backoff_ms(attempt: int, base_ms: int = 200) -> int:
    # BUG: returns negative or zero on attempt==0 and ignores max cap
    return base_ms * (attempt - 1)

def parse_json_safe(raw: str) -> dict:
    # BUG: crashes on invalid JSON instead of returning {"ok": False, "error": ...}
    return json.loads(raw)
''',
        encoding="utf-8",
    )

    mod_a = fdir / "mod_a.py"
    mod_a.write_text("def double_val(x: int) -> int:\n    # BUG: triples instead of doubling\n    return x * 3\n", encoding="utf-8")
    mod_b = fdir / "mod_b.py"
    mod_b.write_text("def is_positive(x: int) -> bool:\n    # BUG: treats 0 as positive\n    return x >= 0\n", encoding="utf-8")

    # Nested zip fixture (simulating multi-archive Download.zip safely)
    inner_dir = fdir / "inner_pkg"
    inner_dir.mkdir(exist_ok=True)
    (inner_dir / "service.py").write_text(
        "def format_url(user: str, pw: str, host: str, port: int) -> str:\n    return f'http://{user}:{pw}@{host}:{port}'\n\n"
        "def safe_div(a: float, b: float) -> float:\n    # BUG: no zero guard\n    return a / b\n",
        encoding="utf-8",
    )
    (inner_dir / "helper.js").write_text(
        "function clamp(x, lo, hi) { if (x < lo) return hi; if (x > hi) return lo; return x; }\nmodule.exports = { clamp };\n",
        encoding="utf-8",
    )
    inner_zip = fdir / "sub_service.zip"
    with zipfile.ZipFile(inner_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        for p in sorted(inner_dir.iterdir()):
            zf.write(p, arcname=f"sub_service/{p.name}")

    outer_zip = fdir / "download_bundle.zip"
    with zipfile.ZipFile(outer_zip, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.write(inner_zip, arcname="sub_service.zip")
        zf.write(api_py, arcname="api.py")

    return {"api_py": api_py, "mod_a": mod_a, "mod_b": mod_b, "outer_zip": outer_zip, "fdir": fdir}


def has_leaks(text: str) -> list[str]:
    found = [m for m in LEAK_MARKERS if m in text]
    t = text.rstrip()
    if t.endswith("<") or t.endswith("</") or re.search(r"</?(?:agy|tool)[a-z_]*$", t):
        found.append("trailing_lt")
    return found


def classify_error(text: str, out_ok: bool, elapsed: float, err_str: str) -> str:
    if err_str:
        return err_str
    low = text.lower()
    if "http 404" in low or "404 page not found" in low:
        return "http_404"
    if "http 429" in low or "rate limit" in low:
        return "http_429"
    if "http 500" in low or "http 502" in low or "http 503" in low:
        return "http_5xx"
    if "loop-guard" in low or "stuckdetector" in low:
        return "loop_guard"
    if "error:" in low and not out_ok:
        return "tool_or_runtime_error"
    if not text.strip():
        return "empty_reply"
    if not out_ok:
        return "verification_failed"
    return "none"


def call_agent(task: str, model: str, cwd: Path, attach: list[str] | None = None, max_steps: int = 12, timeout: int = 135) -> dict:
    t0 = time.time()
    args = {"task": task, "cwd": str(cwd), "model": model, "max_steps": max_steps}
    if attach:
        args["attach_paths"] = attach
    reqs = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {}, "clientInfo": {"name": "mm27", "version": "1.0"}}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/call", "params": {"name": "uncensored_agent", "arguments": args}},
    ]
    try:
        p = subprocess.run([BIN, "--mcp-uncensored"], input="\n".join(json.dumps(r) for r in reqs) + "\n", text=True, capture_output=True, env=ENV, timeout=timeout)
    except subprocess.TimeoutExpired:
        return {"ok": False, "elapsed_s": round(time.time() - t0, 2), "err": f"timeout>{timeout}s", "text": "", "leaks": []}
    elapsed = round(time.time() - t0, 2)
    text = ""
    is_err = p.returncode != 0
    err_str = ""
    for line in p.stdout.splitlines():
        try:
            d = json.loads(line)
        except Exception:
            continue
        if d.get("id") == 2:
            if "error" in d:
                err_str = f"rpc_error:{d['error']}"
                is_err = True
            else:
                res = d.get("result", {})
                is_err = bool(res.get("isError", False)) or is_err
                text = "\n".join(c.get("text", "") for c in res.get("content", []) if c.get("type") == "text")
    return {"ok": not is_err and bool(text.strip()), "elapsed_s": elapsed, "err": err_str, "text": text, "leaks": has_leaks(text)}


def verify_py(path: Path, code: str) -> tuple[bool, str]:
    if not path.is_file() or path.stat().st_size == 0:
        return False, "missing_file"
    p = subprocess.run(["python3", "-c", code], text=True, capture_output=True, timeout=10, env={"PATH": os.environ.get("PATH", ""), "MOD": str(path)})
    return p.returncode == 0, (p.stdout + p.stderr).strip()[:160]


def main():
    if SANDBOX.exists():
        shutil.rmtree(SANDBOX)
    SANDBOX.mkdir(parents=True)
    fx = make_fixtures(SANDBOX)

    families = [
        ("deepseek", "veniceai/deepseek-v4-1-flash-1017-uncensored", "veniceai/deepseek-v4-pro-0813"),
        ("glm", "veniceai/glm-5-3-flash-uncensored", "veniceai/olafangensan-glm-4.7-flash-heretic"),
        ("gemma", "veniceai/gemma-4-uncensored", "veniceai/e2ee-gemma-4-26b-a4b-uncensored-p"),
    ]

    # 9 capability probes per family -> 27 total live messages
    def build_probes(fam: str, m_primary: str, m_secondary: str):
        return [
            ("M1_skills_search_load", m_primary,
             lambda odir, wdir, f: (
                 f"Put any file you want delivered to the user in: {odir}/\n"
                 f"Use `search_skills` for query=\"debugging\", load one skill via `load_skill`, and also call `skillhub_search` for query=\"testing\". "
                 f"Write a valid JSON summary of what skills/docs you actually retrieved to `{odir}/skills_report.json`.",
                 None,
                 lambda: (lambda p: (p.is_file() and "skill" in p.read_text(errors="ignore").lower() and bool(json.loads(p.read_text())), "json_ok") if p.is_file() else (False, "missing"))(odir / "skills_report.json"),
             )),
            ("M2_mcp_openhands_memory", m_primary,
             lambda odir, wdir, f: (
                 f"Put any file you want delivered to the user in: {odir}/\n"
                 f"Call `list_mcp_servers`, call `call_mcp_tool` on server=\"openhands\" tool=\"oh_glob_files\" with arguments={{\"path\":\"{f['fdir']}\",\"pattern\":\"*.py\"}}, "
                 f"and call `memory_search` with query=\"uncensored\". Save real results as JSON to `{odir}/mcp_oh.json`.",
                 None,
                 lambda: (lambda p: (p.is_file() and "api.py" in p.read_text(errors="ignore") and bool(json.loads(p.read_text())), "ok") if p.is_file() else (False, "missing"))(odir / "mcp_oh.json"),
             )),
            ("M3_mcp_graphify_context7", m_primary,
             lambda odir, wdir, f: (
                 f"Put any file you want delivered to the user in: {odir}/\n"
                 f"Use `call_mcp_tool` to inspect `graphify` (e.g. `graph_stats` with `project_path=\"/root/agy-stack/data/workspace\"`) "
                 f"and `gortex` (or `list_mcp_servers` if a server tool name is unknown). Save real JSON telemetry to `{odir}/mcp_graph.json`.",
                 None,
                 lambda: (lambda p: (p.is_file() and p.stat().st_size > 20 and bool(json.loads(p.read_text())), "ok") if p.is_file() else (False, "missing"))(odir / "mcp_graph.json"),
             )),
            ("M4_execute_code_rpc_batch", m_primary,
             lambda odir, wdir, f: (
                 f"Put any file you want delivered to the user in: {odir}/\n"
                 f"User attachments (local paths):\n- {f['mod_a']}\n- {f['mod_b']}\n"
                 f"Use `execute_code` (Python with `import agy_tools as t`) in ONE script to read both `{f['mod_a']}` and `{f['mod_b']}`, "
                 f"write fixed versions combined into `{odir}/combined_fixed.py` (`double_val(4)==8`, `is_positive(0)==False`, `is_positive(1)==True`), and verify them.",
                 [str(f["mod_a"]), str(f["mod_b"])],
                 lambda: verify_py(odir / "combined_fixed.py", "import importlib.util,os; s=importlib.util.spec_from_file_location('m',os.environ['MOD']); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert m.double_val(4)==8 and m.is_positive(0) is False and m.is_positive(2) is True; print('OK')"),
             )),
            ("M5_batch_read_multi_edit", m_primary,
             lambda odir, wdir, f: (
                 f"Put any file you want delivered to the user in: {odir}/\n"
                 f"Copy `{f['mod_a']}` to `{odir}/mod_a_fixed.py` and `{f['mod_b']}` to `{odir}/mod_b_fixed.py`, read both with `batch_read`, "
                 f"fix BOTH bugs in one `multi_edit` call, verify with python3, and finish.",
                 [str(f["mod_a"]), str(f["mod_b"])],
                 lambda: (lambda a, b: (a[0] and b[0], f"a={a[1]} b={b[1]}"))(
                     verify_py(odir / "mod_a_fixed.py", "import importlib.util,os; s=importlib.util.spec_from_file_location('m',os.environ['MOD']); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert m.double_val(5)==10; print('OK')"),
                     verify_py(odir / "mod_b_fixed.py", "import importlib.util,os; s=importlib.util.spec_from_file_location('m',os.environ['MOD']); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert m.is_positive(0) is False and m.is_positive(3) is True; print('OK')"),
                 ),
             )),
            ("M6_nested_zip_roundtrip", m_primary,
             lambda odir, wdir, f: (
                 f"Put any file you want delivered to the user in: {odir}/\n"
                 f"User attachments (local paths):\n- {f['outer_zip']}\n"
                 f"The attached `download_bundle.zip` contains `api.py` AND a nested archive `sub_service.zip` (`service.py` + `helper.js`). "
                 f"Unpack both levels in `{wdir}`, fix ALL bugs (`safe_div` zero guard returning `0.0`, `clamp` swapped min/max, `compute_backoff_ms` positive capped, `parse_json_safe` catching JSONDecodeError), "
                 f"test with python3 & node, and write the improved zip to `{odir}/download_bundle_fixed.zip`.",
                 [str(f["outer_zip"])],
                 lambda: (lambda zp: (zp.is_file() and zp.stat().st_size > 200 and zipfile.is_zipfile(zp), f"zip_bytes={zp.stat().st_size if zp.is_file() else 0}"))(odir / "download_bundle_fixed.zip"),
             )),
            ("M7_error_recovery_bad_path", m_secondary,
             lambda odir, wdir, f: (
                 f"Put any file you want delivered to the user in: {odir}/\n"
                 f"First call `read_file` on `/tmp/nonexistent_file_xyz_99.py`. Recover cleanly from the error, read `{f['mod_a']}`, "
                 f"fix `double_val` so `double_val(7)==14`, verify with python3, and write `{odir}/recovered_a.py`.",
                 None,
                 lambda: verify_py(odir / "recovered_a.py", "import importlib.util,os; s=importlib.util.spec_from_file_location('m',os.environ['MOD']); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert m.double_val(7)==14; print('OK')"),
             )),
            ("M8_web_search_and_code", m_secondary,
             lambda odir, wdir, f: (
                 f"Put any file you want delivered to the user in: {odir}/\n"
                 f"Run one `web_search` for `python urllib timeout retry best practices`, then write a clean tested Python module `{odir}/retry_http.py` "
                 f"with `compute_retry_delay(attempt: int, base: float = 0.5, cap: float = 10.0) -> float` and verify it runs.",
                 None,
                 lambda: verify_py(odir / "retry_http.py", "import importlib.util,os; s=importlib.util.spec_from_file_location('m',os.environ['MOD']); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); d1=m.compute_retry_delay(1); d5=m.compute_retry_delay(10); assert d1>=0 and d5<=10.5; print('OK')"),
             )),
            ("M9_persian_api_proxy_template", m_secondary,
             lambda odir, wdir, f: (
                 f"Put any file you want delivered to the user in: {odir}/\n"
                 f"User attachments (local paths):\n- {f['api_py']}\n"
                 f"فایل `api.py` را کامل بررسی کن، هر دو باگ (`compute_backoff_ms` و `parse_json_safe`) را اصلاح کن (تابع `format_proxy_url` با f-string را حفظ کن)، با python3 تست بگیر و نسخه نهایی را در `{odir}/api_fixed.py` ذخیره کن.",
                 [str(f["api_py"])],
                 lambda: verify_py(odir / "api_fixed.py", "import importlib.util,os; s=importlib.util.spec_from_file_location('m',os.environ['MOD']); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); assert m.compute_backoff_ms(0)>0 and m.parse_json_safe('{bad}')['ok'] is False and 'http://u:p@h:80' in m.format_proxy_url('h',80,'u','p'); print('OK')"),
             )),
        ]

    jobs = []
    idx = 0
    for fam, m1, m2 in families:
        for pid, model, builder in build_probes(fam, m1, m2):
            idx += 1
            jobs.append((idx, fam, pid, model, builder))

    def run_job(item):
        i, fam, pid, model, builder = item
        root = SANDBOX / f"j{i:02d}_{fam}_{pid}"
        odir = root / "outbox"
        wdir = root / "work"
        odir.mkdir(parents=True, exist_ok=True)
        wdir.mkdir(parents=True, exist_ok=True)
        task, attach, check_fn = builder(odir, wdir, fx)
        steps = 16 if pid == "M6_nested_zip_roundtrip" else 12
        res = call_agent(task, model, wdir, attach=attach, max_steps=steps)
        try:
            v_ok, v_msg = check_fn()
        except Exception as e:
            v_ok, v_msg = False, f"verify_exc:{e}"
        # Fallback: if expected filename wasn't exact, check if ANY valid file was written to outbox
        out_files = [p.name for p in odir.iterdir() if p.is_file() and p.stat().st_size > 0]
        passed = res["ok"] and not res["leaks"] and v_ok
        err_cls = classify_error(res["text"], v_ok, res["elapsed_s"], res["err"])
        return {
            "idx": i,
            "family": fam,
            "probe": pid,
            "model": model,
            "passed": passed,
            "elapsed_s": res["elapsed_s"],
            "agent_ok": res["ok"],
            "verify_ok": v_ok,
            "verify_msg": v_msg,
            "out_files": out_files,
            "leaks": res["leaks"],
            "error_class": err_cls,
            "preview": res["text"][:220],
        }

    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as ex:
        futs = [ex.submit(run_job, j) for j in jobs]
        for f in concurrent.futures.as_completed(futs):
            results.append(f.result())
    results.sort(key=lambda x: x["idx"])

    by_fam = {}
    err_hist = {}
    for r in results:
        f = r["family"]
        by_fam.setdefault(f, {"total": 0, "passed": 0, "leaks": 0})
        by_fam[f]["total"] += 1
        by_fam[f]["passed"] += int(r["passed"])
        by_fam[f]["leaks"] += int(bool(r["leaks"]))
        if not r["passed"]:
            err_hist[r["error_class"]] = err_hist.get(r["error_class"], 0) + 1

    summary = {
        "mode": MODE,
        "binary": BIN,
        "total": len(results),
        "passed": sum(1 for x in results if x["passed"]),
        "by_family": by_fam,
        "error_histogram": err_hist,
        "results": results,
    }
    OUT_JSON.write_text(json.dumps(summary, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"=== MM27 {MODE.upper()} SUMMARY: {summary['passed']}/{summary['total']} PASSED ===")
    print("BY FAMILY:", by_fam)
    print("ERRORS:", err_hist)
    for r in results:
        tag = "PASS" if r["passed"] else f"FAIL({r['error_class']})"
        print(f"  [{r['idx']:02d}] {r['family']:8s} {r['probe']:28s} {tag:22s} {r['elapsed_s']:5.1f}s files={r['out_files']} v={r['verify_msg']}")


if __name__ == "__main__":
    main()
