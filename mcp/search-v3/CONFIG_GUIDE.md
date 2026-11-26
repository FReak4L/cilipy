# راهنمای جامع پیکربندی و پارامترهای Search Pipeline v3 (`search-v3`)

این راهنما بر اساس کد واقعی `/root/ntest/v3/` (`core/models.py`، `cli/main.py` و `plugins/google/common.py`) نوشته شده است.

---

## ۱. انواع روش‌های کانفیگ و ترتیب اولویت (Precedence)

کلاس `PipelineSettings` (مبتنی بر `pydantic-settings` v2) **۵ روش کانفیگ** را پشتیبانی می‌کند و با اولویت زیر ترکیب می‌شوند (بالاترین اولویت در ردیف ۱):

1. **فلگ‌های خط فرمان (CLI Flags / `init kwargs`)** — بالاترین اولویت (`search-v3 --concurrency 8 ...`)
2. **متغیرهای محیطی سیستم (Environment Variables با پیشوند `SEARCH_*`)** — مثلاً `SEARCH_CONCURRENCY=8`
3. **فایل `.env`** در مسیر اجرای دستور — همان کلیدهای `SEARCH_*` به همراه کلیدهای `GOOGLE_CSE_*`
4. **فایل کانفیگ (`.toml` یا `.yaml` / `.yml`)** — از طریق `--config path/to/config.toml` یا تشخیص خودکار فایل‌های `config.toml` / `config.yaml` / `config.yml` در دایرکتوری جاری
5. **مقادیر پیش‌فرض (Defaults)** تعریف‌شده در `core/models.py`

*(نکته: برای استفاده از فایل `.yaml`/`.yml` پکیج `PyYAML` لازم است که در `direct_search_env` نصب است؛ برای `.toml` از `tomllib` داخلی Python 3.12 استفاده می‌شود.)*

---

## ۲. جدول کامل تمام پارامترهای `PipelineSettings` (۳۹ پارامتر)

نام کلید در TOML/YAML دقیقاً ستون «نام پارامتر» است، و معادل Environment Variable با پیشوند `SEARCH_` و حروف بزرگ ساخته می‌شود (مثلاً `max_retries` ⇐ `SEARCH_MAX_RETRIES`).

### الف) اتصال SearXNG
| پارامتر (TOML/YAML/Python) | فلگ CLI | نوع و محدودیت | پیش‌فرض | توضیح |
|---|---|---|---|---|
| `searxng_url` | `--searxng-url` | `str \| None` | `None` | آدرس صریح SearXNG؛ اگر `None` باشد پورت‌های محلی خودکار پروب می‌شوند |
| `searxng_host` | *(Env/Config)* | `str` | `"127.0.0.1"` | میزبان برای کشف خودکار SearXNG محلی |
| `searxng_probe_ports` | *(Env/Config)* | `list[int]` | `[8888, 8080, 80]` | لیست پورت‌های پروب TCP+JSON |
| `searxng_engines` | *(Env/Config)* | `str` | `"brave,yahoo,wikipedia,qwant,duckduckgo"` | زیرموتورهای درخواستی از SearXNG |

### ب) استخر پروکسی (Proxy Pool + Thompson Bandit)
| پارامتر | فلگ CLI | نوع و محدودیت | پیش‌فرض | توضیح |
|---|---|---|---|---|
| `proxies_file` | `--proxies` | `Path \| None` | `None` | فایل لیست پروکسی (`http/https/socks4/socks4a/socks5/socks5h`) |
| `proxy_quarantine_seconds` | *(Env/Config)* | `float >= 1.0` | `120.0` | مدت قرنطینه پروکسی پس از خطای شبکه یا WAF |
| `proxy_probe_timeout` | *(Env/Config)* | `float >= 0.5` | `5.0` | تایم‌اوت تست سلامت اولیه (`preflight_probe`) |

### ج) کش دیسکی SQLite (`aiosqlite`)
| پارامتر | فلگ CLI | نوع و محدودیت | پیش‌فرض | توضیح |
|---|---|---|---|---|
| `cache_db_path` | `--cache-db` | `Path` | `search_cache.db` | مسیر فایل دیتابیس SQLite کش |
| `cache_ttl_seconds` | `--cache-ttl` | `int >= 0` | `86400` | عمر کش به ثانیه (`0` کش را خاموش می‌کند) |
| `enable_cache` | `--no-cache` | `bool` | `True` | فعال/غیرفعال‌سازی خواندن و نوشتن کش |

### د) هم‌زمانی، Token Bucket و شبکه
| پارامتر | فلگ CLI | نوع و محدودیت | پیش‌فرض | توضیح |
|---|---|---|---|---|
| `max_results_per_query` | `--max-results` | `int (1..200)` | `15` | حداکثر لینک ارگانیک برای هر کوئری |
| `concurrency` | `--concurrency` | `int (1..64)` | `4` | تعداد کارگرهای هم‌زمان `asyncio` |
| `queue_maxsize` | *(Env/Config)* | `int >= 1` | `128` | ظرفیت صف با Backpressure |
| `tokens_per_second` | *(Env/Config)* | `float > 0.0` | `1.2` | نرخ پر شدن سطل توکن میکروثانیه‌ای |
| `jitter_min` | *(Env/Config)* | `float >= 0.0` | `0.8` | حداقل فاصله تصادفی بین درخواست‌های یک خانواده موتور (ثانیه) |
| `jitter_max` | *(Env/Config)* | `float >= 0.0` | `1.8` | حداکثر فاصله تصادفی (ثانیه) |
| `max_retries` | *(Env/Config)* | `int (1..10)` | `3` | حداکثر تعداد تلاش مجدد (`tenacity`) — به لایه‌های گوگل هم منتقل می‌شود |
| `request_timeout` | *(Env/Config)* | `float >= 1.0` | `18.0` | تایم‌اوت هر درخواست HTTP (ثانیه) |

### هـ) کنترل‌های کرنل ریاضی و NLP (`math_kernel/`)
| پارامتر | فلگ CLI | نوع و محدودیت | پیش‌فرض | توضیح |
|---|---|---|---|---|
| `enable_thompson_sampling` | `--no-thompson` | `bool` | `True` | انتخاب موتور و پروکسی با Thompson Sampling `Beta(α, β)` |
| `poisson_mean_delay` | `--poisson-mean` | `float > 0.0` | `2.0` | میانگین پایه تاخیر پواسون `t̄` (`λ₀ = 1/t̄`) |
| `strict_ast_filter` | `--no-ast-filter` | `bool` | `True` | گیت قطعی جدول درستی Boolean AST (`Eval == 1` الزامی) |
| `enable_query_relaxation` | `--no-relax` / `--allow-relax` | `bool` | `False` | در v3 پیش‌فرض خاموش است تا دقت ۱۰۰٪ حفظ شود |
| `simhash_max_hamming` | `--simhash-hamming` | `int (0..64)` | `3` | حداکثر فاصله همینگ SimHash ۶۴بیتی برای تشخیص تکراری |
| `jaccard_threshold` | `--jaccard-threshold` | `float (0.0..1.0)` | `0.85` | حداقل شباهت ژاکارد توکنی برای تشخیص تکراری |

### و) رجیستری موتورها، صفحه‌بندی و Circuit Breaker
| پارامتر | فلگ CLI | نوع و محدودیت | پیش‌فرض | توضیح |
|---|---|---|---|---|
| `pagination_depth` | `--pagination-depth` | `int (1..5)` | `2` | تعداد صفحات بررسی‌شده به ازای هر موتور سالم |
| `enable_http1_fallback` | `--no-http1-fallback` | `bool` | `True` | سوییچ خودکار HTTP/2 به HTTP/1.1 در صورت ریست تونل |
| `engine_park_bot_threshold` | *(Env/Config)* | `int >= 1` | `3` | تعداد خطای WAF/Bot متوالی تا Park شدن موتور |
| `engine_park_empty_threshold` | *(Env/Config)* | `int >= 1` | `5` | تعداد خروجی خالی متوالی تا Park موقت |
| `engine_park_seconds` | *(Env/Config)* | `float >= 10.0` | `180.0` | مدت Park شدن در Circuit Breaker (ثانیه) |
| `enabled_engines` | `--engines` | `list[str]` | `["searxng","ddg_html","yahoo_direct","ddg_lite","ddgs"]` | لیست موتورهای فعال (اسامی معتبر پایین آمده است) |

**اسامی معتبر موتورها برای `enabled_engines` / `--engines`:**
`searxng`, `ddg_html`, `yahoo_direct`, `ddg_lite`, `ddgs`, `google` *(یا `google_suite`)*, `google_cse`, `google_web_udm14` *(یا `google_direct`)*, `google_mobile_web` *(یا `google_mobile`)*, `google_basic_html` *(یا `google_basic`)*.

### ز) خزنده عمیق Katana (Tier 4) و نمایش/لاگ
| پارامتر | فلگ CLI | نوع و محدودیت | پیش‌فرض | توضیح |
|---|---|---|---|---|
| `enable_crawl` | `--crawl` | `bool` | `False` | فعال‌سازی خزش عمیق Katana و استخراج اسکیمای HTML |
| `crawl_depth` | *(Env/Config)* | `int (1..5)` | `2` | عمق خزش Katana |
| `crawl_rate_limit_rps` | *(Env/Config)* | `int >= 1` | `10` | محدودیت نرخ درخواست خزش در ثانیه |
| `crawl_concurrency` | *(Env/Config)* | `int >= 1` | `5` | هم‌زمانی خزش Katana |
| `crawl_timeout_seconds` | *(Env/Config)* | `int >= 5` | `90` | تایم‌اوت کل فرایند Katana |
| `crawl_enrich_metadata` | *(Env/Config)* | `bool` | `True` | تکمیل فرم‌ها، OpenGraph و canonical با fetch مستقیم |
| `allowed_crawl_domains` | `--allowed-domains` | `list[str]` | `[]` | لیست سفید دامنه‌های مجاز برای خزش |
| `crawl_output_path` | `--crawl-output` | `Path \| None` | `None` | مسیر ذخیره خروجی خزش (`.json` یا `.jsonl`) |
| `enable_tui` | `--no-tui` | `bool` | `True` | نمایش داشبورد زنده Rich در ترمینال |
| `debug` | `--debug` | `bool` | `False` | ثبت لاگ کامل سطح DEBUG روی stderr |

### ح) فلگ‌های اختصاصی CLI (ورودی، خروجی و حالت Fan-Out)
| فلگ CLI | نوع | توضیح |
|---|---|---|
| `-q`, `--query` | `str` (تکرارپذیر) | کوئری مستقیم در خط فرمان (می‌توان چندین `-q` داد) |
| `-i`, `--input-file` | `Path` | فایل دسته‌ای کوئری‌ها (پشتیبانی از کامنت‌های `#`, `//`, `/* */` و برچسب اختیاری `[D=001]`) |
| `--config` | `Path` | مسیر فایل `.toml`, `.yaml` یا `.yml` |
| `--output` | `Path` | مسیر فایل JSON خروجی نهایی (پیش‌فرض: `stdout`) |
| `--all-engines` | پرچم (`bool`) | حالت Fan-Out: اجرای **همه موتورهای فعال** برای هر کوئری و ثبت وضعیت تک‌تک موتورها در خروجی |
| `--links-output` | `Path` | مسیر گزارش Markdown تفکیک‌شده لینک‌ها برای هر دورک/موتور (در حالت `--all-engines`) |
| `--log-file` | `Path` | ذخیره کامل لاگ اجرای زنده در فایل |

### ط) متغیرهای محیطی و تنظیمات اختصاصی سوئیت گوگل (`GoogleSuiteConfig`)
- `GOOGLE_CSE_CREDENTIALS`: جفت‌های `api_key:cx` جداشده با کاما برای چرخش Round-Robin (ریست سهمیه در `00:00 UTC`)
- `GOOGLE_CSE_API_KEY` و `GOOGLE_CSE_CX`: حالت تک‌کلید CSE
- در Python API (`GoogleSuiteConfig` / `GoogleLocaleConfig`): `locale` (`hl`, `gl`, `pws`, `safe`, `filter_duplicates`, `nfpr`, `socs_cookie`, `consent_cookie`)، `regional_domains`، `domain_cooldown_seconds` (`120.0`)، `tier_cooldown_seconds` (`180.0`)، `tier_failure_threshold` (`3`)، اولویت لایه‌ها (`cse_priority=1`, `web_udm14_priority=2`, `mobile_web_priority=3`, `basic_html_priority=4`)، `enable_warmup=True`، `pacer_mean_delay=2.0`، `cse_timeout=12.0`.

---

## ۳. قالب آماده فایل‌های کانفیگ

### قالب `config.toml`
```toml
searxng_url = "http://127.0.0.1:8888"
searxng_engines = "brave,yahoo,wikipedia,qwant,duckduckgo"
enabled_engines = ["searxng", "yahoo_direct", "ddg_html", "ddg_lite", "ddgs"]

concurrency = 4
max_results_per_query = 15
pagination_depth = 2
request_timeout = 15.0
max_retries = 2

# Pure-Math & NLP Kernel
enable_thompson_sampling = true
poisson_mean_delay = 1.5
strict_ast_filter = true
enable_query_relaxation = false
simhash_max_hamming = 3
jaccard_threshold = 0.85

# Cache & Resilience
enable_cache = true
cache_db_path = "search_cache.db"
cache_ttl_seconds = 86400
engine_park_bot_threshold = 3
engine_park_empty_threshold = 5
engine_park_seconds = 120.0

enable_tui = false
debug = false
```

### قالب `config.yaml`
```yaml
searxng_host: "127.0.0.1"
searxng_probe_ports: [8888, 8080, 80]
enabled_engines:
  - searxng
  - yahoo_direct
  - ddg_html
  - ddgs
concurrency: 6
max_results_per_query: 10
pagination_depth: 1
enable_thompson_sampling: true
poisson_mean_delay: 0.8
strict_ast_filter: true
enable_query_relaxation: false
simhash_max_hamming: 3
jaccard_threshold: 0.85
enable_cache: true
enable_tui: false
```

### قالب `.env`
```dotenv
SEARCH_SEARXNG_URL=http://127.0.0.1:8888
SEARCH_CONCURRENCY=4
SEARCH_MAX_RETRIES=2
SEARCH_REQUEST_TIMEOUT=15.0
SEARCH_POISSON_MEAN_DELAY=1.2
SEARCH_STRICT_AST_FILTER=true
SEARCH_ENABLE_QUERY_RELAXATION=false
SEARCH_ENABLE_THOMPSON_SAMPLING=true
SEARCH_ENGINE_PARK_SECONDS=90.0
GOOGLE_CSE_CREDENTIALS=YOUR_KEY_1:YOUR_CX_1,YOUR_KEY_2:YOUR_CX_2
```

---

## ۴. ۱۰ مثال کاربردی و واقعی از استفاده و کانفیگ v3

### مثال ۱: جست‌وجوی سریع تک‌کوئری بدون کش و بدون TUI (خروجی مستقیم JSON روی stdout)
```bash
/root/ntest/direct_search_env/bin/search-v3 \
  -q 'site:docs.python.org inurl:library "asyncio"' \
  --engines searxng,yahoo_direct \
  --no-relax --no-tui --no-cache --max-results 10
```

### مثال ۲: چند کوئری هم‌زمان با عملگرهای پیچیده بولی (AND / OR / NOT) و ذخیره در فایل JSON
```bash
/root/ntest/direct_search_env/bin/search-v3 \
  -q 'site:peps.python.org ("PEP 492" OR "PEP 525") asyncio' \
  -q 'site:rfc-editor.org ("6585" OR "9110") "Retry-After"' \
  -q 'site:fastapi.tiangolo.com "FastAPI" -deprecated' \
  --engines searxng,yahoo_direct,ddgs \
  --pagination-depth 2 --max-results 15 --no-tui \
  --output /tmp/tech_docs.json
```

### مثال ۳: اجرا با فایل کانفیگ TOML و Override کردن یک پارامتر از CLI (اولویت CLI > TOML)
```bash
/root/ntest/direct_search_env/bin/search-v3 \
  --config /root/ntest/v3/config.toml \
  -i /root/ntest/v3/benchmark_100_queries.txt \
  --concurrency 8 --max-results 10 \
  --output /tmp/batch_out.json
```

### مثال ۴: اجرا با فایل کانفیگ YAML و تنظیم پارامترهای شبکه از طریق Environment Variables
```bash
SEARCH_MAX_RETRIES=1 SEARCH_REQUEST_TIMEOUT=10.0 SEARCH_ENGINE_PARK_SECONDS=60.0 \
/root/ntest/direct_search_env/bin/search-v3 \
  --config /tmp/config.yaml \
  -q 'site:*.org inurl:docs "postgresql" "JSONB"' \
  --no-tui --output /tmp/pg_docs.json
```

### مثال ۵: حالت Fan-Out روی همه انجین‌ها برای هر دورک (`--all-engines`) به‌همراه خروجی لینک‌ها و لاگ کامل
```bash
SEARCH_MAX_RETRIES=1 SEARCH_REQUEST_TIMEOUT=10.0 SEARCH_ENGINE_PARK_SECONDS=45.0 \
/root/ntest/direct_search_env/bin/search-v3 \
  -i /root/ntest/v3/benchmark_100_queries.txt \
  --engines searxng,yahoo_direct,ddg_html,ddg_lite,ddgs,google_web_udm14,google_mobile_web,google_basic_html \
  --all-engines --pagination-depth 1 --max-results 5 --concurrency 6 \
  --poisson-mean 0.4 --no-relax --no-tui --no-cache \
  --output /tmp/matrix.json \
  --links-output /tmp/matrix_links.md \
  --log-file /tmp/matrix_live.log
```

### مثال ۶: اجرا با استخر پروکسی چرخشی (Thompson Sampling روی پروکسی‌ها + قرنطینه خودکار)
```bash
SEARCH_PROXY_QUARANTINE_SECONDS=180 SEARCH_PROXY_PROBE_TIMEOUT=4.0 \
/root/ntest/direct_search_env/bin/search-v3 \
  -q 'site:developer.mozilla.org inurl:Status "429"' \
  --engines yahoo_direct,ddg_html,ddgs \
  --proxies /root/ntest/pack/proxies.txt \
  --concurrency 4 --no-tui --output /tmp/proxied_run.json
```

### مثال ۷: فعال‌سازی Google Custom Search API (Tier 1) با چند کلید چرخشی + Failover به لایه‌های بعدی گوگل
```bash
GOOGLE_CSE_CREDENTIALS="KEY1_HERE:CX1_HERE,KEY2_HERE:CX2_HERE" \
/root/ntest/direct_search_env/bin/search-v3 \
  -q 'site:arxiv.org "Thompson sampling" "Beta"' \
  --engines google,searxng,yahoo_direct \
  --poisson-mean 2.0 --no-relax --no-tui \
  --output /tmp/google_cse_cascade.json
```

### مثال ۸: تیونینگ دقیق کرنل ریاضی (تغییر آستانه SimHash، Jaccard و میانگین پواسون یا غیرفعال‌سازی Thompson)
```bash
/root/ntest/direct_search_env/bin/search-v3 \
  -q 'site:en.wikipedia.org ("SimHash" OR "MinHash") "Hamming"' \
  --engines searxng,yahoo_direct,ddgs \
  --poisson-mean 1.2 \
  --simhash-hamming 2 \
  --jaccard-threshold 0.80 \
  --no-thompson --no-tui \
  --output /tmp/tuned_kernel.json
```

### مثال ۹: جست‌وجو + خزش عمیق Katana (Tier 4) محدود به دامنه‌های مجاز خودتان + خروجی JSONL
```bash
SEARCH_CRAWL_DEPTH=2 SEARCH_CRAWL_RATE_LIMIT_RPS=5 \
/root/ntest/direct_search_env/bin/search-v3 \
  -q 'site:yourdomain.com inurl:docs' \
  --engines searxng,yahoo_direct \
  --crawl --allowed-domains yourdomain.com \
  --crawl-output /tmp/crawl_schema.jsonl \
  --output /tmp/search_plus_crawl.json --no-tui
```

### مثال ۱۰: استفاده مستقیم به‌عنوان کتابخانه مستقل در Python (بدون CLI)
```python
import asyncio
from pathlib import Path
from core.models import PipelineSettings
from engine.orchestrator import SearchOrchestrator
from plugins.google import GoogleLocaleConfig, GoogleSuiteConfig


async def main() -> None:
    settings = PipelineSettings.load(
        cli_overrides={
            "enabled_engines": ["searxng", "yahoo_direct", "ddgs"],
            "concurrency": 4,
            "max_results_per_query": 10,
            "strict_ast_filter": True,
            "enable_query_relaxation": False,
            "enable_thompson_sampling": True,
            "poisson_mean_delay": 1.0,
            "simhash_max_hamming": 3,
            "jaccard_threshold": 0.85,
            "enable_cache": True,
            "cache_db_path": Path("/tmp/my_v3_cache.db"),
            "enable_tui": False,
        }
    )
    google_cfg = GoogleSuiteConfig(
        locale=GoogleLocaleConfig(hl="en", gl="us", nfpr="1"),
        max_retries=2,
    )
    orch = SearchOrchestrator(settings, google_config=google_cfg)

    async def _queries():
        yield 'site:docs.python.org inurl:library "hashlib"'
        yield 'site:rfc-editor.org "6585" "Too Many Requests"'

    result = await orch.execute_stream(_queries(), total_hint=2)
    print(f"Verified results: {result.total_results}, AST dropped: {result.ast_dropped_results}")
    for r in result.results:
        print(r.rank, r.engine, r.url)


asyncio.run(main())
```
