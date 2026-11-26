# طرح معماری و پیاده‌سازی TUI مینیمال و پروفایل‌محور برای Search Pipeline v3

**وضعیت:** طرح آماده تایید پیش از کدنویسی
**هدف:** ساخت یک رابط ترمینالی (TUI) کاملاً داخلی، مینیمال، ریسپانسیو روی همه سایزهای صفحه، **بدون هیچ کتابخانه UI** (فقط ANSI خالص)، با **جدول‌کشی مبتنی بر `jq` (`jq-1.7` تاییدشده روی سرور)**، ۳ پروفایل اجرایی (`Fast` / `Medium` / `Advanced`)، نمایشگر `Status` زنده و اکسپورت مستقیم لینک‌ها (`links.txt`).

---

## ۱. ساختار مرتب و دسته‌بندی‌شده فولدرها (`workspace/`)

با اولین اجرای TUI، ساختار زیر به‌صورت خودکار درون `/root/ntest/v3/workspace/` ایجاد (و در صورت وجود حفظ) می‌شود تا هیچ فایلی پراکنده نشود:

```
/root/ntest/v3/
├── cli/
│   ├── main.py              # نقطه ورود اصلی: بدون آرگومان یا با --tui وارد TUI می‌شود؛ با --status وضعیت را نشان می‌دهد
│   ├── tui_ansi.py          # موتور رنگ و استایل بدون کتابخانه (Pure ANSI 16/256 + پشتیبانی NO_COLOR + عرض ریسپانسیو)
│   ├── tui_tables.py        # موتور جدول‌کشی ریسپانسیو با `jq` (jq -r @tsv -> ستون‌بندی تطبیقی با عرض ترمینال)
│   ├── tui_profiles.py      # تعریف ۳ پروفایل نصب (Fast / Medium / Advanced) + ذخیره/بارگذاری پریست TOML
│   ├── tui_status.py        # ردیاب اتمیک وضعیت اجرا (.active_run.json + run_history.jsonl) برای منوی Status
│   ├── tui_exporters.py     # اکسپورت لینک‌تک‌خطی (.txt)، JSON کامل، گزارش Markdown و فیلتر با jq
│   └── tui_app.py           # ویزارد مینیمال تعاملی + داشبورد زنده حین اجرا
└── workspace/
    ├── dorks/               # فایل‌های .txt کوئری (شناسایی خودکار با شمارش دقیق در پرانتز)
    ├── proxies/             # فایل‌های .txt لیست پروکسی
    ├── configs/             # پروفایل‌های شخصی ذخیره‌شده (.toml / .yaml)
    ├── cache/               # دیتابیس‌های SQLite کش (search_cache.db)
    ├── logs/                # لاگ زنده اجراها + .active_run.json + run_history.jsonl
    └── exports/
        ├── links/           # خروجی فقط لینک‌ها (هر خط دقیقاً ۱ URL یکتا: <run>_links.txt)
        ├── json/            # خروجی ساخت‌یافته کامل (<run>.json)
        ├── reports/         # گزارش تفکیکی پر-دورک / پر-انجین (<run>_report.md)
        └── crawl/           # خروجی اسکیمای Katana (<run>_crawl.jsonl)
```

---

## ۲. دسته‌بندی کامل قابلیت‌ها (۶ ستون معماری)

### ستون ۱: کشف خودکار فولدر `dorks/` و شمارش هوشمند
- اسکن تمام فایل‌های `*.txt` در `workspace/dorks/` (با قابلیت تغییر مسیر دلخواه).
- شمارش دقیق کوئری‌های معتبر با همان پارسر `strip_query_line()` خود پایپ‌لاین (حذف کامنت‌های `#`, `//`, `/* */` و خطوط خالی).
- نمایش تمیز با تعداد داخل پرانتز `()`:
  - `[1] benchmark_100.txt      (100)`
  - `[2] official_docs.txt      (8)`
  - `[3] research_queries.txt   (42)`
  - `[A] همه فایل‌ها یکجا       (150)`
  - `[P] وارد کردن مسیر دلخواه...`

### ستون ۲: ۳ پروفایل اجرایی از پیش نصب‌شده

| پروفایل | هدف | موتورها | سطح سوال و تنظیمات |
|---|---|---|---|
| **1. `FAST`** *(Direct All-Engine)* | اجرای فوق‌سریع روی همه انجین‌های دایرکت با حداکثر قابلیت‌های کرنل ریاضی بدون درگیری با کانفیگ | همه ۶ انجین دایرکت (`yahoo_direct`, `ddg_html`, `ddg_lite`, `google_web_udm14`, `google_mobile_web`, `google_basic_html`) + حالت `--all-engines` یا Failover | فقط ۳ سوال کوتاه (با پیش‌فرض Enter): <br>۱) فایل از `dorks/` <br>۲) تطابق دقیق دورک (`--no-relax` + AST) یا جست‌وجوی حالت‌های مشابه/آزادتر (`--allow-relax`)؟ <br>۳) اجرای Katana؟ + اکسپورت `links.txt`؟ |
| **2. `MEDIUM`** *(Balanced)* | یک پله کنترل بیشتر از حالت خودکار؛ انتخاب نوع سرچ و روشن/خاموش کردن قابلیت‌های کلیدی | انتخاب گروهی: `Direct` / `API (SearXNG+CSE+DDGS)` / `Hybrid (All)` + انتخاب `Failover` یا `--all-engines` | منوی سوییچ `[ON/OFF]` روی امکانات اصلی: **AST Strict Filter** *(منظور از avt در متن)*، **Query Relaxation**، **Thompson Sampling**، **SimHash/Jaccard Dedup**، **SQLite Cache**، **Proxies** (اسکن خودکار `workspace/proxies/` با تعداد)، **Katana Crawl** + تنظیم سریع `concurrency` و `max_results` |
| **3. `ADVANCED`** *(Full Control)* | کنترل ۱۰۰٪ روی تمام ۳۹ پارامتر `PipelineSettings` و `GoogleSuiteConfig` | انتخاب تکی هر ۱۰ موتور (`searxng`, `yahoo_direct`, `ddg_html`, `ddg_lite`, `ddgs`, `google`, `google_cse`, `google_web_udm14`, `google_mobile_web`, `google_basic_html`) | دسترسی دسته‌بندی‌شده به ۶ زیرصفحه: **(1) Engines & Mode**، **(2) Math/AST Kernel** (`poisson_mean`, `simhash_hamming`, `jaccard_threshold`, `AST`, `Thompson`, `Relax`)، **(3) Network & Proxies** (`concurrency`, `tokens_per_second`, `jitter`, `timeout`, `retries`, `HTTP/1.1`)، **(4) Circuit Breaker** (`bot_threshold`, `empty_threshold`, `park_seconds`)، **(5) SearXNG & Google CSE** (`url`, `engines`, `GOOGLE_CSE_CREDENTIALS`, `hl/gl`)، **(6) Cache, Katana & Export** + **ذخیره به عنوان پریست TOML** + **پیش‌نمایش دستور CLI معادل** |

### ستون ۳: موتور رنگ بدون کتابخانه (Pure ANSI) + طراحی ریسپانسیو برای همه سایزهای صفحه
- **بدون وابستگی به `rich`/`curses`/`textual`:** کلاس سبک `Ansi` در `cli/tui_ansi.py` با کدهای استاندارد `\033[...m`:
  - پالت مینیمال و چشم‌نواز (۵ رنگ محدود برای جلوگیری از شلوغی): Cyan (هدر/عنوان)، Green (`OK`/`ON`)، Yellow (`WARN`/`PARKED`)، Red (`ERR`/`OFF`)، Dim Gray (خطوط کادر و توضیحات فرعی).
  - تشخیص خودکار `sys.stdout.isatty()`، `NO_COLOR` و `TERM=dumb` (در غیر ترمینال کد رنگ حذف می‌شود).
- **ریسپانسیو واقعی با `shutil.get_terminal_size()` + سیگنال `SIGWINCH`:**
  - **حالت Compact (`cols < 72` — موبایل / ترمینال باریک SSH):** چیدمان تک‌ستونه، کوتاه‌سازی هوشمند URL و نام فایل (`…`)، ستون‌های جدول فشرده (فقط ستون‌های حیاتی)، بدون شکستن خطوط جدول.
  - **حالت Standard (`72 <= cols < 110` — لپ‌تاپ/پنجره عادی):** هدر دوخطی + جدول کامل ۵ ستونه + نوار پیشرفت تمیز.
  - **حالت Wide (`cols >= 110` — مانیتور عریض):** نمایش کامل‌تر ستون‌های جدول (شامل میانگین تاخیر `ms` و پسین `α/β` تامپسون) و نوار وضعیت یک‌خطی، همچنان کاملاً مینیمال و خلوت.

### ستون ۴: موتور جدول‌کشی با `jq` (`cli/tui_tables.py`)
- تمام داده‌های ساختاریافته (وضعیت موتورها، لیست فایل‌های `dorks/`، جدول `Status`، خلاصه نتایج و دامنه‌های برتر) به‌صورت JSON به `jq -r` پاس داده می‌شوند.
- `jq` فیلتر، مرتب‌سازی، قالب‌بندی عددی و استخراج `@tsv` را انجام می‌دهد و لایه Pure-Python با توجه به عرض لحظه‌ای ترمینال (`cols`) عرض ستون‌ها را محاسبه، متن‌های بلند را با `…` برش و جدول ANSI تمیز چاپ می‌کند.
- **مثال کوئری `jq` داخلی برای جدول موتورها:**
  ```jq
  .engine_metrics[] | [
    .engine,
    (.requests|tostring),
    (.successes|tostring),
    (.rate_limits|tostring),
    ((.thompson_posterior_mean * 100 | round | tostring) + "%"),
    (if .parked then "PARKED" else "ACTIVE" end)
  ] | @tsv
  ```
- اگر زمانی روی سیستمی `jq` نصب نباشد، خودکار Fallback به فیلتر داخلی پایتون انجام می‌شود (روی سرور فعلی `/usr/bin/jq` نسخه `1.7` تایید شد).

### ستون ۵: منوی `Status` و مانیتورینگ زنده (`cli/tui_status.py`)
- در حین اجرا، یک فایل وضعیت اتمیک (`workspace/logs/.active_run.json` با نوشتن در فایل موقت + `os.replace`) هر لحظه به‌روزرسانی می‌شود:
  - `run_id`, `pid`, `state` (`running` / `completed` / `stopped` / `failed`), `profile` (`fast`/`medium`/`advanced`), `mode` (`failover`/`all_engines`), `input_file`, `done_queries`, `total_queries`, `verified_links`, `ast_dropped`, `elapsed_seconds`, `engine_metrics`.
- هر زمان از منوی اصلی کلید `[S]` را بزنید (یا در یک ترمینال دوم دستور `search-v3 --status` بزنید):
  - بررسی زنده بودن PID با `os.kill(pid, 0)` (جلوگیری از نمایش وضعیت‌های stale/مرده).
  - نمایش جدول `jq` از اجرای فعال کنونی + ۵ اجرای اخیر از `workspace/logs/run_history.jsonl`.
- پشتیبانی از توقف تمیز با `Ctrl+C`: نتایج جمع‌آوری‌شده تا آن لحظه ذخیره می‌شوند و وضعیت به `stopped` تغییر می‌کند.

### ستون ۶: سیستم اکسپورت و «فقط لینک‌ها در هر خط» (`cli/tui_exporters.py`)
- افزودن فلگ جدید `--links-txt <Path>` به CLI و به هر ۳ پروفایل TUI:
  - استخراج لینک‌های یکتای تاییدشده با `jq` (یا مستقیم از مدل خروجی) و ذخیره به شکل **دقیقاً یک URL در هر خط** داخل `workspace/exports/links/<timestamp>_links.txt`:
    ```text
    https://docs.python.org/3/library/asyncio.html
    https://peps.python.org/pep-0492/
    https://fastapi.tiangolo.com/tutorial/
    ```
- منوی **Post-Run Export** بلافاصله پس از پایان سرچ:
  - `[1]` ذخیره فقط لینک‌ها (هر خط یک لینک `.txt`)
  - `[2]` ذخیره JSON کامل
  - `[3]` ذخیره گزارش تفکیکی Markdown (همه انجین‌ها برای هر دورک)
  - `[4]` مشاهده جدول خلاصه دامنه‌ها / لینک‌ها با `jq`
  - `[0]` بازگشت به منوی اصلی

---

## ۳. طرح بصری مینیمال صفحات (Wireframe ریسپانسیو)

### صفحه اصلی (حالت Standard / Wide)
```text
┌──────────────────────────────────────────────────────────────────────┐
│  SEARCH-V3  │  Mode: Interactive TUI  │  SearXNG: UP  │  jq: 1.7     │
├──────────────────────────────────────────────────────────────────────┤
│  Profiles                                                            │
│    [1] Fast      Direct All-Engine · حداقل سوال · اجرای سریع         │
│    [2] Medium    انتخاب Direct/API · سوییچ AST/Cache/Proxy/Katana    │
│    [3] Advanced  دسترسی کامل به تمام ۳۹ پارامتر + ذخیره پریست TOML   │
│                                                                      │
│  Tools                                                               │
│    [S] Status    وضعیت اجرای فعال (Idle / Running) + تاریخچه         │
│    [E] Exports   مشاهده و اکسپورت لینک‌های خروجی‌های قبلی (links.txt)│
│    [Q] Quit                                                          │
└──────────────────────────────────────────────────────────────────────┘
  > Select [1-3, S, E, Q]:
```

### صفحه انتخاب فایل از `workspace/dorks/`
```text
  Step 1/3 · Select Query Source (workspace/dorks/)
  ─────────────────────────────────────────────────
  #   File                         Queries   Size
  1   benchmark_100_queries.txt    (100)     5.1 KB
  2   docs_official.txt            (8)       0.4 KB
  A   All .txt files combined      (108)     —
  P   Custom file path...

  > Choice [1]:
```

### داشبورد مینیمال حین اجرا (بدون شلوغی، بازنویسی با ANSI Cursor Home)
```text
  RUN #20261123-1610  │  Profile: FAST (Direct All-Engine)  │  00:18
  [████████████░░░░░░░░] 62/100 (62%)  │  Verified: 148  │  AST Drop: 91

  Engine             Req   OK   429   Theta   State
  ──────────────────────────────────────────────────
  yahoo_direct        62   41     0    66%    ACTIVE
  ddg_html            48   12    18    21%    ACTIVE
  ddg_lite            19    0    15     6%    PARKED
  google_web_udm14    22    0    19     5%    PARKED
  google_mobile_web   20    0    17     5%    PARKED
  google_basic_html   18    0    15     6%    PARKED

  Recent Hits:
   • [yahoo_direct] https://docs.python.org/3/library/asyncio.html
   • [ddg_html]     https://peps.python.org/pep-0492/

  Ctrl+C: Stop & Save Partial Results
```

### نمایش در سایز باریک / موبایل (`cols < 72`)
```text
=== SEARCH-V3 [FAST] ===
62/100 (62%) | Hit:148 | Drop:91
Engine       OK  429  State
───────────────────────────
yahoo_direct 41    0  ACTIVE
ddg_html     12   18  ACTIVE
ddg_lite      0   15  PARKED
google_web    0   19  PARKED
...
[Ctrl+C] Stop & Export
```

---

## ۴. نقشه اجرای گام‌به‌گام (Implementation Roadmap)

1. **گام ۱ — زیرساخت پوشه‌ها و خروجی لینک‌تک‌خطی (`workspace/` + `tui_exporters.py` + `--links-txt`):**
   - ایجاد خودکار ساختار `workspace/{dorks,proxies,configs,cache,logs,exports/{links,json,reports,crawl}}`.
   - پیاده‌سازی `export_links_only_txt()` با `jq` + Fallback پایتون و افزودن فلگ `--links-txt` به `cli/main.py`.
2. **گام ۲ — موتور ANSI بدون کتابخانه و جدول‌کشی `jq` (`tui_ansi.py` + `tui_tables.py`):**
   - رنگ‌بندی Pure ANSI با پشتیبانی `NO_COLOR` و تشخیص سایز لحظه‌ای ترمینال (`Compact`/`Standard`/`Wide`).
   - رندر جداول با `jq -r @tsv` + برش دقیق رشته‌ها بدون به‌هم‌ریختگی جدول.
3. **گام ۳ — ردیاب وضعیت اتمیک (`tui_status.py` + `--status`):**
   - ثبت زنده وضعیت در `.active_run.json` و `run_history.jsonl` از طریق پیاده‌سازی یک `TelemetrySink` اختصاصی (بدون تغییر در معماری Acyclic ارکستراتور!).
   - بررسی زنده بودن PID و رندر جدول `Status` با `jq`.
4. **گام ۴ — تعریف ۳ پروفایل (`tui_profiles.py`) و ویزارد کامل (`tui_app.py`):**
   - اسکن `workspace/dorks/` با `(N)` تعداد معتبر، پیاده‌سازی جریان `FAST`، `MEDIUM` و `ADVANCED` (شامل ذخیره/بارگذاری TOML و پیش‌نمایش دستور CLI).
   - داشبورد مینیمال حین اجرا + توقف امن با `Ctrl+C` + منوی Post-Run Export.
5. **گام ۵ — یکپارچه‌سازی با `cli/main.py` و تست خودکار (`tests/test_tui.py`):**
   - اجرای خودکار TUI هنگام صدا زدن `search-v3` بدون آرگومان یا با `--tui`.
   - تست واحد کامل: عرض‌های مختلف ترمینال (`45`, `80`, `140` ستون)، `NO_COLOR`، خروجی `jq`، شمارش `dorks/` با کامنت‌ها، هر ۳ پروفایل، وضعیت `Status`، و اکسپورت `links.txt` + بازتایید همه ۲۷ تست قبلی.

---

## ۵. نکات و تصمیم‌های باز برای تایید نهایی پیش از کدنویسی

1. **منظور از «avt» در پروفایل Medium:** آیا منظورتان **AST** (فیلتر دقیق جدول درستی Boolean AST روی نتایج) بوده است؟ *(پیشنهاد پیش‌فرض: بله، AST Strict Filter + سوییچ Relax)*
2. **رفتار پیش‌فرض اجرای `search-v3` بدون آرگومان:** وقتی فقط دستور `search-v3` بدون فلگ زده می‌شود، مستقیماً وارد TUI شود؟ *(پیشنهاد پیش‌فرض: بله؛ و هر وقت `-q` یا `-i` داده شود مثل قبل در حالت CLI مستقیم اجرا شود)*
3. **پیش‌فرض حالت اجرا در پروفایل `FAST`:** آیا در `FAST` همه انجین‌های دایرکت برای هر دورک اجرا شوند (`--all-engines` روی ۶ انجین دایرکت) یا حالت سریع‌تر Failover هوشمند (توقف پس از اولین موتورِ دارای نتیجه AST)؟ *(پیشنهاد پیش‌فرض: `--all-engines` روی ۶ انجین دایرکت دقیقاً مطابق توضیح شما، با گزینه سریع تغییر در پروفایل Medium/Advanced)*
