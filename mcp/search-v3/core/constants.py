"""Default timeouts, user-agents, Client-Hints profiles, and domain registries."""

from __future__ import annotations

DEFAULT_REQUEST_TIMEOUT_SECONDS: float = 18.0
DEFAULT_SEARXNG_TIMEOUT_SECONDS: float = 12.0
DEFAULT_PROXY_PROBE_TIMEOUT_SECONDS: float = 5.0
DEFAULT_PROXY_QUARANTINE_SECONDS: float = 120.0
DEFAULT_ENGINE_PARK_SECONDS: float = 180.0
DEFAULT_POISSON_MEAN_DELAY_SECONDS: float = 2.0
DEFAULT_POISSON_FAILURE_WINDOW: int = 10
DEFAULT_POISSON_FAILURE_THRESHOLD: float = 0.2
DEFAULT_SIMHASH_MAX_HAMMING: int = 3
DEFAULT_JACCARD_THRESHOLD: float = 0.85

SUPPORTED_PROXY_SCHEMES: frozenset[str] = frozenset(
    {"http", "https", "socks4", "socks4a", "socks5", "socks5h"}
)

CHROME_IMPERSONATION_PROFILES: tuple[str, ...] = (
    "chrome",
    "chrome136",
    "chrome131",
)

DESKTOP_CLIENT_PROFILES: tuple[dict[str, str], ...] = (
    {
        "user-agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/130.0.6723.117 Safari/537.36"
        ),
        "sec-ch-ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"Windows"',
        "sec-ch-ua-platform-version": '"15.0.0"',
        "sec-ch-ua-arch": '"x86"',
        "sec-ch-ua-bitness": '"64"',
        "sec-ch-ua-model": '""',
        "sec-ch-ua-full-version-list": (
            '"Chromium";v="130.0.6723.117", "Google Chrome";v="130.0.6723.117", '
            '"Not?A_Brand";v="99.0.0.0"'
        ),
    },
    {
        "user-agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.6778.86 Safari/537.36"
        ),
        "sec-ch-ua": '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?0",
        "sec-ch-ua-platform": '"macOS"',
        "sec-ch-ua-platform-version": '"14.6.1"',
        "sec-ch-ua-arch": '"arm"',
        "sec-ch-ua-bitness": '"64"',
        "sec-ch-ua-model": '""',
        "sec-ch-ua-full-version-list": (
            '"Chromium";v="131.0.6778.86", "Google Chrome";v="131.0.6778.86", '
            '"Not_A Brand";v="24.0.0.0"'
        ),
    },
)

MOBILE_CLIENT_PROFILES: tuple[dict[str, str], ...] = (
    {
        "user-agent": (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/131.0.6778.81 Mobile Safari/537.36"
        ),
        "sec-ch-ua": '"Chromium";v="131", "Google Chrome";v="131", "Not_A Brand";v="24"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-ch-ua-platform-version": '"14.0.0"',
        "sec-ch-ua-model": '"Pixel 8"',
        "sec-ch-ua-arch": '""',
    },
    {
        "user-agent": (
            "Mozilla/5.0 (Linux; Android 14; Pixel 8 Pro) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/130.0.6723.107 Mobile Safari/537.36"
        ),
        "sec-ch-ua": '"Chromium";v="130", "Google Chrome";v="130", "Not?A_Brand";v="99"',
        "sec-ch-ua-mobile": "?1",
        "sec-ch-ua-platform": '"Android"',
        "sec-ch-ua-platform-version": '"14.0.0"',
        "sec-ch-ua-model": '"Pixel 8 Pro"',
        "sec-ch-ua-arch": '""',
    },
)

BLOCK_SIGNATURES: tuple[str, ...] = (
    "anomaly-modal",
    "/sp/captcha",
    "sorry.google.com",
    "unusual traffic from your computer network",
    "anubis",
    "x-yandex-captcha",
    "from the eea and the united kingdom",
    "yahoo! japan is no longer available in the eea",
)

H2_TRANSPORT_ERROR_SIGNATURES: tuple[str, ...] = (
    "http/2",
    "http2",
    "rst_stream",
    "goaway",
    "protocol_error",
    "internal_error",
    "stream was not closed cleanly",
    "connection reset",
    "recv failure",
    "tls",
    "ssl",
    "proxy connect aborted",
    "empty reply from server",
    "unexpected eof",
    "broken pipe",
    "curle_http2",
    "curle_recv_error",
)

IGNORED_ENGINE_DOMAINS: frozenset[str] = frozenset(
    {
        "duckduckgo.com",
        "html.duckduckgo.com",
        "lite.duckduckgo.com",
        "search.yahoo.com",
        "yahoo.com",
        "r.search.yahoo.com",
        "login.yahoo.com",
        "help.yahoo.com",
        "legal.yahoo.com",
        "policies.yahoo.com",
        "advertising.yahoo.com",
        "bing.com",
        "google.com",
        "accounts.google.com",
        "support.google.com",
        "startpage.com",
        "www.startpage.com",
        "w3.org",
    }
)

GOOGLE_EXCLUDED_HOSTS: frozenset[str] = frozenset(
    {
        "google.com",
        "www.google.com",
        "google.co.uk",
        "www.google.co.uk",
        "google.de",
        "www.google.de",
        "google.ca",
        "www.google.ca",
        "google.fr",
        "www.google.fr",
        "accounts.google.com",
        "support.google.com",
        "policies.google.com",
        "maps.google.com",
        "translate.google.com",
        "webcache.googleusercontent.com",
        "consent.google.com",
        "sorry.google.com",
        "myactivity.google.com",
        "play.google.com",
        "books.google.com",
        "news.google.com",
        "shopping.google.com",
        "googleadservices.com",
        "doubleclick.net",
        "gstatic.com",
        "googleusercontent.com",
        "w3.org",
    }
)

DEFAULT_GOOGLE_REGIONAL_DOMAINS: tuple[str, ...] = (
    "www.google.com",
    "www.google.co.uk",
    "www.google.de",
    "www.google.ca",
    "www.google.fr",
)

AUTH_FIELD_HINTS: frozenset[str] = frozenset(
    {
        "password",
        "passwd",
        "pwd",
        "pass",
        "username",
        "user",
        "userid",
        "login",
        "email",
        "otp",
        "mfa",
        "totp",
        "2fa",
        "csrf",
        "csrf_token",
        "authenticity_token",
    }
)
