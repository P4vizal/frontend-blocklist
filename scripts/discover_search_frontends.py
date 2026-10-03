#!/usr/bin/env python3
from __future__ import annotations

import concurrent.futures
import html
import ipaddress
import json
import os
import re
import sys
import time
import unicodedata
from dataclasses import dataclass, asdict
from html.parser import HTMLParser
import xml.etree.ElementTree as ET
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote, quote_plus, unquote, urljoin, urlparse, urlunparse
from urllib.request import Request, urlopen


OUTPUT = Path("search-discovered-blocklist.txt")
REPORT = Path("search-discovered-report.json")

PAGE_TIMEOUT = 10
FETCH_RETRIES = 2
MAX_PAGE_BYTES = 1_500_000
RETRYABLE_HTTP_CODES = {408, 425, 429, 500, 502, 503, 504}
MAX_CANDIDATES = 360
MIN_ACCEPTED = 1
SEARCH_WORKERS = 4
WORKERS = 10
VALIDATION_DELAY = 0.0

# Prefer Bing public RSS search; keep Bing HTML as the deterministic fallback.
SEARCH_BACKENDS = ("bing-rss", "bing-html")
SEARCH_BACKEND = "bing-rss-fallback"
SEARCH_MAX_RESULTS = 10
SEARCH_PAGES = (1, 2)
SEARCH_TIMEOUT = 7
SEARCH_DELAY = 0.2
SEARCH_RETRIES = 0

# Keep temporarily unreachable, high-signal candidates in the report so later
# daily runs can re-check them without lowering the publication threshold.
PENDING_VERIFICATION_MAX = 120
PENDING_VERIFICATION_TTL_DAYS = 21
NEAR_MISS_DISCOVERY_SCORE = 10
MAX_INTERNAL_SERVICE_LINKS = 3

# Keep the daily search bounded, but let service-intent queries in every
# configured language reach the second results page.

DISCOVERY_MODE = os.environ.get("DISCOVERY_MODE", "daily").strip().lower()
if DISCOVERY_MODE not in {"daily", "deep", "all"}:
    raise ValueError(f"Unsupported DISCOVERY_MODE={DISCOVERY_MODE!r}")

LANGUAGE_ROTATION = ("fr", "de", "zh", "ja", "ko", "hi", "ru", "ar", "pt", "it")

# External discovery sources are deliberately low-rate and fail-soft.
REPOSITORY_SOURCE_LIMIT = 10
COMMON_CRAWL_LIMIT = 40
COMMON_CRAWL_DELAY = 1.25
URLSCAN_MAX_RESULTS = 20
URLSCAN_DELAY = 1.0
PENDING_RETRY_BASE_SECONDS = 86400
PENDING_RETRY_MAX_SECONDS = 7 * 86400
WEB_VERIFIED_SEEDS = [
    ("reddit", "https://www.peekstr.com/"),
    ("reddit", "https://tryadlicio.com/tools/reddit-viewer"),
    ("reddit", "https://viewanonymous.com/tools/reddit/link/"),
    ("reddit", "https://redditprofile.com/reddit-profile-viewer"),
    ("tumblr", "https://zoomblr.com/"),
    ("tumblr", "https://cascadr.co/"),
    ("tumblr", "https://www.tumviews.com/"),
    ("twitter", "https://twitterviewer.net/"),
    ("twitter", "https://tweetviewer.com/"),
    ("twitter", "https://www.sotwe.com/"),
    ("twitter", "https://www.twitter-viewer.com/twitter-profile-viewer"),
    ("twitter", "https://ilo.so/twitter-viewer"),
]

CONTENT_HOST_SUFFIXES = (
    ".blogspot.com", ".wordpress.com", ".medium.com", ".substack.com",
    ".wixsite.com", ".weebly.com",
)

EDITORIAL_HOSTS = {
    "aiseesoft.com", "www.aiseesoft.com",
    "techtactician.com", "www.techtactician.com",
    "techbii.com", "www.techbii.com",
    "tuffermagazine.com", "www.tuffermagazine.com",
    "begindot.com", "www.begindot.com",
    "journaldufreenaute.fr", "www.journaldufreenaute.fr",
    "painonsocial.com", "www.painonsocial.com",
}

SEARCH_SERVICE_HOST_RE = re.compile(
    r"(viewer|frontend|browser|slideshow|reader|nitter|xcancel|twiiit|tweetviewer|twitterviewer|"
    r"twiewer|xviewer|redlib|libreddit|teddit|troddit|redlite|eddrit|"
    r"priviblur|tumblrviewer|tumlook|tumviews|zoomblr)",
    re.IGNORECASE,
)

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0 Safari/537.36 frontend-blocklist-discovery/1.0"
)

LANGUAGES = {
    "en": {
        "hl": "en", "gl": "us",
        "service": ["viewer", "frontend", "mirror", "proxy", "alternative frontend", "instance"],
        "identity": ["profile", "user", "post"],
    },
    "es": {
        "hl": "es", "gl": "es",
        "service": ["visor", "visualizador", "interfaz alternativa", "espejo", "proxy", "frontend", "instancia"],
        "identity": ["perfil", "usuario", "publicación", "post"],
    },
    "fr": {
        "hl": "fr", "gl": "fr",
        "service": ["visionneuse", "interface alternative", "miroir", "proxy", "frontend", "instance"],
        "identity": ["profil", "utilisateur", "publication", "post"],
    },
    "de": {
        "hl": "de", "gl": "de",
        "service": ["betrachter", "alternative oberfläche", "spiegel", "proxy", "frontend", "instanz"],
        "identity": ["profil", "benutzer", "beitrag", "post"],
    },
    "ru": {
        "hl": "ru", "gl": "ru",
        "service": ["просмотрщик", "альтернативный интерфейс", "зеркало", "прокси", "frontend", "экземпляр"],
        "identity": ["профиль", "пользователь", "публикация", "пост"],
    },
    "zh": {
        "hl": "zh-CN", "gl": "cn",
        "service": ["查看器", "替代前端", "镜像", "代理", "前端", "实例"],
        "identity": ["个人资料", "用户", "帖子", "博文"],
    },
    "ja": {
        "hl": "ja", "gl": "jp",
        "service": ["ビューア", "代替フロントエンド", "ミラー", "プロキシ", "フロントエンド", "インスタンス"],
        "identity": ["プロフィール", "ユーザー", "投稿", "ポスト"],
    },
    "ko": {
        "hl": "ko", "gl": "kr",
        "service": ["뷰어", "대체 프론트엔드", "미러", "프록시", "프론트엔드", "인스턴스"],
        "identity": ["프로필", "사용자", "게시물", "포스트"],
    },
    "hi": {
        "hl": "hi", "gl": "in",
        "service": ["व्यूअर", "वैकल्पिक फ्रंटएंड", "मिरर", "प्रॉक्सी", "फ्रंटएंड", "इंस्टेंस"],
        "identity": ["प्रोफ़ाइल", "उपयोगकर्ता", "पोस्ट", "प्रकाशन"],
    },
    "ar": {
        "hl": "ar", "gl": "sa",
        "service": ["عارض", "واجهة بديلة", "مرآة", "وكيل", "واجهة أمامية", "مثيل"],
        "identity": ["ملف شخصي", "مستخدم", "منشور", "مشاركة"],
    },
    "pt": {
        "hl": "pt-BR", "gl": "br",
        "service": ["visualizador", "frontend alternativo", "espelho", "proxy", "ver sem login"],
        "identity": ["perfil", "usuário", "post", "publicação"],
    },
    "it": {
        "hl": "it", "gl": "it",
        "service": ["visualizzatore", "frontend alternativo", "specchio", "proxy", "vedere senza login"],
        "identity": ["profilo", "utente", "post", "pubblicazione"],
    },
}

PLATFORMS = {
    "twitter": {
        "platform_terms": ["twitter", "x", "nitter"],
        "core": ["twitter", "nitter", "xcancel", "twiiit"],
        "brands": ["nitter", "xcancel", "twiiit"],
        "queries": [
            "{platform} {service1} alternative to nitter",
            "{platform} {service2} {object} viewer similar to nitter",
            "x twitter viewer alternatives to xcancel twiiit",
        ],
        "query_object": "profile",
        "identity_extra": [
            "tweet", "tweets", "user", "profile", "post", "posts",
            "timeline", "handle", "media",
        ],
    },
    "reddit": {
        "platform_terms": ["reddit"],
        "core": ["reddit", "redlib", "libreddit", "teddit", "eddrit", "troddit", "kddit"],
        "brands": ["redlib", "libreddit", "teddit", "eddrit", "troddit", "kddit"],
        "queries": [
            "{platform} {service1} alternatives to redlib libreddit",
            "{platform} {service2} {object} viewer similar to teddit troddit",
        ],
        "query_object": "subreddit",
        "identity_extra": [
            "subreddit", "subreddits", "comment", "comments", "post", "posts",
            "user", "profile", "thread",
        ],
    },
    "tumblr": {
        "platform_terms": ["tumblr"],
        "core": ["tumblr", "priviblur"],
        "brands": ["priviblur"],
        "queries": [
            "{platform} {service1} alternatives to priviblur",
            "{platform} {service2} {object} viewer similar to priviblur",
        ],
        "query_object": "blog",
        "identity_extra": [
            "blog", "blogs", "post", "posts", "user", "profile",
            "avatar", "tag", "tags",
        ],
    },
}

TRUSTED_SOURCES = [
    ("Farside", "json", "https://raw.githubusercontent.com/benbusby/farside/main/services-full.json"),
    ("Redlib", "json", "https://raw.githubusercontent.com/redlib-org/redlib-instances/main/instances.json"),
    ("Libreddit", "json", "https://raw.githubusercontent.com/libreddit/libreddit-instances/master/instances.json"),
    ("LibRedirect", "json", "https://raw.githubusercontent.com/libredirect/instances/main/data.json"),
    ("Priviblur", "text", "https://raw.githubusercontent.com/syeopite/priviblur/master/instances.md"),
    ("Alternative frontends 1", "text", "https://raw.githubusercontent.com/digitalblossom/alternative-frontends/main/README.md"),
    ("Alternative frontends 2", "text", "https://raw.githubusercontent.com/toka-kun/alternative-front-ends/web/README.md"),
    ("Alternative frontends 3", "text", "https://raw.githubusercontent.com/Myzel394/awesome-alternative-frontends/main/README.md"),
    ("Alternative frontends 4", "text", "https://raw.githubusercontent.com/mendel5/alternative-front-ends/main/README.md"),
    ("Alternative frontends 5", "text", "https://raw.githubusercontent.com/skynet2982/awesome-alternative-front-ends/main/README.md"),
    ("Alternative frontends 6", "text", "https://raw.githubusercontent.com/ParniDEO/alternative-front-ends-unofficial/main/README.md"),
    ("Alternative frontends 7", "text", "https://raw.githubusercontent.com/duyfken/alternative-front-ends/web/README.md"),
]

DIRECT_TRUSTED_SOURCES = {"Farside", "Redlib", "Libreddit", "Priviblur"}

FARSIDE_PLATFORM_TYPES = {
    "twitter": {"nitter", "xcancel"},
    "reddit": {"redlib", "libreddit", "teddit", "eddrit", "troddit"},
    "tumblr": {"priviblur"},
}

EXCLUDED_HOSTS = {
    "google.com", "www.google.com", "googleusercontent.com", "gstatic.com",
    "googleapis.com", "googleadservices.com", "youtube.com",
    "reddit.com", "www.reddit.com", "redd.it",
    "twitter.com", "www.twitter.com", "x.com", "www.x.com", "t.co",
    "tumblr.com", "www.tumblr.com",
    "facebook.com", "www.facebook.com", "instagram.com", "www.instagram.com",
    "wikipedia.org", "www.wikipedia.org", "github.com", "www.github.com",
    "githubusercontent.com", "gitlab.com", "codeberg.org",
    "bing.com", "www.bing.com", "duckduckgo.com", "search.brave.com",
}

EXCLUDED_SUFFIXES = (
    ".google.com", ".googleusercontent.com", ".gstatic.com",
    ".youtube.com", ".reddit.com", ".x.com", ".twitter.com",
    ".tumblr.com", ".facebook.com", ".instagram.com",
    ".wikipedia.org", ".github.com", ".githubusercontent.com",
    ".gitlab.com", ".codeberg.org", ".bing.com", ".duckduckgo.com",
)

CHALLENGE_MARKERS = (
    "captcha", "unusual traffic", "verify you are human",
    "just a moment", "checking your browser", "cf-chl-",
    "enable javascript and cookies to continue",
)

# Paths that are strong editorial/content signals. Deliberately exclude
# /post/, /posts/, /thread/, /topic/, /subreddit/ and /app/ because real
# viewers/frontends commonly use those routes as service endpoints.
BAD_PATH_MARKERS = (
    "/news/", "/article/", "/articles/", "/press/",
    "/blog/", "/blogs/", "/guide/", "/guides/", "/how-to/",
    "/category/", "/categories/", "/tag/", "/tags/", "/topics/",
    "/discussion/", "/discussions/", "/resource/", "/resources/",
    "/company/", "/companies/", "/self-hosted-apps/",
    "/alternatives/", "/what-is-",
)

# Editorial title language is only a rejection signal when the page also
# lacks a service route/hostname/header. "alternatives" is intentionally not
# here because a real viewer can legitimately describe itself as an alternative.
CONTENT_TITLE_MARKERS = (
    "what is ", "what are ", "how to ", "best ", "top ",
    "guide", "explained", "comparison", "review",
    "list of ", "methods for ",
)

EDITORIAL_PAGE_MARKERS = (
    "published", "last updated", "read time", "reading time",
    "author", "byline", "table of contents", "pros and cons",
    "subscribe", "newsletter",
)

STRONG_SERVICE_TERMS = (
    "viewer", "frontend", "front-end", "front end",
    "alternative frontend", "alternative front-end", "alternative front end",
    "private frontend", "private front-end", "private front end",
    "browser", "slideshow",
    "reader", "gallery", "content browser", "web client",
    "visor", "visualizador", "visionneuse", "betrachter",
    "ビューア", "просмотрщик", "visualizzatore",
    "查看器", "뷰어", "व्यूअर", "عارض",
)

NON_FRONTEND_SERVICE_TERMS = (
    "analyzer", "analyser", "analytics", "tracker", "tracking",
    "account analyzer", "profile analyzer", "account tracker",
    "profile tracker", "karma analyzer", "statistics", "stats dashboard",
    "suivi de profil", "analyseur de profil",
    "profil tracker", "konto-analyse", "profil-analyse",
)

SEARCH_RESULT_SERVICE_TERMS = STRONG_SERVICE_TERMS

SEARCH_RESULT_EDITORIAL_MARKERS = (
    "what is ", "what are ", "how to ", "best ", "top ",
    "guide", "comparison", "review", "published", "byline",
    "read time", "reading time", "newsletter", "restaurant",
    "hotel", "calculator", "dictionary", "definition", "jobs",
    "career", "travel", "tourism",
)

PERMANENT_FETCH_ERROR_CODES = {404, 410, 451}

SERVICE_PATH_SEGMENTS = {
    "viewer", "view", "browse", "browser", "search", "nitter", "xcancel",
    "redlib", "libreddit", "teddit", "troddit", "priviblur",
}

SERVICE_COMPOUND_RE = re.compile(
    r"^(?:twitter|x|reddit|tumblr)[_-](?:viewer|browser|frontend)$",
    re.IGNORECASE,
)


def sanitize_request_url(value: str) -> str | None:
    """Return an HTTP(S) URL safe for urllib requests, quoting path and query safely."""
    if not isinstance(value, str):
        return None
    value = html.unescape(value).strip()
    if not value:
        return None
    try:
        parsed = urlparse(value)
        host = parsed.hostname
        parsed.port
    except ValueError:
        return None
    if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc or not host:
        return None
    if parsed.username or parsed.password:
        return None
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in parsed.netloc):
        return None

    safe_path = quote(parsed.path, safe="/:@-._~%")
    safe_query = quote(parsed.query, safe="=&/?:@-._~%")
    return urlunparse(parsed._replace(path=safe_path, query=safe_query, fragment=""))


def path_looks_like_service(path: str) -> bool:
    parts = [unquote(part).strip().lower() for part in path.split("/") if part.strip()]
    for part in parts:
        normalized = re.sub(r"[^a-z0-9_-]+", "-", part)
        if normalized in SERVICE_PATH_SEGMENTS or SERVICE_COMPOUND_RE.fullmatch(normalized):
            return True
    return False

URL_IN_HTML_RE = re.compile(r"(?i)https?://[^\s\"<>]+")
ENCODED_URL_RE = re.compile(r"(?i)https?%3A%2F%2F[^\s\"&<>]+")

DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$",
    re.IGNORECASE,
)


def fold(text: str) -> str:
    text = unicodedata.normalize("NFKC", text or "")
    return re.sub(r"\s+", " ", text).strip().casefold()


def term_present(term: str, text: str) -> bool:
    term = fold(term)
    text = fold(text)
    if not term:
        return False
    if any(ord(c) > 127 for c in term):
        return term in text
    pattern = r"(?<![\w-])" + re.escape(term) + r"(?![\w-])"
    return re.search(pattern, text, re.IGNORECASE) is not None


def normalize_host(value: str) -> str | None:
    value = html.unescape(value).strip().strip("'\"()[]{}<>.,;|")
    if value.startswith("//"):
        value = "https:" + value
    elif "://" not in value:
        value = "https://" + value
    try:
        host = urlparse(value).hostname
    except ValueError:
        return None
    if not host:
        return None
    host = host.rstrip(".").lower()
    if host in EXCLUDED_HOSTS or any(host.endswith(s) for s in EXCLUDED_SUFFIXES):
        return None
    if host.endswith((".onion", ".i2p", ".loki")):
        return None
    try:
        ipaddress.ip_address(host.strip("[]"))
        return None
    except ValueError:
        pass
    return host if DOMAIN_RE.fullmatch(host) else None


class SearchResultParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        attrs_map = dict(attrs)
        href = attrs_map.get("href")
        classes = set((attrs_map.get("class") or "").split())
        if not href:
            return
        if "result__a" in classes or "b_algo" in classes or href.startswith(("/url?", "https://www.google.com/url?")):
            self.hrefs.append(href)
        elif href.startswith(("http://", "https://")):
            self.hrefs.append(href)


class PageParser(HTMLParser):
    SKIP = {"script", "style", "noscript", "template", "svg", "canvas"}
    CONTROL_ROLES = {"textbox", "searchbox", "combobox", "button", "search"}

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.skip_depth = 0
        self.tag_stack: list[str] = []
        self.anchor_stack: list[int] = []
        self.title_parts: list[str] = []
        self.heading_parts: list[str] = []
        self.meta_parts: list[str] = []
        self.body_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self.forms = 0
        self.inputs = 0
        self.buttons = 0
        self.article_count = 0
        self.control_parts: list[str] = []

    def _append_attr_text(self, attrs_map: dict[str, str | None], keys: tuple[str, ...]) -> None:
        for key in keys:
            value = attrs_map.get(key)
            if value:
                self.control_parts.append(value)

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self.SKIP:
            self.skip_depth += 1
            return

        attrs_map = dict(attrs)
        self.tag_stack.append(tag)

        role = (attrs_map.get("role") or "").strip().lower()
        if role in self.CONTROL_ROLES:
            self.control_parts.append(role)

        if attrs_map.get("aria-label"):
            self.control_parts.append(attrs_map["aria-label"] or "")
        if attrs_map.get("aria-labelledby"):
            self.control_parts.append(attrs_map["aria-labelledby"] or "")

        if tag == "meta":
            name = (attrs_map.get("name") or "").lower()
            prop = (attrs_map.get("property") or "").lower()
            if name in {"description", "keywords"} or prop in {"og:title", "og:description"}:
                content = attrs_map.get("content")
                if content:
                    self.meta_parts.append(content)
        elif tag == "article":
            self.article_count += 1
        elif tag == "form":
            self.forms += 1
        elif tag in {"input", "textarea", "select"}:
            self.inputs += 1
            self._append_attr_text(
                attrs_map,
                ("type", "name", "placeholder", "aria-label", "value", "title", "data-placeholder"),
            )
        elif tag == "button":
            self.buttons += 1
            self._append_attr_text(
                attrs_map,
                ("type", "name", "aria-label", "value", "title"),
            )
        elif tag == "a":
            href = attrs_map.get("href") or ""
            self.links.append((href, ""))
            self.anchor_stack.append(len(self.links) - 1)

        if attrs_map.get("contenteditable", "").strip().lower() in {"true", "plaintext-only"}:
            self.inputs += 1
            self.control_parts.append("contenteditable")
            self._append_attr_text(
                attrs_map,
                ("name", "placeholder", "aria-label", "title"),
            )
        elif role in {"textbox", "searchbox", "combobox"}:
            self.inputs += 1
        elif role == "button":
            self.buttons += 1

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self.SKIP:
            if self.skip_depth:
                self.skip_depth -= 1
            return

        if self.anchor_stack and tag == "a":
            self.anchor_stack.pop()

        for index in range(len(self.tag_stack) - 1, -1, -1):
            if self.tag_stack[index] == tag:
                del self.tag_stack[index:]
                break

    def handle_data(self, data: str) -> None:
        if self.skip_depth or not data.strip():
            return
        cleaned = data.strip()
        if not cleaned:
            return

        if "title" in self.tag_stack:
            self.title_parts.append(cleaned)
        elif any(tag in {"h1", "h2", "h3"} for tag in self.tag_stack):
            self.heading_parts.append(cleaned)
        else:
            self.body_parts.append(cleaned)

        if self.anchor_stack:
            index = self.anchor_stack[-1]
            href, label = self.links[index]
            self.links[index] = (href, f"{label} {cleaned}".strip())

    def result(self) -> dict:
        return {
            "title": " ".join(self.title_parts),
            "headings": " ".join(self.heading_parts),
            "meta": " ".join(self.meta_parts),
            "body": " ".join(self.body_parts),
            "links": list(self.links),
            "forms": self.forms,
            "inputs": self.inputs,
            "buttons": self.buttons,
            "article_count": self.article_count,
            "controls": " ".join(self.control_parts),
        }

@dataclass
class SearchHit:
    domain: str
    platform: str
    queries: list[str]
    urls: list[str]
    sources: list[str]
    providers: list[str]
    search_evidence: list[str]


@dataclass
class Evaluation:
    domain: str
    platform: str
    accepted: bool
    score: int
    query_count: int
    final_url: str
    evidence: dict
    reason: str
    error: str = ""


def read_existing_domains() -> set[str]:
    path = Path("blocklist.txt")
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\|\|([^\^/\s]+)\^", line.strip())
        if m:
            host = normalize_host(m.group(1))
            if host:
                out.add(host)
    return out


def read_discovered_domains() -> set[str]:
    """Read the historical discovery list; entries are append-only."""
    if not OUTPUT.exists():
        return set()
    out = set()
    for line in OUTPUT.read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"^\|\|([^\^/\s]+)\^", line.strip())
        if m:
            host = normalize_host(m.group(1))
            if host:
                out.add(host)
    return out


def safe_nonnegative_int(value: object, default: int = 0) -> int:
    try:
        return max(0, int(value))
    except (TypeError, ValueError):
        return default


def read_pending_verification() -> list[dict]:
    """Read a bounded set of recent candidates that were strong but unreachable."""
    if not REPORT.exists():
        return []
    try:
        data = json.loads(REPORT.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return []

    raw = data.get("pending_verification", [])
    if not isinstance(raw, list):
        return []

    cutoff = time.time() - (PENDING_VERIFICATION_TTL_DAYS * 86400)
    out: list[dict] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        domain = normalize_host(item.get("domain", ""))
        platform = item.get("platform")
        if not domain or platform not in PLATFORMS:
            continue
        try:
            last_attempt_epoch = float(item.get("last_attempt_epoch", 0) or 0)
        except (TypeError, ValueError):
            last_attempt_epoch = 0
        if last_attempt_epoch and last_attempt_epoch < cutoff:
            continue

        attempts = safe_nonnegative_int(item.get("attempts", 0))
        next_retry_epoch = 0.0
        try:
            next_retry_epoch = max(0.0, float(item.get("next_retry_epoch", 0) or 0))
        except (TypeError, ValueError):
            next_retry_epoch = 0.0
        out.append({
            "domain": domain,
            "platform": platform,
            "queries": [q for q in item.get("queries", []) if isinstance(q, str)][:12],
            "urls": [
                safe_url for url in item.get("urls", [])
                if isinstance(url, str)
                for safe_url in [sanitize_request_url(url)]
                if safe_url
            ][:12],
            "sources": [s for s in item.get("sources", []) if isinstance(s, str)][:8],
            "providers": [p for p in item.get("providers", []) if isinstance(p, str)][:8],
            "search_evidence": [
                e for e in item.get("search_evidence", []) if isinstance(e, str)
            ][:12],
            "first_seen": str(item.get("first_seen", "")),
            "last_attempt": str(item.get("last_attempt", "")),
            "last_attempt_epoch": last_attempt_epoch,
            "attempts": attempts,
            "status": str(item.get("status", "temporary_unavailable") or "temporary_unavailable"),
            "last_reason": str(item.get("last_reason", "")),
            "discovery_score": safe_nonnegative_int(item.get("discovery_score", 0)),
            "next_retry_epoch": next_retry_epoch,
        })

    out.sort(key=lambda item: (
        -len(item["sources"]),
        -len(item["search_evidence"]),
        -len(item["queries"]),
        -item["last_attempt_epoch"],
        item["domain"],
    ))
    return out[:PENDING_VERIFICATION_MAX]


def pending_hits_from_report(entries: list[dict]) -> dict[tuple[str, str], SearchHit]:
    found: dict[tuple[str, str], SearchHit] = {}
    now_epoch = time.time()
    for item in entries:
        next_retry_epoch = float(item.get("next_retry_epoch", 0) or 0)
        if next_retry_epoch and next_retry_epoch > now_epoch:
            continue
        hit = SearchHit(
            item["domain"],
            item["platform"],
            list(item["queries"]),
            list(item["urls"]),
            list(item["sources"]),
            list(item["providers"]),
            list(item["search_evidence"]),
        )
        if pending_candidate_has_strong_signal(hit):
            found[(hit.platform, hit.domain)] = hit
    return found


def cfg_lang_service(lang: str, index: int) -> str:
    terms = LANGUAGES[lang]["service"]
    return terms[min(index, len(terms) - 1)]


def active_search_languages() -> tuple[str, ...]:
    if DISCOVERY_MODE == "deep":
        return ()
    day_index = int(time.time() // 86400)
    extras = (
        LANGUAGE_ROTATION[(day_index * 2) % len(LANGUAGE_ROTATION)],
        LANGUAGE_ROTATION[(day_index * 2 + 1) % len(LANGUAGE_ROTATION)],
    )
    return ("en", "es", *extras)


def search_pages_for(lang: str, query: str = "") -> tuple[int, ...]:
    if lang not in LANGUAGES:
        return (1,)
    q = fold(query)
    deep_terms = tuple(dict.fromkeys(
        (
            "viewer", "frontend", "alternative", "similar", "anonymous",
            "browser", "slideshow", "gallery", "content browser", "web client",
            "without login", "without account", "no login", "no account",
            "sin iniciar sesión", "sin cuenta",
            "sans connexion", "sans compte",
            "ohne anmeldung", "ohne konto",
            "без входа", "без аккаунта",
            "로그인 없이", "계정 없이",
            "ログインなし", "アカウントなし",
            "无登录", "无需账户",
            "sem login", "sem conta",
            "senza accesso", "senza account",
            "بدون تسجيل دخول", "بدون حساب",
            "बिना लॉगिन", "बिना अकाउंट",
        )
        + tuple(LANGUAGES[lang]["service"])
    ))
    return SEARCH_PAGES if any(term_present(term, q) for term in deep_terms) else (1,)


def build_queries() -> list[tuple[str, str, str]]:
    # Keep the daily search bounded and high-signal. EN/ES run every day;
    # two additional languages rotate through the remaining locales.
    query_specs: list[tuple[str, str, str]] = []

    intents = {
        "en": [
            '"{platform} viewer" "without login"',
            '"{platform} viewer" "without account"',
            '"{platform} web viewer" "without login"',
            '"{platform} anonymous viewer"',
        ],
        "es": [
            '"{platform} visor" "sin iniciar sesión"',
            '"{platform} visor" "sin cuenta"',
            '"{platform} visor web" "sin iniciar sesión"',
            '"{platform} visor anónimo"',
        ],
        "fr": [
            '"{platform} visionneuse" "sans connexion"',
            '"{platform} visionneuse" "sans compte"',
            '"{platform} visionneuse web" "sans connexion"',
            '"{platform} visionneuse anonyme"',
        ],
        "de": [
            '"{platform} Betrachter" "ohne Anmeldung"',
            '"{platform} Betrachter" "ohne Konto"',
            '"{platform} Web-Betrachter" "ohne Anmeldung"',
            '"{platform} anonymer Betrachter"',
        ],
        "zh": [
            '"{platform} 查看器" "无登录"',
            '"{platform} 查看器" "无需账户"',
            '"{platform} 网页查看器"',
            '"{platform} 匿名 查看器"',
        ],
        "ja": [
            '"{platform} ビューア" "ログインなし"',
            '"{platform} ビューア" "アカウントなし"',
            '"{platform} Webビューア"',
            '"{platform} 匿名 ビューア"',
        ],
        "ko": [
            '"{platform} 뷰어" "로그인 없이"',
            '"{platform} 뷰어" "계정 없이"',
            '"{platform} 웹 뷰어"',
            '"{platform} 익명 뷰어"',
        ],
        "hi": [
            '"{platform} व्यूअर" "बिना लॉगिन"',
            '"{platform} व्यूअर" "बिना अकाउंट"',
            '"{platform} वेब व्यूअर"',
            '"{platform} अनाम व्यूअर"',
        ],
        "ru": [
            '"{platform} просмотрщик" "без входа"',
            '"{platform} просмотрщик" "без аккаунта"',
            '"{platform} веб-просмотрщик" "без входа"',
            '"{platform} анонимный просмотрщик"',
        ],
        "ar": [
            '"{platform} عارض" "بدون تسجيل دخول"',
            '"{platform} عارض" "بدون حساب"',
            '"{platform} عارض ويب"',
            '"{platform} عارض مجهول"',
        ],
        "pt": [
            '"{platform} visualizador" "sem login"',
            '"{platform} visualizador" "sem conta"',
            '"{platform} visualizador web" "sem login"',
            '"{platform} visualizador anônimo"',
        ],
        "it": [
            '"{platform} visualizzatore" "senza accesso"',
            '"{platform} visualizzatore" "senza account"',
            '"{platform} visualizzatore web" "senza accesso"',
            '"{platform} visualizzatore anonimo"',
        ],
    }

    platform_query_families = (
        {
            "twitter": [
                '"Twitter profile viewer" -news -article -guide -review',
                '"tweet viewer" -news -article -guide -review',
                '"X profile viewer" "no login" -news -article -guide -review',
                '"Twitter alternative front-end" -news -article -guide -review',
                '"Twitter private front-end" -news -article -guide -review',
            ],
            "reddit": [
                '"Reddit post viewer" -news -article -guide -review',
                '"Reddit profile viewer" -news -article -guide -review',
                '"Reddit anonymous viewer" -news -article -guide -review',
                '"subreddit viewer" -news -article -guide -review',
                '"Reddit private front-end" -news -article -guide -review',
            ],
            "tumblr": [
                '"Tumblr blog viewer" -news -article -guide -review',
                '"Tumblr profile viewer" -news -article -guide -review',
                '"Tumblr anonymous viewer" -news -article -guide -review',
                '"Tumblr post viewer" -news -article -guide -review',
                '"Tumblr private front-end" -news -article -guide -review',
            ],
        },
        {
            "twitter": [
                '"Twitter web viewer" public profiles -news -article -guide -review',
                '"tweet browser" "without login" -news -article -guide -review',
                '"X anonymous viewer" profiles -news -article -guide -review',
                '"Nitter alternative" viewer -news -article -guide -review',
                '"Twitter frontend" privacy -news -article -guide -review',
            ],
            "reddit": [
                '"Reddit web viewer" public posts -news -article -guide -review',
                '"Reddit browser" "without login" -news -article -guide -review',
                '"Reddit anonymous viewer" posts -news -article -guide -review',
                '"Redlib alternative" viewer -news -article -guide -review',
                '"Reddit frontend" privacy -news -article -guide -review',
            ],
            "tumblr": [
                '"Tumblr web viewer" public blogs -news -article -guide -review',
                '"Tumblr browser" "without login" -news -article -guide -review',
                '"Tumblr anonymous viewer" posts -news -article -guide -review',
                '"Priviblur alternative" viewer -news -article -guide -review',
                '"Tumblr frontend" privacy -news -article -guide -review',
            ],
        },
        {
            "twitter": [
                '"Twitter profile browser" -news -article -guide -review',
                '"public tweet viewer" -news -article -guide -review',
                '"X viewer" "without account" -news -article -guide -review',
                '"Nitter frontend" alternative -news -article -guide -review',
                '"Twitter viewer" "no account" -news -article -guide -review',
            ],
            "reddit": [
                '"Reddit profile browser" -news -article -guide -review',
                '"public Reddit post viewer" -news -article -guide -review',
                '"Reddit viewer" "without account" -news -article -guide -review',
                '"Redlib frontend" alternative -news -article -guide -review',
                '"Reddit viewer" "no account" -news -article -guide -review',
            ],
            "tumblr": [
                '"Tumblr profile browser" -news -article -guide -review',
                '"public Tumblr post viewer" -news -article -guide -review',
                '"Tumblr viewer" "without account" -news -article -guide -review',
                '"Priviblur frontend" alternative -news -article -guide -review',
                '"Tumblr viewer" "no account" -news -article -guide -review',
            ],
        },
    )
    day_index = int(time.time() // 86400)
    platform_queries = platform_query_families[(day_index // 2) % len(platform_query_families)]

    active = set(active_search_languages())
    for lang in active:
        for platform in PLATFORMS:
            for template in intents[lang]:
                query_specs.append(
                    (
                        lang,
                        platform,
                        template.format(platform=platform),
                    )
                )

    # These are deliberately about *alternative services*, not instance lists
    # that the maintained registries already cover.
    for platform, templates in platform_queries.items():
        if "en" not in active:
            continue
        query_specs.extend(("en", platform, q) for q in templates)

    return list(dict.fromkeys(query_specs))


def is_seed_candidate(hit: SearchHit) -> bool:
    return any(q.startswith("SEED:") for q in hit.queries)


def seed_candidates() -> dict[tuple[str, str], SearchHit]:
    found: dict[tuple[str, str], SearchHit] = {}
    for platform, url in WEB_VERIFIED_SEEDS:
        host = normalize_host(url)
        if not host:
            continue
        found[(platform, host)] = SearchHit(
            host,
            platform,
            [f"SEED:{url}"],
            [url],
            ["Web-verified seed 2026-10-03"],
            [],
            [f"Web-verified viewer seed: {url}"],
        )
    return found


def search_with_bing_rss(query: str, cfg: dict, page: int) -> list[dict]:
    if page != 1:
        return []
    url = (
        "https://www.bing.com/search?format=rss"
        f"&q={quote_plus(query)}"
        f"&setlang={quote_plus(cfg['hl'])}"
        f"&cc={quote_plus(cfg['gl'])}"
    )
    req = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/rss+xml, application/xml, text/xml, */*",
            "Accept-Language": cfg["hl"],
            "Connection": "close",
        },
    )
    with urlopen(req, timeout=SEARCH_TIMEOUT) as response:
        raw = response.read(MAX_PAGE_BYTES)
        charset = response.headers.get_content_charset() or "utf-8"
        payload = raw.decode(charset, errors="replace")

    root = ET.fromstring(payload)
    results: list[dict] = []
    for item in root.iter():
        if item.tag.rsplit("}", 1)[-1].lower() != "item":
            continue
        fields: dict[str, str] = {}
        for child in list(item):
            key = child.tag.rsplit("}", 1)[-1].lower()
            value = "".join(child.itertext()).strip()
            if value:
                fields[key] = html.unescape(value)
        href = fields.get("link", "")
        if not href:
            continue
        results.append({
            "href": href,
            "title": fields.get("title", ""),
            "body": fields.get("description", ""),
        })
        if len(results) >= SEARCH_MAX_RESULTS:
            break
    return results


def search_with_bing_html(query: str, cfg: dict, page: int) -> list[dict]:
    if page < 1:
        return []
    first = 1 + (page - 1) * SEARCH_MAX_RESULTS
    url = (
        "https://www.bing.com/search?"
        f"q={quote_plus(query)}&count={SEARCH_MAX_RESULTS}&first={first}"
        f"&setlang={quote_plus(cfg['hl'])}&cc={quote_plus(cfg['gl'])}"
    )
    req = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,*/*",
            "Accept-Language": cfg["hl"],
            "Connection": "close",
        },
    )
    with urlopen(req, timeout=SEARCH_TIMEOUT) as response:
        raw = response.read(MAX_PAGE_BYTES)
        charset = response.headers.get_content_charset() or "utf-8"
        payload = raw.decode(charset, errors="replace")
    parser = SearchResultParser()
    parser.feed(payload)
    results: list[dict] = []
    seen: set[str] = set()
    for href in parser.hrefs:
        if href in seen:
            continue
        seen.add(href)
        results.append({"href": href, "title": "", "body": ""})
        if len(results) >= SEARCH_MAX_RESULTS:
            break
    return results


def search_with_backend(query: str, cfg: dict, page: int, backend: str) -> list[dict]:
    if backend == "bing-rss":
        return search_with_bing_rss(query, cfg, page)
    if backend == "bing-html":
        return search_with_bing_html(query, cfg, page)
    raise ValueError(f"Unsupported search backend: {backend}")


def run_search_spec(
    index: int,
    lang: str,
    platform: str,
    query: str,
) -> tuple[
    int,
    str,
    str,
    str,
    list[tuple[int, str, list[dict]]],
    list[dict],
    int,
]:
    cfg = LANGUAGES[lang]
    results_by_page: list[tuple[int, str, list[dict]]] = []
    errors: list[dict] = []
    fallback_count = 0

    for page in search_pages_for(lang, query):
        page_results: list[dict] = []
        page_backend = ""
        page_attempt_errors: list[dict] = []

        for backend in SEARCH_BACKENDS:
            try:
                results = search_with_backend(query, cfg, page, backend)
                if results:
                    page_results = results
                    page_backend = backend
                    if page_attempt_errors:
                        fallback_count += 1
                    break
            except (HTTPError, URLError, OSError, ValueError, ET.ParseError) as exc:
                page_attempt_errors.append({
                    "language": lang,
                    "platform": platform,
                    "query": query,
                    "backend": backend,
                    "page": page,
                    "attempt": 1,
                    "error": f"{type(exc).__name__}: {exc}",
                })
            if SEARCH_DELAY:
                time.sleep(SEARCH_DELAY)

        if page_results:
            results_by_page.append((page, page_backend, page_results))
        elif page_attempt_errors:
            errors.extend(page_attempt_errors)

        if SEARCH_DELAY:
            time.sleep(SEARCH_DELAY)

    return index, lang, platform, query, results_by_page, errors, fallback_count



def search_result_is_relevant(
    platform: str,
    query: str,
    evidence: str,
    href: str = "",
) -> bool:
    """Reject obvious search noise while preserving service-shaped candidates."""
    if not evidence and not href:
        return True

    pcfg = PLATFORMS[platform]
    if platform == "twitter":
        platform_ok = any(
            term_present(term, evidence) for term in ("twitter", "tweet", "nitter")
        )
    elif platform == "reddit":
        platform_ok = any(
            term_present(term, evidence)
            for term in ("reddit", "subreddit", "redlib", "libreddit", "teddit")
        )
    else:
        platform_ok = any(
            term_present(term, evidence) for term in ("tumblr", "priviblur")
        )

    service_ok = any(
        term_present(term, evidence) for term in SEARCH_RESULT_SERVICE_TERMS
    )
    brand_ok = any(term_present(term, evidence) for term in pcfg["brands"])
    identity_ok = any(
        term_present(term, evidence)
        for term in pcfg["identity_extra"]
    )
    query_service = query_has_service_intent(platform, query)

    safe_href = sanitize_request_url(href) if href else None
    url_service_hint = bool(
        safe_href
        and (
            SEARCH_SERVICE_HOST_RE.search(normalize_host(safe_href) or "")
            or path_looks_like_service(urlparse(safe_href).path.lower())
        )
    )
    editorial_evidence = any(
        term_present(term, evidence)
        for term in SEARCH_RESULT_EDITORIAL_MARKERS
    )
    non_frontend_evidence = any(
        term_present(term, evidence)
        for term in NON_FRONTEND_SERVICE_TERMS
    )

    if brand_ok and not non_frontend_evidence:
        return True
    if non_frontend_evidence and not service_ok:
        return False
    if url_service_hint and query_service:
        return True
    if platform_ok and service_ok:
        return True
    if query_service and service_ok:
        return True
    if query_service and identity_ok and not editorial_evidence:
        return True
    return False


def merge_search_result(
    candidate_map: dict[tuple[str, str], SearchHit],
    platform: str,
    query: str,
    backend: str,
    result: dict,
) -> None:
    """Merge one relevant search result into the deduplicated candidate map."""
    href = result.get("href") or result.get("url") or ""
    safe_href = sanitize_request_url(href)
    if not safe_href:
        return

    evidence = fold(f"{result.get('title', '')} {result.get('body', '')}")
    if evidence and not search_result_is_relevant(platform, query, evidence, safe_href):
        return

    domain = normalize_host(safe_href)
    if not domain:
        return

    key = (platform, domain)
    if key not in candidate_map:
        candidate_map[key] = SearchHit(
            domain,
            platform,
            [],
            [],
            [],
            [],
            [],
        )

    hit = candidate_map[key]
    if query not in hit.queries:
        hit.queries.append(query)
    if safe_href not in hit.urls:
        hit.urls.append(safe_href)
    if backend not in hit.providers:
        hit.providers.append(backend)

    if evidence:
        marker = f"{backend}:{evidence[:900]}"
        if marker not in hit.search_evidence:
            hit.search_evidence.append(marker)



def fetch_text(url: str, extra_headers: dict[str, str] | None = None) -> str:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json,text/plain,text/markdown,*/*",
        "Accept-Language": "en,es;q=0.7,*;q=0.3",
        "Connection": "close",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = Request(url, headers=headers)
    with urlopen(req, timeout=PAGE_TIMEOUT) as response:
        raw = response.read(MAX_PAGE_BYTES)
        charset = response.headers.get_content_charset() or "utf-8"
        return raw.decode(charset, errors="replace")


LIBREDIRECT_PLATFORM_KEYS = {
    "twitter": {"nitter", "shitter"},
    "reddit": {"redlib", "libreddit", "teddit", "eddrit", "troddit", "kddit"},
    "tumblr": {"priviblur"},
}


def extract_libredirect(text: str, platform: str) -> set[str]:
    data = json.loads(text)
    wanted = LIBREDIRECT_PLATFORM_KEYS.get(platform, set())
    out: set[str] = set()
    if not isinstance(data, dict):
        return out
    for service_name in wanted:
        item = data.get(service_name)
        if not isinstance(item, dict):
            continue
        clearnet = item.get("clearnet", [])
        if not isinstance(clearnet, list):
            continue
        for value in clearnet:
            if not isinstance(value, str):
                continue
            host = normalize_host(value)
            if host:
                out.add(host)
    return out


def extract_farside(text: str, platform: str) -> set[str]:
    data = json.loads(text)
    wanted = FARSIDE_PLATFORM_TYPES.get(platform, set())
    out: set[str] = set()
    if not isinstance(data, list):
        return out
    for item in data:
        if not isinstance(item, dict) or item.get("type") not in wanted:
            continue
        values = list(item.get("instances", []))
        fallback = item.get("fallback")
        if isinstance(fallback, str):
            values.append(fallback)
        for value in values:
            if not isinstance(value, str):
                continue
            for raw in value.split("|"):
                host = normalize_host(raw)
                if host:
                    out.add(host)
    return out


def extract_section_urls(text: str, platform: str) -> set[str]:
    aliases = {
        "twitter": {"twitter", "x"},
        "reddit": {"reddit"},
        "tumblr": {"tumblr"},
    }
    section_lines: list[str] = []
    section_level: int | None = None
    in_section = False

    for line in text.splitlines():
        heading = re.match(r"^\s*(#{2,6})\s+(.+?)\s*#*\s*$", line)
        if heading:
            level = len(heading.group(1))
            title = fold(heading.group(2))
            if in_section and section_level is not None and level <= section_level:
                break
            if any(term_present(alias, title) for alias in aliases[platform]):
                in_section = True
                section_level = level
                continue
        if in_section:
            section_lines.append(line)

    out: set[str] = set()
    for raw_url in URL_IN_HTML_RE.findall("\n".join(section_lines)):
        host = normalize_host(html.unescape(raw_url))
        if host:
            out.add(host)
    return out


GITHUB_SOURCE_QUERIES = [
    "alternative frontend reddit twitter tumblr",
    "privacy alternative frontends reddit",
    "privacy alternative frontends twitter",
    "privacy alternative frontends tumblr",
    "nitter instances",
    "redlib instances",
    "libreddit instances",
    "priviblur instances",
    "teddit instances",
]


def github_repository_candidates() -> dict[tuple[str, str], SearchHit]:
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        print("[WARN] GITHUB_TOKEN unavailable; skipping GitHub repository discovery.")
        return {}

    found: dict[tuple[str, str], SearchHit] = {}
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    repo_keys: set[str] = set()

    for query in GITHUB_SOURCE_QUERIES:
        url = (
            "https://api.github.com/search/repositories"
            f"?q={quote_plus(query)}&sort=updated&order=desc&per_page={REPOSITORY_SOURCE_LIMIT}"
        )
        try:
            data = json.loads(fetch_text(url, headers))
        except Exception as exc:
            print(f"[WARN] GitHub repo search failed for {query!r}: {type(exc).__name__}: {exc}")
            continue

        for item in data.get("items", []):
            if not isinstance(item, dict):
                continue
            full_name = item.get("full_name")
            default_branch = item.get("default_branch")
            if isinstance(full_name, str) and isinstance(default_branch, str):
                if full_name.lower() != "p4vizal/frontend-blocklist":
                    repo_keys.add(f"{full_name}@{default_branch}")

    for repo_key in sorted(repo_keys)[:36]:
        full_name, default_branch = repo_key.rsplit("@", 1)
        readme_url = (
            f"https://raw.githubusercontent.com/{full_name}/"
            f"{quote(default_branch, safe='/')}/README.md"
        )
        source_name = f"GitHub:{full_name}"
        try:
            text = fetch_text(readme_url)
        except Exception:
            continue
        for platform in PLATFORMS:
            for host in extract_section_urls(text, platform):
                key = (platform, host)
                if key not in found:
                    found[key] = SearchHit(host, platform, [], [], [], [], [])
                hit = found[key]
                if source_name not in hit.sources:
                    hit.sources.append(source_name)
                marker = f"SOURCE:{source_name}"
                if marker not in hit.queries:
                    hit.queries.append(marker)
                source_url = f"https://{host}/"
                if source_url not in hit.urls:
                    hit.urls.append(source_url)

    print(f"GitHub repository sources found: {len(repo_keys)}")
    return found


REPOSITORY_SEARCH_QUERIES = [
    "twitter alternative frontend",
    "twitter viewer frontend",
    "reddit alternative frontend",
    "reddit viewer frontend",
    "tumblr alternative frontend",
    "tumblr viewer frontend",
    "nitter alternative frontend",
    "redlib alternative frontend",
    "libreddit alternative frontend",
    "priviblur alternative frontend",
]


def add_source_candidate(
    found: dict[tuple[str, str], SearchHit],
    platform: str,
    host: str,
    source_name: str,
    source_url: str = "",
) -> None:
    key = (platform, host)
    if key not in found:
        found[key] = SearchHit(host, platform, [], [], [], [], [])
    hit = found[key]
    if source_name not in hit.sources:
        hit.sources.append(source_name)
    marker = f"SOURCE:{source_name}"
    if marker not in hit.queries:
        hit.queries.append(marker)
    if source_url:
        if "://" not in source_url:
            source_url = f"https://{source_url}/"
        if source_url not in hit.urls:
            hit.urls.append(source_url)


MARKDOWN_LINK_URL_RE = re.compile(r"(?i)\[[^\]]{1,240}\]\((https?://[^\s)<>]+)")
BACKTICK_URL_RE = re.compile(r"(?i)`(https?://[^\s`<>]+)`")

def repository_service_urls(text: str, platform: str) -> set[str]:
    urls = extract_section_urls(text, platform)
    if urls:
        return urls

    lines = text.splitlines()
    context: list[str] = []
    service_terms = (
        "viewer", "frontend", "nitter", "redlib", "libreddit",
        "teddit", "troddit", "priviblur", "mirror", "proxy",
    )
    platform_terms = [t for t in PLATFORMS[platform]["platform_terms"] if t != "x"]
    for i, line in enumerate(lines):
        folded = fold(line)
        if any(term_present(t, folded) for t in platform_terms) and any(
            term_present(t, folded) for t in service_terms
        ):
            context.extend(lines[max(0, i - 2): min(len(lines), i + 3)])

    context_text = "\n".join(context)
    for raw_url in URL_IN_HTML_RE.findall(context_text):
        host = normalize_host(html.unescape(raw_url))
        if host:
            urls.add(host)
    for raw_url in MARKDOWN_LINK_URL_RE.findall(context_text):
        host = normalize_host(html.unescape(raw_url))
        if host:
            urls.add(host)
    for raw_url in BACKTICK_URL_RE.findall(context_text):
        host = normalize_host(html.unescape(raw_url))
        if host:
            urls.add(host)
    return urls


def gitlab_repository_candidates() -> dict[tuple[str, str], SearchHit]:
    found: dict[tuple[str, str], SearchHit] = {}
    token = os.environ.get("GITLAB_TOKEN", "").strip()
    if not token:
        print("[INFO] GITLAB_TOKEN not configured; GitLab repository discovery skipped.")
        return found
    repo_keys: set[str] = set()
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT, "PRIVATE-TOKEN": token}

    for query in REPOSITORY_SEARCH_QUERIES:
        url = (
            "https://gitlab.com/api/v4/projects"
            f"?search={quote_plus(query)}&simple=true"
            f"&order_by=last_activity_at&sort=desc&per_page={REPOSITORY_SOURCE_LIMIT}"
        )
        try:
            data = json.loads(fetch_text(url, headers))
        except Exception as exc:
            print(f"[WARN] GitLab repository search failed for {query!r}: {type(exc).__name__}: {exc}")
            continue
        if not isinstance(data, list):
            continue
        for item in data:
            if not isinstance(item, dict):
                continue
            web_url = item.get("web_url")
            branch = item.get("default_branch") or "main"
            if isinstance(web_url, str) and isinstance(branch, str):
                repo_keys.add(f"{web_url}@{branch}")

    for repo_key in sorted(repo_keys)[:REPOSITORY_SOURCE_LIMIT * 2]:
        web_url, branch = repo_key.rsplit("@", 1)
        parsed = urlparse(web_url)
        if parsed.netloc != "gitlab.com":
            continue
        full_path = parsed.path.strip("/")
        if not full_path:
            continue
        source_name = f"GitLab:{full_path}"
        readme_url = f"https://gitlab.com/{full_path}/-/raw/{quote(branch, safe='/')}/README.md"
        try:
            text = fetch_text(readme_url)
        except Exception:
            continue
        for platform in PLATFORMS:
            for host in repository_service_urls(text, platform):
                add_source_candidate(found, platform, host, source_name, f"https://{host}/")

    print(f"GitLab repository sources found: {len(repo_keys)}")
    return found


def codeberg_repository_candidates() -> dict[tuple[str, str], SearchHit]:
    found: dict[tuple[str, str], SearchHit] = {}
    repo_keys: set[str] = set()
    headers = {"Accept": "application/json", "User-Agent": USER_AGENT}

    for query in REPOSITORY_SEARCH_QUERIES:
        url = (
            "https://codeberg.org/api/v1/repos/search"
            f"?q={quote_plus(query)}&limit={REPOSITORY_SOURCE_LIMIT}"
        )
        try:
            data = json.loads(fetch_text(url, headers))
        except Exception as exc:
            print(f"[WARN] Codeberg repository search failed for {query!r}: {type(exc).__name__}: {exc}")
            continue
        items = data.get("data", data) if isinstance(data, dict) else data
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            full_name = item.get("full_name")
            branch = item.get("default_branch") or "main"
            if isinstance(full_name, str) and isinstance(branch, str):
                repo_keys.add(f"{full_name}@{branch}")

    for repo_key in sorted(repo_keys)[:REPOSITORY_SOURCE_LIMIT * 2]:
        full_name, branch = repo_key.rsplit("@", 1)
        source_name = f"Codeberg:{full_name}"
        readme_url = (
            f"https://codeberg.org/{full_name}/raw/branch/{quote(branch, safe='/')}/README.md"
        )
        try:
            text = fetch_text(readme_url)
        except Exception:
            continue
        for platform in PLATFORMS:
            for host in repository_service_urls(text, platform):
                add_source_candidate(found, platform, host, source_name, f"https://{host}/")

    print(f"Codeberg repository sources found: {len(repo_keys)}")
    return found


def common_crawl_candidates() -> dict[tuple[str, str], SearchHit]:
    found: dict[tuple[str, str], SearchHit] = {}
    try:
        collections = json.loads(fetch_text("https://index.commoncrawl.org/collinfo.json"))
        latest = collections[0]
        collection_id = latest["id"]
        cdx_api = f"https://index.commoncrawl.org/{collection_id}-index"
    except Exception as exc:
        print(f"[WARN] Common Crawl collection discovery failed: {type(exc).__name__}: {exc}")
        return found

    patterns = {
        "twitter": (
            "*twitter*viewer*", "*twitter*frontend*", "*twitter*browser*",
            "*nitter*", "*xcancel*",
        ),
        "reddit": (
            "*reddit*viewer*", "*reddit*frontend*", "*reddit*browser*",
            "*redlib*", "*libreddit*",
        ),
        "tumblr": (
            "*tumblr*viewer*", "*tumblr*frontend*", "*tumblr*browser*",
            "*priviblur*", "*tumlook*",
        ),
    }
    for platform, platform_patterns in patterns.items():
        for pattern in platform_patterns:
            time.sleep(COMMON_CRAWL_DELAY)
            url = (
                f"{cdx_api}?url={quote_plus(pattern)}&output=json"
                f"&filter=status%3A200&collapse=urlkey&limit={COMMON_CRAWL_LIMIT}"
            )
            try:
                raw = fetch_text(
                    url,
                    {"Accept": "application/json", "User-Agent": USER_AGENT},
                )
            except Exception as exc:
                print(f"[WARN] Common Crawl query failed for {pattern!r}: {type(exc).__name__}: {exc}")
                continue
            for line in raw.splitlines():
                try:
                    record = json.loads(line)
                except json.JSONDecodeError:
                    continue
                target_url = record.get("url")
                if not isinstance(target_url, str):
                    continue
                host = normalize_host(target_url)
                if not host:
                    continue
                add_source_candidate(
                    found,
                    platform,
                    host,
                    f"CommonCrawl:{collection_id}",
                    target_url,
                )

    print(f"Common Crawl candidates found: {len(found)}")
    return found


def urlscan_candidates() -> dict[tuple[str, str], SearchHit]:
    found: dict[tuple[str, str], SearchHit] = {}
    api_key = os.environ.get("URLSCAN_API_KEY", "").strip()
    if not api_key:
        print("[INFO] URLScan API key not configured; optional URLScan discovery skipped.")
        return found

    queries = {
        "twitter": "page.title:(twitter viewer OR tweet viewer OR twitter frontend OR nitter)",
        "reddit": "page.title:(reddit viewer OR reddit frontend OR redlib OR libreddit)",
        "tumblr": "page.title:(tumblr viewer OR tumblr frontend OR priviblur)",
    }
    headers = {
        "API-Key": api_key,
        "Accept": "application/json",
        "User-Agent": USER_AGENT,
    }
    for platform, query in queries.items():
        time.sleep(URLSCAN_DELAY)
        url = (
            "https://urlscan.io/api/v1/search/"
            f"?q={quote_plus(query)}&size={URLSCAN_MAX_RESULTS}&datasource=scans"
        )
        try:
            data = json.loads(fetch_text(url, headers))
        except Exception as exc:
            print(f"[WARN] URLScan search failed for {platform}: {type(exc).__name__}: {exc}")
            continue
        results = data.get("results", []) if isinstance(data, dict) else []
        for item in results:
            if not isinstance(item, dict):
                continue
            page = item.get("page") or {}
            target_url = page.get("url") if isinstance(page, dict) else ""
            host_value = page.get("domain") if isinstance(page, dict) else ""
            host = host_value or normalize_host(target_url if isinstance(target_url, str) else "")
            if not isinstance(host, str):
                continue
            normalized = normalize_host(host)
            if not normalized:
                continue
            add_source_candidate(
                found,
                platform,
                normalized,
                f"URLScan:{platform}",
                target_url if isinstance(target_url, str) else f"https://{normalized}/",
            )

    print(f"URLScan candidates found: {len(found)}")
    return found


def trusted_candidates() -> dict[tuple[str, str], SearchHit]:
    found: dict[tuple[str, str], SearchHit] = {}

    def add(platform: str, host: str, source_name: str):
        key = (platform, host)
        if key not in found:
            found[key] = SearchHit(host, platform, [], [], [], [], [])
        hit = found[key]
        if source_name not in hit.sources:
            hit.sources.append(source_name)
        if f"SOURCE:{source_name}" not in hit.queries:
            hit.queries.append(f"SOURCE:{source_name}")
        if f"https://{host}/" not in hit.urls:
            hit.urls.append(f"https://{host}/")

    for source_name, kind, url in TRUSTED_SOURCES:
        try:
            if kind == "json":
                text = fetch_text(url)
                for platform in PLATFORMS:
                    if source_name == "Farside":
                        hosts = extract_farside(text, platform)
                    elif source_name == "LibRedirect":
                        hosts = extract_libredirect(text, platform)
                    else:
                        hosts = set()
                    for host in hosts:
                        add(platform, host, source_name)
                if source_name == "Redlib":
                    data = json.loads(text)
                    for item in data.get("instances", []):
                        if isinstance(item, dict):
                            host = normalize_host(item.get("url", ""))
                            if host:
                                add("reddit", host, source_name)
                elif source_name == "Libreddit":
                    data = json.loads(text)
                    for item in data.get("instances", []):
                        if isinstance(item, dict):
                            host = normalize_host(item.get("url", ""))
                            if host:
                                add("reddit", host, source_name)
            else:
                text = fetch_text(url) if kind == "text" else fetch_html(url)[0]
                if text is None:
                    continue
                for platform in PLATFORMS:
                    for host in extract_section_urls(text, platform):
                        add(platform, host, source_name)
        except Exception as exc:
            print(f"[WARN] Trusted source {source_name} failed: {type(exc).__name__}: {exc}")

    return found


def fetch_jina_text(url: str) -> tuple[str, dict] | tuple[None, dict]:
    safe_url = sanitize_request_url(url)
    if not safe_url:
        return None, {"error": "invalid candidate URL"}
    jina_url = "https://r.jina.ai/" + safe_url
    req = Request(
        jina_url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/plain",
            "Connection": "close",
        },
    )
    try:
        with urlopen(req, timeout=12) as response:
            raw = response.read(MAX_PAGE_BYTES)
            charset = response.headers.get_content_charset() or "utf-8"
            text = raw.decode(charset, errors="replace")
        return text, {"final_url": url, "via": "jina"}
    except (HTTPError, URLError, TimeoutError, ValueError, OSError) as exc:
        return None, {"error": f"{type(exc).__name__}: {exc}"}


def page_evidence_from_text(url: str, text: str) -> dict:
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    title = lines[0] if lines else ""
    headings = " ".join(line.lstrip("# ").strip() for line in lines[1:8])
    body = " ".join(lines[:500])
    parsed = urlparse(url)
    return {
        "title": title,
        "headings": headings,
        "meta": "",
        "body": body,
        "links": [],
        "forms": 0,
        "inputs": 0,
        "buttons": 0,
        "article_count": 0,
        "controls": "",
        "url_text": f"{parsed.netloc} {parsed.path}",
        "visible": body,
        "link_text": "",
    }


def fetch_html(url: str) -> tuple[str, dict] | tuple[None, dict]:
    safe_url = sanitize_request_url(url)
    if not safe_url:
        return None, {"error": "invalid candidate URL"}

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en,es;q=0.7,*;q=0.3",
        "Connection": "close",
    }

    variants = [safe_url]
    if safe_url.startswith("http://"):
        variants.append(safe_url.replace("http://", "https://", 1))

    last_error = "fetch failed"
    fetch_status = None
    for scheme_url in dict.fromkeys(variants):
        for attempt in range(1, FETCH_RETRIES + 1):
            try:
                req = Request(scheme_url, headers=headers)
                with urlopen(req, timeout=PAGE_TIMEOUT) as response:
                    content_type = response.headers.get("Content-Type", "")
                    if "html" not in content_type.lower() and content_type:
                        return None, {"error": f"non-html content-type: {content_type}"}
                    raw = response.read(MAX_PAGE_BYTES)
                    charset = response.headers.get_content_charset() or "utf-8"
                    text = raw.decode(charset, errors="replace")
                    final_url = response.geturl()
                    status = getattr(response, "status", None)
                return text, {"final_url": final_url, "status_code": status}
            except HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                fetch_status = exc.code
                # Permanent responses do not benefit from a second request.
                if exc.code not in RETRYABLE_HTTP_CODES:
                    break
                if attempt < FETCH_RETRIES:
                    time.sleep(0.5 * attempt)
            except (URLError, TimeoutError, ValueError, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < FETCH_RETRIES:
                    time.sleep(0.5 * attempt)
    return None, {"error": last_error, "status_code": fetch_status}


def page_evidence(url: str, html_text: str) -> dict:
    parser = PageParser()
    parser.feed(html_text)
    data = parser.result()
    parsed = urlparse(url)
    visible = " ".join([data["body"], data["headings"], data["title"], data["meta"]])
    link_text = " ".join(
        f"{label} {href}" for href, label in data["links"]
    )
    return {
        **data,
        "url_text": f"{parsed.netloc} {parsed.path}",
        "visible": visible,
        "link_text": link_text,
    }


def runtime_signals_from_html(html_text: str, platform: str) -> dict:
    """Extract lightweight JS/metadata signals without executing page code."""
    empty = {
        "script_sources": [],
        "manifest_urls": [],
        "framework_hits": [],
        "platform_hits": [],
        "service_hits": [],
        "service_runtime_hint": False,
    }
    if not isinstance(html_text, str) or "<" not in html_text:
        return empty

    script_sources = [
        html.unescape(value)
        for value in re.findall(
            r"(?is)<script[^>]+\bsrc\s*=\s*['\"]([^'\"]+)",
            html_text,
        )
    ][:24]
    manifest_urls = [
        html.unescape(value)
        for value in re.findall(
            r"(?is)<link[^>]+\brel\s*=\s*['\"][^'\"]*manifest[^'\"]*['\"][^>]+\bhref\s*=\s*['\"]([^'\"]+)",
            html_text,
        )
    ][:8]
    jsonld_text = " ".join(
        html.unescape(value)
        for value in re.findall(
            r"(?is)<script[^>]+type\s*=\s*['\"]application/ld\+json['\"][^>]*>(.*?)</script>",
            html_text,
        )
    )[:12000]

    inline_js_text = " ".join(
        value
        for value in re.findall(
            r"(?is)<script(?![^>]+\bsrc\s*=)[^>]*>(.*?)</script>",
            html_text,
        )
    )[:16000]
    runtime_text = fold(" ".join(script_sources + manifest_urls + [jsonld_text, inline_js_text]))
    if platform == "twitter":
        platform_terms = ("twitter", "tweet", "nitter", "xcancel")
    elif platform == "reddit":
        platform_terms = ("reddit", "subreddit", "redlib", "libreddit", "teddit", "troddit")
    else:
        platform_terms = ("tumblr", "priviblur", "tumlook", "tumviews", "zoomblr")
    platform_hits = [t for t in platform_terms if term_present(t, runtime_text)]
    service_hits = [t for t in STRONG_SERVICE_TERMS if term_present(t, runtime_text)]
    framework_hits = [
        t for t in ("react", "vue", "svelte", "angular", "next.js", "nuxt", "astro", "vite")
        if term_present(t, runtime_text)
    ]
    return {
        "script_sources": script_sources,
        "manifest_urls": manifest_urls,
        "framework_hits": framework_hits,
        "platform_hits": platform_hits,
        "service_hits": service_hits,
        "service_runtime_hint": bool(platform_hits and service_hits),
    }


def service_route_candidates(
    final_url: str,
    page: dict,
    platform: str,
) -> list[str]:
    """Rank same-origin links that look like actual frontend/content routes."""
    final_host = normalize_host(final_url)
    if not final_host:
        return []

    pcfg = PLATFORMS[platform]
    identity_terms = list(dict.fromkeys(
        pcfg["identity_extra"] + sum((cfg["identity"] for cfg in LANGUAGES.values()), [])
    ))
    ranked: list[tuple[int, str]] = []
    seen: set[str] = set()

    for href, label in page.get("links", []):
        absolute = sanitize_request_url(urljoin(final_url, href))
        if not absolute:
            continue
        parsed = urlparse(absolute)
        if parsed.hostname != final_host:
            continue
        if absolute in seen:
            continue
        seen.add(absolute)
        combined = fold(f"{href} {label} {parsed.path}")
        if any(marker in parsed.path.lower() for marker in BAD_PATH_MARKERS):
            continue

        route_score = 0
        if path_looks_like_service(parsed.path.lower()):
            route_score += 5
        if any(term_present(term, combined) for term in STRONG_SERVICE_TERMS):
            route_score += 4
        if any(term_present(term, combined) for term in identity_terms):
            route_score += 2
        if any(term_present(term, combined) for term in ("search", "browse", "explore", "view", "open")):
            route_score += 2
        if parsed.query:
            route_score += 1
        if route_score > 0:
            ranked.append((route_score, absolute))

    ranked.sort(key=lambda item: (-item[0], item[1]))
    return [url for _, url in ranked[:MAX_INTERNAL_SERVICE_LINKS]]


def search_result_has_strong_service_evidence(hit: SearchHit) -> bool:
    """Return True when at least one search snippet clearly matches platform + service."""
    for evidence in hit.search_evidence:
        if not isinstance(evidence, str):
            continue
        ev = fold(evidence)
        if hit.platform == "twitter":
            platform_ok = any(
                term_present(term, ev) for term in ("twitter", "tweet", "nitter")
            )
        elif hit.platform == "reddit":
            platform_ok = any(
                term_present(term, ev)
                for term in ("reddit", "subreddit", "redlib", "libreddit", "teddit")
            )
        else:
            platform_ok = any(
                term_present(term, ev) for term in ("tumblr", "priviblur", "blog")
            )

        service_ok = any(
            term_present(term, ev)
            for term in (
                "viewer", "frontend", "alternative frontend", "browser",
                "slideshow", "reader", "gallery", "content browser",
                "web client", "visor", "visualizador", "visionneuse",
                "betrachter", "ビューア", "просмотрщик", "查看器", "뷰어",
                "व्यूअर", "عارض", "visualizzatore",
            )
        )
        if platform_ok and service_ok:
            return True
    return False


def query_has_service_intent(platform: str, query: str) -> bool:
    """Return True when the query itself expresses platform + service intent."""
    if query.startswith(("SOURCE:", "SEED:")):
        return False
    q = fold(query)

    if platform == "twitter":
        platform_ok = any(term_present(t, q) for t in ("twitter", "tweet", "nitter", "x"))
    elif platform == "reddit":
        platform_ok = any(
            term_present(t, q)
            for t in ("reddit", "subreddit", "redlib", "libreddit", "teddit")
        )
    else:
        platform_ok = any(term_present(t, q) for t in ("tumblr", "priviblur"))

    if not platform_ok:
        return False

    service_terms = tuple(dict.fromkeys(
        (
            "viewer", "frontend", "front-end", "browser", "slideshow", "gallery", "reader",
            "anonymous", "content browser", "web client", "private frontend",
            "private front-end", "visor", "visualizador",
        )
        + tuple(
            term
            for cfg in LANGUAGES.values()
            for term in cfg["service"]
        )
    ))
    return any(term_present(term, q) for term in service_terms)


def search_query_intent_hits(hit: SearchHit) -> int:
    return sum(
        1 for query in hit.queries
        if query_has_service_intent(hit.platform, query)
    )


def discovery_score(hit: SearchHit) -> int:
    """Rank candidates using independent discovery evidence before page validation."""
    score = 0
    direct_trusted = bool(set(hit.sources) & DIRECT_TRUSTED_SOURCES)
    score += 6 if direct_trusted else 0
    score += min(8, 3 * len(hit.sources))
    score += min(6, 2 * len(hit.providers))
    score += min(8, 2 * search_query_intent_hits(hit))
    score += min(6, 2 * len({
        q for q in hit.queries
        if not q.startswith("SOURCE:") and not q.startswith("SEED:")
    }))
    score += 4 if search_result_has_strong_service_evidence(hit) else 0
    score += 3 if SEARCH_SERVICE_HOST_RE.search(hit.domain) else 0
    score += 2 if any(
        path_looks_like_service(urlparse(url).path.lower())
        for url in hit.urls
    ) else 0
    score += 2 if any(
        term_present(term, " ".join(hit.search_evidence))
        for term in PLATFORMS[hit.platform]["brands"]
    ) else 0
    return score


def pending_candidate_has_strong_signal(hit: SearchHit) -> bool:
    """Keep only candidates with independent service evidence worth retrying."""
    if is_seed_candidate(hit):
        return True
    source_names = {source for source in hit.sources if isinstance(source, str)}
    if source_names & DIRECT_TRUSTED_SOURCES:
        return True
    if len(source_names) >= 2:
        return True
    if SEARCH_SERVICE_HOST_RE.search(hit.domain):
        return True
    if any(
        path_looks_like_service(urlparse(url).path.lower())
        for url in hit.urls
    ):
        return True
    return search_result_has_strong_service_evidence(hit)


def fetch_error_is_permanent(error: str) -> bool:
    if not isinstance(error, str):
        return False
    return bool(re.search(
        r"HTTP Error (?:" + "|".join(str(code) for code in sorted(PERMANENT_FETCH_ERROR_CODES)) + r")\b",
        error,
        re.IGNORECASE,
    ))


def pending_next_retry_epoch(status: str, attempts: int, now_epoch: float) -> float:
    """Bound retry frequency for unavailable or challenged candidates."""
    if status == "challenge_blocked":
        return now_epoch + min(PENDING_RETRY_MAX_SECONDS, 2 * PENDING_RETRY_BASE_SECONDS)
    exponent = max(0, min(3, attempts - 1))
    return now_epoch + min(PENDING_RETRY_MAX_SECONDS, PENDING_RETRY_BASE_SECONDS * (2 ** exponent))


def classify_pending_status(evaluation: Evaluation, hit: SearchHit) -> str | None:
    """Return a retry state for strong candidates that are not yet publishable."""
    error = str(evaluation.evidence.get("fetch_error", "") or "")
    if fetch_error_is_permanent(error):
        return "permanent_4xx"
    if "challenge/parked page detected" in evaluation.reason:
        return "challenge_blocked"
    if evaluation.reason == "page unavailable":
        status_code = evaluation.evidence.get("status_code")
        if status_code == 429:
            return "rate_limited"
        if status_code == 403:
            return "forbidden"
        if isinstance(status_code, int) and 500 <= status_code <= 599:
            return "server_error"
        lowered = error.casefold()
        if "429" in lowered or "rate limit" in lowered:
            return "rate_limited"
        if "timeout" in lowered or "timed out" in lowered:
            return "timeout"
        if re.search(r"HTTP Error 5\d\d", error, re.IGNORECASE):
            return "server_error"
        return "temporary_unavailable"
    if (
        discovery_score(hit) >= NEAR_MISS_DISCOVERY_SCORE
        and evaluation.reason not in {
            "already covered by blocklist.txt",
            "redirected outside candidate host",
            "service URL resolved to an article/news page",
            "content/publishing host, not a service host",
            "article/content page, not a frontend endpoint",
            "non-frontend service/tool page",
        }
    ):
        return "search_strong_but_page_unverified"
    return None


def evaluate_candidate(hit: SearchHit, existing: set[str]) -> Evaluation:
    seed_candidate = is_seed_candidate(hit)
    strong_search_evidence_hint = search_result_has_strong_service_evidence(hit)
    if hit.domain in existing and not seed_candidate:
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), hit.urls[0],
            {"already_covered": True}, "already covered by blocklist.txt"
        )

    direct_trusted = bool(set(hit.sources) & DIRECT_TRUSTED_SOURCES)

    # Prefer service-like URLs, but do not throw away a real service just
    # because search ranked an article or guide page first.
    ranked_urls = sorted(
        hit.urls,
        key=lambda url: (
            any(marker in urlparse(url).path.lower() for marker in BAD_PATH_MARKERS),
            not path_looks_like_service(urlparse(url).path.lower()),
            -sum(marker in urlparse(url).path.lower() for marker in (
                "viewer", "frontend", "profile", "subreddit", "tweet",
                "status", "search", "view", "tool", "tools"
            )),
            url,
        ),
    )
    candidate_urls = []
    seen_urls: set[str] = set()
    for url in ranked_urls:
        if url in seen_urls:
            continue
        seen_urls.add(url)
        candidate_urls.append(url)

    # Always give the site root a validation slot. This prevents a search
    # snippet/article from becoming the canonical page when the real service
    # lives on the homepage or a dedicated viewer route.
    root_url = f"https://{hit.domain}/"
    candidate_urls = [url for url in candidate_urls if url != root_url]
    candidate_urls.insert(1, root_url)
    candidate_urls = candidate_urls[:5]

    first_url = candidate_urls[0]
    html_text = None
    fetch_meta: dict = {"error": "fetch failed"}
    via = "direct"

    for candidate_url in candidate_urls[:4]:
        candidate_html, candidate_meta = fetch_html(candidate_url)
        if candidate_html is None:
            continue
        candidate_final = candidate_meta.get("final_url") or candidate_url
        candidate_final_host = normalize_host(candidate_final)
        candidate_base = hit.domain[4:] if hit.domain.startswith("www.") else hit.domain
        candidate_final_base = (
            candidate_final_host[4:]
            if candidate_final_host and candidate_final_host.startswith("www.")
            else candidate_final_host
        )
        if candidate_final_base != candidate_base:
            continue
        final_path = urlparse(candidate_final).path.lower()
        if any(marker in final_path for marker in BAD_PATH_MARKERS):
            continue
        first_url = candidate_url
        html_text = candidate_html
        fetch_meta = candidate_meta
        break

    # Some legitimate viewers are JS-heavy or block GitHub Actions' direct
    # HTTP fetch. Use Jina only for high-signal service URLs/hosts (and seeds),
    # not for arbitrary search results, to improve recall without turning
    # editorial pages into accepted domains.
    query_intent_hits = search_query_intent_hits(hit)
    distinct_service_queries = len({
        query for query in hit.queries
        if query_has_service_intent(hit.platform, query)
    })
    jina_eligible = (
        seed_candidate
        or strong_search_evidence_hint
        or bool(SEARCH_SERVICE_HOST_RE.search(hit.domain))
        or any(path_looks_like_service(urlparse(url).path.lower()) for url in candidate_urls[:3])
        or distinct_service_queries >= 2
    )
    if html_text is None and jina_eligible:
        for jina_url in candidate_urls[:4]:
            jina_path = urlparse(jina_url).path.lower()
            if any(marker in jina_path for marker in BAD_PATH_MARKERS):
                continue
            jina_text, jina_meta = fetch_jina_text(jina_url)
            if jina_text is None:
                continue

            jina_final = jina_meta.get("final_url") or jina_url
            jina_host = normalize_host(jina_final)
            jina_base = (
                jina_host[4:]
                if jina_host and jina_host.startswith("www.")
                else jina_host
            )
            candidate_base = hit.domain[4:] if hit.domain.startswith("www.") else hit.domain
            if jina_base != candidate_base:
                continue

            jina_final_path = urlparse(jina_final).path.lower()
            if any(marker in jina_final_path for marker in BAD_PATH_MARKERS):
                continue

            first_url = jina_url
            html_text = jina_text
            fetch_meta = {**jina_meta, "via": "jina"}
            via = "jina"
            break

    if html_text is None:
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), first_url,
            {
                "trusted_sources": hit.sources,
                "search_providers": hit.providers,
                "fetch_error": fetch_meta.get("error", "fetch failed"),
                "status_code": fetch_meta.get("status_code"),
            },
            "page unavailable"
        )

    final_url = fetch_meta.get("final_url") or first_url
    final_host = normalize_host(final_url)
    candidate_base = hit.domain[4:] if hit.domain.startswith("www.") else hit.domain
    final_base = final_host[4:] if final_host and final_host.startswith("www.") else final_host
    if final_host is None or final_base != candidate_base:
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {"redirect_host": final_host}, "redirected outside candidate host"
        )

    first_path = urlparse(first_url).path.lower()
    final_path = urlparse(final_url).path.lower()
    if any(marker in final_path for marker in BAD_PATH_MARKERS):
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {}, "service URL resolved to an article/news page"
        )

    if fetch_meta.get("via") == "jina" or via == "jina":
        first = page_evidence_from_text(final_url, html_text)
        runtime = {
            "script_sources": [],
            "manifest_urls": [],
            "framework_hits": [],
            "platform_hits": [],
            "service_hits": [],
            "service_runtime_hint": False,
        }
    else:
        first = page_evidence(final_url, html_text)
        runtime = runtime_signals_from_html(html_text, hit.platform)

    all_pages = [first]

    # Follow a small, scored set of same-origin routes to discover service
    # endpoints exposed from a landing page.
    if via == "direct":
        seen = {final_url}
        for extra_url in service_route_candidates(final_url, first, hit.platform):
            if extra_url in seen:
                continue
            seen.add(extra_url)
            extra_html, extra_meta = fetch_html(extra_url)
            extra_final = extra_meta.get("final_url", "") if extra_html is not None else ""
            if extra_html is None or normalize_host(extra_final) != hit.domain:
                continue
            if any(marker in urlparse(extra_final).path.lower() for marker in BAD_PATH_MARKERS):
                continue
            all_pages.append(page_evidence(extra_final, extra_html))
            if len(all_pages) - 1 >= MAX_INTERNAL_SERVICE_LINKS:
                break

    pcfg = PLATFORMS[hit.platform]
    title = fold(" ".join(p["title"] for p in all_pages))
    headings = fold(" ".join(p["headings"] for p in all_pages))
    meta = fold(" ".join(p["meta"] for p in all_pages))
    body = fold(" ".join(p["body"] for p in all_pages))
    links = fold(" ".join(p["link_text"] for p in all_pages))
    url_text = fold(final_url)
    runtime_text = fold(" ".join(
        runtime["script_sources"]
        + runtime["manifest_urls"]
        + runtime["framework_hits"]
        + runtime["platform_hits"]
        + runtime["service_hits"]
    ))
    total = fold(" ".join([title, headings, meta, body, links, url_text, runtime_text]))
    header_text = fold(" ".join([title, headings, meta]))

    if any(marker in total[:12000] for marker in CHALLENGE_MARKERS):
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {}, "challenge/parked page detected"
        )

    content_host = (
        hit.domain.endswith(CONTENT_HOST_SUFFIXES)
        or hit.domain in EDITORIAL_HOSTS
        or hit.domain in {
            "alternativeto.net", "www.alternativeto.net",
            "beebom.com", "www.beebom.com",
            "makeuseof.com", "www.makeuseof.com",
            "dev.to", "www.dev.to",
            "dev.co", "www.dev.co",
            "libhunt.com", "www.libhunt.com",
            "producthunt.com", "www.producthunt.com",
            "pcmag.com", "www.pcmag.com",
            "ghacks.net", "www.ghacks.net",
            "wired.com", "www.wired.com",
            "analyticsinsight.net", "www.analyticsinsight.net",
            "rankred.com", "www.rankred.com",
            "softwaretestinghelp.com", "www.softwaretestinghelp.com",
            "wbcomdesigns.com", "www.wbcomdesigns.com",
            "journaldufreenaute.fr", "www.journaldufreenaute.fr",
            "begindot.com", "www.begindot.com",
            "techbii.com", "www.techbii.com",
            "techtactician.com", "www.techtactician.com",
            "tuffermagazine.com", "www.tuffermagazine.com",
            "hitpaw.com", "www.hitpaw.com",
            "volumn.ai", "www.volumn.ai",
        }
    )
    if content_host:
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {"content_host": True}, "content/publishing host, not a service host"
        )

    content_path_hint = any(marker in final_path for marker in BAD_PATH_MARKERS)
    content_title_hits = [
        marker for marker in CONTENT_TITLE_MARKERS
        if term_present(marker, header_text)
    ]
    service_path_hint = path_looks_like_service(final_path)
    host_service_hint = bool(SEARCH_SERVICE_HOST_RE.search(hit.domain))
    header_service_identity_hint = bool(
        any(term_present(term, header_text) for term in STRONG_SERVICE_TERMS)
    )
    article_structure_hint = any(
        p.get("article_count", 0) >= 1 for p in all_pages
    )
    def twitter_x_context_ok(text: str) -> bool:
        if hit.platform != "twitter" or not term_present("x", text):
            return False
        return bool(
            re.search(
                r"(?<![\w-])x\s+(?:viewer|browser|frontend|profile|profiles|post|posts|"
                r"tweet|tweets|timeline|reader)(?![\w-])",
                text,
                re.IGNORECASE,
            )
            or any(term_present(other, text) for other in ("twitter", "tweet", "nitter"))
        )

    platform_hits = [
        t for t in pcfg["platform_terms"]
        if term_present(t, total)
        and (hit.platform != "twitter" or t != "x" or twitter_x_context_ok(total))
    ]
    brand_hits = [t for t in pcfg["brands"] if term_present(t, total)]
    header_platform_hits = [
        t for t in pcfg["platform_terms"]
        if term_present(t, header_text)
        and (hit.platform != "twitter" or t != "x" or twitter_x_context_ok(header_text))
    ]
    header_brand_hits = [t for t in pcfg["brands"] if term_present(t, header_text)]

    identity_terms = list(dict.fromkeys(
        pcfg["identity_extra"] + sum((cfg["identity"] for cfg in LANGUAGES.values()), [])
    ))
    service_terms = list(dict.fromkeys(
        sum((cfg["service"] for cfg in LANGUAGES.values()), [])
        + ["browser", "slideshow", "reader", "gallery", "content browser"]
    ))
    identity_hits = [t for t in identity_terms if term_present(t, total)]
    service_hits = [t for t in service_terms if term_present(t, total)]
    header_identity_hits = [t for t in identity_terms if term_present(t, header_text)]
    header_service_hits = [t for t in service_terms if term_present(t, header_text)]
    body_identity_hits = [t for t in identity_terms if term_present(t, body[:20000])]
    body_service_hits = [t for t in STRONG_SERVICE_TERMS if term_present(t, body[:20000])]
    strong_service_terms = STRONG_SERVICE_TERMS
    strong_header_service_hits = [
        t for t in strong_service_terms if term_present(t, header_text)
    ]
    non_frontend_service_hits = [
        t for t in NON_FRONTEND_SERVICE_TERMS if term_present(t, header_text)
    ]
    runtime_platform_hits = list(runtime["platform_hits"])
    runtime_service_hits = list(runtime["service_hits"])
    runtime_service_hint = bool(runtime.get("service_runtime_hint"))

    input_count = sum(p["inputs"] for p in all_pages)
    form_count = sum(p["forms"] for p in all_pages)
    button_count = sum(p["buttons"] for p in all_pages)
    control_text = fold(" ".join(p.get("controls", "") for p in all_pages))
    interactive_terms = (
        "username", "user", "profile", "handle", "tweet", "post",
        "subreddit", "blog", "tumblr", "twitter", "reddit", "search url",
        "enter url", "paste url", "paste", "account", "view",
    )
    interactive_target_hits = [
        term for term in interactive_terms if term_present(term, control_text)
    ]
    ui_signal = bool(
        host_service_hint
        or (service_path_hint and (input_count or button_count))
        or interactive_target_hits
        or (header_service_hits and input_count)
    )

    editorial_marker_hits = [
        marker for marker in EDITORIAL_PAGE_MARKERS
        if term_present(marker, header_text)
    ]

    frontend_signal_hint = bool(
        strong_header_service_hits
        or service_path_hint
        or host_service_hint
        or brand_hits
        or runtime_service_hint
    )
    non_frontend_only = bool(
        non_frontend_service_hits
        and not frontend_signal_hint
    )
    if non_frontend_only:
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {
                "non_frontend_service_hits": non_frontend_service_hits,
                "frontend_signal_hint": frontend_signal_hint,
                "header_service_hits": strong_header_service_hits,
                "service_path_hint": service_path_hint,
                "host_service_hint": host_service_hint,
            },
            "non-frontend service/tool page"
        )

    article_like = bool(
        content_path_hint
        or (
            content_title_hits
            and not service_path_hint
            and not host_service_hint
            and not header_service_identity_hint
        )
        or (
            article_structure_hint
            and not (
                ui_signal
                or service_path_hint
                or host_service_hint
                or header_service_identity_hint
                or (header_platform_hits and header_service_hits)
            )
        )
        or (
            len(editorial_marker_hits) >= 2
            and not (
                ui_signal
                or service_path_hint
                or host_service_hint
                or header_service_identity_hint
            )
        )
    )
    if article_like:
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {
                "content_path_hint": content_path_hint,
                "content_title_hits": content_title_hits,
                "editorial_marker_hits": editorial_marker_hits,
                "service_path_hint": service_path_hint,
                "host_service_hint": host_service_hint,
                "article_structure_hint": article_structure_hint,
            },
            "article/content page, not a frontend endpoint"
        )

    action_hits = [t for t in (
        "paste", "enter", "search", "browse", "view", "open", "load",
        "pegar", "buscar", "ver", "ouvrir", "suchen", "просмотр",
        "ビュー", "보기",
    ) if term_present(t, total)]

    # A search hit only counts as discovery evidence when the result itself
    # mentions both the target platform and a service concept.
    search_intent_hits = 0
    search_provider_hits: set[str] = set()
    query_intent_hits = search_query_intent_hits(hit)
    for evidence in hit.search_evidence:
        if not isinstance(evidence, str):
            continue
        ev = fold(evidence)
        if hit.platform == "twitter":
            platform_ok = any(
                term_present(t, ev) for t in ("twitter", "tweet", "nitter")
            ) or (
                term_present("x", ev)
                and any(term_present(t, ev) for t in ("twitter", "tweet", "nitter"))
            )
        elif hit.platform == "reddit":
            platform_ok = any(
                term_present(t, ev)
                for t in ("reddit", "subreddit", "redlib", "libreddit", "teddit")
            )
        else:
            platform_ok = any(
                term_present(t, ev) for t in ("tumblr", "priviblur", "blog")
            )
        localized_strong_services = {
            "viewer", "frontend", "alternative frontend", "browser", "slideshow",
            "reader", "gallery", "content browser", "web client",
            "visor", "visualizador", "visionneuse", "betrachter",
            "ビューア", "просмотрщик", "查看器", "뷰어", "व्यूअर", "عارض",
            "visualizzatore", "visualizador",
        }
        service_ok = any(term_present(t, ev) for t in localized_strong_services)
        if platform_ok and service_ok:
            search_intent_hits += 1
            if ":" in evidence:
                search_provider_hits.add(evidence.split(":", 1)[0])

    distinct_queries = len({
        q for q in hit.queries
        if not q.startswith("SOURCE:") and not q.startswith("SEED:")
    })
    search_confirmed = (
        len(search_provider_hits) >= 2
        or distinct_queries >= 2
        or seed_candidate
    )

    # Strong service identity from the hostname is useful, but not enough
    # without page-level evidence.
    page_platform_ok = bool(
        header_platform_hits
        or runtime_platform_hits
        or (
            platform_hits
            and (
                header_service_hits
                or strong_header_service_hits
                or service_path_hint
                or host_service_hint
                or ui_signal
            )
        )
        or seed_candidate and platform_hits
    )
    page_service_ok = bool(
        strong_header_service_hits
        or runtime_service_hint
        or brand_hits
        or service_path_hint
        or host_service_hint
        or (ui_signal and body_service_hits)
        or seed_candidate and any(term_present(t, body[:7000]) for t in strong_service_terms)
    )
    page_identity_ok = bool(
        header_identity_hits
        or (
            body_identity_hits
            and (ui_signal or service_path_hint or host_service_hint)
        )
    )

    # Many modern viewers are client-rendered and expose little/no form/button
    # markup to a plain HTML fetch. Header-level service identity is therefore
    # accepted when the page itself clearly names the platform and service.
    header_service_identity = bool(
        page_platform_ok
        and strong_header_service_hits
        and header_identity_hits
    )
    strong_service_page = bool(
        page_platform_ok
        and page_service_ok
        and page_identity_ok
        and (
            ui_signal
            or service_path_hint
            or host_service_hint
            or header_service_identity
        )
    )

    # Seeds: published only after page validation, with Jina as a fallback when
    # the origin blocks GitHub Actions.
    seed_accept = (
        seed_candidate
        and strong_service_page
        and bool(platform_hits and service_hits)
    )

    # Search candidates: require actual search-intent evidence plus an
    # independent signal from the hostname, service route, or repeated
    # discovery. A single generic article result is not enough.
    search_signal_hits = search_intent_hits + query_intent_hits
    strong_search_evidence = (
        search_signal_hits >= 1
        and (
            host_service_hint
            or service_path_hint
            or distinct_queries >= 2
        )
    )
    # A dedicated viewer/frontend route can be sufficient on its own when the
    # page is independently validated as a service. This avoids a false
    # negative when search engines surface /twitter-viewer or /reddit-viewer
    # only once.
    single_query_service_ok = bool(
        (search_intent_hits >= 1 or query_intent_hits >= 1)
        and service_path_hint
        and page_service_ok
        and page_identity_ok
        and ui_signal
        and not article_structure_hint
    )
    # Some real frontends are JS-heavy and expose no forms/buttons in a plain
    # HTML fetch. When search results repeatedly identify the platform/service
    # and the page header itself confirms platform + service + identity, accept
    # it without requiring interactive markup. Editorial pages remain blocked
    # by content path/title/structure checks above.
    header_verified_search_service_ok = bool(
        distinct_queries >= 1
        and (query_intent_hits >= 1 or search_intent_hits >= 1)
        and header_platform_hits
        and strong_header_service_hits
        and header_identity_hits
        and not content_path_hint
        and not content_title_hits
        and not article_structure_hint
    )
    search_quality_ok = (
        strong_search_evidence
        or bool(brand_hits)
        or single_query_service_ok
        or header_verified_search_service_ok
    )
    search_interactive_ok = bool(
        host_service_hint
        or (service_path_hint and (input_count or button_count))
        or interactive_target_hits
        or header_verified_search_service_ok
    )
    independent_query_ok = (
        distinct_queries >= 2
        or host_service_hint
        or single_query_service_ok
        or header_verified_search_service_ok
    )
    query_service_ok = bool(
        search_intent_hits >= 1
        or header_verified_search_service_ok
        or (
            query_intent_hits >= 1
            and (
                service_path_hint
                or host_service_hint
                or (
                    query_intent_hits >= 2
                    and ui_signal
                    and not article_structure_hint
                )
            )
        )
    )
    search_accept = (
        not seed_candidate
        and strong_service_page
        and query_service_ok
        and search_quality_ok
        and search_interactive_ok
        and independent_query_ok
    )

    trusted_accept = (
        direct_trusted
        and strong_service_page
        and (ui_signal or service_path_hint or host_service_hint)
        and bool(platform_hits)
        and bool(header_platform_hits or brand_hits)
    )

    source_accept = bool(
        hit.sources
        and strong_service_page
        and (ui_signal or service_path_hint or host_service_hint)
        and bool(platform_hits)
        and bool(header_platform_hits or brand_hits)
    )
    accepted = bool(seed_accept or search_accept or trusted_accept or source_accept)

    score = 0
    score += 6 if header_brand_hits else 0
    score += 4 if header_platform_hits else 0
    score += 4 if header_service_hits else 0
    score += 3 if header_identity_hits else 0
    score += 3 if ui_signal else 0
    score += min(5, 2 * len(search_provider_hits))
    score += min(4, distinct_queries)
    score += 2 if single_query_service_ok else 0
    score += 2 if header_verified_search_service_ok else 0
    score += 2 if len(hit.sources) >= 2 else (1 if hit.sources else 0)
    if host_service_hint:
        score += 2
    if via == "jina":
        score += 1

    positive_frontend_signals = (
        len(strong_header_service_hits)
        + len(runtime_service_hits)
        + int(service_path_hint)
        + int(host_service_hint)
        + int(ui_signal)
        + int(bool(brand_hits))
    )
    tool_signal_hits = [
        t for t in NON_FRONTEND_SERVICE_TERMS if term_present(t, total[:20000])
    ]
    editorial_signal_count = len(editorial_marker_hits) + len(content_title_hits)
    score += min(6, 2 * positive_frontend_signals)
    score += min(3, len(runtime["framework_hits"]))
    score -= min(6, 2 * len(tool_signal_hits)) if tool_signal_hits and not frontend_signal_hint else 0
    score -= min(6, editorial_signal_count) if editorial_signal_count and not frontend_signal_hint else 0

    evidence = {
        "platform_hits": platform_hits,
        "twitter_x_context_ok": twitter_x_context_ok(total),
        "brand_hits": brand_hits,
        "header_platform_hits": header_platform_hits,
        "header_brand_hits": header_brand_hits,
        "header_service_hits": header_service_hits,
        "header_identity_hits": header_identity_hits,
        "body_service_hits": body_service_hits,
        "body_identity_hits": body_identity_hits,
        "service_hits": service_hits,
        "identity_hits": identity_hits,
        "ui_signal": ui_signal,
        "inputs": input_count,
        "forms": form_count,
        "buttons": button_count,
        "article_count": sum(p.get("article_count", 0) for p in all_pages),
        "article_structure_hint": article_structure_hint,
        "interactive_target_hits": interactive_target_hits,
        "service_path_hint": service_path_hint,
        "host_service_hint": host_service_hint,
        "content_path_hint": content_path_hint,
        "content_title_hits": content_title_hits,
        "editorial_marker_hits": editorial_marker_hits,
        "non_frontend_service_hits": non_frontend_service_hits,
        "service_kind": (
            "viewer/frontend+tool"
            if non_frontend_service_hits and frontend_signal_hint
            else "viewer/frontend"
            if frontend_signal_hint
            else "unknown"
        ),
        "header_service_identity_hint": header_service_identity_hint,
        "single_query_service_ok": single_query_service_ok,
        "header_verified_search_service_ok": header_verified_search_service_ok,
        "search_intent_hits": search_intent_hits,
        "query_intent_hits": query_intent_hits,
        "search_signal_hits": search_intent_hits + query_intent_hits,
        "strong_search_evidence_hint": strong_search_evidence_hint,
        "search_provider_hits": sorted(search_provider_hits),
        "distinct_queries": distinct_queries,
        "search_providers": hit.providers,
        "search_evidence": hit.search_evidence[:12],
        "trusted_sources": hit.sources,
        "fetch_via": via,
        "fetch_status_code": fetch_meta.get("status_code"),
        "runtime_platform_hits": runtime_platform_hits,
        "runtime_service_hits": runtime_service_hits,
        "runtime_framework_hits": runtime["framework_hits"],
        "runtime_service_hint": runtime_service_hint,
        "positive_frontend_signals": positive_frontend_signals,
        "tool_signal_hits": tool_signal_hits,
        "editorial_signal_count": editorial_signal_count,
        "internal_routes_checked": len(all_pages) - 1,
        "query_urls": hit.urls[:10],
    }

    return Evaluation(
        hit.domain,
        hit.platform,
        accepted,
        score,
        distinct_queries,
        final_url,
        evidence,
        f"platform={'/'.join(header_platform_hits or platform_hits) or '-'}; "
        f"service={'/'.join(header_service_hits or service_hits) or '-'}; "
        f"identity={'/'.join(header_identity_hits or identity_hits) or '-'}; "
        f"search_intent={search_intent_hits}; providers={len(search_provider_hits)}; "
        f"queries={distinct_queries}",
    )


def safe_evaluate_candidate(hit: SearchHit, existing: set[str]) -> Evaluation:
    try:
        return evaluate_candidate(hit, existing)
    except Exception as exc:
        return Evaluation(
            hit.domain,
            hit.platform,
            False,
            0,
            len(hit.queries),
            hit.urls[0] if hit.urls else "",
            {},
            "candidate validation crashed safely",
            f"{type(exc).__name__}: {exc}",
        )

def main() -> int:
    existing = read_existing_domains()
    historical = read_discovered_domains()
    known_domains = existing | historical
    query_specs = build_queries()

    candidate_map: dict[tuple[str, str], SearchHit] = {}
    search_errors: list[dict] = []
    search_results_seen = 0
    search_pages_succeeded = 0
    search_queries_with_results = 0
    search_fallbacks = 0

    seeds = seed_candidates()
    candidate_map.update(seeds)

    trusted = trusted_candidates()
    for key, hit in trusted.items():
        if key not in candidate_map:
            candidate_map[key] = hit
        else:
            current = candidate_map[key]
            for source in hit.sources:
                if source not in current.sources:
                    current.sources.append(source)
            for query in hit.queries:
                if query not in current.queries:
                    current.queries.append(query)
            for url in hit.urls:
                if url not in current.urls:
                    current.urls.append(url)

    github_sources = github_repository_candidates()
    if DISCOVERY_MODE in {"deep", "all"}:
        gitlab_sources = gitlab_repository_candidates()
        codeberg_sources = codeberg_repository_candidates()
        common_crawl_sources = common_crawl_candidates()
        urlscan_sources = urlscan_candidates()
    else:
        gitlab_sources = {}
        codeberg_sources = {}
        common_crawl_sources = {}
        urlscan_sources = {}

    source_maps = (
        github_sources,
        gitlab_sources,
        codeberg_sources,
        common_crawl_sources,
        urlscan_sources,
    )
    pending_entries = read_pending_verification()
    pending_hits = pending_hits_from_report(pending_entries)
    for source_map in source_maps:
        for key, hit in source_map.items():
            if key not in candidate_map:
                candidate_map[key] = hit
            else:
                current = candidate_map[key]
                for source in hit.sources:
                    if source not in current.sources:
                        current.sources.append(source)
                for query in hit.queries:
                    if query not in current.queries:
                        current.queries.append(query)
                for url in hit.urls:
                    if url not in current.urls:
                        current.urls.append(url)

    for key, hit in pending_hits.items():
        if key not in candidate_map:
            candidate_map[key] = hit
        else:
            current = candidate_map[key]
            current.queries.extend(q for q in hit.queries if q not in current.queries)
            current.urls.extend(u for u in hit.urls if u not in current.urls)
            current.providers.extend(p for p in hit.providers if p not in current.providers)
            current.search_evidence.extend(
                e for e in hit.search_evidence if e not in current.search_evidence
            )

    seed_candidate_count = len(seeds)
    verified_seed_domains = sorted(seeds)
    trusted_candidate_count = len(trusted)
    github_candidate_count = len(github_sources)

    print(f"Verified web seeds: {seed_candidate_count}")
    print(f"Trusted-source candidates: {trusted_candidate_count}")
    trusted_source_names = sorted({
        source
        for hit in trusted.values()
        for source in hit.sources
    })
    print(f"GitHub-discovered candidates: {github_candidate_count}")

    if DISCOVERY_MODE != "deep":
        with concurrent.futures.ThreadPoolExecutor(max_workers=SEARCH_WORKERS) as executor:
            futures = [
                executor.submit(run_search_spec, index, lang, platform, query)
                for index, (lang, platform, query) in enumerate(query_specs, start=1)
            ]
            for future in concurrent.futures.as_completed(futures):
                (
                    index,
                    lang,
                    platform,
                    query,
                    results_by_page,
                    errors,
                    fallback_count,
                ) = future.result()
                search_fallbacks += fallback_count
                if results_by_page:
                    search_queries_with_results += 1
                for page, backend, results in results_by_page:
                    search_pages_succeeded += 1
                    search_results_seen += len(results)
                    for result in results:
                        merge_search_result(candidate_map, platform, query, backend, result)
                    print(
                        f"[SEARCH {index}/{len(query_specs)}] {lang}/{platform}: {query} "
                        f"backend={backend} page={page} results={len(results)}"
                    )
                for error in errors:
                    search_errors.append(error)
                    print(
                        f"[WARN] search page failed after fallback "
                        f"{lang}/{platform} page={error['page']}: {error['error']}"
                    )

    # Prioritise maintained registries and GitHub-discovered instances so the
    # validation cap cannot crowd them out with noisy search-engine results.
    seed_keys = set(seeds)
    priority_hits = sorted(
        [
            h for h in candidate_map.values()
            if h.sources
            and h.domain not in known_domains
            and (h.platform, h.domain) not in seed_keys
        ],
        key=lambda h: (
            -discovery_score(h),
            -len(h.sources),
            -len(h.search_evidence),
            h.domain,
        ),
    )
    pending_keys = set(pending_hits)
    pending_search_hits = [
        h for h in candidate_map.values()
        if not h.sources
        and h.domain not in known_domains
        and (h.platform, h.domain) not in seed_keys
        and (h.platform, h.domain) in pending_keys
    ]
    search_hits = sorted(
        [
            h for h in candidate_map.values()
            if not h.sources
            and h.domain not in known_domains
            and (h.platform, h.domain) not in seed_keys
            and (h.platform, h.domain) not in pending_keys
        ],
        key=lambda h: (
            -discovery_score(h),
            -int(search_result_has_strong_service_evidence(h)),
            -search_query_intent_hits(h),
            -len(h.providers),
            -len([q for q in h.queries if not q.startswith("SOURCE:") and not q.startswith("SEED:")]),
            -len(h.search_evidence),
            h.domain,
        ),
    )
    # Always validate the small, curated seed set even when it is already in
    # blocklist.txt. They are not re-added; validation is for report accuracy
    # and catches stale/incorrect seed metadata without touching the list.
    seed_hits = list(seeds.values())
    remaining_capacity = max(0, MAX_CANDIDATES - len(seed_hits) - len(priority_hits))
    pending_selected = min(len(pending_search_hits), remaining_capacity)
    search_capacity = max(0, remaining_capacity - pending_selected)
    hits = (
        seed_hits
        + priority_hits
        + pending_search_hits[:pending_selected]
        + search_hits[:search_capacity]
    )

    already_known_candidates = sum(
        1 for h in candidate_map.values() if h.domain in known_domains
    )
    candidate_domains = {h.domain for h in candidate_map.values()}

    print(f"Candidates discovered: {len(candidate_map)}")
    print(f"Candidates selected for validation: {len(hits)}")
    print(f"Previously known candidates skipped: {already_known_candidates}")
    print(f"Pending verification candidates rechecked: {len(pending_search_hits)}")
    expected_search_pages = sum(len(search_pages_for(lang, query)) for lang, _, query in query_specs)
    print(f"Search mode: {DISCOVERY_MODE}; active languages: {', '.join(active_search_languages()) or 'none'}")
    print(f"Search pages succeeded: {search_pages_succeeded}/{expected_search_pages}")
    print(f"Search queries with at least one page: {search_queries_with_results}/{len(query_specs)}")
    print(f"Search queries without any page: {len(query_specs) - search_queries_with_results}")
    print(f"Search results seen: {search_results_seen}")
    print(f"Search pages with fallback recovery: {search_fallbacks}")
    print(f"Search pages with no backend result: {len(search_errors)}")

    evaluations: list[Evaluation] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = [executor.submit(safe_evaluate_candidate, hit, existing) for hit in hits]
        for completed in concurrent.futures.as_completed(futures):
            evaluations.append(completed.result())
            time.sleep(VALIDATION_DELAY)

    evaluation_hit_map = {(hit.platform, hit.domain): hit for hit in hits}
    for evaluation in evaluations:
        source_hit = evaluation_hit_map.get((evaluation.platform, evaluation.domain))
        if source_hit is not None:
            evaluation.evidence["discovery_score"] = discovery_score(source_hit)

    evaluations.sort(
        key=lambda e: (
            -e.accepted,
            -int(e.evidence.get("discovery_score", 0)),
            -e.score,
            e.domain,
        )
    )

    seed_evaluations = {
        (e.platform, e.domain): e
        for e in evaluations
        if (e.platform, e.domain) in seed_keys
    }
    seed_report = []
    for platform, domain in verified_seed_domains:
        evaluation = seed_evaluations.get((platform, domain))
        seed_report.append({
            "platform": platform,
            "domain": domain,
            "known": domain in known_domains,
            "in_blocklist": domain in existing,
            "in_discovery_history": domain in historical,
            "verified_seed": True,
            "validation_accepted": bool(evaluation and evaluation.accepted),
            "validation_reason": evaluation.reason if evaluation else "not validated",
        })

    accepted_by_domain: dict[str, Evaluation] = {}
    for evaluation in evaluations:
        if (
            evaluation.accepted
            and evaluation.domain not in existing
            and evaluation.domain not in historical
        ):
            current = accepted_by_domain.get(evaluation.domain)
            if current is None or evaluation.score > current.score:
                accepted_by_domain[evaluation.domain] = evaluation

    accepted = sorted(
        accepted_by_domain.values(),
        key=lambda e: (-e.score, e.domain),
    )

    evaluation_hits = {(hit.platform, hit.domain): hit for hit in hits}
    pending_state = {
        (item["platform"], item["domain"]): item
        for item in pending_entries
        if (item["platform"], item["domain"]) in pending_hits
    }
    now_epoch = time.time()
    now_iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    for evaluation in evaluations:
        key = (evaluation.platform, evaluation.domain)
        source_hit = evaluation_hits.get(key)

        if evaluation.accepted or evaluation.domain in known_domains:
            pending_state.pop(key, None)
            continue

        if source_hit is None:
            continue

        status = classify_pending_status(evaluation, source_hit)
        meaningful_signal = pending_candidate_has_strong_signal(source_hit)
        if status == "permanent_4xx" or not meaningful_signal:
            pending_state.pop(key, None)
            continue
        if status is None:
            pending_state.pop(key, None)
            continue

        previous = pending_state.get(key, {})
        pending_state[key] = {
            "domain": evaluation.domain,
            "platform": evaluation.platform,
            "queries": source_hit.queries[:12],
            "urls": source_hit.urls[:12],
            "sources": source_hit.sources[:8],
            "providers": source_hit.providers[:8],
            "search_evidence": source_hit.search_evidence[:12],
            "first_seen": previous.get("first_seen") or now_iso,
            "last_attempt": now_iso,
            "last_attempt_epoch": now_epoch,
            "attempts": safe_nonnegative_int(previous.get("attempts", 0)) + 1,
            "status": status,
            "last_reason": evaluation.reason,
            "discovery_score": discovery_score(source_hit),
            "next_retry_epoch": pending_next_retry_epoch(
                status,
                safe_nonnegative_int(previous.get("attempts", 0)) + 1,
                now_epoch,
            ),
        }

    pending_verification = sorted(
        pending_state.values(),
        key=lambda item: (
            -len(item.get("sources", [])),
            -len(item.get("search_evidence", [])),
            -int(item.get("discovery_score", 0) or 0),
            -len(item.get("queries", [])),
            -float(item.get("last_attempt_epoch", 0) or 0),
            item.get("domain", ""),
        ),
    )[:PENDING_VERIFICATION_MAX]

    rejection_reason_counts = {}
    for evaluation in evaluations:
        if not evaluation.accepted:
            rejection_reason_counts[evaluation.reason] = rejection_reason_counts.get(evaluation.reason, 0) + 1

    definitive_rejection_reasons = {
        "already covered by blocklist.txt",
        "redirected outside candidate host",
        "service URL resolved to an article/news page",
        "content/publishing host, not a service host",
        "article/content page, not a frontend endpoint",
        "non-frontend service/tool page",
    }
    near_misses = []
    for evaluation in evaluations:
        source_hit = evaluation_hit_map.get((evaluation.platform, evaluation.domain))
        if (
            not evaluation.accepted
            and source_hit is not None
            and discovery_score(source_hit) >= NEAR_MISS_DISCOVERY_SCORE
            and evaluation.reason not in definitive_rejection_reasons
        ):
            near_misses.append({
                "domain": evaluation.domain,
                "platform": evaluation.platform,
                "discovery_score": discovery_score(source_hit),
                "validation_score": evaluation.score,
                "reason": evaluation.reason,
                "status": classify_pending_status(evaluation, source_hit),
                "evidence": evaluation.evidence,
            })
    near_misses = sorted(
        near_misses,
        key=lambda item: (-item["discovery_score"], -item["validation_score"], item["domain"]),
    )[:40]

    verified_frontend_domains = [
        {
            "platform": item["platform"],
            "domain": item["domain"],
            "kind": "verified_seed",
            "verified": True,
        }
        for item in seed_report
        if item["validation_accepted"]
    ]
    verified_frontend_domains.extend(
        {
            "platform": evaluation.platform,
            "domain": evaluation.domain,
            "kind": "newly_discovered",
            "verified": True,
        }
        for evaluation in accepted
    )

    if len(accepted) < MIN_ACCEPTED:
        print("[WARN] No sufficient validated domains were found.")
        print("The previous search-discovered-blocklist.txt is intentionally left untouched.")
        validation_crash_count = sum(
            1 for evaluation in evaluations
            if evaluation.reason == "candidate validation crashed safely"
        )
        REPORT.write_text(
            json.dumps(
                {
                    "status": "no_update",
                    "accepted": [],
                    "accepted_count": 0,
                    "trusted_candidate_count": trusted_candidate_count,
                    "trusted_source_names": trusted_source_names,
                    "verified_web_seed_count": seed_candidate_count,
                    "verified_seed_domains": seed_report,
                    "verified_frontend_count": len(verified_frontend_domains),
                    "verified_existing_seed_count": sum(1 for item in seed_report if item["validation_accepted"]),
                    "verified_existing_seeds": [
                        item["domain"] for item in seed_report if item["validation_accepted"]
                    ],
                    "verified_frontend_domains": verified_frontend_domains,
                    "newly_discovered_count": 0,
                    "github_discovered_candidate_count": github_candidate_count,
                    "search_backend": SEARCH_BACKEND,
                    "discovery_mode": DISCOVERY_MODE,
                    "active_search_languages": list(active_search_languages()),
                    "language_rotation": list(LANGUAGE_ROTATION),
                    "search_page2_rotating_language": LANGUAGE_ROTATION[
                        (int(time.time() // 86400) * 2) % len(LANGUAGE_ROTATION)
                    ],
                    "search_backends": list(SEARCH_BACKENDS),
                    "search_pages": list(SEARCH_PAGES),
                    "search_backend_disabled": False,
                    "search_pages_succeeded": search_pages_succeeded,
                    "search_queries_with_results": search_queries_with_results,
                    "search_queries_without_results": len(query_specs) - search_queries_with_results,
                    "search_backend_failures": len(search_errors),
                    "search_fallbacks": search_fallbacks,
                    "source_candidate_counts": {
                        "github": len(github_sources),
                        "gitlab": len(gitlab_sources),
                        "codeberg": len(codeberg_sources),
                        "common_crawl": len(common_crawl_sources),
                        "urlscan": len(urlscan_sources),
                    },
                    "validation_crash_count": validation_crash_count,
                    "candidates_discovered": len(candidate_map),
                    "validated_candidates": len(evaluations),
                    "pending_verification_count": len(pending_verification),
                    "pending_status_counts": {
                        status: sum(1 for item in pending_verification if item.get("status") == status)
                        for status in sorted({item.get("status", "") for item in pending_verification if item.get("status")})
                    },
                    "pending_verification": pending_verification,
                    "near_miss_count": len(near_misses),
                    "top_near_misses": near_misses[:20],
                    "retained_historical_count": len(historical),
                    "retained_total_count": len(historical),
                    "append_only": True,
                    "output_preserved": True,
                    "newly_discovered_count": 0,
                    "rejection_reason_counts": rejection_reason_counts,
                    "search_strategy": "maintained registries + curated alternative-frontends sources + GitHub + bounded rotated Bing RSS search + same-engine HTML fallback + parallel page validation",
                    "candidates": [asdict(e) for e in evaluations[:200]],
                    "search_errors": search_errors,
                    "note": "Publish guard triggered; output list was not replaced.",
                },
                ensure_ascii=False,
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
        return 0

    retained_domains = historical | {e.domain for e in accepted}
    OUTPUT.write_text(
        "# Generated from maintained frontend registries + GitHub + resilient search-engine fallback + page validation.\n"
        "# Append-only discovery history: previously accepted domains are never removed.\n"
        "# A domain is added once; later runs skip it when it is already in this file or blocklist.txt.\n"
        + "\n".join(f"||{domain}^" for domain in sorted(retained_domains))
        + "\n",
        encoding="utf-8",
    )

    report = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "append_only": True,
        "output_preserved": False,
        "newly_discovered_count": len(accepted),
        "verified_existing_seed_count": sum(1 for item in seed_report if item["validation_accepted"]),
        "verified_existing_seeds": [
            item["domain"] for item in seed_report if item["validation_accepted"]
        ],
        "rejection_reason_counts": rejection_reason_counts,
        "search_queries": len(query_specs),
        "search_backend": SEARCH_BACKEND,
        "search_backends": list(SEARCH_BACKENDS),
        "search_pages": list(SEARCH_PAGES),
        "search_backend_disabled": False,
        "search_pages_succeeded": search_pages_succeeded,
        "search_queries_with_results": search_queries_with_results,
        "search_queries_without_results": len(query_specs) - search_queries_with_results,
        "search_backend_failures": len(search_errors),
        "source_candidate_counts": {
            "github": len(github_sources),
            "gitlab": len(gitlab_sources),
            "codeberg": len(codeberg_sources),
            "common_crawl": len(common_crawl_sources),
            "urlscan": len(urlscan_sources),
        },
        "validation_crash_count": sum(
            1 for evaluation in evaluations
            if evaluation.reason == "candidate validation crashed safely"
        ),
        "verified_web_seed_count": seed_candidate_count,
        "verified_seed_domains": seed_report,
        "verified_frontend_count": len(verified_frontend_domains),
        "verified_frontend_domains": verified_frontend_domains,
        "trusted_candidate_count": trusted_candidate_count,
        "github_discovered_candidate_count": github_candidate_count,
        "search_strategy": "maintained registries + curated alternative-frontends sources + GitHub + bounded multilingual rotated search with language-aware page-2 expansion + query-level intent scoring + persistent pending verification + parallel validation",
        "trusted_source_names": trusted_source_names,
        "candidates_discovered": len(candidate_map),
        "validated_candidates": len(evaluations),
        "pending_verification_count": len(pending_verification),
        "pending_status_counts": {
            status: sum(1 for item in pending_verification if item.get("status") == status)
            for status in sorted({item.get("status", "") for item in pending_verification if item.get("status")})
        },
        "pending_verification": pending_verification,
        "near_miss_count": len(near_misses),
        "top_near_misses": near_misses[:20],
        "candidate_selection_score_top": [
            {
                "domain": hit.domain,
                "platform": hit.platform,
                "discovery_score": discovery_score(hit),
                "sources": hit.sources[:6],
                "providers": hit.providers[:6],
                "queries": hit.queries[:8],
            }
            for hit in sorted(
                (h for h in candidate_map.values() if h.domain not in known_domains),
                key=lambda h: (-discovery_score(h), h.domain),
            )[:40]
        ],
        "accepted_count": len(accepted),
        "newly_accepted_count": len(accepted),
        "retained_historical_count": len(historical),
        "retained_total_count": len(retained_domains),
        "already_covered_count": len(existing & candidate_domains),
        "already_discovered_count": len(historical & candidate_domains),
        "known_candidates_skipped_before_validation": already_known_candidates,
        "search_results_seen": search_results_seen,
        "search_errors": search_errors,
        "accepted": [asdict(e) for e in accepted],
        "rejected_sample": [
            asdict(e) for e in evaluations if not e.accepted
        ][:120],
        "rejection_reason_counts": {
            reason: sum(1 for e in evaluations if not e.accepted and e.reason == reason)
            for reason in sorted({e.reason for e in evaluations if not e.accepted})
        },
    }
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"[OK] New validated domains: {len(accepted)}")
    print(f"[OK] Retained historical domains: {len(historical)}")
    print(f"[OK] Total discovery list domains: {len(retained_domains)}")
    print(f"[OK] Search workers: {SEARCH_WORKERS}; validation workers: {WORKERS}; search backends: {' -> '.join(SEARCH_BACKENDS)}; fetch retries: {FETCH_RETRIES}")
    for e in accepted:
        print(f"[ACCEPT] {e.domain} | {e.platform} | {e.reason}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
