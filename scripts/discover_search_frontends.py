# CI trigger: keep discovery workflow immediately testable without touching stable blocklist files.
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
from urllib.parse import parse_qs, quote_plus, unquote, urljoin, urlparse
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

# Keep the daily search bounded, but let service-intent queries in every
# configured language reach the second results page.

DISCOVERY_MODE = os.environ.get("DISCOVERY_MODE", "daily").strip().lower()
if DISCOVERY_MODE not in {"daily", "deep", "all"}:
    raise ValueError(f"Unsupported DISCOVERY_MODE={DISCOVERY_MODE!r}")

LANGUAGE_ROTATION = ("fr", "de", "zh", "ja", "ko", "hi", "ru", "ar", "pt", "it")

# External discovery sources are deliberately low-rate and fail-soft.
REPOSITORY_SOURCE_LIMIT = 10
COMMON_CRAWL_LIMIT = 40
COMMON_CRAWL_DELAY = 2.0
URLSCAN_MAX_RESULTS = 20
URLSCAN_DELAY = 1.0
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
    "viewer", "frontend", "alternative frontend", "browser", "slideshow",
    "reader", "gallery", "content browser", "web client",
    "visor", "visualizador", "visionneuse", "betrachter",
    "ビューア", "просмотрщик", "visualizzatore",
    "查看器", "뷰어", "व्यूअर", "عارض",
)

SERVICE_PATH_SEGMENTS = {
    "viewer", "view", "browse", "browser", "search", "nitter", "xcancel",
    "redlib", "libreddit", "teddit", "troddit", "priviblur",
}

SERVICE_COMPOUND_RE = re.compile(
    r"^(?:twitter|x|reddit|tumblr)[_-](?:viewer|browser|frontend)$",
    re.IGNORECASE,
)


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
            '"{platform} frontend" "without login"',
            '"{platform} anonymous viewer"',
        ],
        "es": [
            '"{platform} visor" "sin iniciar sesión"',
            '"{platform} visor" "sin cuenta"',
            '"{platform} frontend" "sin iniciar sesión"',
            '"{platform} visor anónimo"',
        ],
        "fr": [
            '"{platform} visionneuse" "sans connexion"',
            '"{platform} visionneuse" "sans compte"',
            '"{platform} interface alternative" "sans connexion"',
            '"{platform} visionneuse anonyme"',
        ],
        "de": [
            '"{platform} Betrachter" "ohne Anmeldung"',
            '"{platform} Betrachter" "ohne Konto"',
            '"{platform} Frontend" "ohne Anmeldung"',
            '"{platform} anonymer Betrachter"',
        ],
        "zh": [
            '"{platform} 查看器" "无登录"',
            '"{platform} 查看器" "无需账户"',
            '"{platform} 替代前端"',
            '"{platform} 匿名 查看器"',
        ],
        "ja": [
            '"{platform} ビューア" "ログインなし"',
            '"{platform} ビューア" "アカウントなし"',
            '"{platform} フロントエンド"',
            '"{platform} 匿名 ビューア"',
        ],
        "ko": [
            '"{platform} 뷰어" "로그인 없이"',
            '"{platform} 뷰어" "계정 없이"',
            '"{platform} 프론트엔드"',
            '"{platform} 익명 뷰어"',
        ],
        "hi": [
            '"{platform} व्यूअर" "बिना लॉगिन"',
            '"{platform} व्यूअर" "बिना अकाउंट"',
            '"{platform} फ्रंटएंड"',
            '"{platform} अनाम व्यूअर"',
        ],
        "ru": [
            '"{platform} просмотрщик" "без входа"',
            '"{platform} просмотрщик" "без аккаунта"',
            '"{platform} фронтенд" "без входа"',
            '"{platform} анонимный просмотрщик"',
        ],
        "ar": [
            '"{platform} عارض" "بدون تسجيل دخول"',
            '"{platform} عارض" "بدون حساب"',
            '"{platform} واجهة بديلة"',
            '"{platform} عارض مجهول"',
        ],
        "pt": [
            '"{platform} visualizador" "sem login"',
            '"{platform} visualizador" "sem conta"',
            '"{platform} frontend" "sem login"',
            '"{platform} visualizador anônimo"',
        ],
        "it": [
            '"{platform} visualizzatore" "senza accesso"',
            '"{platform} visualizzatore" "senza account"',
            '"{platform} frontend" "senza accesso"',
            '"{platform} visualizzatore anonimo"',
        ],
    }

    platform_queries = {
        "twitter": [
            '"Twitter profile viewer" -news -article -guide -review',
            '"tweet viewer" -news -article -guide -review',
            '"X profile viewer" "no login" -news -article -guide -review',
            '"Twitter browser" "public profiles" -news -article -guide',
            '"view Twitter profiles" "without login" -news -article -guide',
        ],
        "reddit": [
            '"Reddit post viewer" -news -article -guide -review',
            '"Reddit profile viewer" -news -article -guide -review',
            '"Reddit anonymous viewer" -news -article -guide -review',
            '"subreddit viewer" -news -article -guide -review',
            '"Reddit browser" "without login" -news -article -guide',
        ],
        "tumblr": [
            '"Tumblr blog viewer" -news -article -guide -review',
            '"Tumblr profile viewer" -news -article -guide -review',
            '"Tumblr anonymous viewer" -news -article -guide -review',
            '"Tumblr post viewer" -news -article -guide -review',
            '"Tumblr browser" "without login" -news -article -guide',
        ],
    }

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



def merge_search_result(
    candidate_map: dict[tuple[str, str], SearchHit],
    platform: str,
    query: str,
    backend: str,
    result: dict,
) -> None:
    """Merge one search result into the deduplicated candidate map."""
    href = result.get("href") or result.get("url") or ""
    domain = normalize_host(href)
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
    if href not in hit.urls:
        hit.urls.append(href)
    if backend not in hit.providers:
        hit.providers.append(backend)

    evidence = fold(f"{result.get('title', '')} {result.get('body', '')}")
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
            f"?q={quote_plus(query)}&sort=updated&order=desc&per_page=6"
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

    for repo_key in sorted(repo_keys)[:30]:
        full_name, default_branch = repo_key.rsplit("@", 1)
        readme_url = (
            f"https://raw.githubusercontent.com/{full_name}/"
            f"{default_branch}/README.md"
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

    for raw_url in URL_IN_HTML_RE.findall("\n".join(context)):
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
        readme_url = f"https://gitlab.com/{full_path}/-/raw/{quote_plus(branch)}/README.md"
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
            f"https://codeberg.org/{full_name}/raw/branch/{quote_plus(branch)}/README.md"
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
        "twitter": ("*twitter*viewer*", "*twitter*frontend*"),
        "reddit": ("*reddit*viewer*", "*reddit*frontend*"),
        "tumblr": ("*tumblr*viewer*", "*tumblr*frontend*"),
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
        "twitter": "page.title:(twitter viewer)",
        "reddit": "page.title:(reddit viewer)",
        "tumblr": "page.title:(tumblr viewer)",
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
                    for host in extract_farside(text, platform) if source_name == "Farside" else set():
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
    jina_url = "https://r.jina.ai/" + url
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
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en,es;q=0.7,*;q=0.3",
        "Connection": "close",
    }

    variants = [url]
    if url.startswith("http://"):
        variants.append(url.replace("http://", "https://", 1))

    last_error = "fetch failed"
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
                return text, {"final_url": final_url}
            except HTTPError as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                # Permanent responses do not benefit from a second request.
                if exc.code not in RETRYABLE_HTTP_CODES:
                    break
                if attempt < FETCH_RETRIES:
                    time.sleep(0.5 * attempt)
            except (URLError, TimeoutError, ValueError, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                if attempt < FETCH_RETRIES:
                    time.sleep(0.5 * attempt)
    return None, {"error": last_error}


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
            "viewer", "frontend", "browser", "slideshow", "gallery", "reader",
            "anonymous", "content browser", "web client", "visor", "visualizador",
        )
        + sum((cfg["service"] for cfg in LANGUAGES.values()), [])
    ))
    return any(term_present(term, q) for term in service_terms)


def search_query_intent_hits(hit: SearchHit) -> int:
    return sum(
        1 for query in hit.queries
        if query_has_service_intent(hit.platform, query)
    )


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
    jina_eligible = (
        seed_candidate
        or strong_search_evidence_hint
        or bool(SEARCH_SERVICE_HOST_RE.search(hit.domain))
        or any(path_looks_like_service(urlparse(url).path.lower()) for url in candidate_urls[:3])
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
    else:
        first = page_evidence(final_url, html_text)

    all_pages = [first]

    # On direct HTML, follow at most two same-origin service links.
    if via == "direct":
        relevant = []
        for href, label in first["links"]:
            absolute = urljoin(final_url, href)
            parsed = urlparse(absolute)
            if parsed.scheme not in {"http", "https"} or parsed.hostname != final_host:
                continue
            combined = fold(f"{href} {label}")
            if any(
                term_present(term, combined)
                for term in (
                    "profile", "user", "post", "tweet", "subreddit", "blog",
                    "viewer", "frontend", "instance", "proxy", "mirror",
                    "search", "профиль", "пользователь", "帖子", "プロフィール", "사용자",
                )
            ):
                relevant.append(absolute)

        seen = {final_url}
        for extra_url in relevant[:2]:
            if extra_url in seen:
                continue
            seen.add(extra_url)
            extra_html, extra_meta = fetch_html(extra_url)
            extra_final = extra_meta.get("final_url", "") if extra_html is not None else ""
            if extra_html is not None and normalize_host(extra_final) == hit.domain:
                all_pages.append(page_evidence(extra_final, extra_html))

    pcfg = PLATFORMS[hit.platform]
    title = fold(" ".join(p["title"] for p in all_pages))
    headings = fold(" ".join(p["headings"] for p in all_pages))
    meta = fold(" ".join(p["meta"] for p in all_pages))
    body = fold(" ".join(p["body"] for p in all_pages))
    links = fold(" ".join(p["link_text"] for p in all_pages))
    url_text = fold(final_url)
    total = fold(" ".join([title, headings, meta, body, links, url_text]))
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
    strong_service_terms = STRONG_SERVICE_TERMS
    strong_header_service_hits = [
        t for t in strong_service_terms if term_present(t, header_text)
    ]
    page_service_ok = bool(
        strong_header_service_hits
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
    search_accept = (
        not seed_candidate
        and strong_service_page
        and (search_intent_hits >= 1 or header_verified_search_service_ok)
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
    priority_hits = sorted(
        [h for h in candidate_map.values() if h.sources and h.domain not in known_domains],
        key=lambda h: (
            -len(h.sources),
            -len(h.search_evidence),
            h.domain,
        ),
    )
    search_hits = sorted(
        [h for h in candidate_map.values() if not h.sources and h.domain not in known_domains],
        key=lambda h: (
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
    hits = seed_hits + (priority_hits + search_hits)[:MAX_CANDIDATES]

    already_known_candidates = sum(
        1 for h in candidate_map.values() if h.domain in known_domains
    )
    candidate_domains = {h.domain for h in candidate_map.values()}

    print(f"Candidates discovered: {len(candidate_map)}")
    print(f"Candidates selected for validation: {len(hits)}")
    print(f"Previously known candidates skipped: {already_known_candidates}")
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

    evaluations.sort(key=lambda e: (-e.accepted, -e.score, e.domain))

    seed_keys = set(seeds)
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

    rejection_reason_counts = {}
    for evaluation in evaluations:
        if not evaluation.accepted:
            rejection_reason_counts[evaluation.reason] = rejection_reason_counts.get(evaluation.reason, 0) + 1

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
        "search_strategy": "maintained registries + curated alternative-frontends sources + GitHub + low-concurrency rotated search + sequential backend fallback + parallel validation",
        "trusted_source_names": trusted_source_names,
        "candidates_discovered": len(candidate_map),
        "validated_candidates": len(evaluations),
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
