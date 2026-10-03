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
from ddgs import DDGS
from ddgs.exceptions import DDGSException, RatelimitException, TimeoutException
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote_plus, unquote, urljoin, urlparse
from urllib.request import Request, urlopen


OUTPUT = Path("search-discovered-blocklist.txt")
REPORT = Path("search-discovered-report.json")

PAGE_TIMEOUT = 10
FETCH_RETRIES = 2
MAX_PAGE_BYTES = 1_500_000
MAX_CRAWL_PAGES = 3
MAX_CANDIDATES = 180
MAX_CONSECUTIVE_SEARCH_ERRORS = 3
MIN_ACCEPTED = 2
WORKERS = 6
VALIDATION_DELAY = 0.35

SEARCH_BACKENDS = ["duckduckgo", "bing", "yahoo", "brave", "google", "mojeek", "startpage", "yandex"]
SEARCH_MAX_RESULTS = 8
SEARCH_TIMEOUT = 8
SEARCH_DELAY = 0.25
SEARCH_AUTO_FALLBACK = True
WEB_VERIFIED_SEEDS = [
    ("reddit", "https://www.peekstr.com/"),
    ("tumblr", "https://zoomblr.com/"),
    ("twitter", "https://twitterviewer.net/"),
    ("twitter", "https://tweetviewer.com/"),
    ("twitter", "https://www.sotwe.com/"),
]

CONTENT_HOST_SUFFIXES = (
    ".blogspot.com", ".wordpress.com", ".medium.com", ".substack.com",
    ".wixsite.com", ".weebly.com",
)
SEARCH_SERVICE_HOST_RE = re.compile(
    r"(viewer|frontend|nitter|xcancel|twiiit|tweetviewer|twitterviewer|"
    r"twiewer|xviewer|redlib|libreddit|teddit|troddit|redlite|eddrit|"
    r"priviblur|tumblrviewer|zoomblr)",
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
}

PLATFORMS = {
    "twitter": {
        "platform_terms": ["twitter", "x", "nitter"],
        "core": ["twitter", "nitter", "xcancel", "twiiit"],
        "brands": ["nitter", "xcancel", "twiiit"],
        "queries": [
            "{platform} {service1} nitter",
            "{platform} {service2} {object} nitter",
            "x viewer twitter nitter",
        ],
        "query_object": "profile",
        "identity_extra": ["tweet", "tweets", "user", "profile", "post"],
    },
    "reddit": {
        "platform_terms": ["reddit"],
        "core": ["reddit", "redlib", "libreddit", "teddit", "eddrit", "troddit", "kddit"],
        "brands": ["redlib", "libreddit", "teddit", "eddrit", "troddit", "kddit"],
        "queries": [
            "{platform} {service1} redlib libreddit",
            "{platform} {service2} {object} teddit",
        ],
        "query_object": "subreddit",
        "identity_extra": ["subreddit", "subreddits", "comment", "comments", "post", "posts", "user", "profile"],
    },
    "tumblr": {
        "platform_terms": ["tumblr"],
        "core": ["tumblr", "priviblur"],
        "brands": ["priviblur"],
        "queries": [
            "{platform} {service1} priviblur",
            "{platform} {service2} {object} priviblur",
        ],
        "query_object": "blog",
        "identity_extra": ["blog", "blogs", "post", "posts", "user", "profile"],
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

BAD_PATH_MARKERS = (
    "/news/", "/article/", "/articles/", "/press/",
)

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

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.skip_depth = 0
        self.title_parts: list[str] = []
        self.heading_parts: list[str] = []
        self.meta_parts: list[str] = []
        self.body_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self.forms = 0
        self.inputs = 0
        self.buttons = 0
        self.current_tag: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        tag = tag.lower()
        if tag in self.SKIP:
            self.skip_depth += 1
            return
        attrs_map = dict(attrs)
        if tag == "meta":
            name = (attrs_map.get("name") or "").lower()
            prop = (attrs_map.get("property") or "").lower()
            if name in {"description", "keywords"} or prop in {"og:title", "og:description"}:
                content = attrs_map.get("content")
                if content:
                    self.meta_parts.append(content)
        elif tag == "form":
            self.forms += 1
        elif tag in {"input", "textarea", "select"}:
            self.inputs += 1
        elif tag == "button":
            self.buttons += 1
        elif tag == "a":
            href = attrs_map.get("href") or ""
            self.links.append((href, ""))
        self.current_tag = tag

    def handle_endtag(self, tag: str) -> None:
        tag = tag.lower()
        if tag in self.SKIP and self.skip_depth:
            self.skip_depth -= 1
        if tag == self.current_tag:
            self.current_tag = None

    def handle_data(self, data: str) -> None:
        if self.skip_depth or not data.strip():
            return
        cleaned = data.strip()
        if not cleaned:
            return
        if self.current_tag == "title":
            self.title_parts.append(cleaned)
        elif self.current_tag in {"h1", "h2", "h3"}:
            self.heading_parts.append(cleaned)
        else:
            self.body_parts.append(cleaned)
            if self.links:
                href, label = self.links[-1]
                if not label and self.current_tag == "a":
                    self.links[-1] = (href, cleaned)

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


def quote_term(term: str) -> str:
    return '"' + term.replace('"', ' ') + '"'


def build_queries() -> list[tuple[str, str, str]]:
    intents = {
        "en": ["viewer", "alternative frontend", "mirror", "proxy"],
        "es": ["visor", "interfaz alternativa", "espejo", "proxy"],
        "fr": ["visionneuse", "interface alternative"],
        "de": ["Betrachter", "alternative Oberfläche"],
        "ja": ["ビューア", "代替フロントエンド"],
        "ru": ["просмотрщик", "альтернативный интерфейс"],
    }
    queries: list[tuple[str, str, str]] = []
    for lang, terms in intents.items():
        for platform in PLATFORMS:
            for intent in terms:
                queries.append((lang, platform, f'"{platform} {intent}"'))
    queries.extend([
        ("en", "twitter", '"X viewer" twitter'),
        ("en", "twitter", '"X profile viewer"'),
        ("en", "twitter", '"tweet viewer"'),
    ])
    return queries


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
            [f"Human-verified viewer seed: {url}"],
        )
    return found


def search_with_ddgs(searcher: DDGS, query: str, region: str, backend: str) -> list[dict]:
    results = searcher.text(
        query,
        region=region,
        safesearch="moderate",
        max_results=SEARCH_MAX_RESULTS,
        page=1,
        backend=backend,
    )
    return [r for r in results if isinstance(r, dict)]


def merge_search_result(
    candidate_map: dict[tuple[str, str], SearchHit],
    platform: str,
    query: str,
    backend: str,
    result: dict,
) -> None:
    href = result.get("href") or result.get("url") or ""
    domain = normalize_host(href)
    if not domain:
        return
    key = (platform, domain)
    if key not in candidate_map:
        candidate_map[key] = SearchHit(domain, platform, [], [], [], [], [])
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
            except (HTTPError, URLError, TimeoutError, ValueError, OSError) as exc:
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


def evaluate_candidate(hit: SearchHit, existing: set[str]) -> Evaluation:
    if hit.domain in existing:
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), hit.urls[0],
            {"already_covered": True}, "already covered by blocklist.txt"
        )

    seed_candidate = is_seed_candidate(hit)
    direct_trusted = bool(set(hit.sources) & DIRECT_TRUSTED_SOURCES)

    # Prefer search-result URLs that actually look like the service page.
    ranked_urls = sorted(
        hit.urls,
        key=lambda url: (
            -sum(marker in urlparse(url).path.lower() for marker in (
                "viewer", "frontend", "profile", "subreddit", "tweet",
                "status", "blog", "search", "view"
            )),
            url,
        ),
    )
    first_url = ranked_urls[0]

    html_text, fetch_meta = fetch_html(first_url)
    via = "direct"
    if html_text is None and seed_candidate:
        jina_text, jina_meta = fetch_jina_text(first_url)
        if jina_text is not None:
            html_text = jina_text
            fetch_meta = jina_meta
            via = "jina"

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
    if any(marker in first_path for marker in BAD_PATH_MARKERS):
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {}, "search result points to an article/news page"
        )

    if html_text == (fetch_meta.get("jina_text") or ""):
        first = page_evidence_from_text(final_url, html_text)
    elif fetch_meta.get("via") == "jina" or via == "jina":
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
        or hit.domain in {"alternativeto.net", "www.alternativeto.net", "beebom.com",
                          "www.beebom.com", "makeuseof.com", "www.makeuseof.com"}
    )
    if content_host:
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {"content_host": True}, "content/publishing host, not a service host"
        )

    platform_hits = [t for t in pcfg["platform_terms"] if term_present(t, total)]
    brand_hits = [t for t in pcfg["brands"] if term_present(t, total)]
    header_platform_hits = [t for t in pcfg["platform_terms"] if term_present(t, header_text)]
    header_brand_hits = [t for t in pcfg["brands"] if term_present(t, header_text)]

    identity_terms = list(dict.fromkeys(
        pcfg["identity_extra"] + sum((cfg["identity"] for cfg in LANGUAGES.values()), [])
    ))
    service_terms = list(dict.fromkeys(
        sum((cfg["service"] for cfg in LANGUAGES.values()), [])
    ))
    identity_hits = [t for t in identity_terms if term_present(t, total)]
    service_hits = [t for t in service_terms if term_present(t, total)]
    header_identity_hits = [t for t in identity_terms if term_present(t, header_text)]
    header_service_hits = [t for t in service_terms if term_present(t, header_text)]

    service_path_hint = any(
        marker in first_path
        for marker in ("/viewer", "/frontend", "/view", "/profile", "/tweet",
                       "/tweets", "/status", "/subreddit", "/r/", "/user")
    )
    host_service_hint = bool(SEARCH_SERVICE_HOST_RE.search(hit.domain))

    input_count = sum(p["inputs"] for p in all_pages)
    form_count = sum(p["forms"] for p in all_pages)
    button_count = sum(p["buttons"] for p in all_pages)
    ui_signal = bool(input_count or form_count or button_count or service_path_hint)

    action_hits = [t for t in (
        "paste", "enter", "search", "browse", "view", "open", "load",
        "pegar", "buscar", "ver", "ouvrir", "suchen", "просмотр",
        "ビュー", "보기",
    ) if term_present(t, total)]

    # A search hit only counts as discovery evidence when the result itself
    # mentions both the target platform and a service concept.
    search_intent_hits = 0
    search_provider_hits: set[str] = set()
    for evidence in hit.search_evidence:
        if not isinstance(evidence, str):
            continue
        ev = fold(evidence)
        platform_ok = any(term_present(t, ev) for t in (
            ["twitter", "tweet", "nitter", "x"] if hit.platform == "twitter"
            else ["reddit", "subreddit", "redlib", "libreddit", "teddit"]
            if hit.platform == "reddit"
            else ["tumblr", "priviblur", "blog"]
        ))
        service_ok = any(term_present(t, ev) for t in (
            "viewer", "frontend", "mirror", "proxy", "visor", "visualizador",
            "visionneuse", "betrachter", "ビューア", "просмотрщик",
        ))
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
        or host_service_hint and any(
            term_present(t, header_text)
            for t in pcfg["platform_terms"] if t != "x"
        )
        or seed_candidate and platform_hits
    )
    page_service_ok = bool(header_service_hits or service_path_hint or (
        seed_candidate and any(term_present(t, body[:7000]) for t in service_terms)
    ))
    page_identity_ok = bool(
        header_identity_hits
        or (ui_signal and any(term_present(t, body[:7000]) for t in identity_terms))
    )

    strong_service_page = (
        page_platform_ok
        and page_service_ok
        and page_identity_ok
        and ui_signal
    )

    # Seeds: published only after page validation, with Jina as a fallback when
    # the origin blocks GitHub Actions.
    seed_accept = (
        seed_candidate
        and strong_service_page
        and bool(platform_hits and service_hits)
    )

    # Search candidates: require actual search-intent evidence plus independent
    # corroboration, unless the hostname itself is a very strong service name.
    search_accept = (
        not seed_candidate
        and strong_service_page
        and search_intent_hits >= 1
        and search_confirmed
        and (len(hit.providers) >= 2 or distinct_queries >= 2 or host_service_hint)
    )

    trusted_accept = (
        direct_trusted
        and strong_service_page
        and bool(platform_hits and service_hits)
    )

    accepted = bool(seed_accept or search_accept or trusted_accept)

    score = 0
    score += 6 if header_brand_hits else 0
    score += 4 if header_platform_hits else 0
    score += 4 if header_service_hits else 0
    score += 3 if header_identity_hits else 0
    score += 3 if ui_signal else 0
    score += min(5, 2 * len(search_provider_hits))
    score += min(4, distinct_queries)
    score += 2 if len(hit.sources) >= 2 else (1 if hit.sources else 0)
    if host_service_hint:
        score += 2
    if via == "jina":
        score += 1

    evidence = {
        "platform_hits": platform_hits,
        "brand_hits": brand_hits,
        "header_platform_hits": header_platform_hits,
        "header_brand_hits": header_brand_hits,
        "header_service_hits": header_service_hits,
        "header_identity_hits": header_identity_hits,
        "service_hits": service_hits,
        "identity_hits": identity_hits,
        "ui_signal": ui_signal,
        "inputs": input_count,
        "forms": form_count,
        "buttons": button_count,
        "service_path_hint": service_path_hint,
        "host_service_hint": host_service_hint,
        "search_intent_hits": search_intent_hits,
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
    query_specs = build_queries()

    candidate_map: dict[tuple[str, str], SearchHit] = {}
    search_errors: list[dict] = []

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
    for key, hit in github_sources.items():
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

    provider_disabled: set[str] = set()
    searcher = DDGS(timeout=SEARCH_TIMEOUT, verify=True)

    for index, (lang, platform, query) in enumerate(query_specs, start=1):
        cfg = LANGUAGES[lang]
        region = f"{cfg['gl']}-{cfg['hl'].split('-')[0]}"
        print(f"[SEARCH {index}/{len(query_specs)}] {lang}/{platform}: {query}")
        result_count = 0

        for backend in SEARCH_BACKENDS:
            if backend in provider_disabled:
                continue
            try:
                results = search_with_ddgs(searcher, query, region, backend)
                for result in results:
                    merge_search_result(candidate_map, platform, query, backend, result)
                result_count += len(results)
                print(f"[DDGS/{backend}] {len(results)} results")
            except (RatelimitException, TimeoutException, DDGSException, OSError, ValueError) as exc:
                error = f"{type(exc).__name__}: {exc}"
                search_errors.append({
                    "language": lang,
                    "platform": platform,
                    "query": query,
                    "backend": backend,
                    "error": error,
                })
                print(f"[WARN] DDGS/{backend}: {error}")
                message_lower = error.lower()
                if isinstance(exc, (RatelimitException, TimeoutException)) or "429" in message_lower or "403" in message_lower:
                    provider_disabled.add(backend)
                    print(f"[WARN] Disabling DDGS/{backend} after a rate-limit/block response.")

        if result_count == 0:
            print("[WARN] No search results from active backends.")
        time.sleep(SEARCH_DELAY)

    print(f"DDGS backends disabled: {sorted(provider_disabled)}")
    print(f"Search errors recorded: {len(search_errors)}")

    # Stronger discovery signal first: domains seen in multiple independent queries.
    hits = sorted(
        candidate_map.values(),
        key=lambda h: (
            -len(h.providers),
            -len([q for q in h.queries if not q.startswith("SOURCE:") and not q.startswith("SEED:")]),
            -len(h.sources),
            -len(h.search_evidence),
            h.domain,
        ),
    )
    hits = hits[:MAX_CANDIDATES]

    print(f"Candidates discovered: {len(hits)}")
    print(f"Search-engine failures: {len(search_errors)}")

    evaluations: list[Evaluation] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = [executor.submit(safe_evaluate_candidate, hit, existing) for hit in hits]
        for completed in concurrent.futures.as_completed(futures):
            evaluations.append(completed.result())
            time.sleep(VALIDATION_DELAY)

    evaluations.sort(key=lambda e: (-e.accepted, -e.score, e.domain))

    accepted_by_domain: dict[str, Evaluation] = {}
    for evaluation in evaluations:
        if evaluation.accepted and evaluation.domain not in existing:
            current = accepted_by_domain.get(evaluation.domain)
            if current is None or evaluation.score > current.score:
                accepted_by_domain[evaluation.domain] = evaluation

    accepted = sorted(
        accepted_by_domain.values(),
        key=lambda e: (-e.score, e.domain),
    )
    if len(accepted) < MIN_ACCEPTED:
        print("[WARN] No sufficient validated domains were found.")
        print("The previous search-discovered-blocklist.txt is intentionally left untouched.")
        REPORT.write_text(
            json.dumps(
                {
                    "status": "no_update",
                    "accepted": [],
                    "accepted_count": 0,
                    "trusted_candidate_count": trusted_candidate_count,
                    "trusted_source_names": trusted_source_names,
                    "verified_web_seed_count": seed_candidate_count,
                    "github_discovered_candidate_count": github_candidate_count,
                    "search_backends": SEARCH_BACKENDS,
                    "disabled_backends": sorted(provider_disabled),
                    "search_strategy": "maintained registries + GitHub repository discovery + DDGS per-backend search + page validation",
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

    OUTPUT.write_text(
        "# Generated from maintained frontend registries + GitHub + DDGS multi-engine search + page validation.\n"
        "# Only newly discovered domains are included; domains already in blocklist.txt are omitted.\n"
        + "\n".join(f"||{e.domain}^" for e in accepted)
        + "\n",
        encoding="utf-8",
    )

    report = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "search_queries": len(query_specs),
        "search_backends": SEARCH_BACKENDS,
        "disabled_backends": sorted(provider_disabled),
        "verified_web_seed_count": seed_candidate_count,
        "trusted_candidate_count": trusted_candidate_count,
        "github_discovered_candidate_count": github_candidate_count,
        "search_strategy": "maintained registries + GitHub + DDGS multi-engine search; each backend queried separately",
        "trusted_source_names": trusted_source_names,
        "candidates_discovered": len(hits),
        "validated_candidates": len(evaluations),
        "accepted_count": len(accepted),
        "already_covered_count": sum(
            1 for e in evaluations if "already covered" in e.reason
        ),
        "search_errors": search_errors,
        "accepted": [asdict(e) for e in accepted],
        "rejected_sample": [
            asdict(e) for e in evaluations if not e.accepted
        ][:120],
    }
    REPORT.write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(f"[OK] Validated new domains: {len(accepted)}")
    print(f"[OK] Validation workers: {WORKERS}; fetch retries: {FETCH_RETRIES}")
    for e in accepted:
        print(f"[ACCEPT] {e.domain} | {e.platform} | {e.reason}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
