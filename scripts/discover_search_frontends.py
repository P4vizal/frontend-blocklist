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
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import parse_qs, quote_plus, urljoin, urlparse
from urllib.request import Request, urlopen


OUTPUT = Path("search-discovered-blocklist.txt")
REPORT = Path("search-discovered-report.json")

GOOGLE_URL = "https://www.google.com/search"
GOOGLE_DELAY = 1.0
GOOGLE_RESULTS = 10
PAGE_TIMEOUT = 10
MAX_PAGE_BYTES = 1_500_000
MAX_CRAWL_PAGES = 3
MAX_CANDIDATES = 180
MIN_ACCEPTED = 2
WORKERS = 12

USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/140.0 Safari/537.36 frontend-blocklist-discovery/1.0"
)

LANGUAGES = {
    "en": {
        "hl": "en", "gl": "us",
        "service": ["viewer", "frontend", "mirror", "proxy", "alternative", "instance"],
        "identity": ["profile", "user", "post"],
    },
    "es": {
        "hl": "es", "gl": "es",
        "service": ["visor", "visualizador", "interfaz alternativa", "espejo", "proxy", "alternativa", "instancia"],
        "identity": ["perfil", "usuario", "publicación", "post"],
    },
    "fr": {
        "hl": "fr", "gl": "fr",
        "service": ["visionneuse", "interface alternative", "miroir", "proxy", "alternative", "instance"],
        "identity": ["profil", "utilisateur", "publication", "post"],
    },
    "de": {
        "hl": "de", "gl": "de",
        "service": ["betrachter", "alternative oberfläche", "spiegel", "proxy", "alternative", "instanz"],
        "identity": ["profil", "benutzer", "beitrag", "post"],
    },
    "ru": {
        "hl": "ru", "gl": "ru",
        "service": ["просмотр", "просмотрщик", "альтернативный интерфейс", "зеркало", "прокси", "альтернативный", "экземпляр"],
        "identity": ["профиль", "пользователь", "публикация", "пост"],
    },
    "zh": {
        "hl": "zh-CN", "gl": "cn",
        "service": ["查看器", "替代前端", "镜像", "代理", "替代", "实例"],
        "identity": ["个人资料", "用户", "帖子", "博文"],
    },
    "ja": {
        "hl": "ja", "gl": "jp",
        "service": ["ビューア", "代替フロントエンド", "ミラー", "プロキシ", "代替", "インスタンス"],
        "identity": ["プロフィール", "ユーザー", "投稿", "ポスト"],
    },
    "ko": {
        "hl": "ko", "gl": "kr",
        "service": ["뷰어", "대체 프론트엔드", "미러", "프록시", "대체", "인스턴스"],
        "identity": ["프로필", "사용자", "게시물", "포스트"],
    },
    "hi": {
        "hl": "hi", "gl": "in",
        "service": ["व्यूअर", "वैकल्पिक फ्रंटएंड", "मिरर", "प्रॉक्सी", "वैकल्पिक", "इंस्टेंस"],
        "identity": ["प्रोफ़ाइल", "उपयोगकर्ता", "पोस्ट", "प्रकाशन"],
    },
    "ar": {
        "hl": "ar", "gl": "sa",
        "service": ["عارض", "واجهة بديلة", "مرآة", "وكيل", "بديل", "مثيل"],
        "identity": ["ملف شخصي", "مستخدم", "منشور", "مشاركة"],
    },
}

PLATFORMS = {
    "twitter": {
        "core": ["twitter", "nitter"],
        "brands": ["nitter"],
        "queries": [
            "{platform} {service1} nitter",
            "{platform} {service2} {object} nitter",
        ],
        "query_object": "profile",
        "identity_extra": ["tweet", "tweets", "user", "profile", "post"],
    },
    "reddit": {
        "core": ["reddit", "redlib", "libreddit", "teddit"],
        "brands": ["redlib", "libreddit", "teddit"],
        "queries": [
            "{platform} {service1} redlib libreddit",
            "{platform} {service2} {object} teddit",
        ],
        "query_object": "subreddit",
        "identity_extra": ["subreddit", "subreddits", "comment", "comments", "post", "posts", "user", "profile"],
    },
    "tumblr": {
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


class GoogleParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.hrefs: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag.lower() != "a":
            return
        attrs_map = dict(attrs)
        href = attrs_map.get("href")
        if href:
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
        }


@dataclass
class SearchHit:
    domain: str
    platform: str
    queries: list[str]
    urls: list[str]


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


def build_queries() -> list[tuple[str, str, str]]:
    queries: list[tuple[str, str, str]] = []
    for lang, cfg in LANGUAGES.items():
        for platform, pcfg in PLATFORMS.items():
            service1 = cfg["service"][0]
            service2 = cfg["service"][1]
            object_term = pcfg.get("query_object", cfg["identity"][0])
            for template in pcfg["queries"]:
                queries.append(
                    (
                        lang,
                        platform,
                        template.format(
                            platform=platform,
                            service1=service1,
                            service2=service2,
                            object=object_term,
                        ),
                    )
                )
    return queries


def google_search(query: str, hl: str, gl: str) -> list[str]:
    params = {
        "q": query,
        "num": str(GOOGLE_RESULTS),
        "hl": hl,
        "gl": gl,
        "filter": "0",
        "gbv": "1",
    }
    url = GOOGLE_URL + "?" + "&".join(
        f"{quote_plus(k)}={quote_plus(v)}" for k, v in params.items()
    )
    req = Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml",
            "Accept-Language": f"{hl},en;q=0.7",
        },
    )
    with urlopen(req, timeout=PAGE_TIMEOUT) as response:
        raw = response.read(MAX_PAGE_BYTES)
        charset = response.headers.get_content_charset() or "utf-8"
        text = raw.decode(charset, errors="replace")

    lower = fold(text)
    if "our systems have detected unusual traffic" in lower or "captcha" in lower:
        raise RuntimeError("Google returned a bot/challenge page")

    parser = GoogleParser()
    parser.feed(text)
    urls: list[str] = []
    for href in parser.hrefs:
        href = html.unescape(href)
        if href.startswith("/url?") or href.startswith("https://www.google.com/url?"):
            parsed = urlparse(href)
            qs = parse_qs(parsed.query)
            href = (qs.get("q") or qs.get("url") or [""])[0]
        if not href.startswith(("http://", "https://")):
            continue
        host = normalize_host(href)
        if host:
            urls.append(href)
    return urls


def fetch_html(url: str) -> tuple[str, dict] | tuple[None, dict]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en,es;q=0.7,*;q=0.3",
    }
    for scheme_url in (url, url.replace("http://", "https://", 1) if url.startswith("http://") else None):
        if not scheme_url:
            continue
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
        except (HTTPError, URLError, TimeoutError, ValueError) as exc:
            last_error = f"{type(exc).__name__}: {exc}"
    return None, {"error": last_error if "last_error" in locals() else "fetch failed"}


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

    first_url = hit.urls[0]
    html_text, fetch_meta = fetch_html(first_url)
    if html_text is None:
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), first_url,
            {}, "", fetch_meta.get("error", "fetch failed")
        )

    final_url = fetch_meta["final_url"]
    final_host = normalize_host(final_url)
    candidate_base = hit.domain[4:] if hit.domain.startswith("www.") else hit.domain
    final_base = final_host[4:] if final_host and final_host.startswith("www.") else final_host
    if final_host is None or final_base != candidate_base:
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {"redirect_host": final_host}, "redirected outside candidate host"
        )

    if any(marker in urlparse(first_url).path.lower() for marker in BAD_PATH_MARKERS):
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {}, "search result points to an article/news page"
        )

    first = page_evidence(final_url, html_text)
    all_pages = [first]

    # Follow a small number of relevant same-origin links to strengthen validation.
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
    for extra_url in relevant[: MAX_CRAWL_PAGES - 1]:
        if extra_url in seen:
            continue
        seen.add(extra_url)
        extra_html, extra_meta = fetch_html(extra_url)
        if extra_html is not None and normalize_host(extra_meta.get("final_url", "")) == hit.domain:
            all_pages.append(page_evidence(extra_meta["final_url"], extra_html))

    pcfg = PLATFORMS[hit.platform]
    lang_cfg = LANGUAGES[next(iter(
        lang for lang in LANGUAGES
        if lang in " ".join(hit.queries)
    ))] if False else None

    title = fold(" ".join(p["title"] for p in all_pages))
    headings = fold(" ".join(p["headings"] for p in all_pages))
    meta = fold(" ".join(p["meta"] for p in all_pages))
    body = fold(" ".join(p["body"] for p in all_pages))
    visible = fold(" ".join(p["visible"] for p in all_pages))
    links = fold(" ".join(p["link_text"] for p in all_pages))
    url_text = fold(final_url)
    total = fold(" ".join([title, headings, meta, body, links, url_text]))

    if any(marker in total[:12000] for marker in CHALLENGE_MARKERS):
        return Evaluation(
            hit.domain, hit.platform, False, 0, len(hit.queries), final_url,
            {}, "challenge/parked page detected"
        )

    core_hits = [t for t in pcfg["core"] if term_present(t, total)]
    brand_hits = [t for t in pcfg["brands"] if term_present(t, total)]
    header_hits = [t for t in pcfg["core"] if term_present(t, title + " " + headings + " " + meta + " " + url_text)]
    identity_terms = list(dict.fromkeys(
        pcfg["identity_extra"] + sum((cfg["identity"] for cfg in LANGUAGES.values()), [])
    ))
    service_terms = list(dict.fromkeys(
        sum((cfg["service"] for cfg in LANGUAGES.values()), [])
    ))

    identity_hits = [t for t in identity_terms if term_present(t, total)]
    service_hits = [t for t in service_terms if term_present(t, total)]
    body_identity_hits = [t for t in identity_terms if term_present(t, body)]
    body_service_hits = [t for t in service_terms if term_present(t, body)]

    app_path_markers = (
        "/search", "/profile", "/user", "/users/", "/u/", "/r/",
        "/subreddit", "/post", "/posts", "/tweet", "/tweets", "/status",
        "/blog", "/blogs", "/tag", "/tags", "/view",
    )
    app_path_hits = sorted({
        marker
        for page in all_pages
        for href, label in page["links"]
        if urlparse(urljoin(final_url, href)).hostname == final_host
        for marker in app_path_markers
        if marker in urlparse(urljoin(final_url, href)).path.lower()
    })
    ui_signal = bool(app_path_hits or sum(p["forms"] for p in all_pages) or len(first["links"]) >= 3)

    score = 0
    if header_hits:
        score += 5
    elif core_hits:
        score += 3
    if brand_hits:
        score += 4
    if len(service_hits) >= 1:
        score += 2
    if len(service_hits) >= 2:
        score += 2
    if len(identity_hits) >= 1:
        score += 2
    if len(identity_hits) >= 2:
        score += 2
    if body_service_hits and body_identity_hits:
        score += 2
    if len(hit.queries) >= 2:
        score += 2
    if any(term_present(b, url_text) for b in pcfg["brands"]):
        score += 2
    if ui_signal:
        score += 2

    structured_combo = bool(core_hits and service_hits and identity_hits)
    strong_brand = bool(brand_hits and header_hits)
    repeated_search = len(hit.queries) >= 2
    accepted = (
        (strong_brand and (service_hits or identity_hits) and score >= 10 and ui_signal)
        or (structured_combo and repeated_search and score >= 12 and ui_signal)
        or (structured_combo and len(hit.urls) >= 2 and score >= 12 and ui_signal)
    )

    reason_parts = [
        f"core={','.join(core_hits) or '-'}",
        f"service={','.join(service_hits[:6]) or '-'}",
        f"identity={','.join(identity_hits[:6]) or '-'}",
        f"queries={len(hit.queries)}",
        f"score={score}",
    ]

    evidence = {
        "core_hits": core_hits,
        "brand_hits": brand_hits,
        "header_core_hits": header_hits,
        "service_hits": service_hits,
        "identity_hits": identity_hits,
        "body_service_hits": body_service_hits,
        "body_identity_hits": body_identity_hits,
        "forms": sum(p["forms"] for p in all_pages),
        "app_path_hits": app_path_hits,
        "ui_signal": ui_signal,
        "crawled_pages": len(all_pages),
        "query_urls": hit.urls[:10],
    }

    return Evaluation(
        hit.domain,
        hit.platform,
        accepted,
        score,
        len(hit.queries),
        final_url,
        evidence,
        "; ".join(reason_parts),
    )


def main() -> int:
    existing = read_existing_domains()
    query_specs = build_queries()

    candidate_map: dict[tuple[str, str], SearchHit] = {}
    search_errors: list[dict] = []

    for index, (lang, platform, query) in enumerate(query_specs, start=1):
        cfg = LANGUAGES[lang]
        print(f"[SEARCH {index}/{len(query_specs)}] {lang}/{platform}: {query}")
        try:
            urls = google_search(query, cfg["hl"], cfg["gl"])
            for url in urls:
                domain = normalize_host(url)
                if not domain:
                    continue
                key = (platform, domain)
                if key not in candidate_map:
                    candidate_map[key] = SearchHit(domain, platform, [], [])
                hit = candidate_map[key]
                if query not in hit.queries:
                    hit.queries.append(query)
                if url not in hit.urls:
                    hit.urls.append(url)
        except Exception as exc:
            search_errors.append({
                "language": lang,
                "platform": platform,
                "query": query,
                "error": f"{type(exc).__name__}: {exc}",
            })
        time.sleep(GOOGLE_DELAY)

    # Stronger discovery signal first: domains seen in multiple independent queries.
    hits = sorted(
        candidate_map.values(),
        key=lambda h: (-len(h.queries), -len(h.urls), h.domain),
    )
    hits = hits[:MAX_CANDIDATES]

    print(f"Candidates discovered: {len(hits)}")
    print(f"Google query errors: {len(search_errors)}")

    evaluations: list[Evaluation] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=WORKERS) as executor:
        futures = [executor.submit(evaluate_candidate, hit, existing) for hit in hits]
        for completed in concurrent.futures.as_completed(futures):
            evaluations.append(completed.result())

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
        print("[ERROR] No sufficient validated domains were found.")
        print("The previous search-discovered-blocklist.txt is intentionally left untouched.")
        REPORT.write_text(
            json.dumps(
                {
                    "accepted": [],
                    "accepted_count": 0,
                    "candidates": [asdict(e) for e in evaluations[:200]],
                    "search_errors": search_errors,
                    "note": "Publish guard triggered; output list was not replaced.",
                },
                ensure_ascii=False,
                indent=2,
            ) + "\n",
            encoding="utf-8",
        )
        return 1

    OUTPUT.write_text(
        "# Generated from Google discovery + page validation.\n"
        "# Only newly discovered domains are included; domains already in blocklist.txt are omitted.\n"
        + "\n".join(f"||{e.domain}^" for e in accepted)
        + "\n",
        encoding="utf-8",
    )

    report = {
        "generated": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "google_queries": len(query_specs),
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
    for e in accepted:
        print(f"[ACCEPT] {e.domain} | {e.platform} | {e.reason}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
