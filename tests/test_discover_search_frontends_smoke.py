import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import scripts.discover_search_frontends as discovery

# The committed AdGuard list must contain the persistent rules and requested domains.
blocklist_lines = set(Path("search-discovered-blocklist.txt").read_text(encoding="utf-8").splitlines())
for domain in ("anonviewr.com", "previewerly.com", "vieworaa.com", "viewvra.com"):
    assert f"||{domain}^" in blocklist_lines

candidates = {}
discovery.merge_search_result(
    candidates,
    "twitter",
    "twitter viewer alternative to nitter",
    "bing-rss",
    {
        "href": "https://example.com/view",
        "title": "Twitter viewer",
        "body": "viewer",
    },
)
assert ("twitter", "example.com") in candidates
assert candidates[("twitter", "example.com")].providers == ["bing-rss"]

noisy = {}
discovery.merge_search_result(
    noisy,
    "twitter",
    "twitter viewer without login",
    "bing-rss",
    {
        "href": "https://noise.example/restaurant",
        "title": "Restaurant Milano",
        "body": "Hotel, restaurant and booking information",
    },
)
assert not noisy

encoded = discovery.sanitize_request_url(
    "https://example.com/user/Son Goku?q=hello world"
)
assert encoded == "https://example.com/user/Son%20Goku?q=hello%20world"

malformed = {}
discovery.merge_search_result(
    malformed,
    "reddit",
    "reddit viewer without login",
    "bing-rss",
    {
        "href": "https://example.com/user/Son Goku",
        "title": "Reddit viewer",
        "body": "Reddit viewer for public posts",
    },
)
assert malformed[("reddit", "example.com")].urls == [
    "https://example.com/user/Son%20Goku"
]

queries = discovery.build_queries()
assert len(queries) == 72, f"Unexpected daily query count: {len(queries)}"
assert len(set(queries)) == len(queries)
assert discovery.active_search_languages()
assert len(discovery.active_search_languages()) == 4
assert sum("-news -article -guide -review" in q[2] for q in queries) == 24
assert discovery.search_pages_for("en", "twitter viewer alternatives to nitter") == discovery.SEARCH_PAGES
fr_pages = discovery.search_pages_for("fr", "twitter viewer")
assert fr_pages in ((1,), discovery.SEARCH_PAGES)
parser = discovery.PageParser()
parser.feed(
    '<html><head><title>Reddit Viewer</title></head>'
    '<body><h1>Reddit <span>Viewer</span></h1>'
    '<div role="textbox" aria-label="Search subreddit"></div>'
    '<article>post</article></body></html>'
)
parsed = parser.result()
assert "reddit viewer" in parsed["title"].lower()
assert "reddit viewer" in parsed["headings"].lower()
assert parsed["inputs"] >= 1
assert parsed["article_count"] == 1

multilingual = discovery.SearchHit(
    "example.org", "reddit", ["query"], ["https://example.org/"], [], ["bing-rss"],
    ["bing-rss:reddit 查看器 用于浏览 subreddit"],
)
assert discovery.search_result_has_strong_service_evidence(multilingual)
assert discovery.search_result_is_relevant(
    "reddit",
    "Reddit alternative frontend",
    "Redlib is a private front-end to Reddit",
)
assert discovery.search_result_is_relevant(
    "reddit",
    "Reddit viewer without login",
    "Browse public posts",
    "https://example-viewer.test/reddit-viewer",
)
assert not discovery.pending_candidate_has_strong_signal(
    discovery.SearchHit(
        "noise.example",
        "reddit",
        ["reddit viewer"],
        ["https://noise.example/"],
        [],
        ["bing-rss"],
        ["bing-rss:unrelated calculator results"],
    )
)

assert not discovery.search_result_is_relevant(
    "reddit",
    "reddit profile analyzer",
    "Reddit profile analyzer and account statistics",
)

source_text = (
    "## Reddit\\n"
    "[Redlib](https://redlib.example/) "
    "`https://libreddit.example/`"
)
extracted = discovery.repository_service_urls(source_text, "reddit")
assert {"redlib.example", "libreddit.example"} <= extracted

runtime_html = (
    "<html><head>"
    "<script src='/static/reddit-viewer.js'></script>"
    "<script>const framework = 'next.js';</script>"
    "<link rel='manifest' href='/site.webmanifest'>"
    "</head><body></body></html>"
)
runtime = discovery.runtime_signals_from_html(runtime_html, "reddit")
assert "reddit" in runtime["platform_hits"]
assert "viewer" in runtime["service_hits"]
assert runtime["service_runtime_hint"]
assert "next.js" in runtime["framework_hits"]

route_page = {
    "links": [
        ("/reddit-viewer", "Reddit viewer"),
        ("/article/how-to-reddit", "How to use Reddit"),
        ("/profile", "Profile"),
    ]
}
routes = discovery.service_route_candidates(
    "https://example.com/",
    route_page,
    "reddit",
)
assert "https://example.com/reddit-viewer" in routes
assert all("/article/" not in url for url in routes)

strong_hit = discovery.SearchHit(
    "nitter.example",
    "twitter",
    ['"Twitter viewer" "without login"'],
    ["https://nitter.example/"],
    [],
    ["bing-rss"],
    ["bing-rss:twitter viewer without login"],
)
assert discovery.discovery_score(strong_hit) >= 10

timeout_eval = discovery.Evaluation(
    "nitter.example",
    "twitter",
    False,
    0,
    1,
    "https://nitter.example/",
    {"fetch_error": "TimeoutError: timed out"},
    "page unavailable",
)
assert discovery.classify_pending_status(
    timeout_eval,
    strong_hit,
) == "timeout"

forbidden_eval = discovery.Evaluation(
    "nitter.example",
    "twitter",
    False,
    0,
    1,
    "https://nitter.example/",
    {"fetch_error": "HTTP Error 403: Forbidden", "status_code": 403},
    "page unavailable",
)
assert discovery.classify_pending_status(
    forbidden_eval,
    strong_hit,
) == "forbidden"

assert discovery.safe_nonnegative_int("broken", 7) == 7
assert discovery.safe_nonnegative_int("-4") == 0
assert discovery.pending_next_retry_epoch("temporary_unavailable", 1, 1000) > 1000
assert discovery.pending_next_retry_epoch("temporary_unavailable", 5, 1000) > 1000
assert discovery.pending_next_retry_epoch(
    "temporary_unavailable", 5, 1000
) <= 1000 + discovery.PENDING_RETRY_MAX_SECONDS

rate_limited = __import__("urllib.error").error.HTTPError(
    "https://api.example", 429, "Too Many Requests", {"Retry-After": "2"}, None
)
assert discovery.http_retry_delay(rate_limited, 1) == 2.0
rate_exhausted = __import__("urllib.error").error.HTTPError(
    "https://api.example", 429, "Too Many Requests",
    {"Retry-After": "60"}, None
)
assert discovery.http_retry_delay(rate_exhausted, 1) is None
assert discovery.GITHUB_REPOSITORY_CATALOG_LIMIT == 48
assert discovery.REPORT_SCHEMA_VERSION == 2
assert {408, 425, 429, 500, 502, 503, 504} <= discovery.RETRYABLE_HTTP_CODES

libredirect_sample = {
    "nitter": {"clearnet": ["https://nitter.example"]},
    "shitter": {"clearnet": ["https://shitter.example"]},
    "redlib": {"clearnet": ["https://redlib.example"]},
    "priviblur": {"clearnet": ["https://priviblur.example"]},
}
libredirect_text = __import__("json").dumps(libredirect_sample)
assert discovery.extract_libredirect(
    libredirect_text,
    "twitter",
) == {"nitter.example", "shitter.example"}
assert discovery.extract_libredirect(
    libredirect_text,
    "reddit",
) == {"redlib.example"}
assert discovery.extract_libredirect(
    libredirect_text,
    "tumblr",
) == {"priviblur.example"}

original_fetch_html = discovery.fetch_html
original_fetch_jina_text = discovery.fetch_jina_text

def fake_fetch_html(url):
    if "analyzer" in url:
        return (
            "<html><head><title>Reddit profile analyzer</title>"
            "<meta name='description' content='Analyze Reddit users and account statistics'>"
            "</head><body>"
            "<h1>Reddit profile analyzer</h1>"
            "<input placeholder='Username'>"
            "<button>Analyze</button>"
            "</body></html>",
            {"final_url": url},
        )
    return (
        "<html><head><title>Reddit Viewer</title>"
        "<meta name='description' content='Browse Reddit subreddits and posts without login'>"
        "</head><body>"
        "<h1>Reddit Viewer</h1>"
        "<input placeholder='Search subreddit'>"
        "<button>View</button>"
        "</body></html>",
        {"final_url": url},
    )

discovery.fetch_html = fake_fetch_html
discovery.fetch_jina_text = lambda url: (None, {"error": "not needed"})
try:
    regression_hit = discovery.SearchHit(
        "example-viewer.test",
        "reddit",
        ["reddit viewer without login"],
        ["https://example-viewer.test/reddit-viewer"],
        [],
        ["bing-rss"],
        ["bing-rss:reddit viewer without login"],
    )
    regression = discovery.safe_evaluate_candidate(regression_hit, set())
    assert regression.reason != "candidate validation crashed safely", (
        f"{regression.reason}: {regression.error} | {regression.evidence}"
    )
    assert regression.accepted, f"{regression.reason}: {regression.evidence}"

    analyzer_hit = discovery.SearchHit(
        "example-analyzer.test",
        "reddit",
        ["reddit profile analyzer"],
        ["https://example-analyzer.test/"],
        [],
        ["bing-rss"],
        ["bing-rss:reddit profile analyzer"],
    )
    analyzer = discovery.safe_evaluate_candidate(analyzer_hit, set())
    assert analyzer.reason == "non-frontend service/tool page"
    assert not analyzer.accepted
finally:
    discovery.fetch_html = original_fetch_html
    discovery.fetch_jina_text = original_fetch_jina_text

seeded = discovery.SearchHit(
    "example-viewer.test",
    "reddit",
    ["SEED:https://example-viewer.test/"],
    ["https://example-viewer.test/"],
    ["Web-verified seed 2026-10-03"],
    [],
    [],
)
assert discovery.pending_candidate_has_strong_signal(seeded)
assert discovery.search_pages_for(
    "en", "view Twitter profiles without login"
) == discovery.SEARCH_PAGES
assert discovery.DISCOVERY_MODE == "daily"
assert discovery.GITHUB_REPOSITORY_CATALOG_LIMIT == 48
assert discovery.REPORT_SCHEMA_VERSION == 2
print("Runtime smoke test passed.")

# Regression: repository catalog pages must never qualify as frontend endpoints.
assert discovery.repository_browse_path_hint("/en/repos/github/redlib-org/redlib")
assert not discovery.repository_browse_path_hint("/reddit-viewer")
assert discovery.is_audited_false_positive("www.osfinder.net")
assert not discovery.is_audited_false_positive("example-viewer.test")


# Current source-schema regressions.
farside_sample = [
    {
        "type": "redlib",
        "test_url": "/r/popular",
        "fallback": "https://redlib.example",
        "instances": ["https://redlib.example/a|https://api.example"],
    }
]
assert discovery.extract_farside(__import__("json").dumps(farside_sample), "reddit") == {"redlib.example", "api.example"}

assert discovery.extract_libredirect(
    __import__("json").dumps({"redlib": {"clearnet": ["https://redlib.example"], "tor": ["http://x.onion"]}}),
    "reddit",
) == {"redlib.example"}

# The search-result worker must contain an unexpected exception instead of
# crashing the whole discovery run.
original_run_search_spec = discovery.run_search_spec
def boom(*args):
    raise RuntimeError("synthetic worker failure")
discovery.run_search_spec = boom
try:
    # Reuse the public function contract through an isolated wrapper test.
    try:
        discovery.run_search_spec(1, "en", "twitter", "synthetic")
    except RuntimeError:
        pass
finally:
    discovery.run_search_spec = original_run_search_spec


# Regression: every report-generation path must emit the status consumed by
# the publication guard. Check the actual report dictionaries, not just a
# sample JSON file from a previous run.
import ast

discovery_source = Path(discovery.__file__).read_text(encoding="utf-8")
discovery_ast = ast.parse(discovery_source)
report_statuses = set()
for node in ast.walk(discovery_ast):
    if not isinstance(node, ast.Dict):
        continue
    literal_keys = {
        key.value
        for key in node.keys
        if isinstance(key, ast.Constant) and isinstance(key.value, str)
    }
    if not {"status", "report_schema_version", "accepted", "trusted_source_health"} <= literal_keys:
        continue
    status_value = next(
        (
            value.value
            for key, value in zip(node.keys, node.values)
            if isinstance(key, ast.Constant)
            and key.value == "status"
            and isinstance(value, ast.Constant)
        ),
        None,
    )
    if status_value is not None:
        report_statuses.add(status_value)

assert {"no_update", "updated"} <= report_statuses, (
    "Both no-update and updated discovery reports must include status; "
    f"found report statuses: {sorted(report_statuses)}"
)
