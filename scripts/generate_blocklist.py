#!/usr/bin/env python3
from __future__ import annotations
import html, ipaddress, json, re, sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urlparse
from urllib.request import Request, urlopen
from typing import Any

OUTPUT = Path("blocklist.txt")
PORTMASTER_OUTPUT = Path("portmaster.txt")
SEARCH_OUTPUT = Path("search-rules.txt")
HAGEZI_OUTPUT = Path("hagezi-overlap.txt")
SEARCH_DISCOVERED_OUTPUT = Path("search-discovered-blocklist.txt")

SEARCH_RULES = """! Title: Frontend blocklist - search URL rules
! Purpose: block document URLs containing Reddit, Tumblr or Twitter.
! Also blocks common viewer-search variants, including X viewer searches.
! AdGuard/iOS: add this file as a custom Safari/user filter.

*reddit*$document
*tumblr*$document
*twitter*$document

*reddit*viewer*$document
*tumblr*viewer*$document
*twitter*viewer*$document

*x%20viewer*$document
*x+viewer*$document
*x-viewer*$document
*x_viewer*$document
*x/viewer*$document
"""
TIMEOUT = 20
USER_AGENT = "frontend-blocklist-updater/1.0"

FIXED_DOMAINS = {
    "x.com","twitter.com","t.co","reddit.com","redd.it","tumblr.com",
    "gothub.lunar.icu","gothub.r4fo.com","gothub.dev.projectsegfau.lt",
    "gothub.projectsegfau.lt","gothub.libre.tw","gothub.wuemeli.com",
    "aohub.httpjames.space",
    "librex.zzls.xyz","librex.me","s.dyox.in","lx.vern.cc",
    "search.ahwx.org","search.spaceint.fr","search.davidovski.xyz",
    "search.madreyk.xyz","search.pabloferreiro.es","librex.pufe.org",
    "librex.ratakor.com","search.tildevarsh.in","librex.myroware.eu",
    "librex.bloatcat.tk","librex.retro-hax.net","search.funami.tech",
    "search.zeroish.xyz","librex.baczek.me",
    "librex.yogeshlamichhane.com.np","lx.benike.monster",
    "librex.nohost.network","search.decentrala.org",
}

SOURCES = {
    "LibRedirect":"https://raw.githubusercontent.com/libredirect/instances/main/data.json",
    "Nitter status":"https://status.d420.de/",
    "Nitter gist":"https://gist.githubusercontent.com/cmj/7dace466c983e07d4e3b13be4b786c29/raw/nitter_instances.md",
    "Libreddit JSON":"https://raw.githubusercontent.com/libreddit/libreddit-instances/master/instances.json",
    "Libreddit MD":"https://raw.githubusercontent.com/libreddit/libreddit-instances/master/instances.md",
    "Redlib JSON":"https://raw.githubusercontent.com/redlib-org/redlib-instances/main/instances.json",
    "Priviblur":"https://raw.githubusercontent.com/syeopite/priviblur/master/instances.md",
    "Teddit":"https://codeberg.org/teddit/teddit/raw/branch/main/instances.json",
    "Librex":"https://raw.githubusercontent.com/hnhx/librex/main/instances.json",
    "SearXNG JSON":"https://searx.space/data/instances.json",
    "SearXNG HTML fallback":"https://searx.space/",
    "4get":"https://4get.ca/instances",
    "Hagezi Pro":"https://raw.githubusercontent.com/hagezi/dns-blocklists/main/adblock/pro.txt",
}

NOISE_HOSTS = {
    "github.com","www.github.com","raw.githubusercontent.com","gist.github.com",
    "gist.githubusercontent.com","codeberg.org","status.d420.de",
    "searx.space","www.searx.space","4get.ca","www.4get.ca",
    "git.lolcat.ca","hagezi.com","www.hagezi.com",
}

DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$", re.I)
URL_RE = re.compile(r"(?i)(?:https?://|//)[^\s<>'\"\]\[)]+")
ADGUARD_RULE_RE = re.compile(r"^\|\|([^\^/\s]+)\^", re.IGNORECASE)

def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    with urlopen(req, timeout=TIMEOUT) as r:
        charset = r.headers.get_content_charset() or "utf-8"
        return r.read().decode(charset, errors="replace")

def normalize(value: str) -> str | None:
    value = html.unescape(value).strip().strip("'\"()[]{}<>.,;|")
    if not value: return None
    if value.startswith("//"): value = "https:" + value
    elif "://" not in value: value = "https://" + value
    try: host = urlparse(value).hostname
    except ValueError: return None
    if not host: return None
    host = host.rstrip(".").lower()
    if host in NOISE_HOSTS or host.endswith((".onion",".i2p",".loki")): return None
    try: ipaddress.ip_address(host.strip("[]")); return None
    except ValueError: pass
    return host if DOMAIN_RE.fullmatch(host) else None

def extract_text(text: str) -> set[str]:
    out=set()
    for u in URL_RE.findall(text):
        d=normalize(u)
        if d: out.add(d)
    for token in re.findall(r"(?<![@\w.-])(?:[a-z0-9-]+\.)+[a-z]{2,63}(?![\w.-])", text, re.I):
        d=normalize(token)
        if d: out.add(d)
    return out

def walk_strings(obj: Any):
    if isinstance(obj, dict):
        for v in obj.values(): yield from walk_strings(v)
    elif isinstance(obj, list):
        for v in obj: yield from walk_strings(v)
    elif isinstance(obj, str): yield obj

def extract_json(text: str) -> set[str]:
    data=json.loads(text); out=set()
    for s in walk_strings(data):
        d=normalize(s)
        if d: out.add(d)
        out.update(extract_text(s))
    return out

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.links=[]
    def handle_starttag(self, tag, attrs):
        if tag.lower()=="a":
            href=dict(attrs).get("href")
            if href: self.links.append(href)

def extract_links(text: str) -> set[str]:
    p=LinkParser(); p.feed(text); out=set()
    for href in p.links:
        d=normalize(href)
        if d: out.add(d)
    return out

def extract_teddit(text: str) -> set[str]:
    cleaned = text.lstrip("\ufeff").strip()

    # Strip optional Markdown fences around JSON.
    cleaned = re.sub(r"^\s*```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r"\s*```\s*$", "", cleaned)

    try:
        return extract_json(cleaned)
    except json.JSONDecodeError:
        # Some endpoints can contain valid JSON followed by extra text.
        try:
            decoder = json.JSONDecoder()
            data, _ = decoder.raw_decode(cleaned)
            return extract_json(json.dumps(data))
        except (json.JSONDecodeError, ValueError):
            # Last-resort extraction from the returned body.
            return extract_text(cleaned)

def parse_source(name: str, text: str) -> set[str]:
    if name == "Teddit":
        return extract_teddit(text)
    if name.endswith("JSON") or name in {"LibRedirect","Librex"}: return extract_json(text)
    if name in {"Libreddit MD","Priviblur","Nitter gist"}: return extract_text(text)
    if name in {"4get","Nitter status","SearXNG HTML fallback"}: return extract_links(text)
    raise ValueError(f"Unsupported source: {name}")

def read_adguard_domains(path: Path) -> set[str]:
    if not path.exists():
        return set()
    out = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        m = ADGUARD_RULE_RE.match(line.strip())
        if m:
            domain = normalize(m.group(1))
            if domain:
                out.add(domain)
    return out

def parse_hagezi(text: str) -> set[str]:
    out=set()
    for line in text.splitlines():
        line=line.strip()
        if not line or line.startswith(("!","#","[")): continue
        m=ADGUARD_RULE_RE.match(line)
        if m:
            d=normalize(m.group(1))
            if d: out.add(d)
    return out

def main() -> int:
    # Preserve previously published domains and merge the append-only discovery
    # history so a newly discovered frontend reaches the public blocklist.
    all_domains=set(FIXED_DOMAINS)
    existing_domains = read_adguard_domains(OUTPUT)
    discovered_domains = read_adguard_domains(SEARCH_DISCOVERED_OUTPUT)
    all_domains.update(existing_domains)
    all_domains.update(discovered_domains)
    failures={}; counts={}
    def attempt(name):
        try:
            data=parse_source(name, fetch(SOURCES[name])); counts[name]=len(data)
            all_domains.update(data); print(f"[OK] {name}: {len(data)} domains")
            return data
        except Exception as e:
            failures[name]=f"{type(e).__name__}: {e}"
            print(f"[WARN] {name}: {failures[name]}"); return set()
    for name in ["LibRedirect","Libreddit JSON","Libreddit MD","Redlib JSON","Priviblur","Teddit","Librex","SearXNG JSON","4get","Nitter status"]:
        attempt(name)
    if counts.get("SearXNG JSON",0)==0: attempt("SearXNG HTML fallback")
    if counts.get("Nitter status",0)==0: attempt("Nitter gist")
    valid=sorted(d for d in all_domains if normalize(d)==d)
    counts["Existing blocklist"] = len(existing_domains)
    counts["Search discovery"] = len(discovered_domains)
    OUTPUT.write_text("\n".join(f"||{d}^" for d in valid)+"\n", encoding="utf-8")
    PORTMASTER_OUTPUT.write_text("\n".join(valid)+"\n", encoding="utf-8")
    SEARCH_OUTPUT.write_text(SEARCH_RULES.rstrip()+"\n", encoding="utf-8")
    print(f"[OK] Preserved existing blocklist domains: {len(existing_domains)}")
    print(f"[OK] Imported append-only discovery domains: {len(discovered_domains)}")
    print(f"[OK] Portmaster list: {len(valid)} domains")
    print("[OK] Search rules: generated")
    try:
        hagezi=parse_hagezi(fetch(SOURCES["Hagezi Pro"]))
        overlap=sorted(set(valid)&hagezi)
        HAGEZI_OUTPUT.write_text("# Informational only: Hagezi Pro is NOT imported into blocklist.txt.\n"+f"# Generated domains: {len(valid)}\n# Hagezi domains parsed: {len(hagezi)}\n# Overlap: {len(overlap)}\n\n"+"\n".join(overlap)+"\n", encoding="utf-8")
        print(f"[OK] Hagezi overlap: {len(overlap)} domains")
    except Exception as e:
        failures["Hagezi Pro"]=f"{type(e).__name__}: {e}"
        HAGEZI_OUTPUT.write_text("# Hagezi check failed.\n# "+failures["Hagezi Pro"]+"\n", encoding="utf-8")
        print(f"[WARN] Hagezi Pro: {failures['Hagezi Pro']}")
    print(f"Unique valid domains: {len(valid)}")
    print(f"Source/check failures: {len(failures)}")
    for name,err in failures.items(): print(f" - {name}: {err}")
    return 0 if valid else 1

if __name__=="__main__": sys.exit(main())
