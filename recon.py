#!/usr/bin/env python3
"""
Full Recon Suite  (no bs4 — stdlib + requests only)
  1. Subdomain enum  — crt.sh, certspotter, hackertarget, alienvault,
                       rapiddns, urlscan, bufferover, assetfinder, subfinder
  2. Live probe      — 200/3xx/401/403  →  subdomains.txt + subdomains_200.txt
  3. JS scan         — regex-only HTML parse, endpoint + interesting-link extract
                       →  <domain>_api-endpoints.txt

Usage:
    python3 recon.py <domain> [--threads N] [--timeout N] [--delay F] [--skip-tools]
"""

import re, sys, json, time, random, argparse, subprocess
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("\033[91m[!] Missing: pip install requests\033[0m")
    sys.exit(1)


# ── Colors ─────────────────────────────────────────────────────────────────────
class C:
    R="\033[0m"; B="\033[1m"
    RED="\033[91m"; GRN="\033[92m"; YLW="\033[93m"
    BLU="\033[94m"; MGT="\033[95m"; CYN="\033[96m"
    WHT="\033[97m"; GRY="\033[90m"; ORG="\033[38;5;208m"

_lock = Lock()

def log(color, tag, msg):
    with _lock:
        print(f"{color}{C.B}{tag}{C.R}{color} {msg}{C.R}")

def section(title):
    w = 58
    print(f"\n{C.CYN}{C.B}{'─'*w}{C.R}")
    print(f"{C.CYN}{C.B}  {title}{C.R}")
    print(f"{C.CYN}{C.B}{'─'*w}{C.R}\n")

def banner(domain, args):
    print(f"""
{C.CYN}{C.B}╔══════════════════════════════════════════════════════════╗
║            Full Recon Suite  v2.0  (no bs4)              ║
║   subdomain enum → live probe → JS endpoint extract      ║
╚══════════════════════════════════════════════════════════╝{C.R}
{C.YLW}  Target   : {C.WHT}{domain}{C.R}
{C.YLW}  Threads  : {C.WHT}{args.threads}{C.R}
{C.YLW}  Timeout  : {C.WHT}{args.timeout}s{C.R}
{C.YLW}  JS Delay : {C.WHT}{args.delay}s (+jitter){C.R}
{C.YLW}  Started  : {C.WHT}{time.strftime('%Y-%m-%d %H:%M:%S')}{C.R}
""")


# ── HTTP helpers ───────────────────────────────────────────────────────────────
UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_3) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:124.0) Gecko/20100101 Firefox/124.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 Chrome/112.0.0.0 Mobile Safari/537.36",
    "curl/8.4.0",
    "python-httpx/0.27.0",
    "Wget/1.21.4",
    "Go-http-client/2.0",
]

def rand_hdrs():
    return {
        "User-Agent": random.choice(UAS),
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.7",
        "Connection": "keep-alive",
    }

def get(url, timeout=10, allow_redirects=True):
    try:
        return requests.get(url, headers=rand_hdrs(), timeout=timeout,
                            verify=False, allow_redirects=allow_redirects)
    except Exception:
        return None

def get_text(url, timeout=10):
    r = get(url, timeout=timeout)
    return r.text if r else None


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 1 — Subdomain Enumeration
# ══════════════════════════════════════════════════════════════════════════════

def run_cli(cmd):
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        return set(filter(None, p.stdout.strip().splitlines()))
    except FileNotFoundError:
        return set()
    except Exception:
        return set()

def _clean(subs, domain):
    out = set()
    for s in subs:
        s = s.strip().lower().lstrip("*.")
        if s and domain in s and " " not in s:
            out.add(s)
    return out

def src_crtsh(domain):
    subs = set()
    try:
        r = requests.get(f"https://crt.sh/?q=%.{domain}&output=json",
                         headers=rand_hdrs(), timeout=20, verify=False)
        for e in r.json():
            for n in e.get("name_value","").splitlines():
                subs.add(n)
    except Exception:
        pass
    return _clean(subs, domain)

def src_certspotter(domain):
    subs = set()
    try:
        r = requests.get(
            f"https://api.certspotter.com/v1/issuances?domain={domain}"
            f"&include_subdomains=true&expand=dns_names",
            headers=rand_hdrs(), timeout=20, verify=False)
        for e in r.json():
            for n in e.get("dns_names", []):
                subs.add(n)
    except Exception:
        pass
    return _clean(subs, domain)

def src_hackertarget(domain):
    subs = set()
    try:
        text = get_text(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
        if text and "error" not in text[:50].lower():
            for line in text.splitlines():
                subs.add(line.split(",")[0])
    except Exception:
        pass
    return _clean(subs, domain)

def src_alienvault(domain):
    subs = set()
    try:
        page = 1
        while page <= 5:
            r = requests.get(
                f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}"
                f"/passive_dns?page={page}",
                headers=rand_hdrs(), timeout=15, verify=False)
            data = r.json()
            for e in data.get("passive_dns", []):
                subs.add(e.get("hostname", ""))
            if not data.get("has_next"):
                break
            page += 1
            time.sleep(0.3)
    except Exception:
        pass
    return _clean(subs, domain)

def src_rapiddns(domain):
    subs = set()
    try:
        r = requests.get(f"https://rapiddns.io/subdomain/{domain}?full=1",
                         headers=rand_hdrs(), timeout=15, verify=False)
        subs = set(re.findall(
            r'<td>([\w.\-]+\.' + re.escape(domain) + r')</td>', r.text, re.I))
    except Exception:
        pass
    return _clean(subs, domain)

def src_urlscan(domain):
    subs = set()
    try:
        r = requests.get(
            f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=200",
            headers=rand_hdrs(), timeout=15, verify=False)
        for res in r.json().get("results", []):
            subs.add(res.get("page", {}).get("domain", ""))
    except Exception:
        pass
    return _clean(subs, domain)

def src_bufferover(domain):
    subs = set()
    try:
        r = requests.get(f"https://dns.bufferover.run/dns?q=.{domain}",
                         headers=rand_hdrs(), timeout=15, verify=False)
        data = r.json()
        for rec in data.get("FDNS_A", []) + data.get("RDNS", []):
            parts = rec.split(",")
            if len(parts) >= 2:
                subs.add(parts[1].strip().rstrip("."))
    except Exception:
        pass
    return _clean(subs, domain)

def src_assetfinder(domain):
    log(C.BLU, "[TOOL]", "assetfinder ...")
    s = _clean(run_cli(["assetfinder", "--subs-only", domain]), domain)
    log(C.GRN if s else C.GRY, "[TOOL]", f"assetfinder  -> {len(s)}")
    return s

def src_subfinder(domain):
    log(C.BLU, "[TOOL]", "subfinder ...")
    s = _clean(run_cli(["subfinder", "-d", domain, "-silent"]), domain)
    log(C.GRN if s else C.GRY, "[TOOL]", f"subfinder    -> {len(s)}")
    return s

API_SOURCES = [
    ("crt.sh",       src_crtsh),
    ("certspotter",  src_certspotter),
    ("hackertarget", src_hackertarget),
    ("alienvault",   src_alienvault),
    ("rapiddns",     src_rapiddns),
    ("urlscan",      src_urlscan),
    ("bufferover",   src_bufferover),
]

def phase1(domain, skip_tools):
    section("PHASE 1 - Subdomain Enumeration")
    all_subs = {domain}

    with ThreadPoolExecutor(max_workers=len(API_SOURCES)) as ex:
        futures = {ex.submit(fn, domain): name for name, fn in API_SOURCES}
        for f in as_completed(futures):
            name = futures[f]
            try:
                result = f.result()
                all_subs.update(result)
                col = C.GRN if result else C.GRY
                log(col, f"  [{name}]", f"{len(result)} subdomains")
            except Exception as e:
                log(C.RED, f"  [{name}]", f"error: {e}")

    if not skip_tools:
        all_subs.update(src_assetfinder(domain))
        all_subs.update(src_subfinder(domain))

    all_subs = sorted(all_subs)
    log(C.MGT, "\n[+]", f"Total unique subdomains: {C.B}{C.WHT}{len(all_subs)}{C.R}")
    return all_subs


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 2 — Live Host Probing
# ══════════════════════════════════════════════════════════════════════════════

INTERESTING = {200, 201, 204, 301, 302, 303, 307, 308, 401, 403}

STATUS_COL = {
    200: C.GRN, 201: C.GRN, 204: C.GRN,
    301: C.YLW, 302: C.YLW, 303: C.YLW, 307: C.YLW, 308: C.YLW,
    401: C.ORG, 403: C.ORG,
}

def probe(sub, timeout):
    for scheme in ("https", "http"):
        url = f"{scheme}://{sub}"
        try:
            r = requests.get(url, headers=rand_hdrs(), timeout=timeout,
                             verify=False, allow_redirects=True)
            if r.status_code in INTERESTING:
                return url, r.status_code, r.url
        except Exception:
            continue
    return None

def phase2(subdomains, threads, timeout):
    section("PHASE 2 - Live Host Probing")
    live, live_200 = [], []
    total = len(subdomains)
    done = 0

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(probe, s, timeout): s for s in subdomains}
        for f in as_completed(futures):
            done += 1
            res = f.result()
            if res:
                url, code, final = res
                col = STATUS_COL.get(code, C.GRY)
                final_short = str(final)[:72]
                log(col, f"  [{code}]", f"{url}  {C.GRY}-> {final_short}{C.R}")
                live.append((url, code, str(final)))
                if code == 200:
                    live_200.append(url)

            # inline progress bar
            pct = int((done / total) * 44)
            bar = "#" * pct + "." * (44 - pct)
            with _lock:
                print(f"\r{C.CYN}  [{bar}] {done}/{total}{C.R}  ", end="", flush=True)

    print()
    log(C.GRN, "\n[+]", f"Live: {C.B}{len(live)}{C.R}  |  200-only: {C.B}{len(live_200)}{C.R}")
    return live, live_200


# ══════════════════════════════════════════════════════════════════════════════
# PHASE 3 — JS Discovery & Endpoint Extraction  (regex-only, no bs4)
# ══════════════════════════════════════════════════════════════════════════════

RE_SCRIPT_SRC = re.compile(
    r'<script[^>]+src=["\']([^"\']+\.js(?:\?[^"\']*)?)["\']', re.I)
RE_JS_BARE = re.compile(r'["\']([^"\']*\.js(?:\?[^"\']*)?)["\']')

EP_PATTERNS = [
    re.compile(
        r'["\`](\/(?:api|v\d+|rest|graphql|gql|auth|oauth|rpc|ws|wss|'
        r'service|services|data|query|mutation|admin|public|private|internal|'
        r'mobile|gateway|proxy|backend|user|users|account|order|product|payment|'
        r'invoice|report|analytics|upload|download|file|media|config|health|'
        r'status|ping|token|refresh|login|logout|register|signup|profile|'
        r'dashboard|notification|message|email|sms|webhook|event|log|search|'
        r'filter|batch|export|import|sync|stream|subscribe)'
        r'[\/\w\-\.:\{\}?=&%#]*)["\`]', re.I),
    re.compile(
        r'(?:fetch|axios\.(?:get|post|put|patch|delete|request))\s*\(\s*'
        r'["\`]([^"\`\s]{4,})["\`]', re.I),
    re.compile(
        r'(?:baseURL|baseUrl|BASE_URL|API_URL|apiUrl|apiEndpoint|endpoint|host)'
        r'\s*[=:]\s*["\`]([^"\`\s]{5,})["\`]', re.I),
    re.compile(
        r'["\`](https?://[^\s"\`\'<>]{10,}'
        r'(?:api|v\d+|rest|graphql|auth|service|gateway)'
        r'[^\s"\`\'<>]*)["\`]', re.I),
    re.compile(r'["\`](\/[\w\-]{2,}\/[\w\-\/\.\{\}:?=&%]{2,})["\`]'),
]

NOISE = re.compile(
    r'\.(png|jpe?g|gif|svg|ico|woff2?|ttf|eot|css|map|html?|txt|md)(\?.*)?$'
    r'|^\/\/'
    r'|node_modules'
    r'|\/\*',
    re.I
)

INTERESTING_RE = re.compile(
    r'["\`]((?:https?:\/\/[^\s"\`\'<>]+|\/[\w\-\/\.]+)'
    r'(?:admin|panel|dashboard|login|signup|register|api|swagger|graphql|'
    r'debug|test|dev|staging|internal|config|\.env|\.git|backup|dump|'
    r'db|database|secret|key|token|password)[^\s"\`\'<>]*)["\`]',
    re.I
)

def find_js_in_html(base_url, html):
    js = set()
    base_netloc = urlparse(base_url).netloc
    for pat in (RE_SCRIPT_SRC, RE_JS_BARE):
        for m in pat.finditer(html):
            src = m.group(1)
            full = urljoin(base_url, src) if not src.startswith("http") else src
            pu = urlparse(full)
            if not pu.netloc or pu.netloc == base_netloc:
                js.add(full)
    return js

def extract_endpoints(content):
    eps, interesting = set(), set()
    for pat in EP_PATTERNS:
        for m in pat.finditer(content):
            ep = m.group(1).strip()
            if ep and not NOISE.search(ep) and len(ep) > 3:
                eps.add(ep)
    for m in INTERESTING_RE.finditer(content):
        lnk = m.group(1).strip()
        if lnk:
            interesting.add(lnk)
    return eps, interesting

def scan_js_file(js_url, delay, idx, total, timeout):
    time.sleep(delay + random.uniform(0, delay * 0.5))
    short = js_url.split("/")[-1][:55]
    log(C.BLU, f"  [{idx:>3}/{total}]", f"-> {C.CYN}{short}{C.R}")
    text = get_text(js_url, timeout=timeout)
    if not text:
        log(C.GRY, f"  [{idx:>3}/{total}]", "  skip (no content)")
        return js_url, set(), set()
    eps, interesting = extract_endpoints(text)
    col = C.GRN if eps else C.GRY
    log(col, f"  [{idx:>3}/{total}]",
        f"  {C.B}{len(eps)}{C.R}{col} endpoints  "
        f"{C.ORG}{len(interesting)}{C.R} interesting")
    return js_url, eps, interesting

def phase3(live_200_urls, threads, delay, timeout):
    section("PHASE 3 - JS Discovery & Endpoint Extraction")

    all_js = set()
    log(C.YLW, "[*]", f"Fetching {len(live_200_urls)} homepages to find JS files...")
    for url in live_200_urls:
        html = get_text(url, timeout=timeout)
        if html:
            found = find_js_in_html(url, html)
            if found:
                log(C.CYN, "  [JS]", f"{url}  {C.GRY}-> {len(found)} JS files{C.R}")
            all_js.update(found)

    log(C.MGT, "\n[JS]",
        f"Total unique JS files: {C.B}{C.WHT}{len(all_js)}{C.R}\n")

    if not all_js:
        log(C.YLW, "[~]", "No JS files found.")
        return set(), set()

    js_list = sorted(all_js)
    total = len(js_list)
    all_eps, all_interesting = set(), set()

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {
            ex.submit(scan_js_file, url, delay, i+1, total, timeout): url
            for i, url in enumerate(js_list)
        }
        for f in as_completed(futures):
            _, eps, interesting = f.result()
            all_eps.update(eps)
            all_interesting.update(interesting)

    return all_eps, all_interesting


# ══════════════════════════════════════════════════════════════════════════════
# Save helpers
# ══════════════════════════════════════════════════════════════════════════════

def save_subdomains(live, live_200_urls, domain):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    with open("subdomains.txt", "w") as f:
        f.write(f"# Live subdomains -- {domain}  ({ts})\n\n")
        for url, code, final in sorted(live, key=lambda x: x[1]):
            f.write(f"[{code}]  {url:<50}  ->  {final}\n")
    with open("subdomains_200.txt", "w") as f:
        f.write(f"# HTTP-200 subdomains -- {domain}  ({ts})\n\n")
        for url in sorted(live_200_urls):
            f.write(url + "\n")

def save_endpoints(domain, eps, interesting):
    fname = f"{domain}_api-endpoints.txt"
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    with open(fname, "w") as f:
        f.write(f"# API Endpoints -- {domain}  ({ts})\n")
        f.write(f"# endpoints: {len(eps)}   interesting: {len(interesting)}\n")
        f.write("=" * 60 + "\n\n")
        f.write("## API ENDPOINTS\n")
        for ep in sorted(eps):
            f.write(f"  {ep}\n")
        f.write("\n## INTERESTING LINKS\n")
        for lnk in sorted(interesting):
            f.write(f"  {lnk}\n")
    return fname


# ══════════════════════════════════════════════════════════════════════════════
# Print helpers
# ══════════════════════════════════════════════════════════════════════════════

def print_endpoints(eps, interesting):
    if eps:
        log(C.GRN, "\n[ENDPOINTS]",
            f"{C.B}{len(eps)}{C.R}{C.GRN} unique endpoints found:\n")
        for ep in sorted(eps):
            if ep.startswith("http"):
                col = C.MGT
            elif re.search(r'auth|login|token|oauth', ep, re.I):
                col = C.RED
            elif re.search(r'api|v\d|rest|graphql', ep, re.I):
                col = C.GRN
            else:
                col = C.CYN
            log(col, "  >", ep)
    else:
        log(C.GRY, "[~]", "No endpoints extracted.")

    if interesting:
        log(C.ORG, "\n[INTERESTING]",
            f"{C.B}{len(interesting)}{C.R}{C.ORG} interesting links:\n")
        for lnk in sorted(interesting):
            log(C.ORG, "  >", lnk)


# ══════════════════════════════════════════════════════════════════════════════
# Main
# ══════════════════════════════════════════════════════════════════════════════

def main():
    ap = argparse.ArgumentParser(
        description="Full recon: subdomains -> live probe -> JS endpoints",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog="Example:\n  python3 recon.py example.com --threads 15 --timeout 6 --delay 0.3"
    )
    ap.add_argument("domain",
                    help="Target domain  e.g.  example.com")
    ap.add_argument("--threads", "-t", type=int,   default=10,  metavar="N",
                    help="Worker threads  (default: 10)")
    ap.add_argument("--timeout", "-T", type=int,   default=8,   metavar="S",
                    help="HTTP timeout s  (default: 8)")
    ap.add_argument("--delay",   "-d", type=float, default=0.4, metavar="F",
                    help="JS scan delay  (default: 0.4)")
    ap.add_argument("--skip-tools", action="store_true",
                    help="Skip assetfinder / subfinder")
    args = ap.parse_args()

    domain = re.sub(r'^https?://', '', args.domain).split("/")[0].strip().lower()

    banner(domain, args)

    subdomains = phase1(domain, args.skip_tools)

    live, live_200 = phase2(subdomains, args.threads, args.timeout)
    save_subdomains(live, live_200, domain)
    log(C.GRN, "[+]", "Saved -> subdomains.txt  &  subdomains_200.txt")

    live_200_urls = [u for u, c, _ in live if c == 200]
    eps, interesting = phase3(live_200_urls, args.threads, args.delay, args.timeout)
    print_endpoints(eps, interesting)
    ep_file = save_endpoints(domain, eps, interesting)
    log(C.GRN, "[+]", f"Saved -> {ep_file}")

    print(f"""
{C.CYN}{C.B}+{'='*56}+{C.R}
{C.WHT}  Subdomains enumerated : {C.B}{len(subdomains)}{C.R}
{C.WHT}  Live hosts            : {C.B}{len(live)}{C.R}
{C.WHT}  HTTP 200              : {C.B}{len(live_200_urls)}{C.R}
{C.WHT}  API endpoints         : {C.B}{len(eps)}{C.R}
{C.WHT}  Interesting links     : {C.B}{len(interesting)}{C.R}
{C.WHT}  Output files          :
{C.GRY}    subdomains.txt
    subdomains_200.txt
    {ep_file}{C.R}
{C.CYN}{C.B}+{'='*56}+{C.R}
""")


if __name__ == "__main__":
    main()