#!/usr/bin/env python3
"""webprint — fingerprint the technologies a website runs.

Fetches a URL once and infers the server, framework/language, CMS, CDN/WAF, and
analytics from response headers, cookies, and HTML signatures. A lightweight
take on what Wappalyzer does, for the recon phase of an authorized assessment.

Standard library only.
"""
from __future__ import annotations

import argparse
import json
import re
import ssl
import sys
import urllib.request
from typing import Optional

__version__ = "1.0.0"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/123.0 Safari/537.36"
)

# (category, name, source, pattern). source: header:<name> | any-header | body | cookie
SIGNATURES: list[tuple[str, str, str, str]] = [
    # CDN / WAF
    ("cdn", "Cloudflare", "header:server", r"cloudflare"),
    ("cdn", "Cloudflare", "header:cf-ray", r".+"),
    ("cdn", "Fastly", "any-header", r"x-served-by.*cache|fastly"),
    ("cdn", "Akamai", "any-header", r"akamai"),
    ("cdn", "Vercel", "header:server", r"vercel"),
    ("cdn", "Vercel", "header:x-vercel-id", r".+"),
    ("cdn", "Netlify", "any-header", r"netlify"),
    ("cdn", "Amazon CloudFront", "any-header", r"cloudfront"),
    # Servers
    ("server", "nginx", "header:server", r"nginx"),
    ("server", "Apache", "header:server", r"apache"),
    ("server", "Microsoft IIS", "header:server", r"iis|microsoft-iis"),
    ("server", "LiteSpeed", "header:server", r"litespeed"),
    # Language / framework
    ("language", "PHP", "any-header", r"x-powered-by.*php|php/\d"),
    ("language", "PHP", "cookie", r"PHPSESSID"),
    ("language", "ASP.NET", "any-header", r"asp\.net|x-aspnet-version"),
    ("language", "Java", "cookie", r"JSESSIONID"),
    ("framework", "Express", "header:x-powered-by", r"express"),
    ("framework", "Laravel", "cookie", r"laravel_session"),
    ("framework", "Django", "cookie", r"csrftoken|django"),
    ("framework", "Ruby on Rails", "cookie", r"_rails|_session_id"),
    ("framework", "Next.js", "any-header", r"x-nextjs|next\.js"),
    ("framework", "Next.js", "body", r'id="__next"|/_next/static'),
    ("framework", "React", "body", r"react(?:\.min)?\.js|data-reactroot"),
    ("framework", "Vue.js", "body", r"vue(?:\.min)?\.js|data-v-[0-9a-f]{8}"),
    ("framework", "Angular", "body", r"ng-version|angular(?:\.min)?\.js"),
    ("library", "jQuery", "body", r"jquery[.-]\d|jquery(?:\.min)?\.js"),
    # CMS
    ("cms", "WordPress", "body", r"wp-content|wp-includes|<meta name=\"generator\" content=\"WordPress"),
    ("cms", "Drupal", "body", r"Drupal\.settings|/sites/default/files"),
    ("cms", "Joomla", "body", r"/media/jui/|com_content"),
    ("cms", "Shopify", "any-header", r"shopify"),
    ("cms", "Ghost", "body", r"content=\"Ghost"),
    ("cms", "Hugo", "body", r'content="Hugo'),
    # Analytics
    ("analytics", "Google Analytics", "body", r"google-analytics\.com|gtag\(|googletagmanager"),
    ("analytics", "Plausible", "body", r"plausible\.io"),
    ("analytics", "Hotjar", "body", r"hotjar"),
]


class Colors:
    GREEN = "\033[32m"
    CYAN = "\033[36m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    @classmethod
    def disable(cls) -> None:
        for n in ("GREEN", "CYAN", "DIM", "BOLD", "RESET"):
            setattr(cls, n, "")


def normalize_url(target: str) -> str:
    return target if target.startswith(("http://", "https://")) else "https://" + target


def fetch(url: str, timeout: float) -> tuple[dict[str, str], str, str, str]:
    req = urllib.request.Request(url, headers={"User-Agent": UA})
    ctx = ssl.create_default_context()
    with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        cookies = "; ".join(resp.headers.get_all("Set-Cookie") or [])
        body = resp.read(300000).decode("utf-8", errors="ignore")
        final_url = resp.geturl()
    return headers, cookies, body, final_url


def match(sig_source: str, pattern: str, headers: dict, cookies: str, body: str) -> bool:
    rx = re.compile(pattern, re.IGNORECASE)
    if sig_source.startswith("header:"):
        return bool(rx.search(headers.get(sig_source.split(":", 1)[1], "")))
    if sig_source == "any-header":
        joined = "\n".join(f"{k}: {v}" for k, v in headers.items())
        return bool(rx.search(joined))
    if sig_source == "cookie":
        return bool(rx.search(cookies))
    if sig_source == "body":
        return bool(rx.search(body))
    return False


def detect(headers: dict, cookies: str, body: str) -> dict[str, list[str]]:
    out: dict[str, list[str]] = {}
    for category, name, source, pattern in SIGNATURES:
        if match(source, pattern, headers, cookies, body):
            out.setdefault(category, [])
            if name not in out[category]:
                out[category].append(name)
    return out


def title_of(body: str) -> Optional[str]:
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.IGNORECASE | re.DOTALL)
    return re.sub(r"\s+", " ", m.group(1)).strip() if m else None


def main(argv: Optional[list[str]] = None) -> int:
    p = argparse.ArgumentParser(prog="webprint", description=__doc__.splitlines()[0])
    p.add_argument("target", help="URL or hostname")
    p.add_argument("--json", action="store_true")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--timeout", type=float, default=15.0)
    p.add_argument("--version", action="version", version=__version__)
    args = p.parse_args(argv)

    if args.no_color or args.json or not sys.stdout.isatty():
        Colors.disable()
    c = Colors

    url = normalize_url(args.target.strip())
    try:
        headers, cookies, body, final_url = fetch(url, args.timeout)
    except Exception as exc:  # noqa: BLE001 - report any fetch failure cleanly
        print(f"error: could not fetch {url}: {exc}", file=sys.stderr)
        return 2

    found = detect(headers, cookies, body)
    title = title_of(body)

    if args.json:
        print(json.dumps({
            "url": final_url, "title": title,
            "server": headers.get("server"),
            "technologies": found,
        }, indent=2))
        return 0

    print(f"{c.BOLD}webprint{c.RESET} {c.DIM}{final_url}{c.RESET}")
    if title:
        print(f"  {c.DIM}{title}{c.RESET}")
    print()
    order = ["server", "language", "framework", "library", "cms", "cdn", "analytics"]
    if not found:
        print(f"  {c.DIM}no known signatures matched{c.RESET}")
    for cat in order:
        if cat in found:
            print(f"  {c.CYAN}{cat:<11}{c.RESET}{c.GREEN}{', '.join(found[cat])}{c.RESET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
