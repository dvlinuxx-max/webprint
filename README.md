# webprint

Fingerprint the technologies a website runs. Fetches a URL once and infers the
server, language/framework, CMS, CDN/WAF, and analytics from response headers,
cookies, and HTML signatures. A lightweight take on Wappalyzer for the recon
phase of an authorized assessment.

## Usage

```bash
python webprint.py example.com
python webprint.py https://example.com --json
```

## Example

```
$ python webprint.py wordpress.com

webprint https://wordpress.com
  WordPress.com: Everything You Need to Build Your Website

  server     nginx
  cms        WordPress
  analytics  Google Analytics
```

```
$ python webprint.py vercel.com

webprint https://vercel.com

  framework  Next.js
  cdn        Vercel
```

## What it detects

- CDN / WAF: Cloudflare, Fastly, Akamai, CloudFront, Vercel, Netlify.
- Servers: nginx, Apache, IIS, LiteSpeed.
- Language / framework: PHP, ASP.NET, Java, Express, Laravel, Django, Rails,
  Next.js, React, Vue, Angular, jQuery.
- CMS: WordPress, Drupal, Joomla, Shopify, Ghost, Hugo.
- Analytics: Google Analytics, Plausible, Hotjar.

## How it works

```
webprint.py
  SIGNATURES   (category, name, source, regex) over headers/cookies/body
  fetch        one GET, capture headers, set-cookie, first 300 KB of HTML
  detect       run every signature, group matches by category
```

A single request, no brute forcing. Sites that strip identifying headers and
use custom stacks (GitHub, for example) may match nothing — webprint reports
what it can see rather than guessing.

## Requirements

Python 3.9+, network access. No third-party packages.

## License

MIT
