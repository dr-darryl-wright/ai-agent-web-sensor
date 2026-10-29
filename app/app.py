"""Honeypot site: a small, plain website whose every request is logged.

Lures (app/lures.py) are switched on only when HP_LURES=1. With lures off, every page and file
is byte-for-byte the baseline version (checked by tests/test_lures.py against a saved copy).

Run locally:   HP_LOG_DIR=./logs uvicorn app:app --app-dir app --port 8080
On the server: see deploy/honeypot.service (listens on 127.0.0.1 only, behind Caddy).
"""

from __future__ import annotations

import html
import os

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response
from starlette.routing import Route

from lures import THANKS, LureConfig
from reqlog import LoggingMiddleware, RequestLogger

SITE_NAME = os.environ.get("HP_SITE_NAME", "Field Notes")
DOMAIN = os.environ.get("HP_DOMAIN", "localhost")
CONTACT_EMAIL = os.environ.get("HP_CONTACT_EMAIL", "CONTACT-EMAIL-NOT-SET")
RETAIN_UNTIL = os.environ.get("HP_RETAIN_UNTIL", "31 January 2027")
LOG_DIR = os.environ.get("HP_LOG_DIR", "/var/lib/honeypot/logs")
BASE_URL = f"https://{DOMAIN}"

NO_STORE = {"Cache-Control": "no-store"}  # every visit must reach the server

CSS = """body{max-width:40rem;margin:2rem auto;padding:0 1rem;font:16px/1.6 Georgia,serif;color:#222;background:#fdfdfb}
header{display:flex;align-items:center;gap:.6rem}header img{width:28px;height:28px}
a{color:#2a5d8f}footer{margin-top:3rem;font-size:.85rem;color:#666}code{font-size:.9em}"""

MARK_SVG = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 28 28"><rect x="3" y="3" width="22" height="22" rx="5" fill="none" stroke="#2a5d8f" stroke-width="2"/><path d="M8 18h12M8 13h12M8 8h7" stroke="#2a5d8f" stroke-width="2"/></svg>"""

# Minimal beacon: reports that script ran, and the first scroll / pointer / key / hide
# event. Reads nothing from the device and stores nothing on it.
BEACON_JS = """(function(){var t0=Date.now(),sent={};
function b(e){if(sent[e])return;sent[e]=1;var d=JSON.stringify({e:e,p:location.pathname,ms:Date.now()-t0});
try{if(navigator.sendBeacon&&navigator.sendBeacon('/api/b',d))return;}catch(x){}
try{fetch('/api/b',{method:'POST',body:d,keepalive:true});}catch(x){}}
b('load');
addEventListener('scroll',function(){b('scroll')},{passive:true});
addEventListener('pointermove',function(){b('pointer')},{passive:true});
addEventListener('keydown',function(){b('key')});
document.addEventListener('visibilitychange',function(){if(document.visibilityState==='hidden')b('hidden')});})();"""


def page(title: str, body_html: str, alt: str = "", after_main: str = "", end_of_body: str = "") -> str:
    s = html.escape(SITE_NAME)
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{html.escape(title)} - {s}</title>
<link rel="stylesheet" href="/static/site.css">
</head>
<body>
<header><img src="/static/mark.svg" alt="{alt}"><strong><a href="/">{s}</a></strong></header>
<main>
{body_html}
</main>{after_main}
<footer>Requests to this site are logged for research on automated web traffic. <a href="/privacy">Privacy notice</a>.</footer>
<script src="/static/b.js"></script>{end_of_body}
</body>
</html>
"""


INDEX_BODY = """<h1>Short technical notes</h1>
<p>Small notes on web plumbing, written down so I can find them again.</p>
<ul>
<li><a href="/notes/http-caching">HTTP caching in five headers</a></li>
</ul>"""

CACHING_BODY = """<h1>HTTP caching in five headers</h1>
<p><code>Cache-Control: max-age=N</code> says a response stays fresh for N seconds. Until then a cache may reuse it without asking the server.</p>
<p><code>Cache-Control: no-cache</code> does not mean "do not cache". A cache may store the response but must check with the server before reusing it.</p>
<p><code>Cache-Control: no-store</code> is the one that means "do not keep a copy at all".</p>
<p><code>Cache-Control: private</code> allows the browser's own cache but not shared caches such as a CDN.</p>
<p><code>ETag</code> gives a response a version tag. The client sends it back in <code>If-None-Match</code>; if nothing changed, the server answers <code>304 Not Modified</code> with no body.</p>"""


def privacy_body() -> str:
    return f"""<h1>Privacy notice</h1>
<p>This site is part of a research project on automated web traffic, including AI agents.</p>
<p><strong>What is recorded.</strong> For every request: the time, IP address, the address requested, all request headers (including the browser or program name it reports), any data sent, and connection details such as the TLS version. A small script on each page reports whether scripts ran and whether the page was scrolled, the pointer moved or a key pressed. It does not read or store anything on your device. No cookies are set.</p>
<p><strong>Why.</strong> To measure how people, ordinary bots and AI agents differ in the requests they make.</p>
<p><strong>How long.</strong> Raw logs are kept until {html.escape(RETAIN_UNTIL)} and then deleted. Anything published will have IP addresses removed, except addresses on AI companies' published crawler lists.</p>
<p><strong>Contact.</strong> {html.escape(CONTACT_EMAIL)}, for questions or to ask for records of your IP address to be deleted.</p>"""


def html_response(text: str, status: int = 200) -> Response:
    return Response(text, status_code=status, media_type="text/html; charset=utf-8", headers=NO_STORE)


def text_response(text: str, media_type: str = "text/plain; charset=utf-8", status: int = 200) -> Response:
    return Response(text, status_code=status, media_type=media_type, headers=NO_STORE)


def lures_of(request: Request) -> LureConfig:
    return request.app.state.lures


async def index(request: Request):
    lures = lures_of(request)
    return html_response(page("Notes", INDEX_BODY, after_main=lures.hidden_block(),  # P1
                              end_of_body=lures.html_comment()))                      # P2


async def caching(request: Request):
    return html_response(page("HTTP caching in five headers", CACHING_BODY,
                              alt=lures_of(request).alt_text()))                      # P3


async def privacy(request: Request):
    return html_response(page("Privacy notice", privacy_body()))


async def robots(request: Request):
    return text_response(f"User-agent: *\nAllow: /\n\nSitemap: {BASE_URL}/sitemap.xml\n"
                         + lures_of(request).robots_comment())                         # P5


async def sitemap(request: Request):
    urls = ["/", "/notes/http-caching", "/privacy"]
    items = "".join(f"<url><loc>{BASE_URL}{u}</loc></url>" for u in urls)
    xml = f'<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">{items}</urlset>\n'
    return text_response(xml, media_type="application/xml")


async def llms_txt(request: Request):
    return text_response(
        f"# {SITE_NAME}\n\n> Short technical notes on web plumbing.\n\n"
        f"- [HTTP caching in five headers]({BASE_URL}/notes/http-caching)\n"
        + lures_of(request).llms_block()                                                 # P4
    )


async def css(request: Request):
    return text_response(CSS, media_type="text/css; charset=utf-8")


async def mark(request: Request):
    return text_response(MARK_SVG, media_type="image/svg+xml")


async def beacon_js(request: Request):
    return text_response(BEACON_JS, media_type="text/javascript; charset=utf-8")


async def beacon(request: Request):
    # The body is already in the request log; nothing else to do.
    return Response(status_code=204, headers=NO_STORE)


async def lure_hit(request: Request):
    # Same plain answer for every lure URL, right or wrong answer, known or unknown code.
    # What was asked for is in the request log.
    if not lures_of(request).enabled:
        return text_response("Not found\n", status=404)
    return html_response(THANKS)


async def not_found(request: Request, exc):
    return text_response("Not found\n", status=404)


async def method_not_allowed(request: Request, exc):
    return text_response("Method not allowed\n", status=405)


routes = [
    Route("/", index),
    Route("/notes/http-caching", caching),
    Route("/privacy", privacy),
    Route("/robots.txt", robots),
    Route("/sitemap.xml", sitemap),
    Route("/llms.txt", llms_txt),
    Route("/static/site.css", css),
    Route("/static/mark.svg", mark),
    Route("/static/b.js", beacon_js),
    Route("/api/b", beacon, methods=["POST"]),
    Route("/v/{rest:path}", lure_hit),   # L1 reasoning lure: /v/<code>/<answer>
    Route("/r/{rest:path}", lure_hit),   # L2 self-report:    /r/<code>?for_person=..&model=..
    Route("/c/{rest:path}", lure_hit),   # L3 check with user: /c/<code>/ok
]


class PlainHttpRedirect:
    """Requests that reached Caddy on port 80 arrive marked X-HP-Edge: http80.

    They are logged like everything else, then sent to the HTTPS site with a 301.
    Requests for any other host name on port 80 (e.g. scanners using the bare IP) get 404.
    """

    def __init__(self, app, domain: str):
        self.app = app
        self.domain = domain.lower()

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            hdrs = {k.lower(): v for k, v in scope.get("headers", [])}
            if hdrs.get(b"x-hp-edge") == b"http80":
                host = hdrs.get(b"host", b"").decode("latin-1").split(":")[0].lower()
                if host == self.domain:
                    target = f"https://{self.domain}{scope.get('raw_path', b'/').decode('latin-1')}"
                    if scope.get("query_string"):
                        target += "?" + scope["query_string"].decode("latin-1")
                    resp = Response(status_code=301, headers={"Location": target, **NO_STORE})
                else:
                    resp = text_response("Not found\n", status=404)
                await resp(scope, receive, send)
                return
        await self.app(scope, receive, send)


def create_app(log_dir: str = LOG_DIR, domain: str = DOMAIN, lures: LureConfig | None = None) -> LoggingMiddleware:
    inner = Starlette(routes=routes, exception_handlers={404: not_found, 405: method_not_allowed})
    inner.state.lures = lures if lures is not None else LureConfig.from_env(DOMAIN)
    return LoggingMiddleware(PlainHttpRedirect(inner, domain), RequestLogger(log_dir))


app = create_app()
