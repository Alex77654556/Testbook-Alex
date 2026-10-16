# app.py
import os
import hmac
import base64
import hashlib
import httpx
from fastapi import FastAPI, HTTPException, Response, Form, Cookie, Query
from fastapi.responses import HTMLResponse, RedirectResponse
from bs4 import BeautifulSoup
from pydantic import BaseModel
from typing import List, Optional
from urllib.parse import urljoin, quote
import html as html_lib

app = FastAPI(
    title="Testbook Live Scraper",
    description="Koi bhi user apne Testbook token se login karke live scrape kar sakta hai.",
    version="2.0.0",
)

# ---------- Config ----------
BASE_URL = "https://testbook.com"
DEFAULT_PATH = "/rrb-group-d/test-series/my"
TARGET_URL = BASE_URL + DEFAULT_PATH

# Sirf cookie signing ke liye — token nahi. Random string set karo env me.
SESSION_SECRET = os.getenv("SESSION_SECRET", "change-me-please-please")

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
)


def get_headers(token: str) -> dict:
    """Bearer token ke saath headers banao."""
    return {
        "User-Agent": UA,
        "Authorization": f"Bearer {token}",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,"
                  "image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": BASE_URL + "/",
        "Origin": BASE_URL,
    }


# ---------- Signed cookie helpers (stateless — Vercel/Serverless friendly) ----------
def sign_token(token: str) -> str:
    data = base64.urlsafe_b64encode(token.encode()).decode()
    sig = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{data}.{sig}"


def unsign_token(cookie: str) -> Optional[str]:
    try:
        data, sig = cookie.rsplit(".", 1)
        expected = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(sig, expected):
            return None
        return base64.urlsafe_b64decode(data.encode()).decode()
    except Exception:
        return None


def get_token(session_cookie: Optional[str]) -> Optional[str]:
    """Sirf cookie se token lo. Koi hardcoded fallback nahi."""
    if not session_cookie:
        return None
    return unsign_token(session_cookie)


# ---------- Models ----------
class TestInfo(BaseModel):
    title: str
    link: str
    description: Optional[str] = None


class ScrapeResult(BaseModel):
    page_url: str
    count: int
    tests: List[TestInfo]


# ---------- Login page HTML ----------
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Testbook Token Login</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
    min-height: 100vh; display: flex; align-items: center; justify-content: center;
    padding: 20px;
  }
  .card {
    background: #fff; border-radius: 16px; box-shadow: 0 20px 60px rgba(0,0,0,.3);
    padding: 40px; width: 100%; max-width: 480px;
  }
  h1 { color: #1a202c; font-size: 24px; margin-bottom: 8px; }
  p.sub { color: #718096; font-size: 14px; margin-bottom: 24px; }
  label { display: block; font-size: 13px; color: #4a5568; font-weight: 600; margin-bottom: 8px; }
  textarea {
    width: 100%; padding: 12px 14px; border: 1.5px solid #e2e8f0; border-radius: 10px;
    font-size: 13px; font-family: ui-monospace, Menlo, Consolas, monospace;
    transition: border-color .2s; resize: vertical;
  }
  textarea:focus { outline: none; border-color: #667eea; box-shadow: 0 0 0 3px rgba(102,126,234,.15); }
  button {
    width: 100%; padding: 13px; background: linear-gradient(135deg, #667eea, #764ba2);
    color: #fff; border: none; border-radius: 10px; font-size: 15px; font-weight: 600;
    cursor: pointer; margin-top: 20px; transition: transform .15s, box-shadow .15s;
  }
  button:hover { transform: translateY(-1px); box-shadow: 0 8px 20px rgba(102,126,234,.4); }
  .hint {
    margin-top: 20px; padding: 14px; background: #f7fafc; border-radius: 10px;
    font-size: 12px; color: #4a5568; line-height: 1.7;
  }
  .hint code { background:#edf2f7; padding:1px 6px; border-radius:4px; font-size:11px; }
  .error {
    background: #fff5f5; color: #c53030; padding: 12px; border-radius: 8px;
    font-size: 13px; margin-bottom: 16px; border: 1px solid #fed7d7;
  }
</style>
</head>
<body>
  <div class="card">
    <h1>🔐 Testbook Token Login</h1>
    <p class="sub">Apna Testbook access token daaliye — live scraping shuru (OTP ki zarurat nahi).</p>
    __ERROR__
    <form method="post" action="/login">
      <label for="token">Access Token</label>
      <textarea id="token" name="token" rows="5"
        placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        required autofocus></textarea>
      <button type="submit">Login karein →</button>
    </form>
    <div class="hint">
      <strong>Token kaise milega?</strong><br>
      1. <b>testbook.com</b> par login karein.<br>
      2. Browser me <b>F12</b> → <b>Network</b> tab kholein.<br>
      3. Koi bhi <code>/api/</code> request par click karein → <b>Headers</b> → <code>Authorization: Bearer ...</code><br>
      4. Sirf token ka part (jo <code>eyJ...</code> se shuru hota hai) copy karke yahan paste karein.
    </div>
  </div>
</body>
</html>"""


def make_topbar(current_url: str) -> str:
    safe_url = html_lib.escape(current_url or "", quote=True)
    return (
        '<div style="position:sticky;top:0;z-index:999999;'
        'background:linear-gradient(90deg,#1e3a8a,#3730a3);color:#fff;'
        'padding:10px 16px;display:flex;align-items:center;gap:10px;'
        'font-family:-apple-system,BlinkMacSystemFont,Segoe UI,sans-serif;'
        'box-shadow:0 2px 10px rgba(0,0,0,.25);flex-wrap:wrap;">'
        '<strong style="font-size:13px;white-space:nowrap;">📚 Testbook Live</strong>'
        '<form method="get" action="/proxy" style="flex:1;min-width:260px;display:flex;gap:8px;margin:0;">'
        f'<input type="text" name="url" value="{safe_url}" '
        'placeholder="https://testbook.com/..." '
        'style="flex:1;padding:7px 12px;border-radius:6px;border:none;font-size:12px;outline:none;" />'
        '<button type="submit" style="padding:7px 14px;background:#fff;color:#3730a3;'
        'border:none;border-radius:6px;font-weight:700;cursor:pointer;font-size:12px;">Go</button>'
        '</form>'
        '<a href="/dashboard" style="color:#fff;text-decoration:none;font-size:12px;'
        'padding:7px 12px;background:rgba(255,255,255,.18);border-radius:6px;">Home</a>'
        '<a href="/api/tests" target="_blank" style="color:#fff;text-decoration:none;font-size:12px;'
        'padding:7px 12px;background:rgba(255,255,255,.18);border-radius:6px;">JSON</a>'
        '<a href="/logout" style="color:#fff;text-decoration:none;font-size:12px;'
        'padding:7px 12px;background:rgba(255,255,255,.18);border-radius:6px;">Logout</a>'
        '</div>'
    )


# ---------- URL rewriter (Testbook links → /proxy) ----------
def rewrite_links(soup: BeautifulSoup) -> BeautifulSoup:
    pairs = [
        ("a", "href"),
        ("link", "href"),
        ("script", "src"),
        ("img", "src"),
        ("source", "src"),
        ("iframe", "src"),
    ]
    for tag, attr in pairs:
        for el in soup.find_all(tag):
            val = el.get(attr)
            if not val or val.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
                continue
            absolute = urljoin(BASE_URL, val)
            if "testbook.com" in absolute:
                el[attr] = f"/proxy?url={quote(absolute, safe='')}"
            elif val.startswith("//"):
                el[attr] = "https:" + val

    for form in soup.find_all("form"):
        action = form.get("action")
        if action:
            absolute = urljoin(BASE_URL, action)
            if "testbook.com" in absolute:
                form["action"] = f"/proxy?url={quote(absolute, safe='')}"

    # CSP meta tags hataao taaki humara topbar + scripts chal sakein
    for meta in soup.find_all("meta"):
        if meta.get("http-equiv", "").lower() == "content-security-policy":
            meta.decompose()

    return soup


# ---------- Core proxy renderer ----------
async def render_proxy(url: str, token: str) -> Response:
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            r = await client.get(url, headers=get_headers(token))
    except Exception as e:
        return HTMLResponse(
            f"<h1 style='font-family:sans-serif;padding:24px;'>Upstream error</h1>"
            f"<pre style='padding:24px;color:#c53030;'>{html_lib.escape(str(e))}</pre>",
            status_code=502,
        )

    # Token invalid / expire → wapas login page
    if r.status_code in (401, 403):
        resp = RedirectResponse("/?error=session", status_code=302)
        resp.delete_cookie("tb_session")
        return resp

    ctype = r.headers.get("content-type", "").lower()
    if "text/html" not in ctype:
        return Response(
            content=r.content,
            media_type=r.headers.get("content-type", "application/octet-stream"),
        )

    soup = BeautifulSoup(r.text, "html.parser")

    # Har page ke top par toolbar inject karo
    if soup.body:
        bar = BeautifulSoup(make_topbar(url), "html.parser")
        soup.body.insert(0, bar)

    rewrite_links(soup)
    return HTMLResponse(str(soup))


# ---------- Routes ----------
@app.get("/health")
async def health():
    return {"status": "ok", "service": "testbook-live-scraper"}


@app.get("/", response_class=HTMLResponse)
async def root(
    error: Optional[str] = None,
    session_cookie: Optional[str] = Cookie(None, alias="tb_session"),
):
    # Agar already logged in hai to dashboard bhej do
    if get_token(session_cookie):
        return RedirectResponse("/dashboard", status_code=302)

    err_html = ""
    if error == "session":
        err_html = '<div class="error">Token expire ho gaya. Dobara login karein.</div>'

    return HTMLResponse(LOGIN_PAGE.replace("__ERROR__", err_html))


@app.post("/login")
async def login(token: str = Form(...)):
    token = token.strip()
    if not token:
        return HTMLResponse(
            LOGIN_PAGE.replace("__ERROR__", '<div class="error">Token khali hai.</div>'),
            status_code=400,
        )

    # Agar user "Bearer xxx" format me paste kare to strip kar do
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    # Token ko Testbook ke saath validate karo
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            r = await client.get(TARGET_URL, headers=get_headers(token))
    except Exception as e:
        return HTMLResponse(
            LOGIN_PAGE.replace(
                "__ERROR__",
                f'<div class="error">Connection error: {html_lib.escape(str(e))}</div>',
            ),
            status_code=502,
        )

    if r.status_code != 200:
        return HTMLResponse(
            LOGIN_PAGE.replace(
                "__ERROR__",
                f'<div class="error">Token invalid ya expire (status {r.status_code}). '
                f'Dobara check karke try karein.</div>',
            ),
            status_code=401,
        )

    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie(
        "tb_session",
        sign_token(token),
        httponly=True,
        samesite="lax",
        max_age=7 * 24 * 3600,
        secure=False,  # HTTPS only par True kar do
    )
    return resp


@app.get("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("tb_session")
    return resp


@app.get("/dashboard")
async def dashboard(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)
    return await render_proxy(TARGET_URL, token)


@app.get("/proxy")
async def proxy(
    url: str = Query(...),
    session_cookie: Optional[str] = Cookie(None, alias="tb_session"),
):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)
    if not url.startswith("http"):
        url = urljoin(BASE_URL, url)
    return await render_proxy(url, token)


# ---------- Simple HTML parser ----------
def parse_tests(html: str) -> List[TestInfo]:
    soup = BeautifulSoup(html, "html.parser")
    tests: List[TestInfo] = []
    seen = set()

    for a in soup.select("a[href]"):
        href = a.get("href", "")
        text = a.get_text(" ", strip=True)
        if not text or len(text) < 3:
            continue
        if "/test-series/" not in href and "/tests/" not in href:
            continue
        absolute = urljoin(BASE_URL, href)
        if absolute in seen:
            continue
        seen.add(absolute)

        desc = None
        parent = a.find_parent()
        if parent:
            p = parent.find("p")
            if p:
                desc = p.get_text(strip=True)

        tests.append(TestInfo(title=text, link=absolute, description=desc))

    return tests


# ---------- JSON API ----------
@app.get("/api/tests", response_model=ScrapeResult, tags=["Scraper"])
async def api_tests(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        raise HTTPException(401, "Pehle '/' par jaake login karein.")

    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        r = await client.get(TARGET_URL, headers=get_headers(token))

    if r.status_code != 200:
        raise HTTPException(r.status_code, f"Testbook fetch failed ({r.status_code})")

    tests = parse_tests(r.text)
    return ScrapeResult(page_url=TARGET_URL, count=len(tests), tests=tests)


# Vercel ASGI entrypoint
handler = app
