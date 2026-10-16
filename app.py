# app.py
import os
import re
import json
import time
import hmac
import base64
import hashlib
import traceback
import httpx
from fastapi import FastAPI, HTTPException, Form, Cookie, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from bs4 import BeautifulSoup
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from urllib.parse import quote, unquote, urlparse

app = FastAPI(title="Testbook Mirror", version="6.0.0")

# ---------- Config ----------
BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
HOME_PATH = "/rrb-group-d/test-series/my"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

COUNT_API = f"{API_BASE}/api/v2_1/live-panel/count"

SERIES_LIST_CANDIDATES = [
    f"{API_BASE}/api/v2_1/live-panel/test-series",
    f"{API_BASE}/api/v2_1/live-panel/purchased-series",
    f"{API_BASE}/api/v2_1/live-panel/series",
    f"{API_BASE}/api/v2_1/me/test-series",
    f"{API_BASE}/api/v2_1/user/test-series",
    f"{API_BASE}/api/v2_1/test-series/my",
]

def series_detail_candidates(slug_or_id: str) -> List[str]:
    s = quote(slug_or_id, safe="")
    return [
        f"{API_BASE}/api/v2_1/live-panel/test-series/{s}",
        f"{API_BASE}/api/v2_1/live-panel/test-series/{s}/tests",
        f"{API_BASE}/api/v2_1/test-series/{s}",
        f"{API_BASE}/api/v2_1/test-series/{s}/tests",
        f"{API_BASE}/api/v2/test-series/{s}",
        f"{API_BASE}/api/v2/test-series/{s}/tests",
        f"{API_BASE}/api/v3/test-series/{s}",
    ]

def test_detail_candidates(slug_or_id: str) -> List[str]:
    s = quote(slug_or_id, safe="")
    return [
        f"{API_BASE}/api/v2_1/test/{s}",
        f"{API_BASE}/api/v2_1/tests/{s}",
        f"{API_BASE}/api/v2/test/{s}",
        f"{API_BASE}/api/v2/tests/{s}",
        f"{API_BASE}/api/v3/test/{s}",
    ]

def test_questions_candidates(slug_or_id: str) -> List[str]:
    s = quote(slug_or_id, safe="")
    return [
        f"{API_BASE}/api/v2_1/test/{s}/questions",
        f"{API_BASE}/api/v2_1/tests/{s}/questions",
        f"{API_BASE}/api/v2/test/{s}/questions",
        f"{API_BASE}/api/v2/test/{s}/question",
        f"{API_BASE}/api/v2_1/test/{s}/instructions",
    ]

# ---------- Token helpers ----------
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
    if not session_cookie:
        return None
    return unsign_token(session_cookie)

def decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception:
        return None

def validate_jwt(token: str) -> tuple[bool, str]:
    payload = decode_jwt_payload(token)
    if payload is None:
        return False, "Token JWT format me nahi hai"
    exp = payload.get("exp")
    if exp and isinstance(exp, (int, float)) and exp < time.time():
        return False, "Token expire ho gaya hai"
    if not any(k in payload for k in ("sub", "email", "name", "phone")):
        return False, "Token me user info nahi mili"
    return True, "ok"

def get_user_info(token: str) -> dict:
    p = decode_jwt_payload(token) or {}
    return {
        "name": p.get("name") or "User",
        "email": p.get("email") or "",
        "sub": p.get("sub") or "",
    }

def tb_headers(token: str) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Referer": BASE_URL + "/",
        "Origin": BASE_URL,
        "Cookie": f"tb_token={token}",
    }

# ---------- Stats ----------
async def fetch_stats(token: str) -> Optional[dict]:
    url = f"{COUNT_API}?auth_code={quote(token, safe='')}&language=english"
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code == 200:
                j = r.json()
                if j.get("success"):
                    return j.get("data", {})
    except Exception as e:
        print("stats error:", e)
    return None

# ---------- JSON walking helpers ----------
def _looks_like_series(o: Any) -> bool:
    if not isinstance(o, dict):
        return False
    keys = set(o.keys())
    has_id = bool(keys & {"id", "_id", "slug", "seriesId", "testSeriesId"})
    has_title = bool(keys & {"name", "title", "seriesName", "testSeriesName"})
    return has_id and has_title

def _looks_like_test(o: Any) -> bool:
    if not isinstance(o, dict):
        return False
    keys = set(o.keys())
    has_id = bool(keys & {"id", "_id", "slug", "testId"})
    has_title = bool(keys & {"name", "title", "testName"})
    return has_id and has_title

def _looks_like_question(o: Any) -> bool:
    if not isinstance(o, dict):
        return False
    keys = set(o.keys())
    return ("question" in keys or "questionText" in keys or
            ("text" in keys and ("options" in keys or "choices" in keys)))

def _walk(node: Any, out: List[dict], pred, depth: int = 0):
    if depth > 8:
        return
    if isinstance(node, list):
        for x in node:
            _walk(x, out, pred, depth + 1)
    elif isinstance(node, dict):
        if pred(node):
            out.append(node)
        for v in node.values():
            if isinstance(v, (list, dict)):
                _walk(v, out, pred, depth + 1)

def slug_from_link(link: str) -> str:
    """Extract slug or id from a testbook URL."""
    try:
        p = urlparse(link)
        path = p.path.strip("/")
        if "/test-series/" in path:
            return path.split("/test-series/")[-1].split("/")[0]
        if "/tests/" in path:
            return path.split("/tests/")[-1].split("/")[0]
        return path.split("/")[-1]
    except Exception:
        return link

def normalize_series(items: List[dict]) -> List[Dict]:
    seen, result = set(), []
    for it in items:
        sid = str(it.get("slug") or it.get("id") or it.get("_id") or it.get("seriesId") or "")
        if not sid or sid in seen:
            continue
        seen.add(sid)
        title = str(it.get("name") or it.get("title") or it.get("seriesName") or "Test Series")
        desc = str(it.get("description") or it.get("shortDescription") or it.get("subTitle") or "")[:200]
        result.append({"id": sid, "title": title, "description": desc})
    return result

def normalize_tests(items: List[dict]) -> List[Dict]:
    seen, result = set(), []
    for it in items:
        tid = str(it.get("slug") or it.get("id") or it.get("_id") or it.get("testId") or "")
        if not tid or tid in seen:
            continue
        seen.add(tid)
        title = str(it.get("name") or it.get("title") or it.get("testName") or "Test")
        dur = it.get("duration") or it.get("totalTime") or 0
        qcount = it.get("questionCount") or it.get("totalQuestions") or it.get("questionsCount") or 0
        result.append({"id": tid, "title": title, "duration": dur, "questionCount": qcount})
    return result

# ---------- API fetching ----------
async def fetch_stats_and_series(token: str) -> tuple[Optional[dict], List[Dict], str]:
    async with httpx.AsyncClient(follow_redirects=True, timeout=12.0) as client:
        for url in SERIES_LIST_CANDIDATES:
            try:
                full = f"{url}?auth_code={quote(token, safe='')}&language=english"
                r = await client.get(full, headers=tb_headers(token))
                if r.status_code != 200:
                    continue
                try:
                    j = r.json()
                except Exception:
                    continue
                raw: List[dict] = []
                _walk(j, raw, _looks_like_series)
                if raw:
                    return None, normalize_series(raw), url
            except Exception:
                continue
    return None, [], "none"

async def fetch_series_detail(token: str, slug: str) -> tuple[Optional[Dict], List[Dict], str]:
    """Fetch series info + tests inside it."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
        for url in series_detail_candidates(slug):
            try:
                full = f"{url}?auth_code={quote(token, safe='')}&language=english"
                r = await client.get(full, headers=tb_headers(token))
                if r.status_code != 200:
                    continue
                try:
                    j = r.json()
                except Exception:
                    continue

                # tests
                tests_raw: List[dict] = []
                _walk(j, tests_raw, _looks_like_test)
                tests = normalize_tests(tests_raw)

                # series info
                series_raw: List[dict] = []
                _walk(j, series_raw, _looks_like_series)
                series_info = None
                if series_raw:
                    s = series_raw[0]
                    series_info = {
                        "id": str(s.get("slug") or s.get("id") or slug),
                        "title": str(s.get("name") or s.get("title") or "Test Series"),
                        "description": str(s.get("description") or s.get("shortDescription") or "")[:400],
                    }

                if tests or series_info:
                    return series_info, tests, url
            except Exception:
                continue
    return None, [], "none"

async def fetch_test_detail(token: str, slug: str) -> tuple[Optional[Dict], List[Dict], str]:
    """Fetch test info + questions."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
        for url in test_detail_candidates(slug):
            try:
                full = f"{url}?auth_code={quote(token, safe='')}&language=english"
                r = await client.get(full, headers=tb_headers(token))
                if r.status_code != 200:
                    continue
                try:
                    j = r.json()
                except Exception:
                    continue
                test_raw: List[dict] = []
                _walk(j, test_raw, _looks_like_test)
                if test_raw:
                    t = test_raw[0]
                    return {
                        "id": str(t.get("slug") or t.get("id") or slug),
                        "title": str(t.get("name") or t.get("title") or "Test"),
                        "duration": t.get("duration") or t.get("totalTime") or 0,
                        "questionCount": t.get("questionCount") or t.get("totalQuestions") or 0,
                    }, [], url
            except Exception:
                continue

        # Try questions endpoints
        for url in test_questions_candidates(slug):
            try:
                full = f"{url}?auth_code={quote(token, safe='')}&language=english"
                r = await client.get(full, headers=tb_headers(token))
                if r.status_code != 200:
                    continue
                try:
                    j = r.json()
                except Exception:
                    continue
                q_raw: List[dict] = []
                _walk(j, q_raw, _looks_like_question)
                if q_raw:
                    questions = []
                    for q in q_raw[:100]:
                        text = q.get("question") or q.get("questionText") or q.get("text") or ""
                        options = q.get("options") or q.get("choices") or []
                        if isinstance(options, list):
                            opts = []
                            for o in options:
                                if isinstance(o, dict):
                                    opts.append(o.get("text") or o.get("option") or o.get("value") or str(o))
                                else:
                                    opts.append(str(o))
                        else:
                            opts = []
                        questions.append({"text": str(text)[:800], "options": opts})
                    return None, questions, url
            except Exception:
                continue
    return None, [], "none"

# ---------- HTML fallback parsers ----------
def parse_series_html(html_text: str) -> List[Dict]:
    soup = BeautifulSoup(html_text, "html.parser")
    results, seen = [], set()
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        text = a.get_text(" ", strip=True)
        if not text or len(text) < 4:
            continue
        if "/test-series/" not in href or "/my" in href:
            continue
        absolute = href if href.startswith("http") else BASE_URL + href
        slug = slug_from_link(absolute)
        if not slug or slug in seen:
            continue
        seen.add(slug)
        results.append({"id": slug, "title": text, "description": ""})
    return results

def parse_tests_from_html(html_text: str) -> List[Dict]:
    soup = BeautifulSoup(html_text, "html.parser")
    results, seen = [], set()
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        text = a.get_text(" ", strip=True)
        if not text or len(text) < 4:
            continue
        if "/tests/" not in href and "/take-test" not in href:
            continue
        slug = slug_from_link(href)
        if not slug or slug in seen:
            continue
        seen.add(slug)
        results.append({"id": slug, "title": text, "duration": 0, "questionCount": 0})
    return results

# ---------- Error handlers ----------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    print("ERROR:", tb)
    return HTMLResponse(f"<h1>Error</h1><pre style='white-space:pre-wrap'>{tb}</pre>", status_code=500)

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and request.url.path == "/":
        return RedirectResponse("/")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

# ---------- CSS / Shell ----------
COMMON_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#f0f4f8;color:#1a202c;min-height:100vh;padding-bottom:90px}
.topbar{background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;
padding:14px 20px;display:flex;align-items:center;justify-content:space-between;
position:sticky;top:0;z-index:100;box-shadow:0 4px 14px rgba(0,0,0,.15)}
.topbar h1{font-size:17px;font-weight:700}
.topbar .nav{display:flex;gap:8px;font-size:13px}
.topbar .nav a{color:#fff;text-decoration:none;padding:7px 14px;
background:rgba(255,255,255,.18);border-radius:8px;font-weight:600}
.topbar .nav a:hover{background:rgba(255,255,255,.3)}
.container{max-width:920px;margin:0 auto;padding:20px}
.section-title{font-size:15px;font-weight:700;color:#4a5568;margin:8px 0 14px;
text-transform:uppercase;letter-spacing:.5px}
.card{background:#fff;border-radius:14px;padding:18px;margin-bottom:14px;
box-shadow:0 2px 10px rgba(0,0,0,.06);border-left:4px solid #4f46e5;
transition:transform .15s,box-shadow .15s}
.card:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.1)}
.card a{text-decoration:none;color:#1a202c;display:block}
.card h3{font-size:15px;font-weight:700;color:#1a202c;margin-bottom:6px}
.card p{font-size:13px;color:#718096;line-height:1.55}
.badge{display:inline-block;background:#eef2ff;color:#4f46e5;font-size:11px;
font-weight:700;padding:3px 10px;border-radius:12px;margin-top:8px;
text-transform:uppercase;letter-spacing:.3px}
.badge.green{background:#d1fae5;color:#059669}
.row{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.empty{text-align:center;padding:40px 20px;color:#a0aec0}
.empty h2{font-size:18px;margin-bottom:8px;color:#4a5568}
.btn{display:inline-block;padding:11px 20px;background:#4f46e5;color:#fff;
border:none;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;
cursor:pointer;text-align:center;transition:background .15s}
.btn:hover{background:#4338ca}
.btn.gray{background:#e2e8f0;color:#4a5568}
.btn.gray:hover{background:#cbd5e0}
.btn.green{background:#10b981;color:#fff}
.btn.green:hover{background:#059669}
.floating{position:fixed;bottom:16px;right:16px;display:flex;gap:8px;z-index:99}
.floating a{padding:11px 18px;border-radius:26px;text-decoration:none;
font-size:13px;font-weight:700;color:#fff;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.floating .home{background:#4f46e5}
.floating .out{background:#dc2626}
.info-box{background:#eef2ff;border-radius:12px;padding:16px;margin-bottom:18px;
font-size:13px;color:#3730a3;line-height:1.7}
.stat-row{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:16px}
.stat{background:#fff;padding:14px 18px;border-radius:12px;
box-shadow:0 2px 8px rgba(0,0,0,.05);flex:1;min-width:130px;text-align:center}
.stat .num{font-size:26px;font-weight:800;color:#4f46e5}
.stat .lbl{font-size:12px;color:#718096;text-transform:uppercase;
letter-spacing:.4px;margin-top:4px}
.debug{background:#1a202c;color:#a0aec0;padding:16px;border-radius:10px;
font-family:monospace;font-size:11px;overflow:auto;max-height:520px;
line-height:1.5;white-space:pre-wrap;word-break:break-word}
.q-card{background:#fff;border-radius:12px;padding:18px;margin-bottom:14px;
box-shadow:0 2px 8px rgba(0,0,0,.06);border-top:3px solid #4f46e5}
.q-num{display:inline-block;background:#4f46e5;color:#fff;font-size:11px;
font-weight:700;padding:3px 10px;border-radius:8px;margin-bottom:10px}
.q-text{font-size:15px;line-height:1.6;color:#2d3748;margin-bottom:12px}
.opt{display:block;padding:11px 14px;background:#f7fafc;border-radius:9px;
margin-bottom:8px;font-size:14px;color:#2d3748;border:1.5px solid #e2e8f0}
.back-btn{display:inline-block;margin-bottom:14px;padding:8px 16px;
background:#e2e8f0;color:#4a5568;border-radius:8px;text-decoration:none;
font-size:13px;font-weight:600}
"""

def page_shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Testbook Mirror</title>
<style>{COMMON_CSS}</style></head><body>
<div class="topbar"><h1>📚 Testbook Mirror</h1>
<div class="nav"><a href="/dashboard">🏠 Home</a><a href="/logout">Logout</a></div></div>
<div class="container">{body}</div>
<div class="floating"><a href="/dashboard" class="home">🏠 Home</a>
<a href="/logout" class="out">Logout</a></div>
</body></html>"""

LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login · Testbook Mirror</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;
display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:18px;box-shadow:0 20px 60px rgba(0,0,0,.3);
padding:40px;width:100%;max-width:500px}
.logo{font-size:40px;text-align:center;margin-bottom:12px}
h1{color:#1a202c;font-size:22px;text-align:center;margin-bottom:6px}
p.sub{color:#718096;font-size:13px;text-align:center;margin-bottom:26px;line-height:1.6}
label{display:block;font-size:13px;color:#4a5568;font-weight:600;margin-bottom:8px}
textarea{width:100%;padding:13px 14px;border:1.5px solid #e2e8f0;border-radius:10px;
font-size:13px;font-family:ui-monospace,Menlo,Consolas,monospace;resize:vertical}
textarea:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.15)}
button{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);
color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;
cursor:pointer;margin-top:20px}
button:hover{opacity:.92}
.hint{margin-top:22px;padding:14px;background:#f7fafc;border-radius:10px;
font-size:12px;color:#4a5568;line-height:1.75}
.hint b{color:#2d3748}
.hint code{background:#edf2f7;padding:1px 6px;border-radius:4px;font-size:11px}
.error{background:#fff5f5;color:#c53030;padding:12px;border-radius:8px;
font-size:13px;margin-bottom:16px;border:1px solid #fed7d7;text-align:center}
</style></head><body>
<div class="card">
<div class="logo">🔐</div>
<h1>Testbook Token Login</h1>
<p class="sub">Sirf valid token hi accept hoga (JWT + API check).</p>
__ERROR__
<form method="post" action="/login">
<label>Access Token</label>
<textarea name="token" rows="6" placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." required autofocus></textarea>
<button type="submit">Login karein →</button>
</form>
<div class="hint">
<b>🔑 Token kahan milega?</b><br>
1. <b>testbook.com</b> par login karein<br>
2. <b>F12</b> → <b>Network</b> tab → <b>Fetch/XHR</b><br>
3. Koi bhi <code>api.testbook.com</code> request par click<br>
4. URL me <code>auth_code=eyJ...</code> ya Headers me <code>Authorization: Bearer eyJ...</code><br>
5. Sirf <code>eyJ...</code> wala part copy karein
</div>
</div></body></html>"""

# ---------- Routes ----------
@app.get("/health")
async def health():
    return {"status": "ok", "version": "6.0.0"}

@app.get("/", response_class=HTMLResponse)
async def root(error: Optional[str] = None,
               session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    if get_token(session_cookie):
        return RedirectResponse("/dashboard", status_code=302)
    err = '<div class="error">Token expire ho gaya. Dobara login karein.</div>' if error == "session" else ""
    return HTMLResponse(LOGIN_HTML.replace("__ERROR__", err))

@app.post("/login")
async def login(token: str = Form(...)):
    token = token.strip()
    if not token:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", '<div class="error">Token khali hai.</div>'), status_code=400)
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if "auth_code=" in token:
        token = token.split("auth_code=")[1].split("&")[0]

    ok, msg = validate_jwt(token)
    if not ok:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">❌ {msg}</div>'), status_code=401)

    stats = await fetch_stats(token)
    if stats is None:
        return HTMLResponse(
            LOGIN_HTML.replace("__ERROR__", '<div class="error">❌ Token Testbook API ne accept nahi kiya.</div>'),
            status_code=401,
        )

    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie("tb_session", sign_token(token), httponly=True, samesite="lax", max_age=7*24*3600, secure=False)
    return resp

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("tb_session")
    return resp

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(debug: int = 0,
                    session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    user = get_user_info(token)
    stats = await fetch_stats(token)
    _, series, endpoint = await fetch_stats_and_series(token)
    source = f"api:{endpoint}" if series else "none"

    if not series:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
                r = await client.get(BASE_URL + HOME_PATH, headers=tb_headers(token))
            if r.status_code == 200:
                series = parse_series_html(r.text)
                source = f"html ({len(series)})"
        except Exception as e:
            source = f"html err: {e}"

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">source: {source}\nseries_count: {len(series)}\n\n{json.dumps(series[:5], indent=2, ensure_ascii=False)}</div>'

    stats_html = ""
    if stats:
        stats_html = f"""
        <div class="stat-row">
          <div class="stat"><div class="num">{stats.get('testsCount', 0)}</div><div class="lbl">Tests</div></div>
          <div class="stat"><div class="num">{stats.get('quizzesCount', 0)}</div><div class="lbl">Quizzes</div></div>
          <div class="stat"><div class="num">{stats.get('videosCount', 0)}</div><div class="lbl">Videos</div></div>
        </div>
        """

    greeting = f'<div class="info-box">✅ <b>Welcome, {user["name"]}!</b><br>{user["email"]}</div>'

    if series:
        cards = "".join(
            f'<div class="card"><a href="/series?slug={quote(item["id"], safe="")}">'
            f'<h3>{item["title"]}</h3>'
            f'{f"<p>{item["description"]}</p>" if item.get("description") else ""}'
            f'<span class="badge">Open Series →</span></a></div>'
            for item in series
        )
        body = f"""
        {greeting}
        {stats_html}
        <div class="section-title">📚 Your Test Series ({len(series)})</div>
        <div class="row">{cards}</div>
        {debug_html}
        """
    else:
        body = f"""
        {greeting}
        {stats_html}
        <div class="empty">
          <h2>😕 Koi test series nahi mili</h2>
          <p>Source: <b>{source}</b></p>
          <br>
          <a href="/debug/probe" class="btn">🔍 Probe</a>
        </div>
        {debug_html}
        """
    return HTMLResponse(page_shell("Dashboard", body))

# ---------- SERIES PAGE (our own UI) ----------
@app.get("/series", response_class=HTMLResponse)
async def series_page(slug: str = Query(...),
                      debug: int = 0,
                      session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    info, tests, endpoint = await fetch_series_detail(token, slug)
    source = endpoint

    # Fallback: HTML scrape of testbook series page
    if not tests:
        try:
            url = f"{BASE_URL}/test-series/{slug}"
            async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
                r = await client.get(url, headers=tb_headers(token))
            if r.status_code == 200:
                tests = parse_tests_from_html(r.text)
                source = f"html ({len(tests)})"
        except Exception as e:
            source = f"err: {e}"

    title = info["title"] if info else slug.replace("-", " ").title()
    desc = info.get("description", "") if info else ""

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">endpoint: {source}\ntests: {len(tests)}\n\n{json.dumps(tests[:8], indent=2, ensure_ascii=False)}</div>'

    if tests:
        cards = "".join(
            f'<div class="card"><a href="/test?slug={quote(t["id"], safe="")}">'
            f'<h3>{t["title"]}</h3>'
            f'{f"<p>⏱ {t[chr(100)+chr(117)+chr(114)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)]} min · 📝 {t[chr(113)+chr(117)+chr(101)+chr(115)+chr(116)+chr(105)+chr(111)+chr(110)+chr(67)+chr(111)+chr(117)+chr(110)+chr(116)]} Qs</p>" if t.get("duration") or t.get("questionCount") else ""}'
            f'<span class="badge green">Open Test →</span></a></div>'
            for t in tests
        )
        body = f"""
        <a href="/dashboard" class="back-btn">← Back to Dashboard</a>
        <div class="info-box">
          <b>📚 {title}</b>
          {f"<br>{desc}" if desc else ""}
        </div>
        <div class="section-title">📝 Tests ({len(tests)})</div>
        <div class="row">{cards}</div>
        {debug_html}
        """
    else:
        body = f"""
        <a href="/dashboard" class="back-btn">← Back to Dashboard</a>
        <div class="info-box"><b>📚 {title}</b></div>
        <div class="empty">
          <h2>Is series me tests nahi mile</h2>
          <p>Source: <b>{source}</b></p>
          <br>
          <a href="/series?slug={quote(slug, safe='')}&debug=1" class="btn">🔍 Debug</a>
        </div>
        {debug_html}
        """
    return HTMLResponse(page_shell(title, body))

# ---------- TEST PAGE (our own UI) ----------
@app.get("/test", response_class=HTMLResponse)
async def test_page(slug: str = Query(...),
                    debug: int = 0,
                    session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    info, questions, endpoint = await fetch_test_detail(token, slug)
    source = endpoint

    title = (info or {}).get("title") or slug.replace("-", " ").title()
    duration = (info or {}).get("duration", 0)
    qcount = (info or {}).get("questionCount", 0)

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">endpoint: {source}\nquestions: {len(questions)}\n\n{json.dumps(questions[:3], indent=2, ensure_ascii=False)[:2000]}</div>'

    if questions:
        q_html = ""
        for i, q in enumerate(questions, 1):
            opts = ""
            for o in q.get("options", [])[:6]:
                opts += f'<span class="opt">{o}</span>'
            q_html += f"""
            <div class="q-card">
              <span class="q-num">Q{i}</span>
              <div class="q-text">{q['text']}</div>
              {opts}
            </div>
            """
        body = f"""
        <a href="javascript:history.back()" class="back-btn">← Back</a>
        <div class="info-box">
          <b>🎯 {title}</b><br>
          📝 {len(questions)} questions
          {f" · ⏱ {duration} min" if duration else ""}
          {f" · Total {qcount} Qs" if qcount else ""}
        </div>
        <div class="section-title">📖 Questions</div>
        {q_html}
        {debug_html}
        """
    else:
        body = f"""
        <a href="javascript:history.back()" class="back-btn">← Back</a>
        <div class="info-box">
          <b>🎯 {title}</b>
          {f"<br>⏱ {duration} min · 📝 {qcount} Qs" if duration or qcount else ""}
        </div>
        <div class="empty">
          <h2>Questions load nahi ho paye</h2>
          <p>Is test ka question-set API se nahi mila (source: <b>{source}</b>).<br>
          Live test dena ho to neeche button dabayein (Testbook par khulega).</p>
          <br>
          <a href="{BASE_URL}/tests/{slug}" target="_blank" class="btn green">🎯 Start Test on Testbook</a>
          <a href="/test?slug={quote(slug, safe='')}&debug=1" class="btn gray" style="margin-left:8px;">🔍 Debug</a>
        </div>
        {debug_html}
        """
    return HTMLResponse(page_shell(title, body))

# ---------- Debug probe ----------
@app.get("/debug/probe", response_class=HTMLResponse)
async def debug_probe(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    results = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=10.0) as client:
        for url in SERIES_LIST_CANDIDATES:
            full = f"{url}?auth_code={quote(token, safe='')}&language=english"
            try:
                r = await client.get(full, headers=tb_headers(token))
                info = {"url": url, "status": r.status_code, "len": len(r.content)}
                if r.status_code == 200:
                    try:
                        j = r.json()
                        raw: List[dict] = []
                        _walk(j, raw, _looks_like_series)
                        info["series_found"] = len(raw)
                        info["preview"] = json.dumps(j, ensure_ascii=False)[:300]
                    except Exception:
                        info["preview"] = r.text[:200]
                else:
                    info["preview"] = r.text[:200]
                results.append(info)
            except Exception as e:
                results.append({"url": url, "status": "ERR", "error": str(e)})

    lines = []
    for r in results:
        status = r.get("status")
        if status == 200 and r.get("series_found", 0) > 0:
            tag = f'<span style="color:#10b981;font-weight:700">✅ [{status}] series={r["series_found"]}</span>'
        elif status == 200:
            tag = f'<span style="color:#ef4444;font-weight:700">⚠️  [{status}]</span>'
        else:
            tag = f'<span style="color:#ef4444;font-weight:700">❌ [{status}]</span>'
        lines.append(f'{tag}  {r["url"]}')
        prev = r.get("preview") or r.get("error") or ""
        if prev:
            lines.append(f'      {prev[:180]}')
        lines.append("")

    body = f"""
    <a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box">Har candidate endpoint ka result:</div>
    <div class="debug">{chr(10).join(lines)}</div>
    """
    return HTMLResponse(page_shell("Probe", body))

# ---------- JSON API ----------
class TestInfo(BaseModel):
    title: str
    link: str
    description: Optional[str] = None

class ScrapeResult(BaseModel):
    count: int
    tests: List[TestInfo]

@app.get("/api/tests", response_model=ScrapeResult)
async def api_tests(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        raise HTTPException(401, "Pehle login karein.")
    _, series, _ = await fetch_stats_and_series(token)
    return ScrapeResult(
        count=len(series),
        tests=[TestInfo(title=s["title"], link=f"/series?slug={s['id']}", description=s.get("description") or None) for s in series],
    )

@app.get("/api/stats")
async def api_stats(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        raise HTTPException(401, "Pehle login karein.")
    stats = await fetch_stats(token)
    return {"user": get_user_info(token), "stats": stats or {}}
