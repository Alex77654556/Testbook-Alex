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
from fastapi import FastAPI, HTTPException, Response as FastResponse, Form, Cookie, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from bs4 import BeautifulSoup
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
from urllib.parse import quote

app = FastAPI(title="Testbook Mirror", version="5.0.0")

# ---------- Config ----------
BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
HOME_PATH = "/rrb-group-d/test-series/my"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

# Testbook API endpoints (with auth_code param)
COUNT_API = f"{API_BASE}/api/v2_1/live-panel/count"
USER_API = f"{API_BASE}/api/v2/users/me"
SERIES_API = f"{API_BASE}/api/v2_1/live-panel/test-series"

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

# ---------- JWT decoding ----------
def decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        payload = parts[1]
        payload += "=" * (-len(payload) % 4)
        decoded = base64.urlsafe_b64decode(payload)
        return json.loads(decoded)
    except Exception:
        return None

def validate_jwt(token: str) -> tuple[bool, str]:
    payload = decode_jwt_payload(token)
    if payload is None:
        return False, "Token JWT format me nahi hai"
    exp = payload.get("exp")
    if exp and isinstance(exp, (int, float)) and exp < time.time():
        return False, "Token expire ho gaya hai"
    user_keys = ("sub", "email", "phone", "userId", "name", "mobile")
    if not any(k in payload for k in user_keys):
        return False, "Token me user info nahi mili"
    return True, "ok"

def get_user_info(token: str) -> dict:
    payload = decode_jwt_payload(token) or {}
    return {
        "name": payload.get("name") or "User",
        "email": payload.get("email") or "",
        "phone": payload.get("phone") or payload.get("mobile") or "",
        "sub": payload.get("sub") or "",
        "isPaid": payload.get("isPaidUser", False),
    }

# ---------- API headers ----------
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

# ---------- Fetch live stats ----------
async def fetch_stats(token: str) -> Optional[dict]:
    """Fetch user's live test/quiz counts from Testbook API."""
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

# ---------- Fetch test series from API ----------
async def fetch_series_api(token: str) -> List[dict]:
    """Try Testbook API endpoints for test series."""
    candidates = [
        f"{API_BASE}/api/v2_1/live-panel/test-series?auth_code={quote(token, safe='')}",
        f"{API_BASE}/api/v2_1/test-series?auth_code={quote(token, safe='')}",
        f"{API_BASE}/api/v2/test-series/my?auth_code={quote(token, safe='')}",
        f"{API_BASE}/api/v3/test-series/my?auth_code={quote(token, safe='')}",
    ]
    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
        for url in candidates:
            try:
                r = await client.get(url, headers=tb_headers(token))
                if r.status_code == 200:
                    try:
                        j = r.json()
                    except Exception:
                        continue
                    series = _extract_series(j)
                    if series:
                        return series
            except Exception:
                continue
    return []

def _looks_like_series(o: Any) -> bool:
    if not isinstance(o, dict):
        return False
    keys = set(o.keys())
    has_id = bool(keys & {"id", "_id", "slug", "seriesId", "testSeriesId"})
    has_title = bool(keys & {"name", "title", "seriesName", "testSeriesName"})
    return has_id and has_title

def _extract_series(node: Any, out: List[dict], depth: int = 0) -> List[dict]:
    if depth > 6:
        return out
    if isinstance(node, list):
        for x in node:
            _extract_series(x, out, depth + 1)
    elif isinstance(node, dict):
        if _looks_like_series(node):
            out.append(node)
        for v in node.values():
            if isinstance(v, (list, dict)):
                _extract_series(v, out, depth + 1)
    return out

def normalize_series(items: List[dict]) -> List[Dict]:
    seen, result = set(), []
    for it in items:
        sid = str(it.get("id") or it.get("_id") or it.get("slug") or it.get("seriesId") or "")
        if not sid or sid in seen:
            continue
        seen.add(sid)
        title = str(it.get("name") or it.get("title") or it.get("seriesName") or "Test Series")
        desc = str(it.get("description") or it.get("shortDescription") or it.get("subTitle") or "")[:300]
        slug = it.get("slug") or it.get("url") or ""
        if slug.startswith("http"):
            link = slug
        elif slug:
            link = f"{BASE_URL}/test-series/{slug}" if "/test-series/" not in slug else f"{BASE_URL}{slug}"
        else:
            link = f"{BASE_URL}/test-series/{sid}"
        result.append({"id": sid, "title": title, "description": desc, "link": link})
    return result

# ---------- Fallback HTML parse ----------
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
        if absolute in seen:
            continue
        seen.add(absolute)
        results.append({"id": absolute, "title": text, "description": "", "link": absolute})
    return results

# ---------- Global error handler ----------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    print("ERROR:", tb)
    return HTMLResponse(
        f"<h1>Error</h1><pre style='white-space:pre-wrap'>{tb}</pre>",
        status_code=500,
    )

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and request.url.path == "/":
        return RedirectResponse("/")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

# ---------- CSS Shell ----------
COMMON_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:#f0f4f8;color:#1a202c;min-height:100vh;padding-bottom:80px}
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
.row{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
.empty{text-align:center;padding:50px 20px;color:#a0aec0}
.empty h2{font-size:18px;margin-bottom:8px;color:#4a5568}
.btn{display:inline-block;padding:11px 20px;background:#4f46e5;color:#fff;
border:none;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;
cursor:pointer;text-align:center;transition:background .15s}
.btn:hover{background:#4338ca}
.btn.gray{background:#e2e8f0;color:#4a5568}
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
font-family:monospace;font-size:12px;overflow:auto;max-height:400px;
line-height:1.6;white-space:pre-wrap}
.user-chip{background:rgba(255,255,255,.2);padding:7px 12px;border-radius:20px;
font-size:12px;font-weight:600}
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
<p class="sub">Sirf valid token hi accept hoga (JWT structure + expiry check).</p>
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
    return {"status": "ok", "version": "5.0.0"}

@app.get("/", response_class=HTMLResponse)
async def root(error: Optional[str] = None,
               session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    if get_token(session_cookie):
        return RedirectResponse("/dashboard", status_code=302)
    err = ""
    if error == "session":
        err = '<div class="error">Token expire ho gaya. Dobara login karein.</div>'
    return HTMLResponse(LOGIN_HTML.replace("__ERROR__", err))

@app.post("/login")
async def login(token: str = Form(...)):
    token = token.strip()
    if not token:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", '<div class="error">Token khali hai.</div>'), status_code=400)
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    # strip query params if user pasted full URL
    if "auth_code=" in token:
        token = token.split("auth_code=")[1].split("&")[0]

    ok, msg = validate_jwt(token)
    if not ok:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">❌ {msg}</div>'), status_code=401)

    # Validate token by hitting live-panel API
    stats = await fetch_stats(token)
    if stats is None:
        return HTMLResponse(
            LOGIN_HTML.replace("__ERROR__",
                '<div class="error">❌ Token Testbook API ne accept nahi kiya. '
                'Dobara check karein ki token sahi hai aur expire nahi hua.</div>'),
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
    series = await fetch_series_api(token)
    source = "api"

    if not series:
        # Fallback to HTML
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
                r = await client.get(BASE_URL + HOME_PATH, headers=tb_headers(token))
            if r.status_code == 200:
                series = parse_series_html(r.text)
                source = "html"
        except Exception:
            pass

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">{json.dumps({"stats": stats, "series_count": len(series), "series_sample": series[:3]}, indent=2, ensure_ascii=False)}</div>'

    # Stats cards
    stats_html = ""
    if stats:
        stats_html = f"""
        <div class="stat-row">
          <div class="stat"><div class="num">{stats.get('testsCount', 0)}</div><div class="lbl">Tests</div></div>
          <div class="stat"><div class="num">{stats.get('quizzesCount', 0)}</div><div class="lbl">Quizzes</div></div>
          <div class="stat"><div class="num">{stats.get('videosCount', 0)}</div><div class="lbl">Videos</div></div>
        </div>
        """

    # User greeting
    greeting = f"""
    <div class="info-box">
      ✅ <b>Welcome, {user['name']}!</b><br>
      {user['email']}<br>
      Aapka Testbook account successfully connect ho gaya hai.
    </div>
    """

    if series:
        cards = "".join(
            f'<div class="card"><a href="{item["link"]}" target="_blank">'
            f'<h3>{item["title"]}</h3>'
            f'{f"<p>{item[chr(34)+chr(100)+chr(101)+chr(115)+chr(99)+chr(114)+chr(105)+chr(112)+chr(116)+chr(105)+chr(111)+chr(110)+chr(34)]}</p>" if item.get("description") else ""}'
            f'<span class="badge">Test Series</span></a></div>'
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
          <p>API se data fetch nahi ho paya. Aapka token valid hai (stats aa gaye), lekin series list ka endpoint alag ho sakta hai.</p>
          <br>
          <a href="/dashboard?debug=1" class="btn" style="margin-right:8px;">🔍 Debug Info</a>
          <a href="{BASE_URL + HOME_PATH}" target="_blank" class="btn gray">🔗 Original Page</a>
        </div>
        {debug_html}
        """
    return HTMLResponse(page_shell("Dashboard", body))

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
        raise HTTPException(401, "Pehle '/' par jaake login karein.")
    series = await fetch_series_api(token)
    return ScrapeResult(
        count=len(series),
        tests=[TestInfo(title=s["title"], link=s["link"], description=s.get("description") or None) for s in series],
    )

@app.get("/api/stats")
async def api_stats(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        raise HTTPException(401, "Pehle login karein.")
    stats = await fetch_stats(token)
    return {"user": get_user_info(token), "stats": stats or {}}
