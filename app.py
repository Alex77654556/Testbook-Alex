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
from urllib.parse import quote, unquote

app = FastAPI(title="Testbook Mirror", version="4.5.0")

# ---------- Config ----------
BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
HOME_PATH = "/rrb-group-d/test-series/my"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

# Candidate API endpoints (multiple tries)
USER_API_ENDPOINTS = [
    f"{API_BASE}/api/v2/users/me",
    f"{API_BASE}/api/v2/user/profile",
    f"{API_BASE}/api/v1/users/me",
    f"{API_BASE}/api/v3/users/me",
    f"{API_BASE}/api/v2/me",
]
SERIES_API_ENDPOINTS = [
    f"{API_BASE}/api/v2/me/test-series",
    f"{API_BASE}/api/v2/user/test-series",
    f"{API_BASE}/api/v2/users/me/test-series",
    f"{API_BASE}/api/v2/me/testSeries",
    f"{API_BASE}/api/v3/me/test-series",
    f"{API_BASE}/api/v2/me/courses",
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

# ---------- JWT decoding (no signature verification) ----------
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
    """Basic JWT structure + expiry + user field validation."""
    payload = decode_jwt_payload(token)
    if payload is None:
        return False, "Token JWT format me nahi hai (ya decode nahi ho paya)"
    if not isinstance(payload, dict):
        return False, "Token payload invalid hai"

    exp = payload.get("exp")
    if exp and isinstance(exp, (int, float)):
        if exp < time.time():
            return False, "Token expire ho gaya hai"

    user_keys = ("sub", "email", "phone", "userId", "user_id", "id", "mobile",
                 "phoneNumber", "phone_number", "user")
    has_user = any(k in payload for k in user_keys)
    if not has_user:
        return False, "Token me user information nahi mili (galat token lagta hai)"

    return True, "ok"

# ---------- Async Testbook API helpers ----------
def tb_headers(token: str, accept_json: bool = True) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": UA,
        "Accept": "application/json" if accept_json else "text/html,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Referer": BASE_URL + "/",
        "Origin": BASE_URL,
        "Cookie": f"tb_token={token}",
    }

async def try_api_endpoints(token: str, endpoints: List[str]) -> tuple[Optional[dict], Optional[str], int]:
    """Try each endpoint, return (json_data, endpoint_used, status_code)."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=20.0) as client:
        last_status = 0
        for ep in endpoints:
            try:
                r = await client.get(ep, headers=tb_headers(token))
                last_status = r.status_code
                if r.status_code == 200:
                    try:
                        data = r.json()
                        return data, ep, 200
                    except Exception:
                        continue
                if r.status_code == 401:
                    return None, ep, 401
            except Exception:
                continue
        return None, None, last_status

async def validate_token_with_api(token: str) -> tuple[bool, str]:
    """Try Testbook API to validate token."""
    data, ep, status = await try_api_endpoints(token, USER_API_ENDPOINTS)
    if status == 401:
        return False, "Testbook ne token reject kar diya (401 Unauthorized)"
    if status == 200 and data is not None:
        return True, "ok"
    # If API didn't respond clearly, fall back to JWT structure check
    return validate_jwt(token)

# ---------- Extract series from arbitrary JSON ----------
def _looks_like_series(obj: dict) -> bool:
    if not isinstance(obj, dict):
        return False
    keys = set(obj.keys())
    has_id = bool(keys & {"id", "_id", "slug", "seriesId", "testSeriesId"})
    has_title = bool(keys & {"name", "title", "seriesName", "testSeriesName"})
    return has_id and has_title

def _extract_series_list(node: Any, out: List[dict], depth: int = 0) -> None:
    if depth > 6:
        return
    if isinstance(node, list):
        for item in node:
            if _looks_like_series(item):
                out.append(item)
            else:
                _extract_series_list(item, out, depth + 1)
    elif isinstance(node, dict):
        if _looks_like_series(node):
            out.append(node)
        for k, v in node.items():
            if isinstance(v, (list, dict)):
                _extract_series_list(v, out, depth + 1)

def normalize_series(items: List[dict]) -> List[Dict]:
    seen, result = set(), []
    for it in items:
        sid = str(it.get("id") or it.get("_id") or it.get("slug") or it.get("seriesId") or "")
        if not sid or sid in seen:
            continue
        seen.add(sid)
        title = (it.get("name") or it.get("title") or it.get("seriesName")
                 or it.get("testSeriesName") or "Untitled Series")
        desc = it.get("description") or it.get("shortDescription") or it.get("subTitle") or ""
        slug = it.get("slug") or it.get("url") or ""
        link = ""
        if slug.startswith("http"):
            link = slug
        elif slug:
            link = f"{BASE_URL}/test-series/{slug}" if "/test-series/" not in slug else f"{BASE_URL}{slug}"
        else:
            link = f"{BASE_URL}/test-series/{sid}"
        result.append({
            "id": sid,
            "title": str(title),
            "description": str(desc)[:300],
            "link": link,
        })
    return result

# ---------- HTML parsing fallback ----------
def parse_series_from_html(html_text: str) -> List[Dict]:
    """Fallback: scan HTML for test-series links."""
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
        results.append({
            "id": absolute,
            "title": text,
            "description": "",
            "link": absolute,
        })
    return results

def has_login_prompt(html_text: str) -> bool:
    lower = html_text.lower()
    indicators = [
        "sign up to test your exam",
        "enter your mobile number",
        "login to continue",
        "please login",
        "signup & take free tests",
    ]
    return any(x in lower for x in indicators)

# ---------- Fetch series for a token ----------
async def fetch_series(token: str) -> tuple[List[Dict], str]:
    """Return (series_list, source)."""
    # Try API first
    data, ep, status = await try_api_endpoints(token, SERIES_API_ENDPOINTS)
    if status == 200 and data is not None:
        raw = []
        _extract_series_list(data, raw)
        series = normalize_series(raw)
        if series:
            return series, f"api:{ep}"

    # Fallback: fetch HTML /my page and parse
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
            r = await client.get(BASE_URL + HOME_PATH, headers=tb_headers(token, accept_json=False))
        if r.status_code == 200 and not has_login_prompt(r.text):
            series = parse_series_from_html(r.text)
            if series:
                return series, "html"
    except Exception:
        pass

    return [], "none"

# ---------- Global error handler ----------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    print("ERROR:", tb)
    return HTMLResponse(
        f"<h1>Error</h1><pre style='white-space:pre-wrap'>{traceback.format_exc()}</pre>",
        status_code=500,
    )

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and request.url.path == "/":
        return RedirectResponse("/")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

# ---------- CSS / Shell ----------
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
.btn.gray:hover{background:#cbd5e0}
.floating{position:fixed;bottom:16px;right:16px;display:flex;gap:8px;z-index:99}
.floating a{padding:11px 18px;border-radius:26px;text-decoration:none;
font-size:13px;font-weight:700;color:#fff;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.floating .home{background:#4f46e5}
.floating .out{background:#dc2626}
.info-box{background:#eef2ff;border-radius:12px;padding:16px;margin-bottom:18px;
font-size:13px;color:#3730a3;line-height:1.7}
.stat-row{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:16px}
.stat{background:#fff;padding:12px 18px;border-radius:10px;
box-shadow:0 2px 8px rgba(0,0,0,.05);flex:1;min-width:120px}
.stat .num{font-size:22px;font-weight:800;color:#4f46e5}
.stat .lbl{font-size:12px;color:#718096;text-transform:uppercase;letter-spacing:.4px}
.debug{background:#1a202c;color:#a0aec0;padding:16px;border-radius:10px;
font-family:monospace;font-size:12px;overflow:auto;max-height:400px;line-height:1.6}
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
padding:40px;width:100%;max-width:480px}
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
<p class="sub">Apna Testbook access token daaliye — sirf valid token hi accept hoga.</p>
__ERROR__
<form method="post" action="/login">
<label>Access Token</label>
<textarea name="token" rows="5" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." required autofocus></textarea>
<button type="submit">Login karein →</button>
</form>
<div class="hint">
<b>🔑 Token kaise milega?</b><br>
1. <b>testbook.com</b> par login karein<br>
2. <b>F12</b> → <b>Network</b> tab → koi bhi <code>/api/</code> request<br>
3. <b>Headers</b> → <code>Authorization: Bearer ...</code><br>
4. Sirf token wala part (jo <code>eyJ...</code> se shuru hota hai) copy karein
</div>
</div></body></html>"""

# ---------- Routes ----------
@app.get("/health")
async def health():
    return {"status": "ok", "version": "4.5.0"}

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

    # 1. Basic JWT structure check
    ok, msg = validate_jwt(token)
    if not ok:
        return HTMLResponse(
            LOGIN_HTML.replace("__ERROR__", f'<div class="error">❌ {msg}</div>'),
            status_code=401,
        )

    # 2. API validation (if we can reach Testbook)
    ok2, msg2 = await validate_token_with_api(token)
    if not ok2:
        return HTMLResponse(
            LOGIN_HTML.replace("__ERROR__", f'<div class="error">❌ {msg2}</div>'),
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

    series, source = await fetch_series(token)

    debug_html = ""
    if debug == 1:
        debug_html = f"""
        <div class="info-box" style="background:#fef3c7;color:#92400e;">
          <b>Debug mode</b> — Source: <code>{source}</code>, Series found: <b>{len(series)}</b>
        </div>
        <div class="debug">{json.dumps(series[:5], indent=2, ensure_ascii=False)}</div>
        """

    if series:
        cards = "".join(
            f'<div class="card"><a href="/series?url={quote(item["link"], safe="")}">'
            f'<h3>{item["title"]}</h3>'
            f'{f"<p>{item["description"]}</p>" if item["description"] else ""}'
            f'<span class="badge">Test Series</span></a></div>'
            for item in series
        )
        body = f"""
        <div class="info-box">
          ✅ Login successful. Neeche aapki saari test series hain.
          Kisi bhi card par click karein — details isi website par khulengi.
        </div>
        <div class="stat-row">
          <div class="stat"><div class="num">{len(series)}</div><div class="lbl">Test Series</div></div>
          <div class="stat"><div class="num" style="font-size:14px;">{source}</div><div class="lbl">Source</div></div>
        </div>
        {debug_html}
        <div class="section-title">📚 Your Test Series</div>
        <div class="row">{cards}</div>
        """
    else:
        body = f"""
        <div class="empty">
          <h2>😕 Koi test series nahi mili</h2>
          <p>Aapke account me koi test series nahi hai, ya Testbook ne API structure badal diya hai.</p>
          <br>
          <a href="/dashboard?debug=1" class="btn" style="margin-right:8px;">🔍 Debug Info</a>
          <a href="/dashboard" class="btn gray">🔄 Refresh</a>
        </div>
        {debug_html}
        """
    return HTMLResponse(page_shell("Dashboard", body))

@app.get("/series", response_class=HTMLResponse)
async def series_page(url: str = Query(...),
                      session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
            r = await client.get(url, headers=tb_headers(token, accept_json=False))
    except Exception as e:
        return HTMLResponse(page_shell("Error", f"<div class='empty'><h2>Error</h2><p>{str(e)}</p></div>"))

    if r.status_code in (401, 403):
        resp = RedirectResponse("/?error=session", status_code=302)
        resp.delete_cookie("tb_session")
        return resp

    soup = BeautifulSoup(r.text, "html.parser")
    title = soup.title.string.strip() if soup.title and soup.title.string else "Test Series"

    tests, seen = [], set()
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        text = a.get_text(" ", strip=True)
        if not text or len(text) < 4:
            continue
        if "/tests/" not in href and "/take-test" not in href:
            continue
        absolute = href if href.startswith("http") else BASE_URL + href
        if absolute in seen:
            continue
        seen.add(absolute)
        tests.append({"title": text, "link": absolute})

    if tests:
        cards = "".join(
            f'<div class="card"><a href="{item["link"]}" target="_blank">'
            f'<h3>{item["title"]}</h3>'
            f'<span class="badge">Open Test</span></a></div>'
            for item in tests
        )
        body = f"""
        <div style="margin-bottom:14px;"><a href="/dashboard" class="btn gray" style="padding:8px 16px;font-size:13px;">← Back</a></div>
        <div class="info-box"><b>{title}</b></div>
        <div class="section-title">📝 Tests ({len(tests)})</div>
        <div class="row">{cards}</div>
        """
    else:
        body = f"""
        <div style="margin-bottom:14px;"><a href="/dashboard" class="btn gray" style="padding:8px 16px;font-size:13px;">← Back</a></div>
        <div class="empty">
          <h2>Is series me tests nahi mile</h2>
          <p>{title}</p>
          <br>
          <a href="{url}" target="_blank" class="btn">🔗 Original Page</a>
        </div>
        """
    return HTMLResponse(page_shell(title, body))

# ---------- Debug endpoint ----------
@app.get("/debug/api", response_class=HTMLResponse)
async def debug_api(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    lines = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
        for ep in USER_API_ENDPOINTS + SERIES_API_ENDPOINTS:
            try:
                r = await client.get(ep, headers=tb_headers(token))
                preview = r.text[:200].replace("\n", " ") if r.status_code == 200 else ""
                lines.append(f"[{r.status_code}] {ep}\n    {preview}")
            except Exception as e:
                lines.append(f"[ERR] {ep} → {e}")

    body = f"""
    <div style="margin-bottom:14px;"><a href="/dashboard" class="btn gray" style="padding:8px 16px;font-size:13px;">← Back</a></div>
    <div class="section-title">🔍 API Debug</div>
    <div class="debug">{chr(10).join(lines)}</div>
    """
    return HTMLResponse(page_shell("Debug", body))

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
    series, _ = await fetch_series(token)
    return ScrapeResult(
        count=len(series),
        tests=[TestInfo(title=s["title"], link=s["link"], description=s.get("description") or None) for s in series],
    )
