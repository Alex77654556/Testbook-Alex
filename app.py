# app.py
import os
import re
import json
import time
import hmac
import base64
import hashlib
import httpx
from fastapi import FastAPI, Form, Cookie, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from bs4 import BeautifulSoup
from typing import Optional, List, Dict, Any
from urllib.parse import quote, urljoin, urlparse

app = FastAPI(title="Testbook Mirror", version="9.0.0")

BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

COUNT_API = f"{API_BASE}/api/v2_1/live-panel/count"
SERIES_API = f"{API_BASE}/api/v2_1/test-series?exam=rrb-group-d"

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

def validate_jwt(token: str):
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
        "userId": p.get("sub") or "",
    }

def tb_headers(token: str, json_accept: bool = True) -> Dict[str, str]:
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": UA,
        "Accept": "application/json, text/plain, */*" if json_accept else "text/html,*/*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
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

# ---------- Series API ----------
async def fetch_series(token: str) -> List[Dict]:
    """Fetch series from the discovered working endpoint."""
    url = f"{SERIES_API}&auth_code={quote(token, safe='')}&language=english"
    try:
        async with httpx.AsyncClient(timeout=20.0) as client:
            r = await client.get(url, headers=tb_headers(token))
            if r.status_code != 200:
                return []
            j = r.json()
            if not j.get("success"):
                return []
            data = j.get("data", {})
            series_list = data.get("testSeries", [])

            results, seen = [], set()
            for item in series_list:
                d = item.get("details", {})
                sid = str(d.get("slug") or d.get("id") or d.get("_id") or "")
                if not sid or sid in seen:
                    continue
                seen.add(sid)
                title = str(d.get("name") or d.get("title") or "Test Series")
                desc = str(d.get("description") or d.get("shortDescription") or "")[:250]
                total_tests = d.get("totalTests") or d.get("testsCount") or 0
                results.append({
                    "id": sid,
                    "title": title,
                    "description": desc,
                    "totalTests": total_tests,
                })
            return results
    except Exception as e:
        print("series fetch error:", e)
        return []

# ---------- HTML fallback for series detail ----------
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
        absolute = href if href.startswith("http") else BASE_URL + href
        if absolute in seen:
            continue
        seen.add(absolute)
        slug = absolute.rstrip("/").split("/")[-1]
        results.append({"id": slug, "title": text, "url": absolute})
    return results

def parse_series_page(html_text: str) -> Dict:
    soup = BeautifulSoup(html_text, "html.parser")
    title = "Test Series"
    if soup.title and soup.title.string:
        title = soup.title.string.strip()
    h1 = soup.find("h1")
    if h1:
        title = h1.get_text(strip=True)
    return {"title": title}

# ---------- Error handlers ----------
@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and request.url.path == "/":
        return RedirectResponse("/")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

# ---------- CSS / Shell ----------
CSS = """
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
.row{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:14px}
.empty{text-align:center;padding:40px 20px;color:#a0aec0}
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

def shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Testbook Mirror</title><style>{CSS}</style></head><body>
<div class="topbar"><h1>📚 Testbook Mirror</h1>
<div class="nav"><a href="/dashboard">🏠 Home</a><a href="/logout">Logout</a></div></div>
<div class="container">{body}</div>
<div class="floating"><a href="/dashboard" class="home">🏠 Home</a>
<a href="/logout" class="out">Logout</a></div>
</body></html>"""

LOGIN_HTML = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login · Testbook Mirror</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;
align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:18px;box-shadow:0 20px 60px rgba(0,0,0,.3);
padding:40px;width:100%;max-width:500px}
h1{color:#1a202c;font-size:22px;text-align:center;margin-bottom:6px}
p.sub{color:#718096;font-size:13px;text-align:center;margin-bottom:26px}
label{display:block;font-size:13px;color:#4a5568;font-weight:600;margin-bottom:8px}
textarea{width:100%;padding:13px;border:1.5px solid #e2e8f0;border-radius:10px;
font-size:13px;font-family:monospace;resize:vertical}
textarea:focus{outline:none;border-color:#667eea}
button{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);
color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;margin-top:20px}
.hint{margin-top:22px;padding:14px;background:#f7fafc;border-radius:10px;font-size:12px;color:#4a5568;line-height:1.75}
.hint code{background:#edf2f7;padding:1px 6px;border-radius:4px;font-size:11px}
.error{background:#fff5f5;color:#c53030;padding:12px;border-radius:8px;font-size:13px;margin-bottom:16px;text-align:center}
</style></head><body><div class="card">
<h1>🔐 Testbook Login</h1>
<p class="sub">Token daaliye — dashboard par aapki saari test series live aayengi.</p>
__ERROR__
<form method="post" action="/login">
<label>Access Token</label>
<textarea name="token" rows="6" placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." required autofocus></textarea>
<button type="submit">Login →</button></form>
<div class="hint"><b>Token kahan se?</b><br>
1. testbook.com par login<br>2. F12 → Network → Fetch/XHR<br>
3. Koi bhi <code>api.testbook.com</code> request<br>
4. <code>auth_code=eyJ...</code> wala part copy karein</div>
</div></body></html>"""

# ---------- Routes ----------
@app.get("/health")
async def health(): return {"status":"ok","version":"9.0.0"}

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
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__",'<div class="error">Token khali hai.</div>'), status_code=400)
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    if "auth_code=" in token:
        token = token.split("auth_code=")[1].split("&")[0]
    ok, msg = validate_jwt(token)
    if not ok:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">❌ {msg}</div>'), status_code=401)
    stats = await fetch_stats(token)
    if stats is None:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__",'<div class="error">❌ Token invalid ya expire.</div>'), status_code=401)
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
    series = await fetch_series(token)

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">series_count: {len(series)}\n\n{json.dumps(series[:5], indent=2, ensure_ascii=False)}</div>'

    stats_html = ""
    if stats:
        stats_html = f"""<div class="stat-row">
        <div class="stat"><div class="num">{stats.get('testsCount',0)}</div><div class="lbl">Tests</div></div>
        <div class="stat"><div class="num">{stats.get('quizzesCount',0)}</div><div class="lbl">Quizzes</div></div>
        <div class="stat"><div class="num">{stats.get('videosCount',0)}</div><div class="lbl">Videos</div></div>
        </div>"""

    greeting = f'<div class="info-box">✅ <b>Welcome, {user["name"]}!</b><br>{user["email"]}</div>'

    if series:
        # Show first 60 cards to keep page fast
        shown = series[:60]
        cards = "".join(
            f'<div class="card"><a href="/series?slug={quote(item["id"], safe="")}">'
            f'<h3>{item["title"]}</h3>'
            f'{f"<p>{item[chr(100)+chr(101)+chr(115)+chr(99)+chr(114)+chr(105)+chr(112)+chr(116)+chr(105)+chr(111)+chr(110)]}</p>" if item.get("description") else ""}'
            f'{f"<p>📝 {item[chr(116)+chr(111)+chr(116)+chr(97)+chr(108)+chr(84)+chr(101)+chr(115)+chr(116)+chr(115)]} Tests</p>" if item.get("totalTests") else ""}'
            f'<span class="badge">Open Series →</span></a></div>'
            for item in shown
        )
        note = f'<div class="info-box" style="background:#fef3c7;color:#92400e;">Showing first {len(shown)} of {len(series)} series.</div>' if len(series) > 60 else ""
        body = f"""{greeting}{stats_html}
        <div class="section-title">📚 Test Series ({len(series)})</div>
        {note}
        <div class="row">{cards}</div>
        {debug_html}"""
    else:
        body = f"""{greeting}{stats_html}
        <div class="empty">
          <h2>😕 Series list load nahi hui</h2>
          <p>Token sahi hai, lekin API se data nahi mila.</p>
          <br>
          <a href="/dashboard?debug=1" class="btn">🔍 Debug</a>
        </div>
        {debug_html}"""
    return HTMLResponse(shell("Dashboard", body))

# ---------- Series Page (our own UI) ----------
@app.get("/series", response_class=HTMLResponse)
async def series_page(slug: str = Query(...),
                      debug: int = 0,
                      session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    # Fetch Testbook series page HTML and parse tests
    url = f"{BASE_URL}/test-series/{slug}"
    tests, title = [], slug.replace("-", " ").title()
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
            r = await client.get(url, headers=tb_headers(token, json_accept=False))
        if r.status_code == 200:
            tests = parse_tests_from_html(r.text)
            info = parse_series_page(r.text)
            title = info.get("title") or title
    except Exception as e:
        print("series page err:", e)

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">slug: {slug}\ntests: {len(tests)}\n\n{json.dumps(tests[:5], indent=2, ensure_ascii=False)}</div>'

    if tests:
        cards = "".join(
            f'<div class="card"><a href="/test?slug={quote(t["id"], safe="")}">'
            f'<h3>{t["title"]}</h3>'
            f'<span class="badge green">Start Test →</span></a></div>'
            for t in tests
        )
        body = f"""<a href="/dashboard" class="back-btn">← Back</a>
        <div class="info-box"><b>📚 {title}</b></div>
        <div class="section-title">📝 Tests ({len(tests)})</div>
        <div class="row">{cards}</div>
        {debug_html}"""
    else:
        body = f"""<a href="/dashboard" class="back-btn">← Back</a>
        <div class="info-box"><b>📚 {title}</b></div>
        <div class="empty">
          <h2>Is series me tests nahi mile</h2>
          <p>Link: <code>{url}</code></p>
          <br>
          <a href="{url}" target="_blank" class="btn">🔗 Testbook par kholein</a>
          <a href="/series?slug={quote(slug,safe='')}&debug=1" class="btn gray" style="margin-left:8px;">🔍 Debug</a>
        </div>
        {debug_html}"""
    return HTMLResponse(shell(title, body))

# ---------- Test Page (our own UI) ----------
@app.get("/test", response_class=HTMLResponse)
async def test_page(slug: str = Query(...),
                    debug: int = 0,
                    session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    url = f"{BASE_URL}/tests/{slug}"
    body_html = ""
    title = slug.replace("-", " ").title()

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
            r = await client.get(url, headers=tb_headers(token, json_accept=False))
        if r.status_code == 200:
            soup = BeautifulSoup(r.text, "html.parser")
            if soup.title and soup.title.string:
                title = soup.title.string.strip()
            h1 = soup.find("h1")
            if h1:
                title = h1.get_text(strip=True)
            # Extract main visible text
            for t in soup(["script","style","noscript"]):
                t.decompose()
            body_html = soup.get_text("\n", strip=True)[:8000]
    except Exception as e:
        print("test page err:", e)

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">slug: {slug}\nlen(text): {len(body_html)}</div>'

    body = f"""<a href="javascript:history.back()" class="back-btn">← Back</a>
    <div class="info-box"><b>🎯 {title}</b></div>
    <div class="q-card" style="white-space:pre-wrap;font-size:13px;line-height:1.7;color:#4a5568;">
      {body_html[:6000] if body_html else "Content load nahi hua."}
    </div>
    <div style="text-align:center;margin-top:20px;">
      <a href="{url}" target="_blank" class="btn green" style="padding:12px 24px;">
        🎯 Test Start Karein (Testbook par)
      </a>
    </div>
    {debug_html}"""

    return HTMLResponse(shell(title, body))

@app.get("/api/stats")
async def api_stats(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return JSONResponse({"error":"not logged in"}, status_code=401)
    return {"user": get_user_info(token), "stats": await fetch_stats(token) or {}}

@app.get("/api/series")
async def api_series(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return JSONResponse({"error":"not logged in"}, status_code=401)
    series = await fetch_series(token)
    return {"count": len(series), "series": series[:50]}
