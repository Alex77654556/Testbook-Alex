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
from urllib.parse import quote

app = FastAPI(title="Testbook Mirror", version="8.0.0")

BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
HOME_PATH = "/rrb-group-d/test-series/my"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

COUNT_API = f"{API_BASE}/api/v2_1/live-panel/count"

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

# ---------- JSON walker ----------
def _looks_like_series(o):
    if not isinstance(o, dict): return False
    keys = set(o.keys())
    has_id = bool(keys & {"id","_id","slug","seriesId","testSeriesId","series_id"})
    has_title = bool(keys & {"name","title","seriesName","testSeriesName","series_name"})
    return has_id and has_title

def _looks_like_test(o):
    if not isinstance(o, dict): return False
    keys = set(o.keys())
    has_id = bool(keys & {"id","_id","slug","testId"})
    has_title = bool(keys & {"name","title","testName"})
    return has_id and has_title

def _walk(node, out, pred, depth=0):
    if depth > 10: return
    if isinstance(node, list):
        for x in node: _walk(x, out, pred, depth+1)
    elif isinstance(node, dict):
        if pred(node): out.append(node)
        for v in node.values():
            if isinstance(v, (list, dict)): _walk(v, out, pred, depth+1)

def normalize_series(items: List[dict]) -> List[Dict]:
    seen, result = set(), []
    for it in items:
        sid = str(it.get("slug") or it.get("id") or it.get("_id") or it.get("seriesId") or it.get("testSeriesId") or "")
        if not sid or sid in seen: continue
        seen.add(sid)
        title = str(it.get("name") or it.get("title") or it.get("seriesName") or it.get("testSeriesName") or "Test Series")
        desc = str(it.get("description") or it.get("shortDescription") or it.get("subTitle") or "")[:300]
        result.append({"id": sid, "title": title, "description": desc})
    return result

# ---------- Endpoint discovery ----------
def build_endpoints(user_id: str) -> List[str]:
    """Generate many endpoint candidates."""
    uid = quote(user_id, safe="")
    eps = [
        # v2_1 live-panel variants
        f"{API_BASE}/api/v2_1/live-panel/dashboard",
        f"{API_BASE}/api/v2_1/live-panel/home",
        f"{API_BASE}/api/v2_1/live-panel/user",
        f"{API_BASE}/api/v2_1/live-panel/series-count",
        f"{API_BASE}/api/v2_1/live-panel/panel",
        f"{API_BASE}/api/v2_1/live-panel/panel-data",
        f"{API_BASE}/api/v2_1/live-panel/tests-series",
        # v2_1 me/* paths
        f"{API_BASE}/api/v2_1/me/dashboard",
        f"{API_BASE}/api/v2_1/me/home",
        f"{API_BASE}/api/v2_1/me/series",
        f"{API_BASE}/api/v2_1/me/tests",
        f"{API_BASE}/api/v2_1/me/attempted",
        f"{API_BASE}/api/v2_1/me/attempted-tests",
        f"{API_BASE}/api/v2_1/me/purchased-tests",
        f"{API_BASE}/api/v2_1/me/purchased",
        # user-based
        f"{API_BASE}/api/v2_1/users/{uid}",
        f"{API_BASE}/api/v2_1/users/{uid}/dashboard",
        f"{API_BASE}/api/v2_1/users/{uid}/test-series",
        f"{API_BASE}/api/v2_1/user/{uid}/dashboard",
        f"{API_BASE}/api/v2_1/user/{uid}/test-series",
        f"{API_BASE}/api/v2/users/{uid}/dashboard",
        f"{API_BASE}/api/v2/users/{uid}/test-series",
        f"{API_BASE}/api/v2/users/{uid}/purchased-series",
        f"{API_BASE}/api/v2/users/{uid}/my-series",
        # v2 dashboards
        f"{API_BASE}/api/v2/dashboard",
        f"{API_BASE}/api/v2/me/dashboard",
        f"{API_BASE}/api/v2/user/dashboard",
        f"{API_BASE}/api/v2/me",
        f"{API_BASE}/api/v2/users/me",
        f"{API_BASE}/api/v2/user/my-test-series",
        f"{API_BASE}/api/v2/me/test-series",
        f"{API_BASE}/api/v2/user/test-series",
        # v3
        f"{API_BASE}/api/v3/me/dashboard",
        f"{API_BASE}/api/v3/users/me",
        f"{API_BASE}/api/v3/user/test-series",
        # Exam-based
        f"{API_BASE}/api/v2_1/exams/rrb-group-d",
        f"{API_BASE}/api/v2_1/exam/rrb-group-d",
        # Test series by exam
        f"{API_BASE}/api/v2_1/test-series?exam=rrb-group-d",
        f"{API_BASE}/api/v2_1/test-series?examSlug=rrb-group-d",
        f"{API_BASE}/api/v2_1/test-series?examId=rrb-group-d",
    ]
    return eps

async def find_series(token: str, user_id: str) -> tuple[List[Dict], str]:
    """Try every endpoint, return (series, endpoint_used)."""
    async with httpx.AsyncClient(follow_redirects=True, timeout=12.0) as client:
        for base_url in build_endpoints(user_id):
            for auth_style in ("param", "header"):
                try:
                    if auth_style == "param":
                        sep = "&" if "?" in base_url else "?"
                        full = f"{base_url}{sep}auth_code={quote(token, safe='')}&language=english"
                        r = await client.get(full, headers=tb_headers(token))
                    else:
                        r = await client.get(base_url, headers=tb_headers(token))
                    if r.status_code != 200:
                        continue
                    try:
                        j = r.json()
                    except Exception:
                        continue
                    raw: List[dict] = []
                    _walk(j, raw, _looks_like_series)
                    if raw:
                        return normalize_series(raw), f"{base_url} [{auth_style}]"
                except Exception:
                    continue
    return [], "none"

# ---------- HTML deep parsing ----------
def parse_html_for_series(html_text: str) -> List[Dict]:
    """Multi-strategy parser for Testbook SSR HTML."""
    results, seen = [], set()

    # Strategy 1: JSON blobs in <script> tags
    soup = BeautifulSoup(html_text, "html.parser")
    for sc in soup.find_all("script"):
        txt = sc.string or ""
        if not txt or len(txt) < 50:
            continue
        # Look for window.__... = {...} patterns
        for var in ("__INITIAL_STATE__", "__APP_STATE__", "__DATA__", "__NG_STATE__",
                    "window.__data", "window.state", "__REDUX_STATE__"):
            m = re.search(re.escape(var) + r"\s*=\s*(\{.*?\});", txt, re.DOTALL)
            if m:
                try:
                    data = json.loads(m.group(1))
                    raw: List[dict] = []
                    _walk(data, raw, _looks_like_series)
                    for x in normalize_series(raw):
                        if x["id"] not in seen:
                            seen.add(x["id"])
                            results.append(x)
                except Exception:
                    pass
        # Look for JSON with "testSeries" key
        try:
            if '"testSeries"' in txt or '"test_series"' in txt:
                # Extract any JSON-ish object
                for m in re.finditer(r'(\{[^{}]*"testSeries"[^{}]*\[[^\]]*\][^{}]*\})', txt, re.DOTALL):
                    pass  # complex, skip
        except Exception:
            pass

    # Strategy 2: Angular TransferState (script id="...-state" type="application/json")
    for sc in soup.find_all("script", type="application/json"):
        try:
            data = json.loads(sc.string or "")
            raw: List[dict] = []
            _walk(data, raw, _looks_like_series)
            for x in normalize_series(raw):
                if x["id"] not in seen:
                    seen.add(x["id"])
                    results.append(x)
        except Exception:
            continue

    # Strategy 3: Anchor tags
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        text = a.get_text(" ", strip=True)
        if not text or len(text) < 4:
            continue
        if "/test-series/" not in href or "/my" in href:
            continue
        # Skip if link is to a specific test (has /tests/ in path)
        absolute = href if href.startswith("http") else BASE_URL + href
        if absolute in seen:
            continue
        seen.add(absolute)
        # Extract slug
        slug = absolute.rstrip("/").split("/")[-1]
        results.append({"id": slug, "title": text, "description": ""})

    return results

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
.row{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:14px}
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
async def health(): return {"status":"ok","version":"8.0.0"}

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

    # Try API endpoints first
    series, endpoint = await find_series(token, user["userId"])

    # Fallback: fetch HTML and parse deeply
    if not series:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
                r = await client.get(BASE_URL + HOME_PATH, headers=tb_headers(token, json_accept=False))
            if r.status_code == 200:
                series = parse_html_for_series(r.text)
                endpoint = f"html-parse ({len(series)} found, len={len(r.text)})"
        except Exception as e:
            endpoint = f"html err: {e}"

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">endpoint: {endpoint}\nseries: {len(series)}\n\n{json.dumps(series[:5], indent=2, ensure_ascii=False)}</div>'

    stats_html = ""
    if stats:
        stats_html = f"""<div class="stat-row">
        <div class="stat"><div class="num">{stats.get('testsCount',0)}</div><div class="lbl">Tests</div></div>
        <div class="stat"><div class="num">{stats.get('quizzesCount',0)}</div><div class="lbl">Quizzes</div></div>
        <div class="stat"><div class="num">{stats.get('videosCount',0)}</div><div class="lbl">Videos</div></div>
        </div>"""

    greeting = f'<div class="info-box">✅ <b>Welcome, {user["name"]}!</b><br>{user["email"]}</div>'

    if series:
        cards = "".join(
            f'<div class="card"><a href="{BASE_URL}/test-series/{item["id"]}" target="_blank">'
            f'<h3>{item["title"]}</h3>'
            f'{f"<p>{item[chr(100)+chr(101)+chr(115)+chr(99)+chr(114)+chr(105)+chr(112)+chr(116)+chr(105)+chr(111)+chr(110)]}</p>" if item.get("description") else ""}'
            f'<span class="badge">Test Series</span></a></div>'
            for item in series
        )
        body = f"""{greeting}{stats_html}
        <div class="section-title">📚 Aapki Test Series ({len(series)})</div>
        <div class="row">{cards}</div>
        {debug_html}"""
    else:
        body = f"""{greeting}{stats_html}
        <div class="empty">
          <h2>😕 Test series list nahi mili</h2>
          <p>Aapka token sahi hai (stats aa gaye hain). Bas series ka endpoint nahi mil raha.</p>
          <p style="margin-top:8px;font-size:12px;">Tried: <b>{endpoint}</b></p>
          <br>
          <a href="/debug/probe" class="btn">🔍 50+ Endpoints Probe</a>
        </div>
        {debug_html}"""
    return HTMLResponse(shell("Dashboard", body))

# ---------- Probe ----------
@app.get("/debug/probe", response_class=HTMLResponse)
async def probe(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    user = get_user_info(token)
    endpoints = build_endpoints(user["userId"])

    lines = []
    async with httpx.AsyncClient(follow_redirects=True, timeout=8.0) as client:
        for base_url in endpoints:
            for auth_style in ("param", "header"):
                try:
                    if auth_style == "param":
                        sep = "&" if "?" in base_url else "?"
                        full = f"{base_url}{sep}auth_code={quote(token, safe='')}"
                        r = await client.get(full, headers=tb_headers(token))
                    else:
                        r = await client.get(base_url, headers=tb_headers(token))
                    status = r.status_code
                    body_snip = r.text[:100].replace("\n"," ")
                    if status == 200:
                        try:
                            j = r.json()
                            raw: List[dict] = []
                            _walk(j, raw, _looks_like_series)
                            mark = f'✅ [200] series={len(raw)}' if raw else '⚠️  [200] no-series'
                        except Exception:
                            mark = '⚠️  [200] non-json'
                    else:
                        mark = f'❌ [{status}]'
                    lines.append(f'{mark}  ({auth_style})  {base_url}')
                    if status != 404:
                        lines.append(f'      {body_snip}')
                except Exception as e:
                    lines.append(f'💥 ERR  ({auth_style})  {base_url}  → {e}')

    body = f"""<a href="/dashboard" class="btn gray" style="margin-bottom:14px;">← Back</a>
    <div class="info-box">Har endpoint do authentication style se test kiya gaya (param + header).</div>
    <div class="debug">{chr(10).join(lines)}</div>"""
    return HTMLResponse(shell("Probe", body))
