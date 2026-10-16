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

app = FastAPI(title="Testbook Mirror", version="10.0.0")

BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

COUNT_API = f"{API_BASE}/api/v2_1/live-panel/count"
SERIES_LIST_API = f"{API_BASE}/api/v2_1/test-series"

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

# ---------- Series list ----------
async def fetch_series(token: str) -> List[Dict]:
    url = f"{SERIES_LIST_API}?exam=rrb-group-d&auth_code={quote(token, safe='')}&language=english"
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
                sid = str(d.get("id") or d.get("_id") or "")
                slug = d.get("slug") or ""
                if not sid or sid in seen:
                    continue
                seen.add(sid)
                title = str(d.get("name") or d.get("title") or "Test Series")
                desc = str(d.get("description") or d.get("shortDescription") or "")[:250]
                total_tests = d.get("totalTests") or d.get("testsCount") or 0
                results.append({
                    "id": sid,
                    "slug": slug,
                    "title": title,
                    "description": desc,
                    "totalTests": total_tests,
                })
            return results
    except Exception as e:
        print("series fetch error:", e)
        return []

# ---------- Series detail: multiple strategies ----------
def series_detail_endpoints(id_or_slug: str) -> List[str]:
    s = quote(id_or_slug, safe="")
    return [
        f"{API_BASE}/api/v2_1/test-series/{s}",
        f"{API_BASE}/api/v2_1/test-series/{s}/tests",
        f"{API_BASE}/api/v2_1/test-series/{s}/details",
        f"{API_BASE}/api/v2_1/test-series/{s}/test-list",
        f"{API_BASE}/api/v2_1/testSeries/{s}",
        f"{API_BASE}/api/v2_1/testSeries/{s}/tests",
        f"{API_BASE}/api/v2/test-series/{s}",
        f"{API_BASE}/api/v2/test-series/{s}/tests",
        f"{API_BASE}/api/v2/testSeries/{s}",
        f"{API_BASE}/api/v3/test-series/{s}",
        f"{API_BASE}/api/v2_1/live-panel/test-series/{s}",
        f"{API_BASE}/api/v2_1/live-panel/test-series/{s}/tests",
    ]

def _looks_like_test(o):
    if not isinstance(o, dict): return False
    keys = set(o.keys())
    has_id = bool(keys & {"id","_id","slug","testId","test_id"})
    has_title = bool(keys & {"name","title","testName","test_name"})
    return has_id and has_title

def _walk(node, out, pred, depth=0):
    if depth > 10: return
    if isinstance(node, list):
        for x in node: _walk(x, out, pred, depth+1)
    elif isinstance(node, dict):
        if pred(node): out.append(node)
        for v in node.values():
            if isinstance(v, (list, dict)): _walk(v, out, pred, depth+1)

def normalize_tests(items: List[dict]) -> List[Dict]:
    seen, result = set(), []
    for it in items:
        tid = str(it.get("slug") or it.get("id") or it.get("_id") or it.get("testId") or "")
        if not tid or tid in seen: continue
        seen.add(tid)
        title = str(it.get("name") or it.get("title") or it.get("testName") or "Test")
        dur = it.get("duration") or it.get("totalTime") or 0
        qcount = it.get("questionCount") or it.get("totalQuestions") or it.get("questionsCount") or 0
        result.append({"id": tid, "title": title, "duration": dur, "questionCount": qcount})
    return result

async def fetch_series_detail(token: str, id_or_slug: str) -> tuple[List[Dict], str, Dict]:
    """Try multiple endpoints; return (tests, endpoint_used, debug_info)."""
    debug = {"tried": [], "series_info": None}
    async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
        for base_url in series_detail_endpoints(id_or_slug):
            try:
                full = f"{base_url}?auth_code={quote(token, safe='')}&language=english"
                r = await client.get(full, headers=tb_headers(token))
                entry = {"url": base_url, "status": r.status_code, "len": len(r.content)}
                if r.status_code == 200:
                    try:
                        j = r.json()
                        entry["success"] = j.get("success")
                        raw: List[dict] = []
                        _walk(j, raw, _looks_like_test)
                        entry["tests_found"] = len(raw)
                        entry["preview"] = json.dumps(j, ensure_ascii=False)[:400]
                        if raw:
                            debug["tried"].append(entry)
                            return normalize_tests(raw), base_url, debug
                    except Exception as e:
                        entry["json_err"] = str(e)
                else:
                    entry["preview"] = r.text[:200]
                debug["tried"].append(entry)
            except Exception as e:
                debug["tried"].append({"url": base_url, "status": "ERR", "error": str(e)})

    # HTML fallback
    html_urls = [
        f"{BASE_URL}/test-series/{id_or_slug}",
    ]
    for url in html_urls:
        try:
            async with httpx.AsyncClient(follow_redirects=True, timeout=25.0) as client:
                r = await client.get(url, headers=tb_headers(token, json_accept=False))
            entry = {"url": url, "status": r.status_code, "len": len(r.content), "type": "html"}
            if r.status_code == 200:
                soup = BeautifulSoup(r.text, "html.parser")
                tests, seen = [], set()
                for a in soup.select("a[href]"):
                    href = a.get("href", "")
                    text = a.get_text(" ", strip=True)
                    if not text or len(text) < 4: continue
                    if "/tests/" not in href and "/take-test" not in href: continue
                    absolute = href if href.startswith("http") else BASE_URL + href
                    if absolute in seen: continue
                    seen.add(absolute)
                    slug = absolute.rstrip("/").split("/")[-1]
                    tests.append({"id": slug, "title": text, "duration": 0, "questionCount": 0})
                entry["tests_found"] = len(tests)
                debug["tried"].append(entry)
                if tests:
                    return tests, url, debug
            else:
                debug["tried"].append(entry)
        except Exception as e:
            debug["tried"].append({"url": url, "status": "ERR", "error": str(e)})

    return [], "none", debug

# ---------- Error handlers ----------
@app.exception_handler(StarletteHTTPException)
async def http_exc(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and request.url.path == "/":
        return RedirectResponse("/")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

@app.exception_handler(Exception)
async def all_exc(request: Request, exc: Exception):
    import traceback
    tb = traceback.format_exc()
    print("ERROR:", tb)
    return HTMLResponse(f"<h1>Error</h1><pre style='white-space:pre-wrap'>{tb}</pre>", status_code=500)

# ---------- CSS ----------
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
.container{max-width:920px;margin:0 auto;padding:20px}
.section-title{font-size:15px;font-weight:700;color:#4a5568;margin:8px 0 14px;
text-transform:uppercase;letter-spacing:.5px}
.card{background:#fff;border-radius:14px;padding:18px;margin-bottom:14px;
box-shadow:0 2px 10px rgba(0,0,0,.06);border-left:4px solid #4f46e5}
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
font-family:monospace;font-size:11px;overflow:auto;max-height:600px;
line-height:1.5;white-space:pre-wrap;word-break:break-word}
.back-btn{display:inline-block;margin-bottom:14px;padding:8px 16px;
background:#e2e8f0;color:#4a5568;border-radius:8px;text-decoration:none;
font-size:13px;font-weight:600}
"""

def shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{title} · Testbook Mirror</title><style>{CSS}</style></head><body>
<div class="topbar"><h1>📚 Testbook Mirror</h1>
<div class="nav"><a href="/dashboard">🏠 Home</a>
<a href="/debug/probe">🔍 Debug</a>
<a href="/logout">Logout</a></div></div>
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
async def health(): return {"status":"ok","version":"10.0.0"}

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
        shown = series[:60]
        cards = "".join(
            f'<div class="card"><a href="/series?id={quote(item["id"], safe="")}&slug={quote(item.get("slug","") or "", safe="")}">'
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

# ---------- Series Page ----------
@app.get("/series", response_class=HTMLResponse)
async def series_page(id: str = Query(""), slug: str = Query(""),
                      debug: int = 0,
                      session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    # Try ID first (more reliable), then slug
    tests, endpoint, dbg = [], "none", {"tried": []}
    if id:
        tests, endpoint, dbg = await fetch_series_detail(token, id)
    if not tests and slug:
        tests, endpoint, dbg = await fetch_series_detail(token, slug)

    title = slug.replace("-", " ").title() if slug else (id[:8] if id else "Test Series")

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">endpoint: {endpoint}\nid: {id}\nslug: {slug}\ntests: {len(tests)}\n\nTRIES:\n{json.dumps(dbg.get("tried",[]), indent=2, ensure_ascii=False)[:3000]}\n\nTESTS:\n{json.dumps(tests[:8], indent=2, ensure_ascii=False)}</div>'

    if tests:
        cards = "".join(
            f'<div class="card"><a href="/test?slug={quote(t["id"], safe="")}">'
            f'<h3>{t["title"]}</h3>'
            f'{f"<p>⏱ {t[chr(100)+chr(117)+chr(114)+chr(97)+chr(116)+chr(105)+chr(111)+chr(110)]} min · 📝 {t[chr(113)+chr(117)+chr(101)+chr(115)+chr(116)+chr(105)+chr(111)+chr(110)+chr(67)+chr(111)+chr(117)+chr(110)+chr(116)]} Qs</p>" if t.get("duration") or t.get("questionCount") else ""}'
            f'<span class="badge green">Open Test →</span></a></div>'
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
          <h2>Is series me tests nahi mil rahe</h2>
          <p>ID: <code>{id or "(none)"}</code><br>Slug: <code>{slug or "(none)"}</code></p>
          <p>Endpoint: <b>{endpoint}</b></p>
          <br>
          <a href="/series?id={quote(id,safe='')}&slug={quote(slug,safe='')}&debug=1" class="btn">🔍 Debug Info</a>
        </div>
        {debug_html}"""
    return HTMLResponse(shell(title, body))

# ---------- Test Page ----------
@app.get("/test", response_class=HTMLResponse)
async def test_page(slug: str = Query(...),
                    debug: int = 0,
                    session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    url = f"{BASE_URL}/tests/{slug}"
    body_text = ""
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
            for t in soup(["script","style","noscript"]):
                t.decompose()
            body_text = soup.get_text("\n", strip=True)[:8000]
    except Exception as e:
        print("test page err:", e)

    debug_html = ""
    if debug == 1:
        debug_html = f'<div class="debug">slug: {slug}\nlen: {len(body_text)}</div>'

    body = f"""<a href="javascript:history.back()" class="back-btn">← Back</a>
    <div class="info-box"><b>🎯 {title}</b></div>
    <div class="card" style="white-space:pre-wrap;font-size:13px;line-height:1.7;color:#4a5568;">
      {body_text[:6000] if body_text else "Content load nahi hua."}
    </div>
    <div style="text-align:center;margin-top:20px;">
      <a href="{url}" target="_blank" class="btn" style="padding:12px 24px;background:#10b981;">
        🎯 Test Start Karein (Testbook par)
      </a>
    </div>
    {debug_html}"""
    return HTMLResponse(shell(title, body))

# ---------- DEBUG: probe all endpoints ----------
@app.get("/debug/probe", response_class=HTMLResponse)
async def probe(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    user = get_user_info(token)

    lines = []
    lines.append("=" * 60)
    lines.append("1. STATS ENDPOINT")
    lines.append("=" * 60)
    lines.append(f"URL: {COUNT_API}")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            r = await client.get(f"{COUNT_API}?auth_code={quote(token,safe='')}", headers=tb_headers(token))
            lines.append(f"Status: {r.status_code}")
            lines.append(f"Body: {r.text[:300]}")
    except Exception as e:
        lines.append(f"ERR: {e}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("2. SERIES LIST ENDPOINTS")
    lines.append("=" * 60)

    series_candidates = [
        f"{API_BASE}/api/v2_1/test-series?exam=rrb-group-d",
        f"{API_BASE}/api/v2_1/test-series?examSlug=rrb-group-d",
        f"{API_BASE}/api/v2_1/test-series?examId=rrb-group-d",
        f"{API_BASE}/api/v2_1/test-series",
    ]
    for base_url in series_candidates:
        sep = "&" if "?" in base_url else "?"
        full = f"{base_url}{sep}auth_code={quote(token, safe='')}&language=english"
        try:
            async with httpx.AsyncClient(timeout=15.0) as client:
                r = await client.get(full, headers=tb_headers(token))
            lines.append(f"\n[{r.status_code}] {base_url}")
            if r.status_code == 200:
                try:
                    j = r.json()
                    data = j.get("data", {})
                    ts = data.get("testSeries", []) if isinstance(data, dict) else []
                    lines.append(f"   → series count: {len(ts)}")
                    if ts:
                        lines.append(f"   → first item keys: {list(ts[0].keys())}")
                        lines.append(f"   → first detail: {json.dumps(ts[0], ensure_ascii=False)[:400]}")
                except Exception as e:
                    lines.append(f"   JSON err: {e} | {r.text[:200]}")
            else:
                lines.append(f"   {r.text[:200]}")
        except Exception as e:
            lines.append(f"\n[ERR] {base_url} → {e}")

    lines.append("")
    lines.append("=" * 60)
    lines.append("3. SERIES DETAIL ENDPOINTS (sample series ID)")
    lines.append("=" * 60)
    sample_id = "6ab5248ae37ee951f170ed7e"
    lines.append(f"Sample ID: {sample_id}")
    for url in series_detail_endpoints(sample_id):
        full = f"{url}?auth_code={quote(token, safe='')}&language=english"
        try:
            async with httpx.AsyncClient(timeout=10.0) as client:
                r = await client.get(full, headers=tb_headers(token))
            lines.append(f"\n[{r.status_code}] {url}")
            if r.status_code == 200:
                try:
                    j = r.json()
                    raw: List[dict] = []
                    _walk(j, raw, _looks_like_test)
                    lines.append(f"   → tests found: {len(raw)}")
                    lines.append(f"   → preview: {json.dumps(j, ensure_ascii=False)[:300]}")
                except Exception as e:
                    lines.append(f"   {r.text[:200]}")
            else:
                lines.append(f"   {r.text[:150]}")
        except Exception as e:
            lines.append(f"\n[ERR] {url} → {e}")

    body = f"""<a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box">Debug output — copy karke bhej sakte hain</div>
    <div class="debug">{chr(10).join(lines)}</div>"""
    return HTMLResponse(shell("Debug Probe", body))

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
    return {"count": len(series), "series": series[:20]}
