# app.py
import os
import json
import time
import hmac
import base64
import hashlib
import asyncio
import httpx
import html as html_lib
from bs4 import BeautifulSoup
from fastapi import FastAPI, Form, Cookie, Query, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Optional, List, Dict, Any
from urllib.parse import quote

app = FastAPI(title="Testbook Mirror", version="40.0.0",
              docs_url=None, redoc_url=None, openapi_url=None)

BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

COUNT_API = f"{API_BASE}/api/v2_1/live-panel/count"
ALL_API = f"{API_BASE}/api/v2_1/live-panel/all"

# ---------- Rate Limiter ----------
_rate_lock = asyncio.Lock()
_last_req_time = 0.0
MIN_DELAY = 1.5  # 1.5 sec delay to avoid 429
_cache: Dict[str, tuple] = {}
CACHE_TTL = 300

async def rate_limited_get(client: httpx.AsyncClient, url: str, headers: dict):
    global _last_req_time
    async with _rate_lock:
        now = time.time()
        wait = MIN_DELAY - (now - _last_req_time)
        if wait > 0:
            await asyncio.sleep(wait)
        _last_req_time = time.time()
        try:
            return await client.get(url, headers=headers)
        except Exception:
            return None

async def cached_get(client: httpx.AsyncClient, url: str, headers: dict):
    now = time.time()
    if url in _cache:
        ts, resp = _cache[url]
        if now - ts < CACHE_TTL:
            return resp
    resp = await rate_limited_get(client, url, headers)
    if resp is not None:
        _cache[url] = (time.time(), resp)
    return resp

# ---------- Helpers ----------
def esc(s) -> str:
    if s is None: return ""
    return (str(s).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;"))

def sign_token(token: str) -> str:
    data = base64.urlsafe_b64encode(token.encode()).decode()
    sig = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{data}.{sig}"

def unsign_token(cookie: str) -> Optional[str]:
    try:
        data, sig = cookie.rsplit(".", 1)
        expected = hmac.new(SESSION_SECRET.encode(), data.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(sig, expected): return None
        return base64.urlsafe_b64decode(data.encode()).decode()
    except Exception: return None

def get_token(session_cookie: Optional[str]) -> Optional[str]:
    if not session_cookie: return None
    return unsign_token(session_cookie)

def decode_jwt_payload(token: str) -> Optional[dict]:
    try:
        parts = token.split(".")
        if len(parts) != 3: return None
        payload = parts[1] + "=" * (-len(parts[1]) % 4)
        return json.loads(base64.urlsafe_b64decode(payload))
    except Exception: return None

def get_user_info(token: str) -> dict:
    p = decode_jwt_payload(token) or {}
    return {"name": p.get("name") or "User", "email": p.get("email") or "",
            "isPaid": p.get("isPaidUser", False), "userId": p.get("sub") or ""}

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

async def fetch_stats(token: str) -> Optional[dict]:
    url = f"{COUNT_API}?auth_code={quote(token, safe='')}&language=english"
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await cached_get(client, url, tb_headers(token))
        if r and r.status_code == 200:
            j = r.json()
            if j.get("success"): return j.get("data", {})
    return None

def _clean_text(s) -> str:
    if s is None: return ""
    s = str(s)
    for _ in range(3):
        new_s = html_lib.unescape(s)
        if new_s == s: break
        s = new_s
    try: s = BeautifulSoup(s, "html.parser").get_text()
    except Exception: pass
    return " ".join(s.replace("\u00a0", " ").split()).strip()

# ---------- STRICT Extraction Logic ----------
# FIX: Ab hum "exam tags" ko test series nahi samjhenge. Sirf real series uthayenge.
def _extract_series_from_obj(obj):
    if not isinstance(obj, dict): return None
    
    # Ignore specificExams / targetGroups (these are just tags)
    keys = set(obj.keys())
    if "isPrimary" in keys or "stateId" in keys or "targetGroup" in keys: return None
    
    details = obj.get("details") or {}
    prog = obj.get("progress") or {}
    
    sid = (obj.get("id") or obj.get("_id") or obj.get("seriesId") or obj.get("tsid") 
           or details.get("id") or details.get("_id"))
    name = (obj.get("name") or obj.get("title") or obj.get("seriesName") 
            or details.get("name") or details.get("title"))
    
    if not sid or not name: return None

    # Agar test count ya progress object hai, tabhi ye real series hai
    has_counts = ("totalTests" in obj or "testCount" in obj or "progress" in obj or 
                  "totalTests" in details or "testCount" in details)
    if not has_counts: return None

    purchase_info = obj.get("purchaseInfo") or details.get("purchaseInfo") or []
    is_free = any(isinstance(p, dict) and p.get("type") == "Free" for p in purchase_info)

    return {
        "id": str(sid),
        "title": _clean_text(name),
        "description": _clean_text(str(obj.get("description") or details.get("description") or ""))[:150],
        "totalTests": int(prog.get("total") or obj.get("totalTests") or obj.get("testCount") or details.get("testCount") or 0),
        "attempted": int(prog.get("attempted") or obj.get("attempted") or 0),
        "hasAccess": bool(obj.get("hasAccess") or details.get("hasAccess") or is_free),
        "isFree": is_free,
    }

def _extract_test_from_obj(obj):
    if not isinstance(obj, dict): return None
    tid = obj.get("id") or obj.get("_id")
    title = obj.get("title") or obj.get("name")
    if not tid or not title: return None
    if not ("questionCount" in obj or "duration" in obj or "totalMarks" in obj): return None
    return {
        "id": str(tid),
        "title": _clean_text(title),
        "questionCount": obj.get("questionCount") or 0,
        "duration": obj.get("duration") or 0,
        "isFree": bool(obj.get("isFree") or False),
    }

def _walk(node, out_series, out_tests, depth=0):
    if depth > 15: return
    if isinstance(node, list):
        for x in node: _walk(x, out_series, out_tests, depth + 1)
    elif isinstance(node, dict):
        s = _extract_series_from_obj(node)
        if s: out_series.append(s)
        t = _extract_test_from_obj(node)
        if t: out_tests.append(t)
        for v in node.values():
            if isinstance(v, (list, dict)): _walk(v, out_series, out_tests, depth + 1)

def extract_questions(data: dict) -> List[Dict]:
    questions = []
    sections = data.get("sections") or []
    if not sections and isinstance(data.get("questions"), list):
        sections = [{"title": "", "questions": data["questions"]}]
    
    for sec in sections:
        for q in sec.get("questions", []):
            if not isinstance(q, dict): continue
            
            def _parse(lang):
                if not isinstance(lang, dict): return {"text": "", "options": [], "correctIndex": -1}
                txt = _clean_text(lang.get("value") or lang.get("questionText") or "")
                opts, ci = [], -1
                for i, o in enumerate(lang.get("options") or []):
                    if isinstance(o, dict):
                        opts.append(_clean_text(o.get("value") or o.get("text") or ""))
                        if o.get("isCorrect") is True or o.get("correct") is True: ci = i
                    else: opts.append(_clean_text(str(o)))
                return {"text": txt, "options": opts, "correctIndex": ci}

            en = _parse(q.get("en") or {})
            hi = _parse(q.get("hi") or {})
            primary = en if en["text"] else hi

            questions.append({
                "id": q.get("_id") or q.get("id") or "", 
                "section": sec.get("title", ""),
                "text": primary["text"], "options": primary["options"],
                "text_en": en["text"], "options_en": en["options"],
                "text_hi": hi["text"], "options_hi": hi["options"],
                "posMarks": q.get("posMarks", 4), "negMarks": q.get("negMarks", 1),
                "correctIndex": primary["correctIndex"],
            })
    return questions

# ---------- CSS ----------
CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:#f0f4f8;color:#1a202c;min-height:100vh}
.topbar{background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;padding:14px 18px;display:flex;align-items:center;justify-content:space-between;position:sticky;top:0;z-index:100;box-shadow:0 4px 14px rgba(0,0,0,.15);flex-wrap:wrap;gap:8px}
.topbar h1{font-size:16px;font-weight:700}
.topbar .nav{display:flex;gap:6px;font-size:12px;flex-wrap:wrap}
.topbar .nav a{color:#fff;text-decoration:none;padding:6px 12px;background:rgba(255,255,255,.18);border-radius:8px;font-weight:600}
.container{max-width:920px;margin:0 auto;padding:18px}
.section-title{font-size:14px;font-weight:700;color:#4a5568;margin:20px 0 12px;text-transform:uppercase;letter-spacing:.5px}
.card{background:#fff;border-radius:14px;padding:16px;margin-bottom:12px;box-shadow:0 2px 10px rgba(0,0,0,.06);border-left:4px solid #4f46e5}
.card a{text-decoration:none;color:#1a202c;display:block}
.card h3{font-size:14px;font-weight:700;margin-bottom:6px;line-height:1.4}
.card p{font-size:12px;color:#718096;line-height:1.55;margin-top:4px}
.badge{display:inline-block;background:#eef2ff;color:#4f46e5;font-size:10px;font-weight:700;padding:3px 9px;border-radius:12px;margin-top:8px;text-transform:uppercase;letter-spacing:.3px}
.badge.green{background:#d1fae5;color:#059669}
.badge.orange{background:#fed7aa;color:#c2410c}
.badge.red{background:#fee2e2;color:#dc2626}
.row{display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px}
.empty{text-align:center;padding:40px 20px;color:#a0aec0}
.empty h2{font-size:18px;margin-bottom:8px;color:#4a5568}
.btn{display:inline-block;padding:11px 20px;background:#4f46e5;color:#fff;border:none;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;cursor:pointer;text-align:center}
.info-box{background:#eef2ff;border-radius:12px;padding:14px;margin-bottom:16px;font-size:13px;color:#3730a3;line-height:1.7}
.warn-box{background:#fef3c7;border-radius:12px;padding:14px;margin-bottom:16px;font-size:13px;color:#78350f;line-height:1.7;border-left:4px solid #f59e0b}
.stat-row{display:flex;gap:12px;flex-wrap:wrap;margin-bottom:14px}
.stat{background:#fff;padding:12px 16px;border-radius:12px;box-shadow:0 2px 8px rgba(0,0,0,.05);flex:1;min-width:110px;text-align:center}
.stat .num{font-size:24px;font-weight:800;color:#4f46e5}
.stat .lbl{font-size:11px;color:#718096;text-transform:uppercase;letter-spacing:.4px;margin-top:4px}
.search-box{display:flex;gap:8px;margin-bottom:18px}
.search-box input{flex:1;padding:12px 16px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:14px;outline:none}
.search-box button{padding:12px 20px;background:#4f46e5;color:#fff;border:none;border-radius:10px;font-weight:600;cursor:pointer}
.back-btn{display:inline-block;margin-bottom:14px;padding:8px 16px;background:#e2e8f0;color:#4a5568;border-radius:8px;text-decoration:none;font-size:13px;font-weight:600}
.tb-header{background:#fff;padding:12px 16px;position:sticky;top:56px;z-index:40;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.tb-header .q-num-big{font-size:24px;font-weight:800;min-width:36px}
.tb-header .q-stats{display:flex;gap:16px;font-size:12px;color:#4a5568;flex:1}
.tb-header .timer-box{background:#1a202c;color:#fff;padding:6px 14px;border-radius:8px;font-family:monospace;font-size:14px;font-weight:700}
.tb-header .lang-select{padding:6px 12px;border:1.5px solid #e2e8f0;border-radius:8px;font-size:13px;font-weight:600;background:#fff;cursor:pointer}
.tb-question{padding:20px 16px;background:#fff}
.tb-question .q-text{font-size:16px;line-height:1.7;margin-bottom:20px;white-space:pre-wrap}
.tb-opt{display:flex;align-items:flex-start;gap:12px;padding:14px 16px;background:#fff;border:1.5px solid #e2e8f0;border-radius:10px;margin-bottom:12px;cursor:pointer;font-size:15px;line-height:1.5;user-select:none}
.tb-opt.selected{border-color:#4f46e5;background:#eef2ff}
.tb-opt .radio{width:22px;height:22px;min-width:22px;border:2px solid #cbd5e0;border-radius:50%}
.tb-opt.selected .radio{border-color:#4f46e5;background:#4f46e5}
.tb-nav{background:#fff;padding:12px 16px;display:flex;gap:10px;flex-wrap:wrap;border-top:1px solid #e2e8f0;position:sticky;bottom:0;z-index:40}
.tb-nav button{flex:1;min-width:100px;padding:12px;border:none;border-radius:8px;font-size:14px;font-weight:700;cursor:pointer}
.btn-clear,.btn-prev{background:#e2e8f0;color:#4a5568}
.btn-save{background:#1fbad6;color:#fff}
.btn-submit{background:#10b981;color:#fff}
.q-indicator{display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:6px;background:#e2e8f0;color:#4a5568;font-size:11px;font-weight:700;margin:2px;cursor:pointer}
.q-indicator.answered{background:#4f46e5;color:#fff}
.q-indicator.current{outline:2px solid #4f46e5;outline-offset:1px}
.q-indicators{display:flex;flex-wrap:wrap;gap:4px;padding:12px 16px;background:#fff;border-bottom:1px solid #e2e8f0}
.result-box{background:linear-gradient(135deg,#4f46e5,#7c3aed);color:#fff;padding:24px;border-radius:14px;text-align:center;margin:16px}
.result-box .score{font-size:42px;font-weight:900;margin:8px 0}
.step{background:#fff;border-radius:12px;padding:16px;margin-bottom:12px;box-shadow:0 2px 8px rgba(0,0,0,.05)}
.step-num{display:inline-flex;align-items:center;justify-content:center;width:26px;height:26px;background:#4f46e5;color:#fff;border-radius:50%;font-weight:700;font-size:13px;margin-right:8px}
.step code{background:#f7fafc;padding:2px 6px;border-radius:4px;font-family:monospace;font-size:12px;color:#4f46e5;border:1px solid #e2e8f0}
.probe-row{padding:10px;border-bottom:1px solid #e2e8f0;display:flex;gap:8px;align-items:center;font-size:12px}
.probe-row:last-child{border-bottom:none}
.probe-status{font-weight:700;min-width:50px}
.probe-path{flex:1;font-family:monospace;word-break:break-all}
"""

def shell(title: str, body: str) -> str:
    return f"""<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{esc(title)} · Testbook Mirror</title><style>{CSS}</style></head><body>
<div class="topbar"><h1>📚 Testbook Mirror</h1>
<div class="nav"><a href="/dashboard">🏠 Home</a>
<a href="/raw">🐛 Raw Data</a>
<a href="/logout">Logout</a></div></div>
{body}
</body></html>"""

LOGIN_HTML = """<!DOCTYPE html><html><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Login</title><style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:18px;box-shadow:0 20px 60px rgba(0,0,0,.3);padding:40px;width:100%;max-width:500px}
h1{color:#1a202c;font-size:22px;text-align:center;margin-bottom:6px}
p.sub{color:#718096;font-size:13px;text-align:center;margin-bottom:26px}
label{display:block;font-size:13px;color:#4a5568;font-weight:600;margin-bottom:8px}
textarea{width:100%;padding:13px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:13px;font-family:monospace;resize:vertical}
textarea:focus{outline:none;border-color:#667eea}
button{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;margin-top:20px}
.error{background:#fff5f5;color:#c53030;padding:12px;border-radius:8px;font-size:13px;margin-bottom:16px;text-align:center}
</style></head><body><div class="card">
<h1>🔐 Testbook Login</h1>
<p class="sub">Token daaliye.</p>
__ERROR__
<form method="post" action="/login">
<label>Access Token</label>
<textarea name="token" rows="6" placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." required autofocus></textarea>
<button type="submit">Login →</button></form>
</div></body></html>"""

# ---------- Routes ----------
@app.get("/health")
async def health(): return {"status": "ok"}

@app.get("/", response_class=HTMLResponse)
async def root(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    if get_token(session_cookie): return RedirectResponse("/dashboard", status_code=302)
    return HTMLResponse(LOGIN_HTML.replace("__ERROR__", ""))

@app.post("/login")
async def login(token: str = Form(...)):
    token = token.strip()
    if not token:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", '<div class="error">Token khali.</div>'), status_code=400)
    if token.lower().startswith("bearer "): token = token[7:].strip()
    if "auth_code=" in token: token = token.split("auth_code=")[1].split("&")[0]
    
    p = decode_jwt_payload(token)
    if not p:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">❌ Token format galat hai.</div>'), status_code=401)
        
    stats = await fetch_stats(token)
    if stats is None:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", '<div class="error">❌ Token invalid ya rate limited.</div>'), status_code=401)
        
    resp = RedirectResponse("/dashboard", status_code=303)
    resp.set_cookie("tb_session", sign_token(token), httponly=True, samesite="lax", max_age=7*24*3600, secure=False)
    return resp

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("tb_session")
    return resp

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)

    user = get_user_info(token)
    stats = await fetch_stats(token)

    stats_html = ""
    if stats:
        stats_html = f"""<div class="stat-row">
        <div class="stat"><div class="num">{stats.get('testsCount',0)}</div><div class="lbl">Tests</div></div>
        <div class="stat"><div class="num">{stats.get('quizzesCount',0)}</div><div class="lbl">Quizzes</div></div>
        </div>"""

    greeting = f'<div class="info-box">✅ <b>Welcome, {esc(user["name"])}!</b><br>{esc(user["email"])}</div>'

    # Live quizzes section
    live_tests_html = ""
    async with httpx.AsyncClient(timeout=10.0) as client:
        r = await cached_get(client, f"{ALL_API}?auth_code={quote(token, safe='')}&language=english", tb_headers(token))
        if r and r.status_code == 200:
            j = r.json()
            if j.get("success"):
                s_list, t_list = [], []
                _walk(j.get("data", {}), s_list, t_list)
                for t in t_list[:15]:
                    live_tests_html += f"""
                    <div class="card">
                      <a href="/test?id={quote(t['id'], safe='')}&name={quote(t['title'], safe='')}">
                        <h3>{esc(t['title'])}</h3>
                        <p>📝 {t['questionCount']} Qs · ⏱ {t['duration']} min</p>
                        <span class="badge green">Start →</span>
                      </a>
                    </div>"""

    body = f"""<div class="container">
    {greeting}
    {stats_html}

    <div class="warn-box">
      <b>🔍 Apni Purchased Test Series Kholo:</b><br>
      Testbook ne apne API endpoints badal diye hain jisse automatic series detect nahi ho rahi. 
      <br><br>
      <b>Aapka Total 224 Tests kahan hai?</b> Isko nikalne ke liye:
      <ol style="margin-left: 20px; margin-top: 8px;">
        <li>Browser me <b>testbook.com</b> login karke apni <b>"My Test Series"</b> page kholo.</li>
        <li><b>F12</b> dabao → <b>Network</b> tab kholo.</li>
        <li>Page ko Refresh karo (Ctrl+R).</li>
        <li>Network list me jo URL me <code>api.testbook.com</code> aur <code>test-series</code> ho, usko <b>Right Click → Copy URL</b> karo.</li>
        <li>Neeche paste karke <b>"Try URL"</b> dabao.</li>
      </ol>
    </div>

    <form class="search-box" method="get" action="/try-url">
      <input type="text" name="url" placeholder="Paste Testbook API URL here..." required>
      <button type="submit">Try URL</button>
    </form>

    <div class="section-title">⚡ Live Quizzes (Working)</div>
    <div class="row">{live_tests_html if live_tests_html else '<div class="empty">No live quizzes found.</div>'}</div>
    </div>"""
    return HTMLResponse(shell("Dashboard", body))

@app.get("/try-url", response_class=HTMLResponse)
async def try_url(url: str = Query(...), session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)

    if "auth_code=" in url: url = url.split("auth_code=")[0].rstrip("?&")
    if not url.startswith("http"): return HTMLResponse(shell("Error", '<div class="container"><div class="empty"><h2>URL "https://" se start hona chahiye</h2><a href="/dashboard" class="btn">← Back</a></div></div>'))
    if "api.testbook.com" not in url: return HTMLResponse(shell("Error", '<div class="container"><div class="empty"><h2>Sirf api.testbook.com allowed</h2><a href="/dashboard" class="btn">← Back</a></div></div>'))

    full = f"{url}{'&' if '?' in url else '?'}auth_code={quote(token, safe='')}&language=english"
    async with httpx.AsyncClient(timeout=20.0) as client:
        r = await rate_limited_get(client, full, tb_headers(token))
    
    if r is None:
        return HTMLResponse(shell("Error", '<div class="container"><div class="empty"><h2>Request failed</h2><a href="/dashboard" class="btn">← Back</a></div></div>'))

    status = r.status_code
    try:
        body_json = r.json()
        series, tests = [], []
        _walk(body_json, series, tests)
        raw_pretty = json.dumps(body_json, indent=2, ensure_ascii=False)[:50000]
    except Exception:
        body_json, series, tests, raw_pretty = None, [], [], r.text[:50000]

    series_cards = "".join([f'<div class="card"><a href="/series?id={quote(s["id"], safe="")}"><h3>{esc(s["title"])}</h3><p>Total Tests: {s["totalTests"]}</p><span class="badge green">Open →</span></a></div>' for s in series])
    test_cards = "".join([f'<div class="card"><a href="/test?id={quote(t["id"], safe="")}&name={quote(t["title"], safe="")}"><h3>{esc(t["title"])}</h3><p>📝 {t["questionCount"]} Qs</p><span class="badge green">Start →</span></a></div>' for t in tests])

    status_color = "#10b981" if status == 200 else "#ef4444"

    body = f"""<div class="container">
    <a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>URL:</b> <code style="word-break:break-all;font-size:11px">{esc(url)}</code></div>
    <div class="stat-row">
      <div class="stat"><div class="num" style="color:{status_color}">{status}</div><div class="lbl">Status</div></div>
      <div class="stat"><div class="num">{len(series)}</div><div class="lbl">Series</div></div>
      <div class="stat"><div class="num">{len(tests)}</div><div class="lbl">Tests</div></div>
    </div>
    {f'<div class="section-title">✅ Real Series ({len(series)})</div><div class="row">{series_cards}</div>' if series_cards else ''}
    {f'<div class="section-title">✅ Tests ({len(tests)})</div><div class="row">{test_cards}</div>' if test_cards else ''}
    <div class="section-title">📄 Raw JSON</div>
    <textarea style="width:100%;min-height:400px;padding:14px;border-radius:10px;border:1.5px solid #e2e8f0;font-family:monospace;font-size:11px;background:#1a202c;color:#a0aec0;resize:vertical">{esc(raw_pretty)}</textarea>
    </div>"""
    return HTMLResponse(shell("Try URL", body))

@app.get("/series", response_class=HTMLResponse)
async def series_page(id: str = Query(...), session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)

    title = "Test Series"
    tests = []
    async with httpx.AsyncClient(timeout=20.0) as client:
        # Fetch series tests
        for path in [f"/api/v2_1/live-panel/all?tsid={quote(id, safe='')}", f"/api/v2_1/live-panel/all?tsid=TS-{quote(id, safe='')}"]:
            full = f"{API_BASE}{path}&auth_code={quote(token, safe='')}&language=english"
            r = await cached_get(client, full, tb_headers(token))
            if r and r.status_code == 200:
                j = r.json()
                if j.get("success"):
                    s, t = [], []
                    _walk(j.get("data", {}), s, t)
                    if t:
                        tests = t
                        if s and s[0].get("title"): title = s[0]["title"]
                        break

    test_cards = "".join([f'<div class="card"><a href="/test?id={quote(t["id"], safe="")}&name={quote(t["title"], safe="")}"><h3>{esc(t["title"])}</h3><p>📝 {t["questionCount"]} Qs · ⏱ {t["duration"]} min</p><span class="badge green">Start →</span></a></div>' for t in tests])

    body = f"""<div class="container">
    <a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box"><b>📚 {esc(title)}</b></div>
    {f'<div class="section-title">📝 Tests ({len(tests)})</div><div class="row">{test_cards}</div>' if test_cards else '<div class="empty"><h2>Tests load nahi hue</h2><p>Is series me direct tests nahi mile.</p></div>'}
    </div>"""
    return HTMLResponse(shell(title, body))

@app.get("/test", response_class=HTMLResponse)
async def test_page(id: str = Query(...), name: str = Query(""), session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)
    
    body = f"""<div id="loading" class="loading-box"><div class="spinner"></div><p>Questions load ho rahe hain...</p></div><div id="quiz"></div>
    <script>
      fetch('/api/test-questions?id=' + encodeURIComponent({json.dumps(id)})).then(r => r.json()).then(data => {{
        document.getElementById('loading').style.display = 'none';
        const box = document.getElementById('quiz');
        if (!data.questions || data.questions.length === 0) {{
          box.innerHTML = '<div class="container"><div class="empty"><h2>😕 Questions load nahi hue</h2><p style="font-size:12px">' + esc(data.error || '') + '</p><a href="/dashboard" class="btn" style="margin-top:16px">← Back</a></div></div>';
          return;
        }}
        renderQuiz(data.questions, data.test_info || {{}});
      }});
      function renderQuiz(questions, info) {{
        window.__answers = {{}}; window.__questions = questions; window.__current = 0; window.__lang = 'en'; window.__timeLeft = (info.duration || 30) * 60;
        let html = '<div class="container" style="padding:0;max-width:100%"><div class="tb-header"><span class="q-num-big" id="qNum">1.</span>';
        html += '<div class="q-stats"><span class="lbl">Marks</span><span class="val" id="qMarks"></span></div><div class="timer-box" id="mainTimer">--:--</div>';
        html += '<select class="lang-select" onchange="switchLang(this.value)"><option value="en">English</option><option value="hi">हिंदी</option></select></div>';
        html += '<div class="q-indicators" id="indicators"></div><div class="tb-question" id="questionArea"></div>';
        html += '<div class="tb-nav"><button class="btn-clear" onclick="clearResponse()">Clear</button><button class="btn-prev" onclick="prevQuestion()">← Prev</button>';
        html += '<button class="btn-save" onclick="saveAndNext()">Save & Next →</button><button class="btn-submit" onclick="submitQuiz()">Submit</button></div></div>';
        document.getElementById('quiz').innerHTML = html;
        renderCurrentQuestion();
        window.__timerInterval = setInterval(() => {{ if(window.__timeLeft<=0){clearInterval(window.__timerInterval);submitQuiz();return;} window.__timeLeft--; updateTimerDisplay(); }}, 1000);
      }}
      function updateTimerDisplay() {{
        const t = window.__timeLeft, h = Math.floor(t/3600), m = Math.floor((t%3600)/60), s = t%60, pad = n => String(n).padStart(2,'0');
        document.getElementById('mainTimer').textContent = (h>0?pad(h)+':':'') + pad(m)+':'+pad(s);
      }}
      function renderCurrentQuestion() {{
        const q = window.__questions[window.__current], lang = window.__lang;
        const qText = (lang === 'hi' && q.text_hi) ? q.text_hi : (q.text_en || q.text);
        const qOpts = (lang === 'hi' && q.options_hi && q.options_hi.length) ? q.options_hi : (q.options_en || q.options);
        document.getElementById('qNum').textContent = (window.__current + 1) + '.';
        document.getElementById('qMarks').innerHTML = '<span style="color:#10b981">+' + (q.posMarks||4) + '</span> / <span style="color:#ef4444">-' + (q.negMarks||1) + '</span>';
        let html = '<div class="q-text">' + esc(qText) + '</div>';
        qOpts.forEach((opt, j) => {{ html += '<div class="tb-opt ' + (window.__answers[window.__current]===j?'selected':'') + '" onclick="pickOption(' + j + ')"><div class="radio"></div><div>' + esc(opt) + '</div></div>'; }});
        document.getElementById('questionArea').innerHTML = html;
        renderIndicators();
      }}
      function renderIndicators() {{
        let html = '';
        for (let i = 0; i < window.__questions.length; i++) {{
          const cls = (i === window.__current ? 'current ' : '') + (window.__answers[i] !== undefined ? 'answered' : '');
          html += '<div class="q-indicator ' + cls + '" onclick="jumpTo(' + i + ')">' + (i+1) + '</div>';
        }}
        document.getElementById('indicators').innerHTML = html;
      }}
      function pickOption(j) {{ window.__answers[window.__current] = j; renderCurrentQuestion(); }}
      function clearResponse() {{ delete window.__answers[window.__current]; renderCurrentQuestion(); }}
      function saveAndNext() {{ if (window.__current < window.__questions.length - 1) {{ window.__current++; renderCurrentQuestion(); }} }}
      function prevQuestion() {{ if (window.__current > 0) {{ window.__current--; renderCurrentQuestion(); }} }}
      function jumpTo(i) {{ window.__current = i; renderCurrentQuestion(); }}
      function switchLang(l) {{ window.__lang = l; renderCurrentQuestion(); }}
      function submitQuiz() {{
        if (!confirm('Submit?')) return; clearInterval(window.__timerInterval);
        const ans = window.__answers, qs = window.__questions; let att = Object.keys(ans).length, corr = 0, scoreable = 0;
        qs.forEach((q, i) => {{ if (q.correctIndex >= 0) { scoreable++; if (ans[i] === q.correctIndex) corr++; } }});
        let res = '<div class="result-box">';
        if (scoreable === 0) res += '<div class="score">' + att + ' / ' + qs.length + '</div><div>Attempted</div>';
        else res += '<div class="score">' + corr + ' / ' + qs.length + '</div><div>Attempted: ' + att + ' · Correct: ' + corr + '</div>';
        res += '<button class="btn" style="background:#fff;color:#4f46e5;margin-top:16px" onclick="window.location.reload()">🔄 Retake</button></div>';
        document.getElementById('quiz').innerHTML = res;
      }}
      function esc(s) {{ if (s == null) return ''; return String(s).replace(/[&<>"']/g, c => ({{'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}}[c])); }}
    </script>"""
    return HTMLResponse(shell(name or "Test", body))

@app.get("/api/test-questions")
async def api_test_questions(id: str = Query(...), session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return JSONResponse({"error": "not logged in", "questions": []}, status_code=401)
    
    candidates = [
        f"/api/v2_1/tests/{quote(id, safe='')}",
        f"/api/v2_1/tests/{quote(id, safe='')}?attemptNo=1",
        f"/api/v2_1/test/{quote(id, safe='')}",
    ]
    async with httpx.AsyncClient(timeout=20.0) as client:
        for path in candidates:
            full = f"{API_BASE}{path}{'&' if '?' in path else '?'}auth_code={quote(token, safe='')}&language=english"
            r = await rate_limited_get(client, full, tb_headers(token))
            if r and r.status_code == 200:
                j = r.json()
                if j.get("success"):
                    data = j.get("data", {})
                    qs = extract_questions(data)
                    if qs:
                        dur = data.get("duration") or 0
                        if dur > 1000: dur = dur // 60
                        return {"questions": qs, "count": len(qs), "test_info": {"title": _clean_text(data.get("title") or "Test"), "duration": dur}}
    return {"questions": [], "error": "Questions API endpoint se nahi mile."}

# ============================================================
# 🐛 RAW DATA & DOWNLOAD (Wapas laga diya)
# ============================================================

@app.get("/raw", response_class=HTMLResponse)
async def raw_page(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)

    user = get_user_info(token)
    body = f"""<div class="container">
    <a href="/dashboard" class="back-btn">← Back</a>
    <div class="info-box">
      <b>🐛 Raw Data Viewer</b><br>
      User: {esc(user['name'])} · isPaid: {user['isPaid']}
    </div>

    <div class="section-title">📡 Custom URL Fetch</div>
    <form class="search-box" method="get" action="/try-url">
      <input type="text" name="url" placeholder="https://api.testbook.com/api/v2_1/..." required>
      <button type="submit">Fetch →</button>
    </form>

    <div class="section-title">📥 Download Full Raw Dump</div>
    <p style="font-size:12px;color:#718096;margin-bottom:12px">Testbook ke saare known endpoints ka data ek sath download karo (JSON format).</p>
    <a href="/raw/full" class="btn" style="background:#10b981">📥 Download Raw JSON</a>
    </div>"""
    return HTMLResponse(shell("Raw Data", body))

@app.get("/raw/full")
async def raw_full(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token: return RedirectResponse("/", status_code=302)

    user = get_user_info(token)
    endpoints = [
        "/api/v2_1/live-panel/all",
        "/api/v2_1/live-panel/count",
        f"/api/v2_1/test-series?exam=ssc-mts",
        f"/api/v2_1/test-series/TS-ssc-mts",
        f"/api/v2_1/users/{user['userId']}/test-series"
    ]
    
    results = []
    async with httpx.AsyncClient(timeout=15.0) as client:
        for ep in endpoints:
            full = f"{API_BASE}{ep}{'&' if '?' in ep else '?'}auth_code={quote(token, safe='')}&language=english"
            r = await rate_limited_get(client, full, tb_headers(token))
            if r:
                try: body = r.json()
                except: body = r.text[:1000]
                results.append({"endpoint": ep, "status": r.status_code, "data": body})
            else:
                results.append({"endpoint": ep, "status": None, "data": "Error"})

    payload = {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        "user": user,
        "results": results
    }
    return JSONResponse(payload, headers={"Content-Disposition": 'attachment; filename="testbook_raw_dump.json"'})

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("PORT", 8000)))
