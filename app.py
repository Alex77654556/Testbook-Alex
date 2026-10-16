# app.py
import os
import re
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
from typing import List, Optional, Dict
from urllib.parse import urljoin, quote, unquote, urlparse, parse_qs
import html as html_lib

app = FastAPI(title="Testbook Mirror", version="4.0.0")

# ---------- Config ----------
BASE_URL = "https://testbook.com"
HOME_PATH = "/rrb-group-d/test-series/my"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-secret-98765")
UA = ("Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36")

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

def tb_headers(token: str) -> Dict[str, str]:
    return {
        "User-Agent": UA,
        "Authorization": f"Bearer {token}",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Referer": BASE_URL + "/",
        "Cookie": f"tb_token={token}",
    }

# ---------- Global error handler ----------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    print("ERROR:", tb)
    return HTMLResponse(page_shell("Error", f"<pre style='white-space:pre-wrap'>{html_lib.escape(tb)}</pre>"), status_code=500)

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and request.url.path == "/":
        return RedirectResponse("/")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

# ---------- Our own CSS / HTML shell ----------
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
.empty{text-align:center;padding:60px 20px;color:#a0aec0}
.empty h2{font-size:18px;margin-bottom:8px;color:#4a5568}
.loader{display:inline-block;width:32px;height:32px;border:3px solid #e2e8f0;
border-top-color:#4f46e5;border-radius:50%;animation:spin .8s linear infinite}
@keyframes spin{to{transform:rotate(360deg)}}
.btn{display:inline-block;padding:11px 20px;background:#4f46e5;color:#fff;
border:none;border-radius:10px;font-size:14px;font-weight:600;text-decoration:none;
cursor:pointer;text-align:center;transition:background .15s}
.btn:hover{background:#4338ca}
.btn.gray{background:#e2e8f0;color:#4a5568}
.btn.gray:hover{background:#cbd5e0}
.btn.green{background:#10b981}
.btn.green:hover{background:#059669}
.floating{position:fixed;bottom:16px;right:16px;display:flex;gap:8px;z-index:99}
.floating a{padding:11px 18px;border-radius:26px;text-decoration:none;
font-size:13px;font-weight:700;color:#fff;box-shadow:0 6px 20px rgba(0,0,0,.25)}
.floating .home{background:#4f46e5}
.floating .out{background:#dc2626}
.q-card{background:#fff;border-radius:12px;padding:18px;margin-bottom:14px;
box-shadow:0 2px 8px rgba(0,0,0,.06)}
.q-card .q-num{display:inline-block;background:#4f46e5;color:#fff;font-size:11px;
font-weight:700;padding:3px 10px;border-radius:8px;margin-bottom:10px}
.q-card .q-text{font-size:15px;line-height:1.6;color:#2d3748;margin-bottom:12px}
.opt{display:block;padding:11px 14px;background:#f7fafc;border-radius:9px;
margin-bottom:8px;font-size:14px;color:#2d3748;border:1.5px solid #e2e8f0}
.info-box{background:#eef2ff;border-radius:12px;padding:16px;margin-bottom:18px;
font-size:13px;color:#3730a3;line-height:1.7}
.stat-row{display:flex;gap:14px;flex-wrap:wrap;margin-bottom:16px}
.stat{background:#fff;padding:12px 18px;border-radius:10px;
box-shadow:0 2px 8px rgba(0,0,0,.05);flex:1;min-width:120px}
.stat .num{font-size:22px;font-weight:800;color:#4f46e5}
.stat .lbl{font-size:12px;color:#718096;text-transform:uppercase;letter-spacing:.4px}
"""

def page_shell(title: str, body: str, show_nav: bool = True) -> str:
    nav = ""
    if show_nav:
        nav = (
            '<div class="nav">'
            '<a href="/dashboard">🏠 Home</a>'
            '<a href="/logout">Logout</a>'
            '</div>'
        )
    return f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{html_lib.escape(title)} · Testbook Mirror</title>
<style>{COMMON_CSS}</style></head><body>
<div class="topbar"><h1>📚 Testbook Mirror</h1>{nav}</div>
<div class="container">{body}</div>
<div class="floating">
  <a href="/dashboard" class="home">🏠 Home</a>
  <a href="/logout" class="out">Logout</a>
</div>
</body></html>"""

# ---------- Login page ----------
LOGIN_HTML = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
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
font-size:13px;font-family:ui-monospace,Menlo,Consolas,monospace;resize:vertical;
transition:border-color .2s}
textarea:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.15)}
button{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);
color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;
cursor:pointer;margin-top:20px;transition:opacity .15s}
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
<p class="sub">Apna Testbook access token daaliye — poori website aapke apne dashboard me live chalegi (kuch bhi Testbook par redirect nahi hoga).</p>
__ERROR__
<form method="post" action="/login">
<label>Access Token</label>
<textarea name="token" rows="5" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." required autofocus></textarea>
<button type="submit">Login karein →</button>
</form>
<div class="hint">
<b>🔑 Token kaise milega?</b><br>
1. <b>testbook.com</b> par login karein<br>
2. Browser me <b>F12</b> → <b>Network</b> tab kholein<br>
3. Koi bhi <code>/api/</code> request par click → <b>Headers</b> → <code>Authorization: Bearer ...</code><br>
4. Sirf token wala part (jo <code>eyJ...</code> se shuru hota hai) copy karke paste karein
</div>
</div></body></html>"""

# ---------- Helpers to fetch Testbook ----------
async def tb_get(url: str, token: str) -> httpx.Response:
    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        return await client.get(url, headers=tb_headers(token))

# ---------- HTML Parsers ----------
def parse_test_series(html_text: str) -> List[Dict]:
    """Parse test series cards from Testbook page."""
    soup = BeautifulSoup(html_text, "html.parser")
    results, seen = [], set()

    for a in soup.select("a[href]"):
        href = a.get("href", "")
        text = a.get_text(" ", strip=True)
        if not text or len(text) < 5:
            continue
        if "/test-series/" not in href:
            continue
        absolute = href if href.startswith("http") else urljoin(BASE_URL, href)
        if absolute in seen:
            continue
        seen.add(absolute)

        desc = ""
        parent = a.find_parent()
        if parent:
            p = parent.find("p")
            if p:
                desc = p.get_text(strip=True)

        results.append({
            "title": text,
            "link": absolute,
            "description": desc,
        })

    return results

def parse_tests_in_series(html_text: str) -> List[Dict]:
    """Parse individual tests from a series page."""
    soup = BeautifulSoup(html_text, "html.parser")
    results, seen = [], set()

    for a in soup.select("a[href]"):
        href = a.get("href", "")
        text = a.get_text(" ", strip=True)
        if not text or len(text) < 5:
            continue
        if "/tests/" not in href and "/test-series/" not in href:
            continue
        # Skip if this is the current series link
        absolute = href if href.startswith("http") else urljoin(BASE_URL, href)
        if absolute in seen:
            continue
        seen.add(absolute)

        # Only keep entries that look like individual tests
        if "/tests/" not in absolute and "/take-test" not in absolute:
            continue

        desc = ""
        parent = a.find_parent()
        if parent:
            p = parent.find("p")
            if p:
                desc = p.get_text(strip=True)

        results.append({
            "title": text,
            "link": absolute,
            "description": desc,
        })

    return results

def parse_questions(html_text: str) -> List[Dict]:
    """Parse questions from a test page."""
    soup = BeautifulSoup(html_text, "html.parser")
    questions = []

    # Try to find question containers - generic selectors
    for q in soup.select("[class*='question'], [class*='Question']"):
        text = q.get_text(" ", strip=True)
        if text and len(text) > 20 and text not in [x["text"] for x in questions]:
            questions.append({"text": text[:500]})

    return questions[:50]

def extract_title(html_text: str, fallback: str = "Page") -> str:
    soup = BeautifulSoup(html_text, "html.parser")
    if soup.title and soup.title.string:
        return soup.title.string.strip()
    h1 = soup.find("h1")
    if h1:
        return h1.get_text(strip=True)
    return fallback

# ---------- Routes ----------
@app.get("/health")
async def health():
    return {"status": "ok"}

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

    # Validate against Testbook
    try:
        r = await tb_get(BASE_URL + HOME_PATH, token)
    except Exception as e:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">Connection error: {html_lib.escape(str(e))}</div>'), status_code=502)

    if r.status_code != 200:
        return HTMLResponse(LOGIN_HTML.replace("__ERROR__", f'<div class="error">Token invalid ya expire (status {r.status_code}).</div>'), status_code=401)

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
    if not token:
        return RedirectResponse("/", status_code=302)

    try:
        r = await tb_get(BASE_URL + HOME_PATH, token)
    except Exception as e:
        return HTMLResponse(page_shell("Error", f"<div class='empty'><h2>Connection error</h2><p>{html_lib.escape(str(e))}</p></div>"))

    if r.status_code in (401, 403):
        resp = RedirectResponse("/?error=session", status_code=302)
        resp.delete_cookie("tb_session")
        return resp

    series_list = parse_test_series(r.text)

    # Build own HTML
    if series_list:
        cards = "".join(
            f'<div class="card"><a href="/series?url={quote(item["link"], safe="")}">'
            f'<h3>{html_lib.escape(item["title"])}</h3>'
            f'{f"<p>{html_lib.escape(item["description"])}</p>" if item["description"] else ""}'
            f'<span class="badge">Test Series</span></a></div>'
            for item in series_list
        )
        body = f"""
        <div class="info-box">
          ✅ Aap Testbook token se login ho chuke hain. Neeche aapki saari <b>test series</b> hain.
          Kisi bhi card par click karke uske tests dekhein — <b>sab kuch isi website par rahega</b>, Testbook par nahi jaayega.
        </div>
        <div class="stat-row">
          <div class="stat"><div class="num">{len(series_list)}</div><div class="lbl">Test Series</div></div>
        </div>
        <div class="section-title">📚 Your Test Series</div>
        <div class="row">{cards}</div>
        """
    else:
        body = """
        <div class="empty">
          <h2>😕 Koi test series nahi mili</h2>
          <p>Aapke account me abhi koi test series nahi hai, ya Testbook ne page structure badal diya hai.</p>
          <br>
          <a href="/dashboard" class="btn">🔄 Refresh</a>
        </div>
        """

    return HTMLResponse(page_shell("Dashboard", body))

@app.get("/series", response_class=HTMLResponse)
async def series(url: str = Query(...), session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    try:
        r = await tb_get(url, token)
    except Exception as e:
        return HTMLResponse(page_shell("Error", f"<div class='empty'><h2>Error</h2><p>{html_lib.escape(str(e))}</p></div>"))

    if r.status_code in (401, 403):
        resp = RedirectResponse("/?error=session", status_code=302)
        resp.delete_cookie("tb_session")
        return resp

    title = extract_title(r.text, "Test Series")
    tests = parse_tests_in_series(r.text)

    if tests:
        cards = "".join(
            f'<div class="card"><a href="/test?url={quote(item["link"], safe="")}">'
            f'<h3>{html_lib.escape(item["title"])}</h3>'
            f'{f"<p>{html_lib.escape(item["description"])}</p>" if item["description"] else ""}'
            f'<span class="badge">Start Test</span></a></div>'
            for item in tests
        )
        body = f"""
        <div style="margin-bottom:14px;">
          <a href="/dashboard" class="btn gray" style="padding:8px 16px;font-size:13px;">← Back</a>
        </div>
        <div class="info-box"><b>{html_lib.escape(title)}</b></div>
        <div class="section-title">📝 Tests in this series</div>
        <div class="row">{cards}</div>
        """
    else:
        body = f"""
        <div style="margin-bottom:14px;">
          <a href="/dashboard" class="btn gray" style="padding:8px 16px;font-size:13px;">← Back</a>
        </div>
        <div class="empty">
          <h2>Is series me tests nahi mile</h2>
          <p>{html_lib.escape(title)}</p>
          <br>
          <a href="{html_lib.escape(url)}" target="_blank" class="btn gray">Original page dekhein</a>
        </div>
        """

    return HTMLResponse(page_shell(title, body))

@app.get("/test", response_class=HTMLResponse)
async def test_page(url: str = Query(...), session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)

    try:
        r = await tb_get(url, token)
    except Exception as e:
        return HTMLResponse(page_shell("Error", f"<div class='empty'><h2>Error</h2><p>{html_lib.escape(str(e))}</p></div>"))

    if r.status_code in (401, 403):
        resp = RedirectResponse("/?error=session", status_code=302)
        resp.delete_cookie("tb_session")
        return resp

    title = extract_title(r.text, "Test")

    # Extract main text content (question paper, instructions etc.)
    soup = BeautifulSoup(r.text, "html.parser")
    for t in soup(["script", "style", "noscript", "iframe"]):
        t.decompose()
    main_text = soup.get_text("\n", strip=True)

    # Show a clean view
    body = f"""
    <div style="margin-bottom:14px;">
      <a href="/dashboard" class="btn gray" style="padding:8px 16px;font-size:13px;">← Back to Dashboard</a>
    </div>
    <div class="info-box">
      <b>📝 {html_lib.escape(title)}</b><br>
      Neeche test ka content hai. Ye page Testbook se live aaya hai.
    </div>
    <div class="q-card" style="font-size:13px;line-height:1.7;white-space:pre-wrap;color:#4a5568;">
      {html_lib.escape(main_text[:8000])}
    </div>
    <div style="text-align:center;margin-top:20px;">
      <a href="{html_lib.escape(url)}" class="btn green" style="padding:12px 24px;">
        🔗 Original Test Start Karein
      </a>
    </div>
    """

    return HTMLResponse(page_shell(title, body))

# ---------- JSON API ----------
class TestInfo(BaseModel):
    title: str
    link: str
    description: Optional[str] = None

class ScrapeResult(BaseModel):
    page_url: str
    count: int
    tests: List[TestInfo]

@app.get("/api/tests", response_model=ScrapeResult)
async def api_tests(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        raise HTTPException(401, "Pehle '/' par jaake login karein.")
    r = await tb_get(BASE_URL + HOME_PATH, token)
    if r.status_code != 200:
        raise HTTPException(r.status_code, f"Testbook fetch failed ({r.status_code})")
    items = parse_test_series(r.text)
    return ScrapeResult(
        page_url=BASE_URL + HOME_PATH,
        count=len(items),
        tests=[TestInfo(title=i["title"], link=i["link"], description=i.get("description") or None) for i in items],
    )
