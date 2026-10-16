# app.py
import os, re, time, hmac, base64, hashlib, json, httpx
from fastapi import FastAPI, Form, Cookie, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response as FastResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from typing import Optional
from urllib.parse import quote

app = FastAPI(title="Testbook Proxy")
BASE_URL = "https://testbook.com"
API_BASE = "https://api.testbook.com"
SESSION_SECRET = os.getenv("SESSION_SECRET", "testbook-proxy-secret-2026")
UA = "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36"

# ---------- cookie sign/unsign ----------
def sign(tok: str) -> str:
    d = base64.urlsafe_b64encode(tok.encode()).decode()
    s = hmac.new(SESSION_SECRET.encode(), d.encode(), hashlib.sha256).hexdigest()[:16]
    return f"{d}.{s}"

def unsign(c: str) -> Optional[str]:
    try:
        d, s = c.rsplit(".", 1)
        exp = hmac.new(SESSION_SECRET.encode(), d.encode(), hashlib.sha256).hexdigest()[:16]
        if not hmac.compare_digest(s, exp): return None
        return base64.urlsafe_b64decode(d.encode()).decode()
    except: return None

def get_token(c): return unsign(c) if c else None

def jwt_payload(tok):
    try:
        p = tok.split(".")[1]
        return json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    except: return {}

def tb_headers(token: str, html: bool = False) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "User-Agent": UA,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" if html else "application/json, text/plain, */*",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
        "Referer": BASE_URL + "/",
        "Origin": BASE_URL,
        "X-Client": "web,1.4",
        "x-platform": "web",
        "Cookie": f"tb_token={token}",
    }

# ---------- JS interceptor (injected into every HTML) ----------
INTERCEPTOR = r"""
(function(){
  if (window.__TB_PROXY_INSTALLED) return;
  window.__TB_PROXY_INSTALLED = true;
  var TB = 'https://testbook.com', API = 'https://api.testbook.com';
  var PP = '/tb', AP = '/tb-api';
  function rw(u){
    if (typeof u !== 'string') return u;
    if (u.indexOf(AP) === 0 || u.indexOf(PP + '/') === 0) return u;
    if (u.indexOf(API) === 0) return AP + u.slice(API.length);
    if (u.indexOf(TB) === 0) return PP + u.slice(TB.length);
    if (u.indexOf('//api.testbook.com') === 0) return AP + u.slice(19);
    if (u.indexOf('//testbook.com') === 0) return PP + u.slice(15);
    if (u.charAt(0) === '/' && u.charAt(1) !== '/') return PP + u;
    return u;
  }
  var _f = window.fetch;
  if (_f) window.fetch = function(inp, init){
    try {
      var u = typeof inp === 'string' ? inp : (inp && inp.url);
      var nu = rw(u);
      if (nu !== u) {
        if (typeof inp === 'string') inp = nu;
        else inp = new Request(nu, inp);
      }
    } catch(e){}
    init = init || {};
    init.credentials = 'same-origin';
    return _f.call(this, inp, init);
  };
  var _o = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function(m, u){
    arguments[1] = rw(u);
    return _o.apply(this, arguments);
  };
  var _push = history.pushState, _rep = history.replaceState;
  history.pushState = function(s, t, u){ return _push.call(this, s, t, u ? rw(u) : u); };
  history.replaceState = function(s, t, u){ return _rep.call(this, s, t, u ? rw(u) : u); };
  try {
    var d = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
    if (d && d.set) {
      Object.defineProperty(HTMLAnchorElement.prototype, 'href', {
        set: function(v){ d.set.call(this, rw(v)); },
        get: d.get, configurable: true
      });
    }
  } catch(e){}
  document.addEventListener('click', function(e){
    var el = e.target;
    while (el && el.tagName !== 'A') el = el.parentElement;
    if (!el) return;
    var h = el.getAttribute('href');
    if (!h) return;
    var nh = rw(h);
    if (nh !== h){ e.preventDefault(); e.stopPropagation(); window.location.href = nh; }
  }, true);
})();
"""

def rewrite_html(html: str, token: str) -> str:
    # base tag
    if re.search(r'<base\s', html, re.IGNORECASE):
        html = re.sub(r'<base[^>]*>', '<base href="/tb/">', html, count=1, flags=re.IGNORECASE)
    else:
        html = re.sub(r'(<head[^>]*>)', r'\1<base href="/tb/">', html, count=1, flags=re.IGNORECASE)

    # absolute URL → relative proxy paths
    html = html.replace('https://api.testbook.com', '/tb-api')
    html = html.replace('http://api.testbook.com', '/tb-api')
    html = html.replace('//api.testbook.com', '/tb-api')
    html = html.replace('https://testbook.com', '/tb')
    html = html.replace('http://testbook.com', '/tb')
    html = html.replace('//testbook.com', '/tb')

    # relative attrs
    def repl(m):
        attr, path = m.group(1), m.group(2)
        if path.startswith('/tb/') or path.startswith('/tb-api/'):
            return m.group(0)
        if path.startswith('/'):
            return f'{attr}="/tb{path}"'
        return m.group(0)
    html = re.sub(r'(href|src|action)="(/[^"]*)"', repl, html)
    html = re.sub(r"(href|src|action)='(/[^']*)'", repl, html)

    # inject interceptor + cookie setter before </head>
    inject = f'<script>{INTERCEPTOR}</script>'
    cookie_js = f'<script>document.cookie="tb_token={token};path=/;max-age=604800;SameSite=Lax";window.__tbToken="{token}";</script>'
    html = re.sub(r'</head>', inject + cookie_js + '</head>', html, count=1, flags=re.IGNORECASE)
    return html

def copy_cookies(resp, upstream):
    for sc in upstream.headers.get_list("set-cookie"):
        sc = re.sub(r';\s*[Dd]omain=[^;]+', '', sc)
        sc = re.sub(r';\s*[Ss]ecure', '', sc)
        sc = re.sub(r';\s*[Ss]ame[Ss]ite=None', '; SameSite=Lax', sc)
        try: resp.headers.append("set-cookie", sc)
        except: pass
    return resp

# ---------- error handler ----------
@app.exception_handler(StarletteHTTPException)
async def http_exc(req: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and req.url.path == "/":
        return RedirectResponse("/")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

# ---------- routes ----------
@app.get("/health")
async def health(): return {"ok": True}

@app.get("/", response_class=HTMLResponse)
async def root(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    if get_token(session_cookie):
        return RedirectResponse("/tb/online-test-series", status_code=302)
    return HTMLResponse(LOGIN_HTML)

@app.post("/login")
async def login(token: str = Form(...)):
    tok = token.strip()
    if not tok:
        return HTMLResponse(LOGIN_HTML.replace("__ERR__", '<div class="error">Token khali hai</div>'), status_code=400)
    if tok.lower().startswith("bearer "): tok = tok[7:].strip()
    if "auth_code=" in tok: tok = tok.split("auth_code=")[1].split("&")[0]
    # validate
    try:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(
                f"{API_BASE}/api/v2_1/live-panel/count?auth_code={quote(tok, safe='')}&language=english",
                headers=tb_headers(tok))
            if r.status_code != 200 or not r.json().get("success"):
                return HTMLResponse(LOGIN_HTML.replace("__ERR__", '<div class="error">❌ Invalid ya expired token</div>'), status_code=401)
    except Exception as e:
        return HTMLResponse(LOGIN_HTML.replace("__ERR__", f'<div class="error">Connection error: {e}</div>'), status_code=502)
    resp = RedirectResponse("/tb/online-test-series", status_code=303)
    resp.set_cookie("tb_session", sign(tok), httponly=True, samesite="lax", max_age=7*24*3600)
    return resp

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("tb_session")
    return resp

# ---------- proxy: API ----------
@app.api_route("/tb-api/{path:path}", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
async def proxy_api(request: Request, path: str,
                    session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return JSONResponse({"error": "not logged in"}, status_code=401)
    target = f"{API_BASE}/{path}"
    qs = request.url.query
    if qs:
        target += "?" + qs
    if "auth_code=" not in target:
        sep = "&" if "?" in target else "?"
        target += f"{sep}auth_code={quote(token, safe='')}"
    body = await request.body()
    headers = tb_headers(token)
    if request.headers.get("content-type"):
        headers["Content-Type"] = request.headers["content-type"]
    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=25) as c:
            r = await c.request(request.method, target, headers=headers, content=body or None)
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=502)
    resp = FastResponse(content=r.content, status_code=r.status_code,
                        media_type=r.headers.get("content-type", "application/json"))
    return copy_cookies(resp, r)

# ---------- proxy: pages + assets ----------
@app.api_route("/tb/{path:path}", methods=["GET","POST","PUT","DELETE","PATCH","OPTIONS"])
async def proxy_page(request: Request, path: str,
                     session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        return RedirectResponse("/", status_code=302)
    target = f"{BASE_URL}/{path}"
    if request.url.query:
        target += "?" + request.url.query

    body = await request.body()
    is_asset = bool(
        re.match(r'^(angular-ssr|assets|node_modules)/', path) or
        re.search(r'\.(js|css|png|jpg|jpeg|svg|woff2?|ttf|ico|gif|webp|map|json)(\?|$)', path)
    )
    headers = tb_headers(token, html=not is_asset)
    if request.headers.get("content-type"):
        headers["Content-Type"] = request.headers["content-type"]
    if request.headers.get("accept"):
        headers["Accept"] = request.headers["accept"]

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=30) as c:
            r = await c.request(request.method, target, headers=headers, content=body or None)
    except Exception as e:
        return HTMLResponse(f"<h1>Upstream error</h1><pre>{e}</pre>", status_code=502)

    # handle redirects
    if r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("location", "/")
        if loc.startswith(BASE_URL): loc = "/tb" + loc[len(BASE_URL):]
        elif loc.startswith(API_BASE): loc = "/tb-api" + loc[len(API_BASE):]
        elif loc.startswith("/") and not loc.startswith("/tb"): loc = "/tb" + loc
        resp = RedirectResponse(loc, status_code=r.status_code)
        return copy_cookies(resp, r)

    ctype = r.headers.get("content-type", "").lower()

    if "text/html" in ctype:
        try:
            html = rewrite_html(r.text, token)
        except Exception as e:
            html = f"<h1>Rewrite error</h1><pre>{e}</pre>"
        resp = HTMLResponse(html, status_code=r.status_code)
        for h in ("x-frame-options", "content-security-policy", "content-security-policy-report-only"):
            if h in resp.headers: del resp.headers[h]
        return copy_cookies(resp, r)

    # passthrough for non-HTML
    resp = FastResponse(content=r.content, status_code=r.status_code,
                        media_type=r.headers.get("content-type", "application/octet-stream"))
    for h in ("cache-control", "etag", "last-modified", "expires"):
        if r.headers.get(h): resp.headers[h] = r.headers[h]
    return copy_cookies(resp, r)

# ---------- login HTML ----------
LOGIN_HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Testbook Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);
min-height:100vh;display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:18px;box-shadow:0 20px 60px rgba(0,0,0,.3);padding:40px;width:100%;max-width:500px}
h1{font-size:22px;text-align:center;margin-bottom:6px}
p.sub{color:#718096;font-size:13px;text-align:center;margin-bottom:26px}
label{display:block;font-size:13px;color:#4a5568;font-weight:600;margin-bottom:8px}
textarea{width:100%;padding:13px;border:1.5px solid #e2e8f0;border-radius:10px;font-size:13px;font-family:monospace;resize:vertical}
button{width:100%;padding:14px;background:linear-gradient(135deg,#667eea,#764ba2);color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;margin-top:20px}
.error{background:#fff5f5;color:#c53030;padding:12px;border-radius:8px;font-size:13px;margin-bottom:16px;text-align:center}
.hint{margin-top:20px;padding:14px;background:#f7fafc;border-radius:10px;font-size:12px;color:#4a5568;line-height:1.7}
.hint code{background:#edf2f7;padding:1px 6px;border-radius:4px}
</style></head><body>
<div class="card">
<h1>🔐 Testbook Proxy</h1>
<p class="sub">Token daaliye — poori Testbook live chalegi.</p>
__ERR__
<form method="post" action="/login">
<label>Access Token</label>
<textarea name="token" rows="6" placeholder="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9..." required autofocus></textarea>
<button type="submit">Login →</button>
</form>
<div class="hint"><b>Token kahan se?</b><br>
1. testbook.com par login karein<br>
2. F12 → Network → koi bhi <code>api.testbook.com</code> request<br>
3. URL me <code>auth_code=eyJ...</code> — sirf token part copy karein</div>
</div></body></html>"""
