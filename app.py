# app.py
import os
import re
import hmac
import base64
import hashlib
import traceback
import httpx
from fastapi import FastAPI, HTTPException, Response as FastResponse, Form, Cookie, Request
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from bs4 import BeautifulSoup
from pydantic import BaseModel
from typing import List, Optional
import html as html_lib

app = FastAPI(title="Testbook Live Mirror", version="3.1.0")

# ---------- Config ----------
BASE_URL = "https://testbook.com"
HOME_PATH = "/rrb-group-d/test-series/my"
TB_PREFIX = "/tb"
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

# ---------- Models ----------
class TestInfo(BaseModel):
    title: str
    link: str
    description: Optional[str] = None

class ScrapeResult(BaseModel):
    page_url: str
    count: int
    tests: List[TestInfo]

# ---------- Error handlers ----------
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    tb = traceback.format_exc()
    print("ERROR:", tb)
    return HTMLResponse(
        f"<h1>Error</h1><pre style='white-space:pre-wrap'>{html_lib.escape(tb)}</pre>",
        status_code=500,
    )

@app.exception_handler(StarletteHTTPException)
async def custom_http_exception_handler(request: Request, exc: StarletteHTTPException):
    if exc.status_code == 404 and not request.url.path.startswith(TB_PREFIX):
        return RedirectResponse("/")
    return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)

# ---------- Login Page ----------
LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Testbook Token Login</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;
background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;
display:flex;align-items:center;justify-content:center;padding:20px}
.card{background:#fff;border-radius:16px;box-shadow:0 20px 60px rgba(0,0,0,.3);
padding:40px;width:100%;max-width:480px}
h1{color:#1a202c;font-size:24px;margin-bottom:8px}
p.sub{color:#718096;font-size:14px;margin-bottom:24px}
label{display:block;font-size:13px;color:#4a5568;font-weight:600;margin-bottom:8px}
textarea{width:100%;padding:12px 14px;border:1.5px solid #e2e8f0;border-radius:10px;
font-size:13px;font-family:ui-monospace,Menlo,Consolas,monospace;resize:vertical}
textarea:focus{outline:none;border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.15)}
button{width:100%;padding:13px;background:linear-gradient(135deg,#667eea,#764ba2);
color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:600;
cursor:pointer;margin-top:20px}
button:hover{opacity:.92}
.hint{margin-top:20px;padding:14px;background:#f7fafc;border-radius:10px;
font-size:12px;color:#4a5568;line-height:1.7}
.hint code{background:#edf2f7;padding:1px 6px;border-radius:4px;font-size:11px}
.error{background:#fff5f5;color:#c53030;padding:12px;border-radius:8px;
font-size:13px;margin-bottom:16px;border:1px solid #fed7d7}
</style></head><body>
<div class="card">
<h1>🔐 Testbook Live Login</h1>
<p class="sub">Apna Testbook access token daaliye — poori website live chalegi.</p>
__ERROR__
<form method="post" action="/login">
<label>Access Token</label>
<textarea name="token" rows="5" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..." required autofocus></textarea>
<button type="submit">Login karein →</button>
</form>
<div class="hint">
<b>Token kaise milega?</b><br>
1. <b>testbook.com</b> par login karein<br>
2. Browser me <b>F12</b> → <b>Network</b> tab kholein<br>
3. Koi bhi <code>/api/</code> request par click → <b>Headers</b> → <code>Authorization: Bearer ...</code><br>
4. Sirf token wala part (jo <code>eyJ...</code> se shuru hota hai) copy karke paste karein
</div>
</div></body></html>"""

# ---------- The magic interceptor ----------
INTERCEPTOR_JS = r"""
(function(){
  var P = '/tb';
  function fix(u){
    try{
      if(typeof u !== 'string') return u;
      if(u.indexOf('https://testbook.com') === 0) return P + u.slice(19);
      if(u.indexOf('http://testbook.com') === 0) return P + u.slice(18);
      if(u.indexOf('//testbook.com') === 0) return P + u.slice(15);
      if(u.indexOf('https://www.testbook.com') === 0) return P + u.slice(23);
      if(u.indexOf('//www.testbook.com') === 0) return P + u.slice(19);
      if(u.charAt(0) === '/' && u.charAt(1) !== '/' && u.indexOf(P+'/') !== 0 && u !== P) return P + u;
      return u;
    }catch(e){ return u; }
  }
  window.__tbFix = fix;

  // 1) Try to override window.location
  try {
    var _realLoc = window.location;
    delete window.location;
    window.location = new Proxy(_realLoc, {
      get: function(t, p){
        if(p === 'href') return _realLoc.href;
        if(p === 'assign') return function(u){ return _realLoc.assign(fix(u)); };
        if(p === 'replace') return function(u){ return _realLoc.replace(fix(u)); };
        var v = _realLoc[p];
        return typeof v === 'function' ? v.bind(_realLoc) : v;
      },
      set: function(t, p, v){
        if(p === 'href'){ _realLoc.href = fix(v); return true; }
        _realLoc[p] = v; return true;
      }
    });
  } catch(e){
    try { var _a = location.assign; location.assign = function(u){ return _a.call(location, fix(u)); }; } catch(_){}
    try { var _r = location.replace; location.replace = function(u){ return _r.call(location, fix(u)); }; } catch(_){}
  }

  // 2) Patch history
  try {
    var _ps = history.pushState, _rs = history.replaceState;
    history.pushState = function(s,t,u){ return _ps.call(this,s,t, u?fix(u):u); };
    history.replaceState = function(s,t,u){ return _rs.call(this,s,t, u?fix(u):u); };
  } catch(e){}

  // 3) Patch window.open
  try {
    var _open = window.open;
    window.open = function(u,n,f){ return _open.call(this, u?fix(u):u, n, f); };
  } catch(e){}

  // 4) Patch fetch
  try {
    var _f = window.fetch;
    if(_f){
      window.fetch = function(input, init){
        try {
          if(typeof input === 'string') input = fix(input);
          else if(input && input.url){
            var nu = fix(input.url);
            if(nu !== input.url){ try{ input = new Request(nu, input); }catch(e){} }
          }
        } catch(e){}
        init = init || {};
        try { init.credentials = 'same-origin'; } catch(e){}
        return _f.call(this, input, init);
      };
    }
  } catch(e){}

  // 5) Patch XHR
  try {
    var _o = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(m,u){
      var rest = Array.prototype.slice.call(arguments, 2);
      return _o.apply(this, [m, fix(u)].concat(rest));
    };
  } catch(e){}

  // 6) Intercept link clicks
  document.addEventListener('click', function(e){
    try {
      var el = e.target;
      while(el && el.tagName !== 'A') el = el.parentElement;
      if(!el) return;
      var href = el.getAttribute('href');
      if(!href) return;
      var fixed = fix(href);
      if(fixed !== href){
        e.preventDefault();
        e.stopPropagation();
        window.location.href = fixed;
      }
    } catch(err){}
  }, true);

  // 7) Intercept form submissions
  document.addEventListener('submit', function(e){
    try {
      var f = e.target;
      if(!f || f.tagName !== 'FORM') return;
      var action = f.getAttribute('action');
      if(!action) return;
      var fixed = fix(action);
      if(fixed !== action) f.setAttribute('action', fixed);
    } catch(err){}
  }, true);

  // 8) Catch any script-injected anchors / observers
  var _setAttr = Element.prototype.setAttribute;
  Element.prototype.setAttribute = function(name, value){
    try {
      if((name === 'href' || name === 'src' || name === 'action') && typeof value === 'string'){
        value = fix(value);
      }
    } catch(e){}
    return _setAttr.call(this, name, value);
  };

  // 9) Also patch HTMLAnchorElement.href setter
  try {
    var _desc = Object.getOwnPropertyDescriptor(HTMLAnchorElement.prototype, 'href');
    if(_desc && _desc.set){
      Object.defineProperty(HTMLAnchorElement.prototype, 'href', {
        set: function(v){ _desc.set.call(this, fix(v)); },
        get: _desc.get,
        configurable: true
      });
    }
  } catch(e){}
})();
"""

FLOATING_BAR = """
<div id="__tb_bar" style="position:fixed;bottom:14px;right:14px;z-index:2147483647;
display:flex;gap:6px;font-family:-apple-system,sans-serif;">
  <a href="/tb/rrb-group-d/test-series/my" style="background:#1e3a8a;color:#fff;padding:9px 14px;
     border-radius:24px;text-decoration:none;font-size:12px;font-weight:600;
     box-shadow:0 4px 14px rgba(0,0,0,.3);">🏠 Home</a>
  <a href="/logout" style="background:#dc2626;color:#fff;padding:9px 14px;
     border-radius:24px;text-decoration:none;font-size:12px;font-weight:600;
     box-shadow:0 4px 14px rgba(0,0,0,.3);">Logout</a>
</div>
"""

def _rewrite_url(v: str) -> str:
    if not v:
        return v
    if v.startswith("https://testbook.com"):
        return TB_PREFIX + v[len("https://testbook.com"):]
    if v.startswith("http://testbook.com"):
        return TB_PREFIX + v[len("http://testbook.com"):]
    if v.startswith("//testbook.com"):
        return TB_PREFIX + v[len("//testbook.com"):]
    if v.startswith("https://www.testbook.com"):
        return TB_PREFIX + v[len("https://www.testbook.com"):]
    if v.startswith("//www.testbook.com"):
        return TB_PREFIX + v[len("//www.testbook.com"):]
    if v.startswith("/") and not v.startswith("//") and not v.startswith(TB_PREFIX + "/"):
        return TB_PREFIX + v
    return v

def rewrite_html(html_text: str) -> str:
    soup = BeautifulSoup(html_text, "html.parser")

    # Remove CSP meta
    for meta in soup.find_all("meta"):
        he = (meta.get("http-equiv") or "").lower()
        if he in ("content-security-policy", "content-security-policy-report-only", "refresh"):
            meta.decompose()

    # <base href="/"> → <base href="/tb/">
    base = soup.find("base")
    if base:
        base["href"] = TB_PREFIX + "/"
    else:
        nb = soup.new_tag("base", href=TB_PREFIX + "/")
        if soup.head:
            soup.head.insert(0, nb)

    # Rewrite attributes
    pairs = [
        ("a", "href"), ("link", "href"), ("script", "src"), ("img", "src"),
        ("source", "src"), ("iframe", "src"), ("form", "action"),
        ("video", "src"), ("video", "poster"), ("audio", "src"),
        ("use", "href"), ("use", "xlink:href"),
        ("image", "href"), ("image", "xlink:href"),
        ("object", "data"), ("embed", "src"), ("track", "src"),
        ("input", "src"), ("area", "href"),
    ]
    for tag, attr in pairs:
        for el in soup.find_all(tag):
            v = el.get(attr)
            if not v or not isinstance(v, str):
                continue
            if v.startswith(("#", "javascript:", "mailto:", "tel:", "data:", "blob:")):
                continue
            el[attr] = _rewrite_url(v)

    # srcset
    for el in soup.find_all(attrs={"srcset": True}):
        srcset = el.get("srcset", "")
        parts = []
        for item in srcset.split(","):
            item = item.strip()
            if not item:
                continue
            sp = item.split()
            if sp:
                sp[0] = _rewrite_url(sp[0])
            parts.append(" ".join(sp))
        el["srcset"] = ", ".join(parts)

    # Inject interceptor at very top of <head>
    sc = soup.new_tag("script")
    sc.string = INTERCEPTOR_JS
    if soup.head:
        soup.head.insert(0, sc)

    if soup.body:
        bar = BeautifulSoup(FLOATING_BAR, "html.parser")
        soup.body.append(bar)

    return str(soup)

# ---------- Cookie forwarding ----------
def _copy_set_cookies(resp, upstream):
    for sc in upstream.headers.get_list("set-cookie"):
        sc = re.sub(r';\s*[Dd]omain=[^;]+', '', sc)
        sc = re.sub(r';\s*[Ss]ecure', '', sc)
        sc = re.sub(r';\s*[Ss]ame[Ss]ite=None', '; SameSite=Lax', sc)
        try:
            resp.headers.append("set-cookie", sc)
        except Exception:
            pass
    return resp

# ---------- Proxy ----------
@app.api_route("/tb", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"])
@app.api_route("/tb/{path:path}", methods=["GET","POST","PUT","PATCH","DELETE","OPTIONS","HEAD"])
async def tb_proxy(request: Request, path: str = "",
                   session_cookie: Optional[str] = Cookie(None, alias="tb_session"),
                   tb_token_cookie: Optional[str] = Cookie(None, alias="tb_token")):
    token = get_token(session_cookie) or tb_token_cookie
    if not token:
        return RedirectResponse("/", status_code=302)

    if path:
        target = f"{BASE_URL}/{path}"
    else:
        target = f"{BASE_URL}/"
    if request.url.query:
        target += "?" + request.url.query

    body = await request.body()

    fwd = {
        "Authorization": f"Bearer {token}",
        "User-Agent": UA,
        "Accept": request.headers.get("accept", "*/*"),
        "Accept-Language": request.headers.get("accept-language", "en-US,en;q=0.9"),
        "Referer": BASE_URL + "/",
    }
    for h in ("content-type", "x-requested-with", "x-xsrf-token", "x-csrf-token", "range"):
        if request.headers.get(h):
            fwd[h.title()] = request.headers[h]
    fwd["Accept-Encoding"] = "identity"

    cookie_parts = [f"tb_token={token}"]
    for k, v in request.cookies.items():
        if k in ("tb_session", "tb_token"):
            continue
        cookie_parts.append(f"{k}={v}")
    fwd["Cookie"] = "; ".join(cookie_parts)

    try:
        async with httpx.AsyncClient(follow_redirects=False, timeout=30.0) as client:
            r = await client.request(
                request.method, target, headers=fwd,
                content=body if body else None,
            )
    except Exception as e:
        return HTMLResponse(
            f"<h1>Proxy error</h1><pre>{html_lib.escape(str(e))}</pre>",
            status_code=502,
        )

    if r.status_code in (301, 302, 303, 307, 308):
        loc = r.headers.get("location", "/")
        if loc.startswith(BASE_URL):
            loc = TB_PREFIX + loc[len(BASE_URL):]
        elif loc.startswith("/") and not loc.startswith(TB_PREFIX):
            loc = TB_PREFIX + loc
        resp = RedirectResponse(loc, status_code=r.status_code)
        return _copy_set_cookies(resp, r)

    ctype = r.headers.get("content-type", "").lower()

    if "text/html" in ctype:
        try:
            text = rewrite_html(r.text)
        except Exception as e:
            text = f"<pre>Rewrite error: {html_lib.escape(str(e))}</pre>"
        resp = HTMLResponse(text, status_code=r.status_code)
        
        # --- YAHAN THI GALTI, AB FIX KAR DI ---
        headers_to_remove = ["x-frame-options", "content-security-policy", "content-security-policy-report-only"]
        for h in headers_to_remove:
            if h in resp.headers:
                del resp.headers[h]
                
        return _copy_set_cookies(resp, r)

    resp = FastResponse(
        content=r.content,
        status_code=r.status_code,
        media_type=r.headers.get("content-type", "application/octet-stream"),
    )
    for h in ("cache-control", "etag", "last-modified", "expires"):
        if r.headers.get(h):
            resp.headers[h] = r.headers[h]
    return _copy_set_cookies(resp, r)

# ---------- Routes ----------
@app.get("/health")
async def health():
    return {"status": "ok", "service": "testbook-live-mirror"}

@app.get("/", response_class=HTMLResponse)
async def root(error: Optional[str] = None,
               session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    if get_token(session_cookie):
        return RedirectResponse(TB_PREFIX + HOME_PATH, status_code=302)
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
    if token.lower().startswith("bearer "):
        token = token[7:].strip()

    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
            r = await client.get(
                BASE_URL + HOME_PATH,
                headers={
                    "User-Agent": UA,
                    "Authorization": f"Bearer {token}",
                    "Cookie": f"tb_token={token}",
                    "Accept": "text/html,*/*",
                    "Accept-Encoding": "identity",
                    "Referer": BASE_URL + "/",
                },
            )
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
                f'<div class="error">Token invalid ya expire (status {r.status_code}).</div>',
            ),
            status_code=401,
        )

    resp = RedirectResponse(TB_PREFIX + HOME_PATH, status_code=303)
    resp.set_cookie(
        "tb_session", sign_token(token),
        httponly=True, samesite="lax", max_age=7*24*3600, secure=False,
    )
    resp.set_cookie(
        "tb_token", token,
        httponly=False, samesite="lax", max_age=7*24*3600, secure=False,
    )
    return resp

@app.get("/logout")
async def logout():
    resp = RedirectResponse("/", status_code=302)
    resp.delete_cookie("tb_session")
    resp.delete_cookie("tb_token")
    return resp

@app.get("/api/tests", response_model=ScrapeResult)
async def api_tests(session_cookie: Optional[str] = Cookie(None, alias="tb_session")):
    token = get_token(session_cookie)
    if not token:
        raise HTTPException(401, "Pehle '/' par jaake login karein.")
    async with httpx.AsyncClient(follow_redirects=True, timeout=30.0) as client:
        r = await client.get(
            BASE_URL + HOME_PATH,
            headers={
                "User-Agent": UA,
                "Authorization": f"Bearer {token}",
                "Cookie": f"tb_token={token}",
                "Accept-Encoding": "identity",
                "Referer": BASE_URL + "/",
            },
        )
    if r.status_code != 200:
        raise HTTPException(r.status_code, f"Testbook fetch failed ({r.status_code})")
    soup = BeautifulSoup(r.text, "html.parser")
    tests, seen = [], set()
    for a in soup.select("a[href]"):
        href = a.get("href", "")
        text = a.get_text(" ", strip=True)
        if not text or len(text) < 3: continue
        if "/test-series/" not in href and "/tests/" not in href: continue
        absolute = href if href.startswith("http") else BASE_URL + href
        if absolute in seen: continue
        seen.add(absolute)
        desc = None
        parent = a.find_parent()
        if parent:
            p = parent.find("p")
            if p: desc = p.get_text(strip=True)
        tests.append(TestInfo(title=text, link=absolute, description=desc))
    return ScrapeResult(page_url=BASE_URL + HOME_PATH, count=len(tests), tests=tests)
