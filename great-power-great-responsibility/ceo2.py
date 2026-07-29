import urllib.request
import urllib.parse
import http.cookiejar

BASE = "https://chameleo-great-power-zcgb4f64hq-el.a.run.app"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

data = urllib.parse.urlencode({"username": "rango.jayamaha", "password": "password"}).encode()
opener.open(urllib.request.Request(BASE + "/api/login", data=data, method="POST"), timeout=15)

def get(path):
    try:
        resp = opener.open(BASE + path, timeout=15)
        return resp.status, resp.geturl(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, path, e.read().decode("utf-8", "replace")

# First look at /ceo/employees config page
st, url, body = get("/ceo/employees")
print("===== /ceo/employees ->", st)
s = body.find('<main'); e = body.find('<script id="_R_"')
print(body[s:e] if s!=-1 else body[:3000])
print()
