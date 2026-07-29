import urllib.request
import urllib.parse
import http.cookiejar

BASE = "https://chameleo-great-power-zcgb4f64hq-el.a.run.app"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# Login as CEO
data = urllib.parse.urlencode({"username": "rango.jayamaha", "password": "password"}).encode()
r = opener.open(urllib.request.Request(BASE + "/api/login", data=data, method="POST"), timeout=15)
print("LOGIN ->", r.status, r.geturl())
for c in cj:
    print("  cookie", c.name, "=", c.value)

def get(path):
    try:
        resp = opener.open(BASE + path, timeout=15)
        return resp.status, resp.geturl(), resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        return e.code, path, e.read().decode("utf-8", "replace")

for p in ["/dashboard",
          "/ceo/employees/search?source=employees&fields=id,full_name,department,role,email,branch&q="]:
    st, url, body = get(p)
    print("=====", p, "->", st, url)
    s = body.find('<main')
    e = body.find('<script id="_R_"')
    if s != -1 and e != -1:
        print(body[s:e])
    else:
        print(body[:3000])
    print()
