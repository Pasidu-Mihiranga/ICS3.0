import urllib.request
import urllib.parse
import http.cookiejar

BASE = "https://chameleo-great-power-zcgb4f64hq-el.a.run.app"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

data = urllib.parse.urlencode({"username": "rango.jayamaha", "password": "password"}).encode()
opener.open(urllib.request.Request(BASE + "/api/login", data=data, method="POST"), timeout=15)

def search(source, fields="id,full_name,department,role,email,branch", q=""):
    qs = urllib.parse.urlencode({"source": source, "fields": fields, "q": q})
    path = "/ceo/employees/search?" + qs
    try:
        resp = opener.open(BASE + path, timeout=15)
        body = resp.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8", "replace")
    # extract data-panel or main portion
    s = body.find('<section class="data-panel"')
    if s == -1:
        s = body.find('<main')
    e2 = body.find('<script id="_R_"')
    print("##### source=", source, "fields=", fields)
    seg = body[s:e2] if s != -1 and e2 != -1 else body[:2000]
    # collapse
    print(seg[:3000])
    print()

# Try different "source" selectors hinted by the migration note (archive service, review records)
for src in ["employees", "archive", "review", "reviews", "restricted", "review_records",
            "restricted_reviews", "archived", "legacy", "secrets", "admin", "flags"]:
    search(src)
