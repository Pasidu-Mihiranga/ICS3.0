import urllib.request
import urllib.parse
import http.cookiejar

BASE = "https://chameleo-great-power-zcgb4f64hq-el.a.run.app"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

# login via recovery
data = urllib.parse.urlencode({"username": "manduka.rapatulo", "answer": "milo"}).encode()
opener.open(urllib.request.Request(BASE + "/api/recover", data=data, method="POST"), timeout=15)

def get(path):
    try:
        resp = opener.open(BASE + path, timeout=15)
        body = resp.read().decode("utf-8", "replace")
        return resp.status, resp.geturl(), body
    except urllib.error.HTTPError as e:
        return e.code, path, e.read().decode("utf-8", "replace")

for p in ["/dashboard", "/ceo", "/ceo/employees", "/ceo/employees/search"]:
    st, url, body = get(p)
    print("=====", p, "->", st, url)
    print(body[:2000])
    print()
