import urllib.request
import urllib.parse
import http.cookiejar
import sys

BASE = "https://chameleo-great-power-zcgb4f64hq-el.a.run.app"

cj = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

data = urllib.parse.urlencode({"username": "manduka.rapatulo", "answer": "milo"}).encode()
opener.open(urllib.request.Request(BASE + "/api/recover", data=data, method="POST"), timeout=15)

path = sys.argv[1] if len(sys.argv) > 1 else "/users"
resp = opener.open(BASE + path, timeout=15)
body = resp.read().decode("utf-8", "replace")

start = body.find('<main')
end = body.find('<script id="_R_"')
print(resp.status, resp.geturl())
print(body[start:end])
