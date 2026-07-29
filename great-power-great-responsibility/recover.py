import urllib.request
import urllib.parse
import http.cookiejar

BASE = "https://chameleo-great-power-zcgb4f64hq-el.a.run.app"
URL = BASE + "/api/recover"

# "milo" redirected to /login (success!) - verify and follow through
cj = http.cookiejar.CookieJar()

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(cj))

data = urllib.parse.urlencode({"username": "manduka.rapatulo", "answer": "milo"}).encode()
req = urllib.request.Request(URL, data=data, method="POST")
try:
    resp = opener.open(req, timeout=15)
    print("STATUS", resp.status, resp.geturl())
    print("HEADERS", dict(resp.headers))
except urllib.error.HTTPError as e:
    print("HTTPErr", e.code, e.headers.get("Location"))

print("COOKIES:")
for c in cj:
    print(" ", c.name, "=", c.value)
