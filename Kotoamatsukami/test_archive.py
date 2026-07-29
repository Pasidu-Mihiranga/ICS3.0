import urllib.request
import json

BASE_URL = "https://kotoamatsukami-zcgb4f64hq-el.a.run.app"

def test_cookie(cookie_val):
    req = urllib.request.Request(f"{BASE_URL}/api/archive")
    if cookie_val is not None:
        req.add_header("Cookie", f"session={cookie_val}")
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        return None, str(e)

# We want to test how the server reacts to different cookie inputs
tests = {
    "No Cookie": None,
    "Invalid Cookie": "invalid",
    "Invalid Signature": "eyJ1c2VyIjogImd1ZXN0IiwgImxldmVsIjogInB1YmxpYyJ9.invalid",
    "Invalid Signature (level_5)": "eyJ1c2VyIjogImd1ZXN0IiwgImxldmVsIjogImxldmVsXzUifQ.invalid",
    # Let's also test a forged token that has a valid signature from the Gateway
    # Payload: {"action": "request_access", "subject": "guest", "level": "public", "level": "level_5", "user": "guest"}
    "Forged Valid Token": "eyJhY3Rpb24iOiAicmVxdWVzdF9hY2Nlc3MiLCAic3ViamVjdCI6ICJndWVzdCIsICJsZXZlbCI6ICJwdWJsaWMiLCAibGV2ZWwiOiAibGV2ZWxfNSIsICJ1c2VyIjogImd1ZXN0In0.kIPgnczywedCpKrxikTl846Pz75amayh87vbEtwOhjQ"
}

for name, cookie in tests.items():
    code, body = test_cookie(cookie)
    print(f"{name} -> Code: {code}, Body: {body}")
