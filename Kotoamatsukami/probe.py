import urllib.request
import json

BASE_URL = "https://kotoamatsukami-zcgb4f64hq-el.a.run.app"

def test_seal(payload):
    url = f"{BASE_URL}/api/seal"
    req = urllib.request.Request(
        url,
        data=payload.encode('utf-8'),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        return None, str(e)

def test_execute(token):
    url = f"{BASE_URL}/api/execute"
    payload = json.dumps({"token": token})
    req = urllib.request.Request(
        url,
        data=payload.encode('utf-8'),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as response:
            return response.status, response.read().decode('utf-8')
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode('utf-8')
    except Exception as e:
        return None, str(e)

print("Testing various values...")

# 1. Test different actions
for action in ["request_access", "grant_access", "elevate", "admin", "authorize"]:
    payload = json.dumps({"action": action, "subject": "guest", "level": "public"})
    code, text = test_seal(payload)
    print(f"Action: {action} -> Code: {code}, Response: {text}")

# 2. Test different subjects
for subject in ["guest", "admin", "root", "system", "user"]:
    payload = json.dumps({"action": "request_access", "subject": subject, "level": "public"})
    code, text = test_seal(payload)
    print(f"Subject: {subject} -> Code: {code}, Response: {text}")

# 3. Test different levels
for level in ["public", "level_1", "level_5", "admin", "root"]:
    payload = json.dumps({"action": "request_access", "subject": "guest", "level": level})
    code, text = test_seal(payload)
    print(f"Level: {level} -> Code: {code}, Response: {text}")
