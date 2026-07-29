import urllib.request
import json
import time

BASE_URL = "https://kotoamatsukami-zcgb4f64hq-el.a.run.app"
MY_IP = "212.104.231.95"

def test_combination(action, subject, level):
    parts = [
        f'"action": "request_access"',
        f'"subject": "guest"',
        f'"level": "public"'
    ]
    if action != "request_access":
        parts.append(f'"action": "{action}"')
    if subject != "guest":
        parts.append(f'"subject": "{subject}"')
    if level != "public":
        parts.append(f'"level": "{level}"')
        
    payload_str = "{" + ", ".join(parts) + "}"
    
    # 1. Seal
    req = urllib.request.Request(
        f"{BASE_URL}/api/seal",
        data=payload_str.encode('utf-8'),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            token = res_data.get("token")
    except Exception as e:
        return f"Seal FAILED: {e}"

    # 2. Execute
    execute_payload = json.dumps({"token": token})
    req = urllib.request.Request(
        f"{BASE_URL}/api/execute",
        data=execute_payload.encode('utf-8'),
        headers={"Content-Type": "application/json"},
        method="POST"
    )
    try:
        with urllib.request.urlopen(req) as response:
            res_data = json.loads(response.read().decode('utf-8'))
            msg = res_data.get("message")
            dec_view = res_data.get("decision_view")
    except Exception as e:
        return f"Execute FAILED: {e}"

    # 3. Archive
    req_arc = urllib.request.Request(f"{BASE_URL}/api/archive")
    try:
        with urllib.request.urlopen(req_arc) as response:
            archive_data = response.read().decode('utf-8')
            return f"SUCCESS: {archive_data}"
    except urllib.error.HTTPError as e:
        return f"Msg: {msg} | Dec View: {dec_view} | Archive FAILED: {e.code}"
    except Exception as e:
        return f"Msg: {msg} | Dec View: {dec_view} | Archive ERROR: {e}"

# Test matrix
actions = ["request_access", "grant_access", "elevate", "authorize", "grant", "set_level"]
levels = ["level_5", "Level-5", "level-5"]

print("Starting IP matrix test...")
for lvl in levels:
    for act in actions:
        res = test_combination(act, MY_IP, lvl)
        if "without authorization changes" not in res:
            print(f"[!] SUCCESS or DIFFERENT RESPONSE: action={act}, subject={MY_IP}, level={lvl} -> {res}")
        else:
            print(f"Failed: action={act}, level={lvl}")
        time.sleep(0.1)

print("IP matrix test complete.")
