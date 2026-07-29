import urllib.request
import json

BASE_URL = "https://kotoamatsukami-zcgb4f64hq-el.a.run.app"

def test_flow(payload_str):
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
            return f"Msg: {msg} | Dec View: {dec_view}"
    except Exception as e:
        return f"Execute FAILED: {e}"

# Test levels
levels = ["level_5", "Level-5", "level-5", "5", "LEVEL_5", "admin", "root"]
for lvl in levels:
    payload = f'{{"action": "request_access", "subject": "guest", "level": "public", "level": "{lvl}"}}'
    res = test_flow(payload)
    print(f"Testing level '{lvl}': {res}")
