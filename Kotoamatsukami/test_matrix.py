import urllib.request
import json
import time

BASE_URL = "https://kotoamatsukami-zcgb4f64hq-el.a.run.app"

def test_combination(action, subject, level):
    # Verification sees: action="request_access", subject="guest", level="public"
    # Decision Engine sees the duplicate keys at the end
    payload = {
        "action": "request_access",
        "action_dup": action,
        "subject": "guest",
        "subject_dup": subject,
        "level": "public",
        "level_dup": level
    }
    # Construct the JSON string manually to control order
    # Gateway (first keys): action, subject, level
    # Engine (last keys): action_dup (named "action"), subject_dup (named "subject"), level_dup (named "level")
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
            # If authorization changes, it might say something else, or return a cookie
            cookie_header = response.info().get("Set-Cookie")
            return f"Msg: {msg} | Dec View: {dec_view} | Cookie: {cookie_header}"
    except Exception as e:
        return f"Execute FAILED: {e}"

# Test matrix
actions = ["request_access", "grant_access", "elevate", "authorize", "grant", "set_level"]
subjects = ["guest", "admin", "root", "system", "operator", "user"]
levels = ["level_5", "Level-5", "level-5"]

print("Starting matrix test...")
for lvl in levels:
    for act in actions:
        for subj in subjects:
            res = test_combination(act, subj, lvl)
            if "without authorization changes" not in res:
                print(f"[!] SUCCESS or DIFFERENT RESPONSE: action={act}, subject={subj}, level={lvl} -> {res}")
            else:
                # Just print a dot for progress to avoid cluttering
                pass
            time.sleep(0.1)

print("Matrix test complete.")
