import urllib.request
import json

BASE_URL = "https://kotoamatsukami-zcgb4f64hq-el.a.run.app"
MY_IP = "212.104.231.95"

payload_str = f'{{"action": "request_access", "subject": "guest", "subject": "{MY_IP}", "level": "public", "level": "level_5"}}'
print("Payload:", payload_str)

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
    print(f"Seal FAILED: {e}")
    exit(1)

# 2. Execute
req = urllib.request.Request(
    f"{BASE_URL}/api/execute",
    data=json.dumps({"token": token}).encode('utf-8'),
    headers={"Content-Type": "application/json"},
    method="POST"
)
try:
    with urllib.request.urlopen(req) as response:
        res_data = json.loads(response.read().decode('utf-8'))
        print("Execute:", res_data)
except Exception as e:
    print(f"Execute FAILED: {e}")
    exit(1)

# 3. Archive
req = urllib.request.Request(f"{BASE_URL}/api/archive")
try:
    with urllib.request.urlopen(req) as response:
        print("Archive:", response.read().decode('utf-8'))
except Exception as e:
    print(f"Archive FAILED: {e}")
