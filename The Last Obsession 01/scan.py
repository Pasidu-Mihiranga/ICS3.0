import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import requests


USERNAME = sys.argv[1] if len(sys.argv) > 1 else "vandal_marty_88"
DATA = Path("sherlock-src/sherlock-master/sherlock_project/resources/data.json")
sites = json.loads(DATA.read_text(encoding="utf-8"))


def eligible(site):
    pattern = site.get("regexCheck")
    return not pattern or re.fullmatch(pattern, USERNAME)


def check(item):
    name, site = item
    if name.startswith("$") or not eligible(site):
        return None
    public_url = site["url"].format(USERNAME)
    probe_url = site.get("urlProbe", public_url).format(USERNAME)
    method = site.get("request_method", "GET").upper()
    payload = site.get("request_payload")
    if payload:
        payload = json.loads(json.dumps(payload).replace("{}", USERNAME))
    try:
        response = requests.request(
            method,
            probe_url,
            json=payload,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
            timeout=12,
            allow_redirects=True,
        )
        kind = site.get("errorType", "status_code")
        if kind == "status_code":
            found = 200 <= response.status_code < 300
        elif kind == "message":
            errors = site.get("errorMsg", [])
            if isinstance(errors, str):
                errors = [errors]
            found = not any(error in response.text for error in errors)
        elif kind == "response_url":
            found = response.url.rstrip("/") == public_url.rstrip("/")
        else:
            found = False
        if found:
            return name, response.status_code, len(response.content), public_url, response.url
    except requests.RequestException:
        pass
    return None


with ThreadPoolExecutor(max_workers=40) as pool:
    futures = [pool.submit(check, item) for item in sites.items()]
    for future in as_completed(futures):
        result = future.result()
        if result:
            print("\t".join(map(str, result)), flush=True)
