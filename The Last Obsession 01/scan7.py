import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

username = sys.argv[1]
start = int(sys.argv[2]) if len(sys.argv) > 2 else 0
count = int(sys.argv[3]) if len(sys.argv) > 3 else 500
path = "maigret-src/maigret-main/maigret/resources/data.json"
sites = json.load(open(path, encoding="utf-8"))["sites"]
eligible = []
for name, site in sites.items():
    pattern = site.get("regexCheck")
    try:
        if pattern and re.fullmatch(pattern, username) is None:
            continue
    except re.error:
        continue
    eligible.append((name, site))
eligible.sort(key=lambda item: item[1].get("alexaRank", 10**12))
eligible = eligible[start : start + count]


def check(item):
    name, site = item
    public_url = site["url"].replace("{username}", username)
    probe_url = site.get("urlProbe", public_url).replace("{username}", username)
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}
    headers.update(site.get("headers", {}))
    method = site.get("requestMethod", "GET").upper()
    try:
        session = requests.Session()
        session.trust_env = False
        response = session.request(
            method,
            probe_url,
            headers=headers,
            timeout=(3, 6),
            allow_redirects=site.get("allowRedirects", True),
        )
        body = response.text
        kind = site.get("checkType", "status_code")
        presence = site.get("presenseStrs", [])
        absence = site.get("absenceStrs", [])
        presence_ok = not presence or any(flag in body for flag in presence)
        absence_ok = not any(flag in body for flag in absence)
        if kind == "message":
            found = presence_ok and absence_ok
        elif kind == "status_code":
            found = 200 <= response.status_code < 300
        elif kind == "response_url":
            found = 200 <= response.status_code < 300 and presence_ok
        else:
            found = False
        if found:
            return (
                name,
                response.status_code,
                len(response.content),
                public_url,
                response.url,
            )
    except Exception:
        return None


with ThreadPoolExecutor(max_workers=100) as pool:
    futures = [pool.submit(check, item) for item in eligible]
    for future in as_completed(futures):
        result = future.result()
        if result:
            print("\t".join(map(str, result)), flush=True)
