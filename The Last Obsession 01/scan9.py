import json
import re
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

username = sys.argv[1]
start, count = map(int, sys.argv[2:4])
db = json.load(
    open(
        "maigret-src/maigret-main/maigret/resources/data.json",
        encoding="utf-8",
    )
)["sites"]
sites = []
for name, site in db.items():
    try:
        if site.get("regexCheck") and not re.fullmatch(site["regexCheck"], username):
            continue
    except re.error:
        continue
    sites.append((name, site))
sites.sort(key=lambda item: item[1].get("alexaRank", 10**12))
sites = sites[start : start + count]


def check(item):
    name, site = item
    public_url = site["url"].replace("{username}", username)
    probe_url = site.get("urlProbe", public_url).replace("{username}", username)
    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)",
        "Accept-Encoding": "identity",
        "Range": "bytes=0-1048575",
    }
    headers.update(site.get("headers", {}))
    session = requests.Session()
    session.trust_env = False
    try:
        with session.request(
            site.get("requestMethod", "GET").upper(),
            probe_url,
            headers=headers,
            timeout=(2, 4),
            allow_redirects=site.get("allowRedirects", True),
            stream=True,
        ) as response:
            raw = response.raw.read(1048576, decode_content=False)
            body = raw.decode(response.encoding or "utf-8", errors="replace")
            status, final_url = response.status_code, response.url
    except Exception:
        return None
    presence = site.get("presenseStrs", [])
    presence_ok = not presence or any(flag in body for flag in presence)
    absence_ok = not any(flag in body for flag in site.get("absenceStrs", []))
    kind = site.get("checkType", "status_code")
    found = (
        (kind == "message" and presence_ok and absence_ok)
        or (kind == "status_code" and 200 <= status < 300)
        or (kind == "response_url" and 200 <= status < 300 and presence_ok)
    )
    if found:
        return name, status, len(raw), public_url, final_url


with ThreadPoolExecutor(max_workers=20) as pool:
    for result in pool.map(check, sites):
        if result:
            print("\t".join(map(str, result)), flush=True)
