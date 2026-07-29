import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

username = sys.argv[1] if len(sys.argv) > 1 else "vandal_marty_88"
sites = json.load(open("wmn-data.json", encoding="utf-8"))["sites"]


def check(site):
    url = site["uri_check"].replace("{account}", username)
    try:
        session = requests.Session()
        session.trust_env = False
        response = session.get(
            url,
            timeout=9,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
    except requests.RequestException:
        return None
    expected = site.get("e_code")
    exists_text = site.get("e_string", "")
    missing_text = site.get("m_string", "")
    if expected is not None and response.status_code != expected:
        return None
    if exists_text and exists_text not in response.text:
        return None
    if missing_text and missing_text in response.text:
        return None
    return (
        site["name"],
        site.get("cat", ""),
        response.status_code,
        len(response.content),
        url,
        response.url,
    )


with ThreadPoolExecutor(max_workers=60) as pool:
    futures = [pool.submit(check, site) for site in sites]
    for future in as_completed(futures):
        result = future.result()
        if result:
            print("\t".join(map(str, result)), flush=True)
