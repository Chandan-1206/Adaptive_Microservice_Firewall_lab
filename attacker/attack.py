import os
import time
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

TARGET_URL = os.environ.get("TARGET_URL", "http://firewall_app:5000/")
TOTAL_REQUESTS = 1000
CONCURRENCY = 50


def send_request(i):
    try:
        r = requests.get(TARGET_URL, timeout=3)
        return (i, r.status_code)
    except Exception as e:
        return (i, f"ERR:{e}")


def main():
    print(f"[ATTACKER] Starting attack on {TARGET_URL}")
    print(f"[ATTACKER] Total requests: {TOTAL_REQUESTS}, concurrency: {CONCURRENCY}")

    start = time.time()
    results = []

    with ThreadPoolExecutor(max_workers=CONCURRENCY) as executor:
        futures = [executor.submit(send_request, i) for i in range(TOTAL_REQUESTS)]
        for fut in as_completed(futures):
            results.append(fut.result())

    duration = time.time() - start
    print(f"[ATTACKER] Completed in {duration:.2f}s")
    # Quick summary
    codes = {}
    for _, status in results:
        codes[status] = codes.get(status, 0) + 1

    print("[ATTACKER] Status code counts:")
    for code, count in codes.items():
        print(f"  {code}: {count}")


if __name__ == "__main__":
    main()
