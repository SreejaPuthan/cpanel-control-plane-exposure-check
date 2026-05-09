#!/usr/bin/env python3
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

requests.packages.urllib3.disable_warnings()

PORTS = [2082, 2083, 2086, 2087, 2095, 2096]

PORT_LABELS = {
    2082: "cPanel_HTTP (Insecure)",
    2083: "cPanel_HTTPS",
    2086: "WHM_HTTP (Insecure)",
    2087: "WHM_HTTPS",
    2095: "Webmail_HTTP (Insecure)",
    2096: "Webmail_HTTPS"
}

TIMEOUT = 6


def get_url(host, port):
    scheme = "http" if port in [2082, 2086, 2095] else "https"
    return f"{scheme}://{host}:{port}"


def check_host_port(host, port):
    url = get_url(host, port)

    result = {
        "host": host,
        "port": port,
        "port_type": PORT_LABELS.get(port, "Unknown"),
        "status": "UNKNOWN",
        "http_code": None,
        "final_url": None,
        "notes": "",
        "fingerprint": ""
    }

    try:
        # Prefer GET (HEAD is often blocked or misleading)
        resp = requests.get(
            url,
            timeout=TIMEOUT,
            verify=False,
            allow_redirects=True,
            headers={"User-Agent": "Mozilla/5.0"}
        )

        result["http_code"] = resp.status_code
        result["final_url"] = resp.url

        headers = {k.lower(): v.lower() for k, v in resp.headers.items()}
        server = headers.get("server", "")
        set_cookie = headers.get("set-cookie", "")

        is_cloudflare = (
            "cloudflare" in server or
            any(h.startswith("cf-") for h in headers.keys())
        )

        is_cpanel = (
            "cpsrvd" in server or
            "cpsession" in set_cookie or
            "cpanel" in resp.text.lower()[:2000]
        )

        # Classification
        if resp.status_code in (200, 401, 403):
            if is_cpanel:
                result["status"] = "CPANEL_EXPOSED"
                result["fingerprint"] = "cpsrvd detected"

                # High-risk note (matches CVE-2026-41940 exposure pattern)
                result["notes"] = "⚠️ cPanel/WHM service exposed; ensure CVE-2026-41940 patch + cpsrvd restart"

            else:
                result["status"] = "REACHABLE_NON_CPANEL"

        elif resp.status_code in (301, 302, 307, 308):
            result["status"] = "REDIRECT"

        elif resp.status_code == 404:
            result["status"] = "NOT_FOUND"

        else:
            result["status"] = f"HTTP_{resp.status_code}"

        if is_cloudflare:
            result["notes"] += " | Cloudflare/WAF present"

        # Flag insecure HTTP exposure
        if port in [2082, 2086, 2095] and result["status"] == "CPANEL_EXPOSED":
            result["notes"] += " | ❗ Insecure HTTP management port"

    except requests.exceptions.SSLError:
        result["status"] = "SSL_ERROR"

    except requests.exceptions.ConnectTimeout:
        result["status"] = "TIMEOUT"

    except requests.exceptions.ConnectionError:
        result["status"] = "CONN_ERROR"

    except Exception as e:
        result["status"] = "ERROR"
        result["notes"] = str(e)

    return result


def run_checks(targets, max_workers=20):
    results = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = []

        for host in targets:
            for port in PORTS:
                futures.append(executor.submit(check_host_port, host, port))

        for future in as_completed(futures):
            results.append(future.result())

    return results


if __name__ == "__main__":
    with open("targets.txt") as f:
        targets = [line.strip() for line in f if line.strip()]

    results = run_checks(targets)

    print(f"{'HOST':30} {'PORT':6} {'TYPE':28} {'STATUS':22} {'HTTP':5} {'NOTES'}")

    for r in results:
        print(
            f"{r['host']:30} {r['port']:6} {r['port_type']:28} "
            f"{r['status']:22} {str(r['http_code']):5} {r['notes']}"
        )
