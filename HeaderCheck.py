import requests
from urllib.parse import urlparse

STATUS_CODES = {
    100: "Continue - Server received the initial request.",
    101: "Switching Protocols - Protocol upgrade accepted.",

    200: "OK - Request successful.",
    201: "Created - Resource successfully created.",
    202: "Accepted - Request accepted for processing.",

    301: "Moved Permanently - Resource permanently redirected.",
    302: "Found - Temporary redirection.",
    304: "Not Modified - Cached version can be used.",

    400: "Bad Request - Invalid request sent by client.",
    401: "Unauthorized - Authentication required.",
    403: "Forbidden - Access denied.",
    404: "Not Found - Requested resource does not exist.",

    500: "Internal Server Error - Server encountered an error.",
    502: "Bad Gateway - Invalid response from upstream server.",
    503: "Service Unavailable - Server temporarily unavailable."
}

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "purpose": "Forces browsers to use HTTPS only.",
        "protects_against": "SSL stripping and downgrade attacks.",
        "recommended": "max-age=31536000; includeSubDomains"
    },
    "Content-Security-Policy": {
        "purpose": "Controls which resources the browser can load.",
        "protects_against": "Cross-Site Scripting (XSS), data injection, malicious scripts.",
        "recommended": "A strict CSP without wildcards (*) or unsafe-inline."
    },
    "X-Content-Type-Options": {
        "purpose": "Stops MIME-type sniffing.",
        "protects_against": "MIME confusion attacks.",
        "recommended": "nosniff"
    },
    "X-Frame-Options": {
        "purpose": "Controls whether the site can be embedded in frames.",
        "protects_against": "Clickjacking attacks.",
        "recommended": "DENY or SAMEORIGIN"
    },
    "Referrer-Policy": {
        "purpose": "Controls referrer information sent by the browser.",
        "protects_against": "Information leakage.",
        "recommended": "strict-origin-when-cross-origin"
    },
    "Permissions-Policy": {
        "purpose": "Restricts browser features and APIs.",
        "protects_against": "Abuse of camera, microphone, geolocation, etc.",
        "recommended": "Disable unnecessary permissions."
    }
}


def divider():
    print("=" * 90)


def summary_section(headers):
    present = []
    missing = []

    for header in SECURITY_HEADERS:
        if headers.get(header):
            present.append(header)
        else:
            missing.append(header)

    print("\n[+] SECURITY HEADERS SUMMARY")
    divider()

    print("\n[FOUND HEADERS]")
    if present:
        for h in present:
            print(f"  [+] {h}")
    else:
        print("  None")

    print("\n[MISSING HEADERS]")
    if missing:
        for h in missing:
            print(f"  [-] {h}")
    else:
        print("  None")

    print("\n")
    divider()


def detailed_analysis(headers):
    print("\n[+] DETAILED SECURITY ANALYSIS")
    divider()

    for header, info in SECURITY_HEADERS.items():

        value = headers.get(header)

        print(f"\nHEADER: {header}")
        print("-" * 90)

        if value:
            print("[STATUS] PRESENT")
            print(f"[PURPOSE] {info['purpose']}")
            print(f"[PROTECTS AGAINST] {info['protects_against']}")

            # Shorten very long CSP
            if header == "Content-Security-Policy" and len(value) > 120:
                print(f"[VALUE] {value[:120]} ...")
            else:
                print(f"[VALUE] {value}")

            # Security checks
            if header == "Strict-Transport-Security":
                if "max-age" in value:
                    print("[SECURITY] Properly configured.")
                else:
                    print("[WARNING] Missing max-age value.")

            elif header == "Content-Security-Policy":

                warnings = []

                if "*" in value:
                    warnings.append("Wildcard (*) detected.")

                if "unsafe-inline" in value:
                    warnings.append("'unsafe-inline' detected.")

                if "unsafe-eval" in value:
                    warnings.append("'unsafe-eval' detected.")

                if warnings:
                    print("[WARNING] Weak CSP configuration:")
                    for w in warnings:
                        print(f"   - {w}")
                else:
                    print("[SECURITY] CSP appears secure.")

            elif header == "X-Content-Type-Options":
                if value.lower() == "nosniff":
                    print("[SECURITY] MIME sniffing protection enabled.")
                else:
                    print("[WARNING] Recommended value is 'nosniff'.")

            elif header == "X-Frame-Options":
                if value.upper() in ["DENY", "SAMEORIGIN"]:
                    print("[SECURITY] Clickjacking protection enabled.")
                else:
                    print("[WARNING] Weak frame protection.")

            elif header == "Referrer-Policy":
                print("[SECURITY] Referrer leakage controlled.")

            elif header == "Permissions-Policy":
                print("[SECURITY] Browser permissions restricted.")

        else:
            print("[STATUS] MISSING")
            print(f"[PURPOSE] {info['purpose']}")
            print(f"[VULNERABLE TO] {info['protects_against']}")
            print(f"[RECOMMENDED] {info['recommended']}")
            print("[RISK] Missing security header may expose the application.")

    print("\n")
    divider()


def fetch_headers(url):
    try:
        response = requests.get(url, timeout=10)

        divider()
        print("WEBSITE SECURITY HEADER SCANNER")
        divider()

        print(f"\nTarget URL : {url}")
        status = response.status_code

        print(f"Status Code: {status}")

        if status in STATUS_CODES:
            print(f"Meaning    : {STATUS_CODES[status]}")
            if 200 <= status < 300:
                print("[INFO] Website is reachable and responding normally.")

            elif 300 <= status < 400:
                print("[INFO] Website is redirecting requests.")

            elif 400 <= status < 500:
                print("[WARNING] Client-side error detected.")

            elif 500 <= status < 600:
                print("[CRITICAL] Server-side issue detected.")

        else:
            print("Meaning    : Unknown HTTP status code.")


        # Step 1 → Brief Summary
        summary_section(response.headers)

        # Step 2 → Detailed Analysis
        detailed_analysis(response.headers)

    except requests.exceptions.RequestException as e:
        print("\n[ERROR] Could not connect to target.")
        print(f"Reason: {e}")


if __name__ == "__main__":

    target = input("Enter target URL: ").strip()

    parsed = urlparse(target)

    if not parsed.scheme:
        target = "https://" + target

    fetch_headers(target)