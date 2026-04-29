import argparse
import os
import random
import sys
import time
from typing import Any

import requests


BASE_URL = "https://api.ssllabs.com/api/v4"


def call_ssl_labs(
    path: str,
    email: str | None = None,
    params: dict[str, Any] | None = None,
    timeout: int = 60
) -> tuple[dict[str, Any], requests.Response]:
    headers = {}

    if email:
        headers["email"] = email

    response = requests.get(
        f"{BASE_URL}/{path}",
        headers=headers,
        params=params or {},
        timeout=timeout
    )

    if response.status_code == 429:
        raise RuntimeError("SSL Labs returned 429 Too Many Requests. Reduce scan rate/concurrency.")

    if response.status_code in (503, 529):
        raise RuntimeError(f"SSL Labs service unavailable/overloaded. HTTP {response.status_code}.")

    if response.status_code == 441:
        raise RuntimeError("SSL Labs returned 441 Unauthorized. Register your email first.")

    response.raise_for_status()
    return response.json(), response


def get_info() -> None:
    data, response = call_ssl_labs("info")

    print("SSL Labs API Info")
    print("-----------------")
    print(f"Engine Version:      {data.get('engineVersion')}")
    print(f"Criteria Version:    {data.get('criteriaVersion')}")
    print(f"Max Assessments:     {data.get('maxAssessments')}")
    print(f"Current Assessments: {data.get('currentAssessments')}")
    print(f"Cooloff ms:          {data.get('newAssessmentCoolOff')}")

    print()
    print("Response Headers")
    print("----------------")
    print(f"X-Max-Assessments:     {response.headers.get('X-Max-Assessments')}")
    print(f"X-Current-Assessments: {response.headers.get('X-Current-Assessments')}")


def run_assessment(host: str, email: str, publish: bool = False) -> dict[str, Any]:
    print(f"Starting SSL Labs assessment for: {host}")

    params = {
        "host": host,
        "startNew": "on",
        "all": "done",
        "publish": "on" if publish else "off"
    }

    data, _ = call_ssl_labs("analyze", email=email, params=params)

    while True:
        status = data.get("status")
        status_message = data.get("statusMessage", "")

        print(f"Status: {status} {status_message}")

        if status in ("READY", "ERROR"):
            return data

        sleep_seconds = 5 if status != "IN_PROGRESS" else 10
        sleep_seconds += random.uniform(0, 2)

        time.sleep(sleep_seconds)

        data, _ = call_ssl_labs(
            "analyze",
            email=email,
            params={
                "host": host,
                "all": "done"
            }
        )


def print_summary(result: dict[str, Any]) -> None:
    print()
    print("Assessment Summary")
    print("------------------")
    print(f"Host:             {result.get('host')}")
    print(f"Port:             {result.get('port')}")
    print(f"Protocol:         {result.get('protocol')}")
    print(f"Status:           {result.get('status')}")
    print(f"Status Message:   {result.get('statusMessage')}")
    print(f"Engine Version:   {result.get('engineVersion')}")
    print(f"Criteria Version: {result.get('criteriaVersion')}")

    print()
    print("Endpoints")
    print("---------")

    endpoints = result.get("endpoints", [])

    if not endpoints:
        print("No endpoints returned.")
        return

    for endpoint in endpoints:
        ip = endpoint.get("ipAddress")
        grade = endpoint.get("grade")
        status_message = endpoint.get("statusMessage")
        has_warnings = endpoint.get("hasWarnings")
        server_name = endpoint.get("serverName")

        print(f"{ip} | Grade: {grade} | Status: {status_message} | Warnings: {has_warnings} | ServerName: {server_name}")


def get_endpoint_details(host: str, ip_address: str, email: str) -> dict[str, Any]:
    data, _ = call_ssl_labs(
        "getEndpointData",
        email=email,
        params={
            "host": host,
            "s": ip_address
        }
    )

    return data


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a Qualys SSL Labs API v4 assessment.")
    parser.add_argument("host", nargs="?", help="Hostname to assess, for example www.example.com")
    parser.add_argument("--email", default=os.getenv("SSLLABS_EMAIL"), help="Registered SSL Labs API email")
    parser.add_argument("--info", action="store_true", help="Show SSL Labs API info only")
    parser.add_argument("--publish", action="store_true", help="Publish results to SSL Labs public boards")
    parser.add_argument("--details", action="store_true", help="Fetch detailed endpoint data after scan")

    args = parser.parse_args()

    if args.info:
        get_info()
        return

    if not args.host:
        print("ERROR: host is required unless using --info", file=sys.stderr)
        sys.exit(1)

    if not args.email:
        print("ERROR: provide --email or set SSLLABS_EMAIL", file=sys.stderr)
        sys.exit(1)

    result = run_assessment(args.host, args.email, publish=args.publish)
    print_summary(result)

    if args.details:
        print()
        print("Endpoint Details")
        print("----------------")

        for endpoint in result.get("endpoints", []):
            ip_address = endpoint.get("ipAddress")

            if not ip_address:
                continue

            details = get_endpoint_details(args.host, ip_address, args.email)
            detail_block = details.get("details", {})

            protocols = detail_block.get("protocols", [])
            suites = detail_block.get("suites", [])

            print(f"\nIP: {ip_address}")
            print(f"HTTP Status Code: {detail_block.get('httpStatusCode')}")
            print(f"Server Header:    {detail_block.get('serverSignature')}")
            print(f"HSTS:             {detail_block.get('hstsPolicy', {}).get('status')}")
            print(f"Supports RC4:     {detail_block.get('supportsRc4')}")
            print(f"OCSP Stapling:    {detail_block.get('ocspStapling')}")

            print("Protocols:")
            for protocol in protocols:
                print(f"  {protocol.get('name')} {protocol.get('version')}")

            print(f"Cipher suite groups returned: {len(suites)}")


if __name__ == "__main__":
    main()
