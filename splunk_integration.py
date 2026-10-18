import getpass
import json
import warnings
from datetime import datetime, timedelta, timezone

import requests
import urllib3
from requests.auth import HTTPBasicAuth

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SPLUNK_URL = "https://127.0.0.1:8089"
TRIAGE_URL = "http://127.0.0.1:8001/triage"

username = input("Splunk username: ").strip()
password = getpass.getpass("Splunk password: ")

auth = HTTPBasicAuth(username, password)

# Read-only search: find source IPs with at least five
# failed SSH logins in the last 24 hours.
spl = r'''
search index=linux sourcetype=linux:ssh
("Failed password" OR "Accepted password")
| rex field=_raw "for (?:invalid user )?(?<username>\S+)"
| rex field=_raw "from (?<source_ip>\d{1,3}(?:\.\d{1,3}){3})"
| eval failed=if(match(_raw,"Failed password"),1,0)
| eval successful=if(match(_raw,"Accepted password"),1,0)
| where isnotnull(source_ip)
| stats sum(failed) as failed_logins
        sum(successful) as successful_logins
        latest(username) as username
        by source_ip
| where failed_logins >= 5
'''

print("\nConnecting to Splunk...")

try:
    response = requests.post(
        f"{SPLUNK_URL}/services/search/jobs/export",
        auth=auth,
        data={
            "search": spl,
            "earliest_time": "-24h",
            "latest_time": "now",
            "output_mode": "json",
        },
        verify=False,  # Local Splunk certificate may be self-signed
        timeout=90,
    )
    response.raise_for_status()

    results = []
    for line in response.text.splitlines():
        try:
            item = json.loads(line)
            if item.get("result"):
                results.append(item["result"])
        except json.JSONDecodeError:
            continue

    print(f"Matching SSH alerts: {len(results)}")

    # Load saved alerts and avoid resubmitting the same source alert
    # during the 24 hours following its most recent saved occurrence.
    saved_response = requests.get(
        "http://127.0.0.1:8001/alerts", timeout=15
    )
    saved_response.raise_for_status()
    saved_alerts = saved_response.json().get("alerts", [])
    cutoff = datetime.now(timezone.utc) - timedelta(hours=24)

    def is_recent_duplicate(source_ip):
        for old in saved_alerts:
            if (
                old.get("alert_name") != "Possible SSH Brute Force"
                or old.get("source_ip") != source_ip
            ):
                continue
            try:
                timestamp = datetime.fromisoformat(
                    old["generated_at"].replace("Z", "+00:00")
                )
                if timestamp.tzinfo is None:
                    timestamp = timestamp.replace(tzinfo=timezone.utc)
                if timestamp >= cutoff:
                    return True
            except (KeyError, TypeError, ValueError):
                continue
        return False

    skipped = 0

    for result in results:
        source_ip = result.get("source_ip")
        if not source_ip:
            continue

        if is_recent_duplicate(source_ip):
            print(
                f"Skipping duplicate alert for {source_ip}: "
                "a matching alert was saved within 24 hours."
            )
            skipped += 1
            continue

        failed = int(float(result.get("failed_logins") or 0))
        successful = int(float(result.get("successful_logins") or 0))

        alert = {
            "alert_name": "Possible SSH Brute Force",
            "source_ip": source_ip,
            "username": result.get("username"),
            "failed_logins": failed,
            "successful_login_after_failures": successful > 0,
            "privileged_account": False,
            "evidence": [
                f"Splunk reported {failed} failed SSH logins "
                f"from {source_ip} in the selected time range.",
                f"Splunk reported {successful} successful SSH logins "
                f"for this source in that time range.",
            ],
        }

        print(f"\nSending alert for {source_ip}...")

        triage_response = requests.post(
            TRIAGE_URL,
            json=alert,
            timeout=15,
        )
        triage_response.raise_for_status()
        print(json.dumps(triage_response.json(), indent=2))

except requests.RequestException as exc:
    print(f"Connection or HTTP error: {exc}")
except (ValueError, TypeError) as exc:
    print(f"Data processing error: {exc}")
