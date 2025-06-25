import json
import requests
import re
import os
from dotenv import load_dotenv
from collections import defaultdict

load_dotenv()
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# Config
ABUSE_THRESHOLD = 50
TOP_COMM_THRESHOLD = 3000
SUSPICIOUS_TLDS = {'.xyz', '.top', '.gq', '.tk', '.ml', '.work'}

def load_report(path='report.json'):
    with open(path) as f:
        return json.load(f)

def check_ip_abuse(ip):
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": ABUSEIPDB_API_KEY,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip,
        "maxAgeInDays": 90
    }
    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json()
        score = data.get("data", {}).get("abuseConfidenceScore", 0)
        return score
    except Exception as e:
        print(f"Error checking {ip}: {e}")
        return 0

def flag_suspicious_domains(domains):
    suspicious = []
    for domain in domains:
        if not "." in domain: continue
        tld = "." + domain.split(".")[-1]
        if tld in SUSPICIOUS_TLDS or "authenticat" in domain.lower():
            suspicious.append(domain)
    return suspicious

def flag_suspicious_emails(emails):
    suspicious = []
    for email in emails:
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            suspicious.append(email)
        elif len(email.split("@")[0]) <= 2 or any(c in email for c in "%_"):
            suspicious.append(email)
    return suspicious

def flag_high_traffic(convos):
    suspicious = []
    for pair, count in convos.items():
        if isinstance(count, int) and count > TOP_COMM_THRESHOLD:
            suspicious.append({"conversation": pair, "packet_count": count})
    return suspicious

def main():
    report = load_report()

    findings = {
        "flagged_ips": [],
        "suspicious_domains": [],
        "suspicious_emails": [],
        "high_traffic_conversations": []
    }

    print("\n[🔍] Checking for malicious activity...\n")

    for ip in report.get("ip_addresses", []):
        score = check_ip_abuse(ip)
        if score > ABUSE_THRESHOLD:
            findings["flagged_ips"].append({
                "ip": ip,
                "abuse_confidence_score": score
            })
            print(f"[⚠️] IP flagged: {ip} (Abuse Score: {score})")

    findings["suspicious_domains"] = flag_suspicious_domains(
        report.get("hostnames", []) + report.get("dns_queries", []) + report.get("http_hosts", [])
    )

    for domain in findings["suspicious_domains"]:
        print(f"[⚠️] Suspicious domain: {domain}")

    findings["suspicious_emails"] = flag_suspicious_emails(report.get("email_addresses", []))
    for email in findings["suspicious_emails"]:
        print(f"[⚠️] Suspicious email: {email}")

    findings["high_traffic_conversations"] = flag_high_traffic(report.get("conversations", {}))
    for conv in findings["high_traffic_conversations"]:
        print(f"[⚠️] High traffic conversation: {conv['conversation']} ({conv['packet_count']} packets)")

    # Write output to JSON
    with open("threat_report.json", "w") as f:
        json.dump(findings, f, indent=2)

    print("\n✅ Findings saved to threat_report.json\n")

if __name__ == "__main__":
    main()
