import requests
import json
from dotenv import load_dotenv
import os

load_dotenv()

JIRA_EMAIL = os.getenv("JIRA_EMAIL")
JIRA_TOKEN = os.getenv("JIRA_TOKEN")
JIRA_PROJECT_KEY = os.getenv("JIRA_PROJECT_KEY")
JIRA_URL = os.getenv("JIRA_URL")  # e.g. https://yourcompany.atlassian.net

def create_ticket(incident_name, criticality, findings, recommendation):
    summary = f"[{criticality}] {incident_name}"
    
    # Create ADF (Atlassian Document Format) description
    description = {
        "version": 1,
        "type": "doc",
        "content": [
            {
                "type": "heading",
                "attrs": {"level": 3},
                "content": [
                    {
                        "type": "text",
                        "text": "Incident Summary"
                    }
                ]
            },
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "Incident Name: ",
                        "marks": [{"type": "strong"}]
                    },
                    {
                        "type": "text",
                        "text": incident_name
                    }
                ]
            },
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "Criticality: ",
                        "marks": [{"type": "strong"}]
                    },
                    {
                        "type": "text",
                        "text": criticality
                    }
                ]
            },
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "Findings:",
                        "marks": [{"type": "strong"}]
                    }
                ]
            },
            {
                "type": "bulletList",
                "content": [
                    {
                        "type": "listItem",
                        "content": [
                            {
                                "type": "paragraph",
                                "content": [
                                    {
                                        "type": "text",
                                        "text": finding
                                    }
                                ]
                            }
                        ]
                    } for finding in findings
                ]
            },
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": "Recommendation:",
                        "marks": [{"type": "strong"}]
                    }
                ]
            },
            {
                "type": "paragraph",
                "content": [
                    {
                        "type": "text",
                        "text": recommendation
                    }
                ]
            }
        ]
    }
    
    payload = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": summary,
            "description": description,
            "issuetype": {"name": "Task"}
        }
    }
    
    response = requests.post(
        f"{JIRA_URL}/rest/api/3/issue",
        headers={
            "Content-Type": "application/json"
        },
        auth=(JIRA_EMAIL, JIRA_TOKEN),
        data=json.dumps(payload)
    )
    
    if response.status_code == 201:
        print(f"[✓] Jira ticket created: {response.json()['key']}")
    else:
        print(f"[!] Failed to create ticket: {response.status_code}, {response.text}")

# === Example Usage ===
if __name__ == "__main__":
    # Load the first incident from recommendations.csv
    import csv
    with open("recommendations.csv") as f:
        reader = csv.DictReader(f)
        first = next(reader)
        create_ticket(
            incident_name=first["Incident"],
            criticality=first["Criticality"],
            findings=[first["Incident"]],
            recommendation=first["Recommendation"]
        )
