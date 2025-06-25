import json
import csv
import os
import openai
import time
import re
from dotenv import load_dotenv

# Load API keys
load_dotenv()
openai.api_key = os.getenv("GROQ_API_KEY")
openai.api_base = "https://api.groq.com/openai/v1"

# Extract confidence from model response
def extract_confidence(text):
    match = re.search(r'\b(\d{1,3})\b', text)
    if match:
        return min(int(match.group(1)), 100)
    return 50

# Classify criticality based on score
def classify_criticality(score):
    if score >= 80:
        return "High"
    elif score >= 50:
        return "Medium"
    return "Low"

# Query Groq's LLM
def call_llm(prompt):
    try:
        response = openai.ChatCompletion.create(
            model="llama3-70b-8192",
            messages=[
                {"role": "system", "content": "You are a security assistant. Respond with a short remediation recommendation and a confidence score from 1–100."},
                {"role": "user", "content": prompt}
            ],
            temperature=0.3
        )
        return response["choices"][0]["message"]["content"]
    except Exception as e:
        print(f"LLM error: {e}")
        return "Error generating recommendation"

# Main logic
def main():
    with open("threat_report.json") as f:
        report = json.load(f)

    with open("recommendations.csv", "w", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["Incident", "Type", "Criticality", "Recommendation", "Confidence"])

        # Flagged IPs
        for entry in report.get("flagged_ips", []):
            ip = entry["ip"]
            score = entry["abuse_confidence_score"]
            criticality = classify_criticality(score)

            prompt = (
                f"The IP {ip} has an AbuseIPDB score of {score} and is classified as {criticality} criticality. "
                f"Give a remediation recommendation and a confidence score from 1–100."
            )
            print(f"[IP] Querying Groq for {ip}...")
            response = call_llm(prompt)
            confidence = extract_confidence(response)
            writer.writerow([f"Flagged IP: {ip}", "IP", criticality, response.strip(), confidence])
            time.sleep(2)

        # Suspicious Domains
        for domain in report.get("suspicious_domains", []):
            criticality = "Medium"
            prompt = (
                f"The domain {domain} appears suspicious (typosquatting or shady TLD). "
                f"It is considered {criticality} criticality. Recommend a remediation with confidence score (1–100)."
            )
            print(f"[Domain] Querying Groq for {domain}...")
            response = call_llm(prompt)
            confidence = extract_confidence(response)
            writer.writerow([f"Suspicious Domain: {domain}", "Domain", criticality, response.strip(), confidence])
            time.sleep(2)

        # Suspicious Emails
        for email in report.get("suspicious_emails", []):
            criticality = "Low"
            prompt = (
                f"The email address {email} appears fake or malformed. "
                f"Classified as {criticality} criticality. Suggest a remediation and confidence score."
            )
            print(f"[Email] Querying Groq for {email}...")
            response = call_llm(prompt)
            confidence = extract_confidence(response)
            writer.writerow([f"Suspicious Email: {email}", "Email", criticality, response.strip(), confidence])
            time.sleep(2)

        # High Traffic Conversations
        for conv in report.get("high_traffic_conversations", []):
            pair = conv["conversation"]
            count = conv["packet_count"]
            criticality = "Medium"
            prompt = (
                f"Detected high traffic between {pair} with {count} packets. "
                f"Classified as {criticality} criticality. Provide remediation and confidence score (1–100)."
            )
            print(f"[Conversation] Querying Groq for {pair}...")
            response = call_llm(prompt)
            confidence = extract_confidence(response)
            writer.writerow([f"High Traffic: {pair}", "Conversation", criticality, response.strip(), confidence])
            time.sleep(2)

    print("\n✅ Remediation recommendations saved to recommendations.csv")

if __name__ == "__main__":
    main()
