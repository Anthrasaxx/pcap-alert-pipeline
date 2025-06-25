# pcap-alert-pipeline

## Overview

`pcap-alert-pipeline` is a Python-based toolchain designed to automate the analysis of network capture (PCAP) files, detect malicious activity, and generate actionable security reports. The pipeline extracts network information, evaluates threat indicators using external intelligence sources, leverages LLMs for recommendations, and facilitates easy integration with ticketing systems such as Jira.

## Features

- **PCAP Analysis:** Extracts IPs, MACs, hostnames, usernames, DNS queries, DHCP info, HTTP, SMB/CIFS, and more from PCAP files.
- **Threat Intelligence:** Checks IPs against AbuseIPDB and classifies suspicious domains, emails, and high-traffic conversations.
- **Automated Recommendations:** Uses Groq's LLM to generate remediation recommendations with confidence scores.
- **Reporting:** Outputs findings to JSON and generates summary CSV/Excel files.
- **Jira Integration:** Automatically creates Jira tickets for critical incidents.

## Pipeline Steps

1. **Analyze PCAP:** Parses the network capture and extracts relevant artifacts.
2. **Threat Detection:** Flags malicious IPs, suspicious domains/emails, and abnormal traffic patterns.
3. **LLM Recommendations:** Queries Groq LLM for remediation suggestions for each finding.
4. **Reporting:** Produces both CSV and XLSX reports.
5. **Ticketing:** Optionally creates Jira tickets for detected incidents.

## Quick Start

### Prerequisites

- Python 3.8+
- [pip](https://pip.pypa.io/en/stable/)
- Place a PCAP file named `capture.pcap` in the project directory or specify your own.

### Installation

```bash
git clone https://github.com/Anthrasaxx/pcap-alert-pipeline.git
cd pcap-alert-pipeline
pip install -r requirements.txt
```

### Usage

Run the pipeline with:

```bash
python main.py
```

Each stage will be executed in sequence. Results and reports will be generated in the project directory.

### Environment Variables

Create a `.env` file in the root directory with the following contents:

```
ABUSEIPDB_API_KEY=your_abuseipdb_key
GROQ_API_KEY=your_groq_api_key

# Jira integration
JIRA_URL=https://your-domain.atlassian.net
JIRA_API_TOKEN=your_jira_api_token
JIRA_USER_EMAIL=your_email@example.com
JIRA_PROJECT_KEY=YOURPROJECTKEY
```

- `JIRA_URL`: Your Jira Cloud site URL (e.g., https://example.atlassian.net)
- `JIRA_API_TOKEN`: Your Jira API token ([how to create](https://id.atlassian.com/manage-profile/security/api-tokens))
- `JIRA_USER_EMAIL`: The email address associated with your Jira account
- `JIRA_PROJECT_KEY`: The key of the project where tickets will be created

## File Structure

- `main.py` - Orchestrates the pipeline.
- `pcap_analyzer.py` - Extracts network information from PCAPs.
- `abuseip.py` - Checks threat intelligence and flags malicious indicators.
- `groq.py` - Queries LLM for remediation steps.
- `jira.py` - Creates Jira tickets for incidents.
- `csv_to_xlsx.py` - Converts CSV reports to Excel.

## Example

```bash
python main.py
```

Output: JSON, CSV, and XLSX reports plus optional Jira ticket creation.

## License

MIT License. See [LICENSE](LICENSE) for details.
