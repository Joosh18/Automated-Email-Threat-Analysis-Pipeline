# Automated-Email-Threat-Analysis-Pipeline
N8N automation for Gmail with VirusTotal to slack 

# Real-Time Phishing Triage with n8n, VirusTotal & Slack

This project is a lightweight **SOAR (Security Orchestration, Automation & Response)** workflow built in [n8n](https://n8n.io/).  
It scans incoming emails in real-time, extracts URLs, analyzes them with **VirusTotal**, and posts verdicts into **Slack**.  

The goal is to demonstrate how email phishing detection and triage can be automated without the need for expensive enterprise SOAR tools.

---

## Features
- Real-time trigger: runs on every new Gmail inbox email.
- IOC extraction: extracts all `http(s)` URLs from the email body/snippet.
- Threat intelligence: queries VirusTotal API for verdicts.
- Slack notifications: posts a formatted alert into Slack with:
  - Verdict (CLEAN / SUSPICIOUS / MALICIOUS)
  - URL scanned
  - Detection statistics (malicious, suspicious, harmless, undetected)
  - Direct link to VirusTotal report
- Extensible design:
  - Can be extended to label/quarantine emails in Gmail.
  - Logs can be sent to Google Sheets, Notion, or a SIEM for auditing.

---

## Architecture
```text
Gmail (trigger: new email)
    ↓
n8n workflow
    ├─ Extract URLs (Code node, regex)
    ├─ VirusTotal API (HTTP Request)
    ├─ Verdict logic (Code node)
    └─ Slack Notification


-----------------------------------------------------------------------------------------

Tech Stack

n8n – Open-source automation platform (low-code SOAR)

Gmail API – Email trigger & processing

VirusTotal API – Threat intelligence enrichment

Slack API – Notifications & collaboration

------------------------------------------------------------------------------------------

Setup and Usage

Clone this repository and import the workflow JSON into your n8n instance:

In n8n → Workflows → Import from File → select workflow/phishing-triage.json.

Configure credentials:

Gmail (with API key or OAuth)

VirusTotal (obtain a free API key at virustotal.com
)

Slack (create an app or use a webhook)

Enable the workflow:

It will fire on every new Gmail inbox email.

Test it:

Send yourself an email containing a URL such as http://example.com

Confirm that a Slack notification is received with the verdict.

Future Improvements

Add Gmail quarantine step: move malicious emails to a "Phishing Suspect" label or folder.

Build audit logs into Google Sheets or Notion.

Aggregate multiple URLs from the same email into a single Slack alert.

Integrate with other threat intelligence sources (AbuseIPDB, OTX, GreyNoise).

About

This project demonstrates security automation and incident response engineering using modern low-code tooling.
It is intended as a portfolio project to showcase practical SOAR workflows for phishing triage.
