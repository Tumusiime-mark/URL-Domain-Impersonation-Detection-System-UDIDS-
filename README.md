# Domain Impersonation Detection System (DIDS)

> **A proactive cybersecurity platform for detecting domain impersonation, phishing infrastructure, typosquatting, homograph attacks, and brand abuse before they impact organizations.**

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-success)

---

# Domain Impersonation Detection System (DIDS)

The **Domain Impersonation Detection System (DIDS)** is an advanced cybersecurity platform developed to help organizations proactively identify domains that imitate or closely resemble legitimate domains. These deceptive domains are commonly used in phishing attacks, credential theft, malware delivery, business email compromise (BEC), and brand impersonation.

DIDS continuously monitors suspicious domains, performs similarity analysis, inspects DNS and SSL configurations, analyzes website content, and calculates risk scores to help security teams detect and investigate threats before they are exploited.

---

# Problem Statement

Every day, attackers register fraudulent domains that resemble trusted organizations. These domains are used to deceive users into disclosing sensitive information, installing malware, or making fraudulent payments.

Examples include:

```
google.com
gooogle.com
g00gle.com
goog1e.com
google-login.com
```

Organizations often become aware of these domains only after customers or employees have already been targeted.

DIDS addresses this challenge through automated discovery, analysis, and continuous monitoring.

---

# Objectives

The project aims to:

- Detect domains similar to legitimate domains
- Identify typosquatting attacks
- Detect Unicode homograph attacks
- Monitor newly registered suspicious domains
- Analyze WHOIS registration information
- Inspect DNS records
- Analyze SSL certificates
- Compare website content and branding
- Calculate threat risk scores
- Generate automated alerts
- Provide centralized monitoring and reporting

---

# Key Features

## Domain Discovery

- Similar domain generation
- Domain permutation analysis
- Newly registered domain monitoring
- Brand keyword detection
- Continuous monitoring

---

## Domain Similarity Detection

The similarity engine uses multiple algorithms including:

- Levenshtein Distance
- Jaro-Winkler Similarity
- Keyboard substitution analysis
- Missing-character detection
- Added-character detection
- Swapped-character detection
- Brand keyword matching

Example:

```
bankofuganda.go.ug

bankofugandaa.go.ug
bank0fuganda.go.ug
bnkofuganda.go.ug
bankof-uganda.com
```

---

## Homograph Attack Detection

Detects deceptive Unicode characters that visually resemble normal characters.

Example:

```
apple.com

аррӏе.com
```

Although these domains appear identical, they contain different Unicode characters.

---

## WHOIS Analysis

The system extracts and analyzes:

- Registrar
- Registration date
- Domain age
- Expiration date
- Registrant privacy
- Name servers

Domains registered recently receive higher risk scores.

---

## DNS Analysis

Analyzes:

- A Records
- AAAA Records
- MX Records
- TXT Records
- NS Records
- CNAME Records

Detects suspicious DNS configurations and hosting infrastructure.

---

## SSL Certificate Analysis

Examines:

- Certificate issuer
- Validity period
- Certificate age
- Self-signed certificates
- Expiration
- Certificate chain

---

## Website Analysis

Performs:

- Screenshot capture
- Logo comparison
- Login form detection
- HTML similarity comparison
- Phishing indicator detection
- Page layout comparison

---

## Risk Scoring Engine

Each detected domain is assigned a risk score using multiple indicators.

Factors include:

- Domain similarity
- Registration age
- SSL certificate trust
- DNS configuration
- Website similarity
- Threat intelligence indicators

### Risk Levels

| Score | Severity |
|--------|----------|
| 0–30 | Low |
| 31–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

---

## Alerting System

Supports:

- Dashboard notifications
- Email alerts
- SMS alerts
- SIEM integration
- SOC notifications

---

# Dashboard

The web dashboard provides:

- Protected domains
- Newly detected domains
- Risk trends
- Investigation management
- Website screenshots
- Reports
- Analytics
- Alert history
- User management

---

# System Architecture

```
                        Protected Domains
                                │
                                ▼
                    Domain Generation Engine
                                │
                                ▼
                    Domain Discovery Engine
                                │
        ┌───────────────┬───────────────┬───────────────┐
        ▼               ▼               ▼
   WHOIS Module     DNS Analysis     SSL Analysis
        │               │               │
        └───────────────┼───────────────┘
                        ▼
            Similarity Analysis Engine
                        │
                        ▼
             Website Analysis Module
                        │
                        ▼
               Risk Scoring Engine
                        │
                        ▼
                 Alert Management
                        │
                        ▼
            Dashboard & Database System
```

---

# Database Design

Main database tables include:

- domains
- detected_domains
- alerts
- investigations
- screenshots
- users
- audit_logs
- risk_assessments

---

# Technology Stack

## Backend

- Python
- Flask / Django

## Database

- PostgreSQL
- SQLite

## Web Scraping

- Requests
- BeautifulSoup

## Browser Automation

- Selenium
- Playwright

## Domain Intelligence

- python-whois
- tldextract

## Similarity Libraries

- RapidFuzz
- Jellyfish
- python-Levenshtein

---

# Integrations

DIDS can integrate with:

- Microsoft Sentinel
- Splunk
- IBM QRadar
- Wazuh
- ELK Stack
- SOAR Platforms
- Threat Intelligence Platforms

---

# Reporting

Automatically generates:

- Daily reports
- Weekly reports
- Monthly reports
- Executive summaries
- Incident reports
- Risk assessments

---

# Security Features

- Role-Based Access Control (RBAC)
- User Authentication
- Audit Logging
- Secure HTTPS Communication
- Encrypted Data Storage
- Session Management

---

# Project Structure

```
DIDS/
│
├── app/
│   ├── dashboard/
│   ├── discovery/
│   ├── similarity/
│   ├── dns/
│   ├── ssl/
│   ├── whois/
│   ├── website/
│   ├── alerts/
│   ├── risk/
│   └── reports/
│
├── database/
├── screenshots/
├── reports/
├── static/
├── templates/
├── config.py
├── requirements.txt
├── run.py
└── README.md
```

---

# Expected Benefits

- Early detection of phishing domains
- Protection against brand impersonation
- Reduced fraud risk
- Improved incident response
- Enhanced organizational cybersecurity
- Continuous domain monitoring
- Faster threat investigations

---

# Future Enhancements

- Machine Learning risk prediction
- AI-powered phishing detection
- Certificate Transparency (CT) monitoring
- Passive DNS integration
- Threat intelligence feeds
- Automated takedown workflows
- Global domain monitoring
- Dark web monitoring
- Real-time notification services

---

# Contributing

Contributions, feature requests, bug reports, and pull requests are welcome. Please open an issue to discuss significant changes before submitting a pull request.

---

# License

This project is licensed under the **MIT License**.

---

# Developer

**Tumusiime Mark**

Digital Forensics & Information Security Analyst

📍 Uganda

📧 Email: **tumusiimemail@gmail.com**

**Areas of Expertise**

- Digital Forensics
- Cybersecurity
- Threat Intelligence
- Malware Analysis
- Incident Response
- Security Operations (SOC)
- Network Security
- Python Development
- Secure System Design

---

## Contact

For collaborations, research, cybersecurity projects, or professional inquiries:

**Tumusiime Mark**

**Digital Forensics & Information Security Analyst**

📧 **tumusiimemail@gmail.com**

📍 **Uganda**

---

> **Domain Impersonation Detection System (DIDS)** was developed to help organizations proactively detect, investigate, and mitigate phishing domains, brand impersonation, typosquatting, homograph attacks, and other domain-based cyber threats before they can be exploited.
