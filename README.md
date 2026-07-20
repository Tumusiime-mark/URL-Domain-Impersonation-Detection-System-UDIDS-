# Domain Impersonation Detection System (DIDS)

> A proactive cybersecurity platform for detecting domain impersonation, phishing infrastructure, typosquatting, homograph attacks, and brand abuse.

![Python](https://img.shields.io/badge/Python-3.x-blue)
![Flask](https://img.shields.io/badge/Framework-Flask-green)
![License](https://img.shields.io/badge/License-MIT-yellow)
![Status](https://img.shields.io/badge/Status-Active-success)

---

## Overview

The **Domain Impersonation Detection System (DIDS)** is a cybersecurity solution that continuously monitors the internet for domains attempting to impersonate an organization's legitimate domain. It enables security teams to detect phishing domains, fraudulent websites, brand abuse, typosquatting, and homograph attacks before they can be used against customers or employees.

---

## Problem Statement

Cybercriminals frequently register deceptive domains that closely resemble legitimate brands. These malicious domains are commonly used for:

- Phishing attacks
- Credential theft
- Malware distribution
- Business email compromise (BEC)
- Brand impersonation
- Financial fraud

Many organizations only discover these domains after users have already been affected.

---

## Objectives

- Detect domains similar to legitimate domains
- Identify typosquatting attacks
- Detect Unicode homograph attacks
- Monitor suspicious newly registered domains
- Analyze DNS configurations
- Inspect SSL certificates
- Compare website content
- Calculate domain risk scores
- Generate automated alerts
- Provide centralized monitoring and reporting

---

# Features

## Domain Discovery

- Domain enumeration
- Similar domain generation
- Newly registered domain monitoring
- Brand keyword detection

---

## Similarity Detection

The system detects look-alike domains using:

- Levenshtein Distance
- Jaro-Winkler Similarity
- Keyboard substitution analysis
- Missing-character detection
- Added-character detection
- Swapped-character detection
- Brand keyword matching

Example:

```
google.com

gooogle.com
goggle.com
goog1e.com
g00gle.com
google-login.com
```

---

## Homograph Detection

Detects Unicode characters used to imitate legitimate domains.

Example:

```
google.com

gοοgle.com
```

(The two "o" characters above are different Unicode characters.)

---

## WHOIS Analysis

Analyzes:

- Registration date
- Domain age
- Registrar
- Registrant privacy
- Expiration date
- Name servers

---

## DNS Analysis

Inspects:

- A Records
- AAAA Records
- MX Records
- TXT Records
- NS Records
- CNAME Records

Detects suspicious infrastructure and misconfigurations.

---

## SSL Certificate Analysis

Checks:

- Certificate issuer
- Certificate validity
- Expiration
- Certificate age
- Self-signed certificates
- Suspicious issuers

---

## Website Analysis

Analyzes websites by:

- Capturing screenshots
- Detecting login forms
- Comparing logos
- Comparing page layouts
- Identifying phishing indicators
- Comparing HTML structure

---

## Risk Scoring Engine

Each detected domain receives a risk score based on:

- Domain similarity
- Domain age
- DNS configuration
- SSL certificate
- Website similarity
- Threat indicators

Example:

| Risk Score | Severity |
|------------|----------|
| 0–30 | Low |
| 31–60 | Medium |
| 61–80 | High |
| 81–100 | Critical |

---

## Alerting

Generate alerts through:

- Dashboard notifications
- Email
- SMS
- SIEM integrations
- SOC notifications

---

## Dashboard

The dashboard provides:

- Protected domains
- Suspicious domains
- Risk trends
- Screenshots
- Investigation queue
- Alerts
- Reports
- Analytics

---

# System Architecture

```
                    +----------------------+
                    | Protected Domains    |
                    +----------+-----------+
                               |
                               v
                   +------------------------+
                   | Domain Generator       |
                   +-----------+------------+
                               |
                               v
                  +-------------------------+
                  | Domain Discovery Engine |
                  +-----------+-------------+
                              |
        +---------------------+----------------------+
        |                     |                      |
        v                     v                      v
+---------------+     +----------------+     +----------------+
| WHOIS Module  |     | DNS Analyzer   |     | SSL Analyzer   |
+---------------+     +----------------+     +----------------+
        |                     |                      |
        +----------+----------+----------+-----------+
                   |                     |
                   v                     v
          +--------------------------------------+
          | Similarity Analysis Engine           |
          +------------------+-------------------+
                             |
                             v
                 +-----------------------------+
                 | Website Analysis            |
                 +-------------+---------------+
                               |
                               v
                 +-----------------------------+
                 | Risk Scoring Engine         |
                 +-------------+---------------+
                               |
                               v
                 +-----------------------------+
                 | Alerting Engine             |
                 +-------------+---------------+
                               |
                               v
                 +-----------------------------+
                 | Dashboard & Database        |
                 +-----------------------------+
```

---

# Database Design

Main tables:

- domains
- detected_domains
- users
- alerts
- investigations
- screenshots
- risk_assessments
- audit_logs

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

- python-Levenshtein
- Jellyfish
- RapidFuzz

---

# Integrations

DIDS can integrate with:

- Splunk
- Microsoft Sentinel
- Wazuh
- ELK Stack
- IBM QRadar
- SOAR platforms
- Email gateways
- Threat intelligence feeds

---

# Reporting

Generate:

- Daily reports
- Weekly reports
- Monthly reports
- Executive summaries
- Incident reports
- Risk assessments

---

# Security Features

- Role-Based Access Control (RBAC)
- Authentication
- Audit logging
- Secure communications (HTTPS/TLS)
- Encrypted data storage
- Session management

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
├── static/
├── templates/
├── database/
├── screenshots/
├── reports/
├── config.py
├── requirements.txt
├── run.py
└── README.md
```

---

# Expected Benefits

- Early phishing detection
- Brand protection
- Reduced fraud risk
- Improved incident response
- Centralized visibility
- Continuous domain monitoring
- Faster investigations
- Enhanced organizational security

---

# Future Enhancements

- Machine learning-based risk classification
- Certificate Transparency (CT) log monitoring
- Threat intelligence feed integration
- Automated domain takedown workflows
- Global domain monitoring
- Passive DNS integration
- AI-powered phishing detection
- Real-time browser fingerprinting

---

# Contributing

Contributions are welcome. Feel free to submit issues, feature requests, or pull requests to improve the project.

---

# License

This project is licensed under the **MIT License**.

---

# Author

**Domain Impersonation Detection System (DIDS)**

A cybersecurity project focused on proactive detection of domain impersonation, phishing campaigns, typosquatting, homograph attacks, and brand abuse through automated monitoring, similarity analysis, and risk assessment.
