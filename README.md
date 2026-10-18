# AI SOC Alert Triage Platform

A Python-based Security Operations Center (SOC) alert triage application that analyzes security alerts, assigns risk scores, classifies severity, and supports analyst investigations. It includes a FastAPI backend, a web dashboard, and optional Splunk integration for SSH authentication event monitoring.

## Project Overview

Security Operations Centers receive large volumes of alerts. This project demonstrates how an alert triage workflow can help analysts prioritize suspicious activity and organize investigations.

### Key Features

- **Automated alert triage** — evaluates alert attributes and calculates risk scores.
- **Severity classification** — categorizes alerts by risk level.
- **Alert management** — view alerts and update investigation status.
- **Audit information** — review available alert audit records.
- **Splunk integration** — retrieve SSH authentication events and submit matching alerts for triage.
- **REST API** — interact with the application through FastAPI.
- **Web dashboard** — access the local interface to review alerts.
- **Automated tests** — includes a pytest test suite.

## Technology Stack

- Python
- FastAPI
- Pydantic
- Uvicorn
- SQLite
- Splunk
- Pytest
- HTML, CSS, and JavaScript

## Architecture

```text
Linux Authentication Logs
          |
          v
    Splunk SIEM
          |
          v
 Splunk Integration Script
          |
          v
 FastAPI Alert Triage API
          |
          v
 Risk Scoring and Severity
          |
          v
 Database and Web Dashboard
          |
          v
     SOC Analyst
```

## Project Structure

```text
ai-soc-triage/
├── app/
│   ├── __init__.py
│   ├── database.py
│   ├── main.py
│   └── static/
│       └── index.html
├── tests/
│   └── test_main.py
├── .gitignore
├── README.md
├── requirements.txt
└── splunk_integration.py
```

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/usif00000/ai-soc-triage.git
cd ai-soc-triage
```

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

### 4. Start the application

```bash
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

## Access the Application

With the server running, open:

| Resource | URL |
|---|---|
| Web dashboard | http://127.0.0.1:8001/ |
| Health check | http://127.0.0.1:8001/health |
| Interactive API documentation | http://127.0.0.1:8001/docs |

The application is configured to listen on the local machine only.

## Running Tests

Run the automated test suite:

```bash
python -m pytest -q
```

The project test suite previously completed with **18 passing tests** in the development environment. Run the command in your own environment to verify the current version.

## Splunk Integration

The optional integration script connects to Splunk to retrieve SSH authentication events and forwards matching activity to the triage API.

Before running the integration:

1. Start Splunk and verify its management API is accessible.
2. Start the FastAPI application.
3. Confirm that the relevant SSH authentication events are indexed.
4. Run the script and enter your Splunk credentials when prompted.

```bash
python splunk_integration.py
```

Use a controlled lab environment and test credentials. Do not commit passwords, tokens, private keys, real authentication logs, or sensitive production data.

## Security and Limitations

- Intended for educational use, portfolio demonstrations, and controlled SOC labs.
- Risk scores are rule-based indicators, not proof that an attack occurred.
- Analysts should validate evidence before taking incident-response actions.
- Production deployment requires authentication, authorization, secure secret management, TLS verification, logging controls, and additional security testing.
- Use synthetic or sanitized events when demonstrating the project publicly.

## Learning Objectives

This project demonstrates practical experience with:

- SOC alert triage workflows
- Linux SSH authentication events
- SIEM integration concepts
- REST API development
- Python backend development
- Security event investigation
- Automated testing and Git-based version control

## Future Improvements

- Add configurable detection rules.
- Integrate additional Linux security log sources.
- Add alert filtering, search, and severity-based views.
- Improve authentication and role-based access control.
- Add structured incident reports and metrics.
- Explore explainable machine-learning assistance for alert prioritization.

## Author

**AI SOC Alert Triage Platform**  
Developed as a cybersecurity portfolio project to practice SOC workflows, security monitoring, and Python API development.

## License

No license is specified yet. Add an appropriate open-source license if you want others to reuse, modify, and distribute the project.
