# AI-Assisted SOC Alert Triage Platform

An educational Security Operations Center (SOC) project that combines Splunk log analysis with a FastAPI-based alert triage application.

## Features

- REST API for submitting and reviewing security alerts
- Risk scoring and severity classification
- SQLite-based alert storage
- Web dashboard for viewing alerts
- Splunk integration for identifying suspicious SSH login activity
- Automated tests for core API functionality

## Technology Stack

- Python
- FastAPI and Uvicorn
- Splunk
- SQLite
- Pytest
- HTML and JavaScript

## Local Setup

1. Install Python 3 and Git.
2. Create and activate a virtual environment:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   python -m pip install -r requirements.txt
   ```

4. Start the API:

   ```bash
   python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
   ```

5. Open these local endpoints:

   - Dashboard: http://127.0.0.1:8001/
   - Health check: http://127.0.0.1:8001/health
   - API documentation: http://127.0.0.1:8001/docs

## Run Tests

With the virtual environment activated:

```bash
python -m pytest -q
```

## Splunk Integration

The integration script connects to a local Splunk management API and submits matching SSH activity to the triage API. Configure Splunk access locally and enter credentials when prompted.

The integration expects the relevant Splunk index and sourcetype to exist. Update the script's settings if your local environment differs.

## Security and Limitations

- Designed for education and authorized lab environments.
- Do not commit credentials, production logs, databases, or private configuration.
- Keep services bound to localhost unless you have deliberately configured appropriate access controls.
- Review TLS certificate verification and authentication settings before using the integration outside a local lab.
- Alert scores are educational triage indicators, not a substitute for analyst investigation.

## License

No license has been specified. All rights are reserved by default unless a license is added to this repository.
