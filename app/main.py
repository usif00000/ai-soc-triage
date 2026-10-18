from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

from app.database import init_db, save_alert, get_alerts, update_alert_status, update_alert_analysis, get_audit_events, VALID_STATUSES, delete_alert

app = FastAPI(
    title="AI-Assisted SOC Alert Triage Platform",
    version="0.3.0",
    description="Lab-based security alert triage API",
)

# Initialize the local SQLite database.
init_db()


class TriageRequest(BaseModel):
    alert_id: str | None = Field(default=None, max_length=128)
    alert_name: str = Field(min_length=1, max_length=200)
    source_ip: str | None = Field(default=None, max_length=45)
    username: str | None = Field(default=None, max_length=128)
    failed_logins: int = Field(default=0, ge=0)
    successful_login_after_failures: bool = False
    privileged_account: bool = False
    evidence: list[str] = Field(default_factory=list, max_length=50)

    @field_validator("alert_name")
    @classmethod
    def validate_alert_name(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Alert name must not be blank.")
        return value

    @field_validator("source_ip")
    @classmethod
    def validate_source_ip(cls, value: str | None) -> str | None:
        if value is None:
            return None

        import ipaddress

        try:
            return str(ipaddress.ip_address(value.strip()))
        except ValueError:
            raise ValueError("source_ip must be a valid IPv4 or IPv6 address.")

    @field_validator("evidence")
    @classmethod
    def validate_evidence_items(cls, items: list[str]) -> list[str]:
        for item in items:
            if len(item) > 1000:
                raise ValueError("Each evidence item must be at most 1000 characters.")
        return items


def calculate_risk(alert: TriageRequest):
    score = 0
    reasons = []

    if alert.failed_logins >= 10:
        score += 40
        reasons.append(
            f"{alert.failed_logins} failed login attempts: high volume"
        )
    elif alert.failed_logins >= 5:
        score += 30
        reasons.append(
            f"{alert.failed_logins} failed login attempts reported"
        )
    elif alert.failed_logins >= 3:
        score += 15
        reasons.append(
            f"{alert.failed_logins} failed login attempts reported"
        )

    if alert.successful_login_after_failures:
        score += 30
        reasons.append(
            "Successful login reported after failed attempts"
        )

    if alert.privileged_account:
        score += 25
        reasons.append("Privileged account involved")

    if alert.source_ip:
        reasons.append(f"Source IP supplied: {alert.source_ip}")

    if alert.username:
        reasons.append(f"Username supplied: {alert.username}")

    if alert.evidence:
        reasons.append(
            f"{len(alert.evidence)} evidence item(s) supplied"
        )

    score = min(score, 100)

    if score >= 80:
        severity = "critical"
    elif score >= 60:
        severity = "high"
    elif score >= 30:
        severity = "medium"
    else:
        severity = "low"

    return score, severity, reasons


@app.get("/", include_in_schema=False)
def dashboard():
    page = Path(__file__).parent / "static" / "index.html"
    return FileResponse(page)


@app.get("/health")
def health():
    return {
        "status": "ok",
        "service": "soc-alert-triage",
    }


@app.get("/alerts")
def list_saved_alerts():
    alerts = get_alerts()
    return {
        "count": len(alerts),
        "alerts": alerts,
    }


class StatusUpdate(BaseModel):
    status: str


@app.patch("/alerts/{alert_id}/status")
def update_alert_status_endpoint(
    alert_id: str,
    update: StatusUpdate,
):
    if update.status not in VALID_STATUSES:
        raise HTTPException(
            status_code=422,
            detail="Status must be New, Investigating, or Resolved.",
        )

    updated = update_alert_status(alert_id, update.status)

    if not updated:
        raise HTTPException(status_code=404, detail="Alert not found.")

    return {
        "alert_id": alert_id,
        "status": update.status,
        "message": "Alert status updated.",
    }

@app.delete("/alerts/{alert_id}")
def delete_alert_endpoint(alert_id: str):
    deleted = delete_alert(alert_id)

    if not deleted:
        raise HTTPException(
            status_code=404,
            detail="Alert not found.",
        )

    return {
        "alert_id": alert_id,
        "message": "Alert deleted. Audit history preserved.",
    }

@app.get("/alerts/{alert_id}/audit")
def alert_audit_history(alert_id: str):
    events = get_audit_events(alert_id)
    return {
        "alert_id": alert_id,
        "count": len(events),
        "events": events,
    }


@app.post("/triage")
def triage(alert: TriageRequest):
    score, severity, reasons = calculate_risk(alert)

    recommended_actions = [
        "Review authentication logs and confirm the activity source.",
        "Check the source IP against trusted network records and approved threat-intelligence sources.",
        "Preserve relevant logs and have an analyst validate the findings.",
    ]

    if alert.successful_login_after_failures:
        recommended_actions.insert(
            0,
            "Verify the successful login, account owner, and surrounding events.",
        )

    if alert.privileged_account:
        recommended_actions.insert(
            0,
            "Prioritize review of privileged-account activity.",
        )

    result = {
        "alert_id": alert.alert_id or str(uuid4()),
        "alert_name": alert.alert_name,
        "severity": severity,
        "risk_score": score,
        "source_ip": alert.source_ip,
        "username": alert.username,
        "reasons": reasons,
        "recommended_actions": recommended_actions,
        "analyst_review_required": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "failed_logins": alert.failed_logins,
        "successful_login_after_failures": alert.successful_login_after_failures,
        "privileged_account": alert.privileged_account,
        "evidence": alert.evidence,
    }

    if alert.alert_id:
        if not update_alert_analysis(alert.alert_id, result):
            raise HTTPException(
                status_code=404,
                detail="Selected alert not found.",
            )
    else:
        save_alert(result)

    return result
