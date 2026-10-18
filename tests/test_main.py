import pytest
from fastapi.testclient import TestClient

import app.database as database
from app.main import app


@pytest.fixture(autouse=True)
def isolated_database(tmp_path, monkeypatch):
    """Give every test its own temporary SQLite database."""
    monkeypatch.setattr(
        database,
        "DB_PATH",
        tmp_path / "test_alerts.db",
    )
    database.init_db()


@pytest.fixture
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_health(client):
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_suspicious_login_alert(client):
    response = client.post(
        "/triage",
        json={
            "alert_name": "SSH Login Investigation",
            "source_ip": "192.0.2.25",
            "username": "testuser",
            "failed_logins": 8,
            "successful_login_after_failures": True,
            "privileged_account": False,
            "evidence": ["Simulated authentication events"],
        },
    )

    assert response.status_code == 200
    result = response.json()
    assert result["risk_score"] == 60
    assert result["severity"] == "high"
    assert result["analyst_review_required"] is True

    queue = client.get("/alerts").json()
    assert queue["count"] == 1


def test_invalid_negative_login_count(client):
    response = client.post(
        "/triage",
        json={
            "alert_name": "Invalid Test",
            "failed_logins": -1,
        },
    )

    assert response.status_code == 422
    assert client.get("/alerts").json()["count"] == 0


def test_update_existing_alert_does_not_create_duplicate(client):
    created = client.post(
        "/triage",
        json={
            "alert_name": "SSH Lab Alert",
            "failed_logins": 5,
        },
    )
    assert created.status_code == 200
    original = created.json()
    alert_id = original["alert_id"]

    updated = client.post(
        "/triage",
        json={
            "alert_id": alert_id,
            "alert_name": "SSH Lab Alert - Updated",
            "failed_logins": 10,
            "successful_login_after_failures": True,
        },
    )

    assert updated.status_code == 200
    result = updated.json()
    assert result["alert_id"] == alert_id
    assert result["alert_name"] == "SSH Lab Alert - Updated"
    assert result["risk_score"] == 70

    queue = client.get("/alerts").json()
    assert queue["count"] == 1
    assert queue["alerts"][0]["alert_id"] == alert_id


def test_updating_alert_preserves_analyst_status(client):
    created = client.post(
        "/triage",
        json={
            "alert_name": "Status Preservation Test",
            "failed_logins": 5,
        },
    )
    alert_id = created.json()["alert_id"]

    status_response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "Investigating"},
    )
    assert status_response.status_code == 200

    updated = client.post(
        "/triage",
        json={
            "alert_id": alert_id,
            "alert_name": "Status Preservation Test Updated",
            "failed_logins": 8,
        },
    )
    assert updated.status_code == 200

    queue = client.get("/alerts").json()
    assert queue["count"] == 1
    assert queue["alerts"][0]["status"] == "Investigating"


def test_unknown_alert_id_does_not_create_new_alert(client):
    response = client.post(
        "/triage",
        json={
            "alert_id": "does-not-exist",
            "alert_name": "Should Not Be Saved",
            "failed_logins": 5,
        },
    )

    assert response.status_code == 404
    assert client.get("/alerts").json()["count"] == 0


@pytest.mark.parametrize(
    "status",
    ["New", "Investigating", "Resolved"],
)
def test_valid_alert_statuses(client, status):
    created = client.post(
        "/triage",
        json={"alert_name": "Status Test"},
    )
    alert_id = created.json()["alert_id"]

    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": status},
    )

    assert response.status_code == 200
    assert response.json()["status"] == status

    queue = client.get("/alerts").json()
    assert queue["alerts"][0]["status"] == status


def test_invalid_alert_status_is_rejected(client):
    created = client.post(
        "/triage",
        json={"alert_name": "Invalid Status Test"},
    )
    alert_id = created.json()["alert_id"]

    response = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "Malicious"},
    )

    assert response.status_code == 422


def test_blank_alert_name_is_rejected(client):
    response = client.post(
        "/triage",
        json={"alert_name": "   "},
    )

    assert response.status_code == 422
    assert client.get("/alerts").json()["count"] == 0


def test_oversized_alert_name_is_rejected(client):
    response = client.post(
        "/triage",
        json={"alert_name": "A" * 201},
    )

    assert response.status_code == 422
    assert client.get("/alerts").json()["count"] == 0


def test_invalid_source_ip_is_rejected(client):
    response = client.post(
        "/triage",
        json={
            "alert_name": "Invalid IP Test",
            "source_ip": "999.999.999.999",
        },
    )

    assert response.status_code == 422
    assert client.get("/alerts").json()["count"] == 0


def test_oversized_evidence_item_is_rejected(client):
    response = client.post(
        "/triage",
        json={
            "alert_name": "Evidence Validation Test",
            "evidence": ["X" * 1001],
        },
    )

    assert response.status_code == 422
    assert client.get("/alerts").json()["count"] == 0


def test_too_many_evidence_items_are_rejected(client):
    response = client.post(
        "/triage",
        json={
            "alert_name": "Evidence Count Test",
            "evidence": ["Test evidence"] * 51,
        },
    )

    assert response.status_code == 422
    assert client.get("/alerts").json()["count"] == 0


def test_new_alert_creates_audit_event(client):
    response = client.post(
        "/triage",
        json={"alert_name": "Audit Test Alert", "failed_logins": 5},
    )
    assert response.status_code == 200
    alert_id = response.json()["alert_id"]

    audit = client.get(f"/alerts/{alert_id}/audit")
    assert audit.status_code == 200
    body = audit.json()
    assert body["count"] == 1
    assert body["events"][0]["action"] == "alert_saved"
    assert body["events"][0]["details"]["alert_name"] == "Audit Test Alert"


def test_status_change_is_audited(client):
    created = client.post(
        "/triage",
        json={"alert_name": "Status Audit Test"},
    )
    alert_id = created.json()["alert_id"]

    changed = client.patch(
        f"/alerts/{alert_id}/status",
        json={"status": "Investigating"},
    )
    assert changed.status_code == 200

    audit = client.get(f"/alerts/{alert_id}/audit").json()
    status_events = [
        event for event in audit["events"]
        if event["action"] == "status_changed"
    ]

    assert len(status_events) == 1
    assert status_events[0]["details"] == {
        "old_status": "New",
        "new_status": "Investigating",
    }


def test_reanalysis_is_audited(client):
    created = client.post(
        "/triage",
        json={"alert_name": "Reanalysis Audit Test", "failed_logins": 3},
    )
    alert_id = created.json()["alert_id"]

    updated = client.post(
        "/triage",
        json={
            "alert_id": alert_id,
            "alert_name": "Reanalysis Audit Test",
            "failed_logins": 10,
        },
    )
    assert updated.status_code == 200

    audit = client.get(f"/alerts/{alert_id}/audit").json()
    assert any(
        event["action"] == "alert_reanalyzed"
        and event["details"]["new_risk_score"] == 40
        for event in audit["events"]
    )
