import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_endpoint():
    response = client.get("/api/v1/tickets/health")
    assert response.status_code == 200
    assert response.json()["status"] == "UP"


def test_login_endpoint_success():
    response = client.post(
        "/api/auth/login",
        json={"email": "alex.devops@enterprise.com", "password": "password123"}
    )
    assert response.status_code == 200
    token = response.json()["access_token"]
    assert token is not None and len(token) > 0


def test_login_endpoint_invalid_password():
    response = client.post(
        "/api/auth/login",
        json={"email": "alex.devops@enterprise.com", "password": "wrongpassword"}
    )
    assert response.status_code == 401


def test_submit_ticket_unauthorized_missing_header():
    response = client.post(
        "/api/v1/tickets",
        json={
            "ticketId": "TCK-UNAUTH-001",
            "userEmail": "unknown@external.com",
            "rawTicketText": "Restart web-prod-01"
        }
    )
    assert response.status_code == 403


def test_submit_ticket_unregistered_user_blocked():
    response = client.post(
        "/api/v1/tickets",
        headers={"X-User-Email": "unknown.attacker@external-domain.com"},
        json={
            "ticketId": "TCK-UNAUTH-003",
            "userEmail": "unknown.attacker@external-domain.com",
            "rawTicketText": "Please restart db-prod-01 database connection pool immediately."
        }
    )
    assert response.status_code == 403


def test_submit_ticket_authorized_user_success():
    response = client.post(
        "/api/v1/tickets",
        headers={"X-User-Email": "alex.devops@enterprise.com"},
        json={
            "ticketId": "TCK-AUTH-001",
            "userEmail": "alex.devops@enterprise.com",
            "rawTicketText": "CRITICAL OUTAGE: payment-service on web-prod-01 is down."
        }
    )
    assert response.status_code == 200
    data = response.json()
    assert data["finalStatus"] == "RESOLVED"
    assert data["stageResults"]["standard_security"] == "PASSED"


def test_logout_endpoint_success():
    login_resp = client.post(
        "/api/auth/login",
        json={"email": "alex.devops@enterprise.com", "password": "password123"}
    )
    assert login_resp.status_code == 200
    token = login_resp.json()["access_token"]

    logout_resp = client.post(
        "/api/auth/logout",
        headers={"Authorization": f"Bearer {token}"}
    )
    assert logout_resp.status_code == 200
    data = logout_resp.json()
    assert data["status"] == "SUCCESS"
    assert data["subject_id"] == "alex.devops@enterprise.com"

