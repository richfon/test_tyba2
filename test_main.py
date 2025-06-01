"""
test_main.py - Automated tests for FastAPI REST API in main.py

this tests are based on the last nodes made on the .ipynb since they were theorical
"""
import pytest
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

def test_register_and_login():
    # Register user
    response = client.post("/register", data={"username": "testuser", "password": "testpass"})
    assert response.status_code == 200

    # Duplicate registration
    response = client.post("/register", data={"username": "testuser", "password": "testpass"})
    assert response.status_code == 400

    # Login
    response = client.post("/token", data={"username": "testuser", "password": "testpass"})
    assert response.status_code == 200
    token = response.json()["access_token"]

    # Login with wrong password
    response = client.post("/token", data={"username": "testuser", "password": "wrongpass"})
    assert response.status_code == 400

    return token

def test_protected_endpoints():
    # No token
    response = client.get("/restaurants")
    assert response.status_code == 401

    # With token
    token = test_register_and_login()
    headers = {"Authorization": f"Bearer {token}"}
    response = client.get("/restaurants?city=London", headers=headers)
    assert response.status_code in [200, 404]  # 404 if city not found

def test_restaurants_and_transactions():
    token = test_register_and_login()
    headers = {"Authorization": f"Bearer {token}"}

    # Valid city
    response = client.get("/restaurants?city=London", headers=headers)
    assert response.status_code in [200, 404]  # 404 if city not found
    if response.status_code == 200:
        assert isinstance(response.json(), list)

    # Invalid city
    response = client.get("/restaurants?city=InvalidCityName", headers=headers)
    assert response.status_code == 404

    # Missing params
    response = client.get("/restaurants", headers=headers)
    assert response.status_code == 400

    # Transactions
    response = client.get("/transactions", headers=headers)
    assert response.status_code == 200
    assert isinstance(response.json(), list)

def test_logout():
    response = client.post("/logout")
    assert response.status_code == 200
    assert "Logout successful" in response.json()["msg"]
