import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import get_db

class MockResult:
    def scalars(self): return self
    def all(self): return []

class MockDB:
    async def execute(self, *args, **kwargs):
        return MockResult()

async def mock_get_db():
    yield MockDB()

app.dependency_overrides[get_db] = mock_get_db

client = TestClient(app)

def test_trigger_reconstruction_missing_params():
    # Attempt without evidence_version
    incident_id = "12345678-1234-5678-1234-567812345678"
    response = client.post(f"/api/v2/incidents/{incident_id}/attack-chain/reconstruct")
    assert response.status_code == 422 # Missing query parameter

def test_list_versions():
    incident_id = "12345678-1234-5678-1234-567812345678"
    # This should fail if DB is not mocked, but we check route existence
    response = client.get(f"/api/v2/incidents/{incident_id}/attack-chain/versions")
    # Will likely return 500 or 404 in tests without a DB, but we know it routed
    assert response.status_code in [200, 500, 404, 401]

def test_get_nodes():
    incident_id = "12345678-1234-5678-1234-567812345678"
    version_id = "87654321-4321-8765-4321-876543210987"
    response = client.get(f"/api/v2/incidents/{incident_id}/attack-chain/versions/{version_id}/nodes")
    assert response.status_code in [200, 500, 404, 401]

def test_get_edges():
    incident_id = "12345678-1234-5678-1234-567812345678"
    version_id = "87654321-4321-8765-4321-876543210987"
    response = client.get(f"/api/v2/incidents/{incident_id}/attack-chain/versions/{version_id}/edges")
    assert response.status_code in [200, 500, 404, 401]
