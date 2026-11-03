import pytest
import threat_service as service
from app import app, _bucket

@pytest.fixture(autouse=True)
def fake_catalog(monkeypatch):
    _bucket.clear()
    monkeypatch.setattr(service,'fetch_catalog',lambda: {'dateReleased':'2026-01-01','vulnerabilities':[{'cveID':'CVE-2024-12345','vendorProject':'Acme','product':'Widget','vulnerabilityName':'Demo issue','dateAdded':'2026-01-01','shortDescription':'Test only','knownRansomwareCampaignUse':'Known'}]})

@pytest.fixture
def client():
    return app.test_client()

def test_invalid_cve(client):
    assert client.get('/api/cve/not-a-cve').status_code==400

def test_read_only(client):
    assert client.post('/api/latest').status_code==405

def test_search(client):
    r=client.get('/api/search?q=Acme')
    assert r.status_code==200 and len(r.json['items'])==1

def test_xss_data_not_html(client):
    r=client.get('/api/search?q=Acme')
    assert r.is_json
    assert 'Content-Security-Policy' in r.headers

def test_limit(client):
    assert client.get('/api/latest?limit=101').status_code==400

def test_rate_limit(client):
    responses=[client.get('/api/health').status_code for _ in range(31)]
    assert responses[:30]==[200]*30
    assert responses[30]==429

def test_no_unbounded_input(client):
    assert client.get('/api/search?q='+'x'*81).status_code==400
