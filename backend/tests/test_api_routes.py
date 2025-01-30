import pytest
import pytest_asyncio
from fastapi.testclient import TestClient
from datetime import datetime, UTC
from unittest.mock import patch, Mock, AsyncMock
from src.api.report_routes import router as report_router
from src.api.trend_routes import router as trend_router
from fastapi import FastAPI

@pytest_asyncio.fixture
async def client():
    """Create test client"""
    app = FastAPI()
    app.include_router(report_router)
    app.include_router(trend_router)
    
    with patch('src.services.risk_analyzer.RiskAnalyzer') as mock_risk_analyzer, \
         patch('src.services.compliance_checker.ComplianceChecker') as mock_compliance_checker:
        
        # Mock risk analyzer
        mock_risk_analyzer.return_value.calculate_risk_score = AsyncMock(return_value={
            'overall_score': 75.0,
            'risk_factors': [{
                'name': 'Test Factor',
                'impact': 7.5,
                'likelihood': 8.0,
                'description': 'Test description'
            }],
            'timestamp': datetime.now(UTC).isoformat()
        })
        
        mock_risk_analyzer.return_value.analyze_security_findings = AsyncMock(return_value=[{
            'finding_id': 'test-finding',
            'severity': 8.0,
            'finding_type': 'Test Finding',
            'resource_type': 'Test Resource',
            'description': 'Test Description',
            'created_at': datetime.now(UTC).isoformat()
        }])
        
        mock_risk_analyzer.return_value.get_risk_trends = AsyncMock(return_value=[{
            'timestamp': datetime.now(UTC).isoformat(),
            'risk_score': 75.0
        }])
        
        # Mock compliance checker
        mock_compliance_checker.return_value.get_overall_compliance = AsyncMock(return_value={
            'standards': [{
                'name': 'CIS AWS Foundations Benchmark',
                'status': True,
                'passing_controls': 45,
                'total_controls': 50,
                'failed_controls': []
            }],
            'overall_compliance_score': 90.0
        })
        
        yield TestClient(app)

@pytest.mark.asyncio
async def test_get_security_report(client):
    """Test security report generation endpoint"""
    response = client.get("/api/reports/security")
    assert response.status_code == 200
    data = response.json()
    
    assert "overview" in data
    assert "compliance" in data
    assert "risks" in data
    assert "recommendations" in data
    assert data["overview"]["risk_score"] > 0
    assert data["overview"]["compliance_score"] > 0

@pytest.mark.asyncio
async def test_get_compliance_report(client):
    """Test compliance report generation endpoint"""
    response = client.get("/api/reports/compliance")
    assert response.status_code == 200
    data = response.json()
    
    assert "standards" in data
    assert "overall_score" in data
    assert isinstance(data["overall_score"], float)
    assert 0 <= data["overall_score"] <= 100

@pytest.mark.asyncio
async def test_get_risk_trends(client):
    """Test risk trends endpoint"""
    response = client.get("/api/trends/risk?days=7")
    assert response.status_code == 200
    data = response.json()
    
    assert "trends" in data
    assert len(data["trends"]) > 0
    assert all(isinstance(point["risk_score"], float) for point in data["trends"])
    assert all(0 <= point["risk_score"] <= 100 for point in data["trends"])

@pytest.mark.asyncio
async def test_get_compliance_trends(client):
    """Test compliance trends endpoint"""
    response = client.get("/api/trends/compliance")
    assert response.status_code == 200
    data = response.json()
    
    assert "cis_compliance" in data
    assert "pci_compliance" in data
    assert "overall_compliance" in data
    
    for standard in ["cis_compliance", "pci_compliance", "overall_compliance"]:
        assert len(data[standard]) > 0
        assert all(0 <= point["score"] <= 100 for point in data[standard])

@pytest.mark.asyncio
async def test_export_report(client):
    """Test report export endpoint"""
    # Test JSON format (default)
    response = client.get("/api/reports/export")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/json"
    data = response.json()
    assert "security" in data
    assert "compliance" in data
    assert "generated_at" in data
    
    # Test CSV format
    response = client.get("/api/reports/export?format=csv")
    assert response.status_code == 200
    assert response.headers["content-type"] == "text/csv"
    assert "attachment; filename=security_report_" in response.headers["content-disposition"]
    
    # Test invalid format
    response = client.get("/api/reports/export?format=invalid")
    assert response.status_code == 400
    data = response.json()
    assert "detail" in data
    assert "Unsupported export format" in data["detail"]
