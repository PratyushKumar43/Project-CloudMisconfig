import pytest
from datetime import datetime
from src.database.repository import DatabaseRepository
from src.database import models

@pytest.fixture
def db_repo(db_session):
    return DatabaseRepository(db_session)

@pytest.mark.asyncio
async def test_store_scan_result(db_repo):
    scan_data = {
        "service_type": "EC2",
        "resource_id": "i-1234567890",
        "configuration": {"instance_type": "t2.micro", "state": "running"},
        "security_score": 85
    }
    result = await db_repo.store_scan_result(scan_data)
    assert result.service_type == "EC2"
    assert result.resource_id == "i-1234567890"
    assert result.security_score == 85
    return result

@pytest.mark.asyncio
async def test_store_security_finding(db_repo):
    scan_result = await test_store_scan_result(db_repo)
    finding_data = {
        "scan_id": scan_result.id,
        "severity": "HIGH",
        "finding_type": "OPEN_PORT",
        "description": "Port 22 is open to 0.0.0.0/0",
        "remediation_steps": "Restrict SSH access to known IP ranges"
    }
    result = await db_repo.store_security_finding(finding_data)
    assert result.severity == "HIGH"
    assert result.finding_type == "OPEN_PORT"

@pytest.mark.asyncio
async def test_store_compliance_result(db_repo):
    scan_result = await test_store_scan_result(db_repo)
    compliance_data = {
        "scan_id": scan_result.id,
        "standard_type": "CIS",
        "compliance_status": False,
        "findings": {"failed_checks": ["1.1", "1.2"], "passed_checks": ["2.1"]}
    }
    result = await db_repo.store_compliance_result(compliance_data)
    assert result.standard_type == "CIS"
    assert result.compliance_status is False

@pytest.mark.asyncio
async def test_store_risk_trend(db_repo):
    risk_data = {
        "service_type": "EC2",
        "risk_score": 75,
        "affected_resources": 5,
        "trend_data": {"previous_score": 80, "trend": "decreasing"}
    }
    result = await db_repo.store_risk_trend(risk_data)
    assert result.service_type == "EC2"
    assert result.risk_score == 75

@pytest.mark.asyncio
async def test_get_recent_scans(db_repo):
    # First store some scan results
    for i in range(3):
        scan_data = {
            "service_type": f"EC2-{i}",
            "resource_id": f"i-{i}",
            "configuration": {"test": "data"},
            "security_score": 85+i
        }
        await db_repo.store_scan_result(scan_data)
    
    results = await db_repo.get_recent_scans(limit=2)
    assert len(results) <= 2
    assert all(isinstance(r.id, str) for r in results)

@pytest.mark.asyncio
async def test_get_service_statistics(db_repo):
    # First store a scan result
    await test_store_scan_result(db_repo)
    
    stats = await db_repo.get_service_statistics("EC2")
    assert isinstance(stats, dict)
    assert "total_scans" in stats
    assert "average_score" in stats
    assert stats["total_scans"] > 0
    assert stats["average_score"] > 0

@pytest.mark.asyncio
async def test_get_compliance_summary(db_repo):
    # First store a compliance result
    await test_store_compliance_result(db_repo)
    
    summary = await db_repo.get_compliance_summary()
    assert isinstance(summary, dict)
    assert "CIS" in summary
    assert summary["CIS"]["total"] > 0
