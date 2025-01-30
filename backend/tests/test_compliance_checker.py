import pytest
import boto3
from datetime import datetime, timedelta
from src.services.compliance_checker import ComplianceChecker
from src.models.compliance import ComplianceStandard, ComplianceStatus

@pytest.fixture
def compliance_checker():
    """Fixture for creating a ComplianceChecker instance with real AWS credentials"""
    return ComplianceChecker()

def test_security_hub_access(compliance_checker):
    """Test actual Security Hub access and functionality"""
    try:
        # Test Security Hub findings retrieval
        findings = compliance_checker.securityhub.get_findings(
            Filters={
                'RecordState': [{'Value': 'ACTIVE', 'Comparison': 'EQUALS'}],
                'UpdatedAt': [{
                    'Start': (datetime.now() - timedelta(days=30)).isoformat(),
                    'End': datetime.now().isoformat()
                }]
            },
            MaxResults=1
        )
        assert 'Findings' in findings
        print(f"Successfully retrieved Security Hub findings: {len(findings.get('Findings', []))} findings found")
        
    except Exception as e:
        pytest.fail(f"Failed to access Security Hub: {str(e)}")

def test_get_compliance_findings(compliance_checker):
    """Test getting actual compliance findings"""
    try:
        findings = compliance_checker.get_compliance_findings()
        assert isinstance(findings, list)
        print(f"Retrieved {len(findings)} compliance findings")
        
        # Verify finding structure
        if findings:
            finding = findings[0]
            assert 'Id' in finding
            assert 'Title' in finding
            assert 'Severity' in finding
            print(f"Sample finding: {finding['Title']} (Severity: {finding['Severity']['Label']})")
            
    except Exception as e:
        pytest.fail(f"Failed to get compliance findings: {str(e)}")

def test_get_security_score(compliance_checker):
    """Test getting actual security score"""
    try:
        score = compliance_checker.get_security_score()
        assert isinstance(score, (int, float))
        assert 0 <= score <= 100
        print(f"Current security score: {score}")
        
    except Exception as e:
        pytest.fail(f"Failed to get security score: {str(e)}")

@pytest.mark.asyncio
async def test_check_cis_compliance(compliance_checker):
    """Test CIS compliance checking"""
    results = await compliance_checker.check_cis_compliance()
    assert isinstance(results, ComplianceStandard)
    assert results.name == "CIS AWS Foundations Benchmark"
    assert results.status is True
    assert results.passing_controls > 0

@pytest.mark.asyncio
async def test_check_pci_compliance(compliance_checker):
    """Test PCI DSS compliance checking"""
    results = await compliance_checker.check_pci_compliance()
    assert isinstance(results, ComplianceStandard)
    assert results.name == "PCI DSS"
    assert isinstance(results.passing_controls, int)
    assert isinstance(results.total_controls, int)

@pytest.mark.asyncio
async def test_get_overall_compliance(compliance_checker):
    """Test overall compliance status"""
    status = await compliance_checker.get_overall_compliance()
    assert isinstance(status, ComplianceStatus)
    assert isinstance(status.overall_compliance_score, float)
    assert 0 <= status.overall_compliance_score <= 100
    assert len(status.standards) > 0
