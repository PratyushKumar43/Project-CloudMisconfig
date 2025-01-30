import pytest
import pytest_asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta, timezone
from src.services.risk_analyzer import RiskAnalyzer
from src.models.risk_score import RiskScore, SecurityFinding

@pytest_asyncio.fixture
async def risk_analyzer():
    """Create RiskAnalyzer instance for testing"""
    with patch('boto3.Session') as mock_session:
        # Mock GuardDuty
        mock_guardduty = Mock()
        mock_guardduty.list_detectors.return_value = {
            'DetectorIds': ['test-detector']
        }
        mock_guardduty.list_findings.return_value = {
            'FindingIds': ['finding1', 'finding2']
        }
        mock_guardduty.get_findings.return_value = {
            'Findings': [{
                'Id': 'finding1',
                'Severity': 8.0,
                'Type': 'UnauthorizedAccess:EC2/SSHBruteForce',
                'Resource': {'ResourceType': 'Instance'},
                'Description': 'Test finding',
                'CreatedAt': datetime.now(timezone.utc).isoformat()
            }]
        }
        
        # Mock CloudWatch
        mock_cloudwatch = Mock()
        mock_cloudwatch.get_metric_data.return_value = {
            'MetricDataResults': [{
                'Values': [75.0, 80.0, 85.0],
                'Timestamps': [
                    (datetime.now(timezone.utc) - timedelta(days=2)).isoformat(),
                    (datetime.now(timezone.utc) - timedelta(days=1)).isoformat(),
                    datetime.now(timezone.utc).isoformat()
                ]
            }]
        }
        
        def get_client(service_name, **kwargs):
            if service_name == 'guardduty':
                return mock_guardduty
            elif service_name == 'cloudwatch':
                return mock_cloudwatch
            return Mock()
        
        mock_session.return_value.client.side_effect = get_client
        analyzer = RiskAnalyzer()
        analyzer.guardduty = mock_guardduty
        analyzer.cloudwatch = mock_cloudwatch
        return analyzer

@pytest.mark.asyncio
async def test_calculate_risk_score(risk_analyzer):
    """Test risk score calculation"""
    risk_score = await risk_analyzer.calculate_risk_score()
    assert isinstance(risk_score, RiskScore)
    assert risk_score.overall_score > 0
    assert len(risk_score.risk_factors) > 0

@pytest.mark.asyncio
async def test_analyze_security_findings(risk_analyzer):
    """Test security findings analysis"""
    findings = await risk_analyzer.analyze_security_findings()
    assert len(findings) > 0
    
    finding = findings[0]
    assert isinstance(finding, SecurityFinding)
    assert finding.severity == 8.0  # Match the mock data
    assert finding.finding_type == 'UnauthorizedAccess:EC2/SSHBruteForce'
    assert finding.resource_type == 'Instance'

@pytest.mark.asyncio
async def test_get_risk_trends(risk_analyzer):
    """Test risk trend analysis"""
    trends = await risk_analyzer.get_risk_trends(days=7)
    assert len(trends) > 0
    
    # Verify trend data points
    for point in trends:
        assert isinstance(point.timestamp, str)
        assert isinstance(point.risk_score, float)
        assert 0 <= point.risk_score <= 100
