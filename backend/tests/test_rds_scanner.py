import pytest
import pytest_asyncio
from unittest.mock import Mock, patch
from src.services.rds_scanner import RDSScanner
from src.models.schemas import SecurityCheckResult, ResourceType, SeverityLevel

@pytest_asyncio.fixture
async def rds_scanner():
    """Create RDS Scanner instance for testing"""
    with patch('boto3.Session') as mock_session:
        mock_rds = Mock()
        mock_rds.describe_db_instances.return_value = {
            'DBInstances': [{
                'DBInstanceIdentifier': 'test-db',
                'Engine': 'mysql',
                'DBInstanceStatus': 'available',
                'StorageEncrypted': True,
                'PubliclyAccessible': False,
                'BackupRetentionPeriod': 7
            }]
        }
        
        mock_session.return_value.client.return_value = mock_rds
        scanner = RDSScanner()
        scanner.rds = mock_rds
        return scanner

@pytest.mark.asyncio
async def test_scan_rds_instances(rds_scanner):
    """Test scanning RDS instances"""
    results = await rds_scanner.scan_rds_instances()
    assert len(results) > 0
    
    # Convert results to list if it's not already
    results_list = list(results)
    
    # Verify encryption check
    encryption_checks = [r for r in results_list if 'ENCRYPTION' in r.check_id]
    assert len(encryption_checks) > 0
    assert encryption_checks[0].status is True
    
    # Verify public access check
    public_access_checks = [r for r in results_list if 'PUBLIC_ACCESS' in r.check_id]
    assert len(public_access_checks) > 0
    assert public_access_checks[0].status is True
    
    # Verify backup retention check
    backup_checks = [r for r in results_list if 'BACKUP_RETENTION' in r.check_id]
    assert len(backup_checks) > 0
    assert backup_checks[0].status is True
