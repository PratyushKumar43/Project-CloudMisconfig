import boto3
from typing import List
import uuid
from datetime import datetime, timezone
from ..models.schemas import SecurityCheckResult, ResourceType, SeverityLevel

class RDSScanner:
    def __init__(self):
        self.session = boto3.Session()
        self.rds = self.session.client('rds')

    async def scan_rds_instances(self) -> List[SecurityCheckResult]:
        """Scan RDS instances for security issues"""
        try:
            results = []
            instances = self.rds.describe_db_instances()
            
            for instance in instances['DBInstances']:
                # Check encryption
                results.append(SecurityCheckResult(
                    check_id=f"RDS_ENCRYPTION_{str(uuid.uuid4())}",
                    resource_id=instance['DBInstanceIdentifier'],
                    resource_type=ResourceType.RDS,
                    severity=SeverityLevel.HIGH,
                    description=f"RDS instance {instance['DBInstanceIdentifier']} encryption check",
                    status=instance.get('StorageEncrypted', False),
                    details={'EncryptionEnabled': instance.get('StorageEncrypted', False)},
                    remediation="Enable encryption for the RDS instance"
                ))
                
                # Check public accessibility
                results.append(SecurityCheckResult(
                    check_id=f"RDS_PUBLIC_ACCESS_{str(uuid.uuid4())}",
                    resource_id=instance['DBInstanceIdentifier'],
                    resource_type=ResourceType.RDS,
                    severity=SeverityLevel.HIGH,
                    description=f"RDS instance {instance['DBInstanceIdentifier']} public accessibility check",
                    status=not instance.get('PubliclyAccessible', True),
                    details={'PubliclyAccessible': instance.get('PubliclyAccessible', True)},
                    remediation="Disable public accessibility for the RDS instance"
                ))
                
                # Check backup retention
                backup_retention = instance.get('BackupRetentionPeriod', 0)
                results.append(SecurityCheckResult(
                    check_id=f"RDS_BACKUP_RETENTION_{str(uuid.uuid4())}",
                    resource_id=instance['DBInstanceIdentifier'],
                    resource_type=ResourceType.RDS,
                    severity=SeverityLevel.MEDIUM,
                    description=f"RDS instance {instance['DBInstanceIdentifier']} backup retention check",
                    status=backup_retention >= 7,
                    details={'BackupRetentionPeriod': backup_retention},
                    remediation="Set backup retention period to at least 7 days"
                ))
            
            return results
            
        except Exception as e:
            print(f"Error scanning RDS instances: {str(e)}")
            return []
