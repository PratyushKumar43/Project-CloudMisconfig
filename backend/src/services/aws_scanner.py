from datetime import datetime
from typing import List, Dict, Optional, Any
from src.models.schemas import (
    ServiceOverview, ServiceStatus, VulnerabilityReport,
    Vulnerability, ComplianceStatus, ComplianceStandard, SeverityLevel,
    ResourceType, SecurityCheckResult, ResourceSummary
)
from src.config.aws_config import aws_config
import asyncio
import uuid
from botocore.exceptions import ClientError

class AWSScanner:
    def __init__(self):
        # Initialize AWS clients using the config
        self.ec2 = aws_config.create_client('ec2')
        self.s3 = aws_config.create_client('s3')
        self.rds = aws_config.create_client('rds')
        self.cloudwatch = aws_config.create_client('cloudwatch')
        self.iam = aws_config.create_client('iam')
        self.config = aws_config.create_client('config')
        self.lambda_client = aws_config.create_client('lambda')
        self.kms = aws_config.create_client('kms')
        self.cloudtrail = aws_config.create_client('cloudtrail')
        self.region = aws_config.region_name

    def scan_ec2_instances(self) -> List[Dict[str, Any]]:
        """Scan EC2 instances for security issues"""
        try:
            instances = []
            paginator = self.ec2.get_paginator('describe_instances')
            
            for page in paginator.paginate():
                for reservation in page['Reservations']:
                    for instance in reservation['Instances']:
                        # Check for security issues
                        security_issues = []
                        
                        # Check for public IP
                        if instance.get('PublicIpAddress'):
                            security_issues.append({
                                'issue': 'Public IP assigned',
                                'severity': 'HIGH',
                                'recommendation': 'Consider using private IP unless public access is required'
                            })
                        
                        # Check for unencrypted volumes
                        for volume in instance.get('BlockDeviceMappings', []):
                            if not volume.get('Ebs', {}).get('Encrypted', False):
                                security_issues.append({
                                    'issue': 'Unencrypted EBS volume',
                                    'severity': 'HIGH',
                                    'recommendation': 'Enable EBS encryption'
                                })
                        
                        instance['SecurityIssues'] = security_issues
                        instances.append(instance)
            
            return instances
        except Exception as e:
            print(f"Error scanning EC2 instances: {str(e)}")
            raise

    def scan_s3_buckets(self) -> List[Dict[str, Any]]:
        """Scan S3 buckets for security issues"""
        try:
            buckets = []
            response = self.s3.list_buckets()
            
            for bucket in response['Buckets']:
                bucket_name = bucket['Name']
                security_issues = []
                
                # Check bucket policy
                try:
                    policy = self.s3.get_bucket_policy(Bucket=bucket_name)
                    if '"Effect": "Allow"' in policy['Policy']:
                        security_issues.append({
                            'issue': 'Potentially permissive bucket policy',
                            'severity': 'HIGH',
                            'recommendation': 'Review bucket policy for overly permissive settings'
                        })
                except ClientError as e:
                    if e.response['Error']['Code'] != 'NoSuchBucketPolicy':
                        raise
                
                # Check encryption
                try:
                    encryption = self.s3.get_bucket_encryption(Bucket=bucket_name)
                except ClientError as e:
                    if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                        security_issues.append({
                            'issue': 'Bucket encryption not enabled',
                            'severity': 'HIGH',
                            'recommendation': 'Enable default encryption for the bucket'
                        })
                
                # Check public access
                try:
                    public_access = self.s3.get_public_access_block(Bucket=bucket_name)
                    if not all(public_access['PublicAccessBlockConfiguration'].values()):
                        security_issues.append({
                            'issue': 'Public access not fully blocked',
                            'severity': 'HIGH',
                            'recommendation': 'Enable all public access block settings'
                        })
                except ClientError:
                    security_issues.append({
                        'issue': 'Public access block not configured',
                        'severity': 'HIGH',
                        'recommendation': 'Configure public access block settings'
                    })
                
                bucket['SecurityIssues'] = security_issues
                buckets.append(bucket)
            
            return buckets
        except Exception as e:
            print(f"Error scanning S3 buckets: {str(e)}")
            raise

    def scan_iam_users(self) -> List[Dict[str, Any]]:
        """Scan IAM users for security issues"""
        try:
            users = []
            paginator = self.iam.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page['Users']:
                    security_issues = []
                    
                    # Check MFA
                    mfa_devices = self.iam.list_mfa_devices(UserName=user['UserName'])
                    if not mfa_devices['MFADevices']:
                        security_issues.append({
                            'issue': 'MFA not enabled',
                            'severity': 'HIGH',
                            'recommendation': 'Enable MFA for the user'
                        })
                    
                    # Check access keys
                    access_keys = self.iam.list_access_keys(UserName=user['UserName'])
                    for key in access_keys['AccessKeyMetadata']:
                        if key['Status'] == 'Active':
                            # Check key age
                            key_age = (datetime.now() - key['CreateDate'].replace(tzinfo=None)).days
                            if key_age > 90:
                                security_issues.append({
                                    'issue': f'Access key {key["AccessKeyId"]} is {key_age} days old',
                                    'severity': 'MEDIUM',
                                    'recommendation': 'Rotate access keys regularly'
                                })
                    
                    user['SecurityIssues'] = security_issues
                    users.append(user)
            
            return users
        except Exception as e:
            print(f"Error scanning IAM users: {str(e)}")
            raise

    def scan_security_groups(self) -> List[Dict[str, Any]]:
        """Scan security groups for security issues"""
        try:
            security_groups = []
            paginator = self.ec2.get_paginator('describe_security_groups')
            
            for page in paginator.paginate():
                for sg in page['SecurityGroups']:
                    security_issues = []
                    
                    # Check inbound rules
                    for rule in sg.get('IpPermissions', []):
                        # Check for open ports
                        for ip_range in rule.get('IpRanges', []):
                            if ip_range.get('CidrIp') == '0.0.0.0/0':
                                port_range = f"port {rule.get('FromPort')} to {rule.get('ToPort')}"
                                security_issues.append({
                                    'issue': f'Open to internet on {port_range}',
                                    'severity': 'HIGH',
                                    'recommendation': 'Restrict access to specific IP ranges'
                                })
                    
                    sg['SecurityIssues'] = security_issues
                    security_groups.append(sg)
            
            return security_groups
        except Exception as e:
            print(f"Error scanning security groups: {str(e)}")
            raise

    def scan_rds_instances(self) -> List[Dict[str, Any]]:
        """Scan RDS instances for security issues"""
        try:
            instances = []
            paginator = self.rds.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for instance in page['DBInstances']:
                    security_issues = []
                    
                    # Check encryption
                    if not instance.get('StorageEncrypted'):
                        security_issues.append({
                            'issue': 'Storage not encrypted',
                            'severity': 'HIGH',
                            'recommendation': 'Enable storage encryption'
                        })
                    
                    # Check public accessibility
                    if instance.get('PubliclyAccessible'):
                        security_issues.append({
                            'issue': 'Database is publicly accessible',
                            'severity': 'HIGH',
                            'recommendation': 'Disable public accessibility unless required'
                        })
                    
                    instance['SecurityIssues'] = security_issues
                    instances.append(instance)
            
            return instances
        except Exception as e:
            print(f"Error scanning RDS instances: {str(e)}")
            raise

    async def get_service_overview(self) -> ServiceOverview:
        """Get comprehensive overview of all AWS services security status"""
        try:
            # Run all scans concurrently
            ec2_task = asyncio.create_task(self._async_wrapper(self.scan_ec2_instances))
            s3_task = asyncio.create_task(self._async_wrapper(self.scan_s3_buckets))
            iam_task = asyncio.create_task(self._async_wrapper(self.scan_iam_users))
            sg_task = asyncio.create_task(self._async_wrapper(self.scan_security_groups))
            rds_task = asyncio.create_task(self._async_wrapper(self.scan_rds_instances))
            
            # Wait for all scans to complete
            results = await asyncio.gather(
                ec2_task, s3_task, iam_task, sg_task, rds_task,
                return_exceptions=True
            )
            
            # Process results
            overview = ServiceOverview(
                compute_services=self._process_service_results(results[0], "EC2"),
                storage_services=self._process_service_results(results[1], "S3"),
                iam_services=self._process_service_results(results[2], "IAM"),
                network_services=self._process_service_results(results[3], "Security Groups"),
                database_services=self._process_service_results(results[4], "RDS"),
                last_scan_time=datetime.now().isoformat()
            )
            
            return overview
        except Exception as e:
            print(f"Error getting service overview: {str(e)}")
            raise

    async def get_service_status(self) -> Dict[str, Any]:
        """Get current status of all AWS services"""
        try:
            # Get service data
            ec2_instances = self.scan_ec2_instances()
            s3_buckets = self.scan_s3_buckets()
            rds_instances = self.scan_rds_instances()
            iam_users = self.scan_iam_users()

            # Calculate severity counts for each service
            def count_severity(items):
                critical = sum(1 for item in items for issue in item.get('SecurityIssues', []) if issue['severity'] == 'CRITICAL')
                high = sum(1 for item in items for issue in item.get('SecurityIssues', []) if issue['severity'] == 'HIGH')
                medium = sum(1 for item in items for issue in item.get('SecurityIssues', []) if issue['severity'] == 'MEDIUM')
                low = sum(1 for item in items for issue in item.get('SecurityIssues', []) if issue['severity'] == 'LOW')
                return critical, high, medium, low

            ec2_critical, ec2_high, ec2_medium, ec2_low = count_severity(ec2_instances)
            s3_critical, s3_high, s3_medium, s3_low = count_severity(s3_buckets)
            rds_critical, rds_high, rds_medium, rds_low = count_severity(rds_instances)
            iam_critical, iam_high, iam_medium, iam_low = count_severity(iam_users)

            # Calculate total counts
            total_critical = ec2_critical + s3_critical + rds_critical + iam_critical
            total_high = ec2_high + s3_high + rds_high + iam_high
            total_medium = ec2_medium + s3_medium + rds_medium + iam_medium
            total_low = ec2_low + s3_low + rds_low + iam_low
            total_resources = len(ec2_instances) + len(s3_buckets) + len(rds_instances) + len(iam_users)

            # Calculate compliance score (0-100)
            max_score = 100
            deductions = {
                'CRITICAL': 25,  # Each critical issue reduces score by 25
                'HIGH': 15,      # Each high issue reduces score by 15
                'MEDIUM': 10,    # Each medium issue reduces score by 10
                'LOW': 5         # Each low issue reduces score by 5
            }
            
            total_deduction = (
                total_critical * deductions['CRITICAL'] +
                total_high * deductions['HIGH'] +
                total_medium * deductions['MEDIUM'] +
                total_low * deductions['LOW']
            )
            
            compliance_score = max(0, max_score - total_deduction)
            compliance_score = min(100, compliance_score)  # Cap at 100

            return {
                "type": "scan_update",
                "timestamp": datetime.utcnow().isoformat(),
                "overview": {
                    "totalResources": total_resources,
                    "criticalIssues": total_critical,
                    "highIssues": total_high,
                    "mediumIssues": total_medium,
                    "lowIssues": total_low,
                    "complianceScore": round(compliance_score, 2)
                },
                "services": {
                    "ec2": {
                        "total": len(ec2_instances),
                        "critical": ec2_critical,
                        "high": ec2_high,
                        "medium": ec2_medium,
                        "low": ec2_low,
                        "instances": ec2_instances
                    },
                    "s3": {
                        "total": len(s3_buckets),
                        "critical": s3_critical,
                        "high": s3_high,
                        "medium": s3_medium,
                        "low": s3_low,
                        "buckets": s3_buckets
                    },
                    "rds": {
                        "total": len(rds_instances),
                        "critical": rds_critical,
                        "high": rds_high,
                        "medium": rds_medium,
                        "low": rds_low,
                        "instances": rds_instances
                    },
                    "iam": {
                        "total": len(iam_users),
                        "critical": iam_critical,
                        "high": iam_high,
                        "medium": iam_medium,
                        "low": iam_low,
                        "users": iam_users
                    }
                }
            }
        except Exception as e:
            return {
                "type": "error",
                "message": f"Error getting service status: {str(e)}"
            }

    async def _async_wrapper(self, func):
        """Wrapper to run synchronous functions asynchronously"""
        return await asyncio.get_event_loop().run_in_executor(None, func)

    def _process_service_results(self, results: List[Dict[str, Any]], service_name: str) -> ServiceStatus:
        """Process scan results into a ServiceStatus object"""
        if isinstance(results, Exception):
            return ServiceStatus(
                name=service_name,
                score=0,
                total=100,
                issues_count=1,
                checks_performed=[SecurityCheckResult(
                    check_id=str(uuid.uuid4()),
                    resource_id="N/A",
                    resource_type=ResourceType.UNKNOWN,
                    severity=SeverityLevel.HIGH,
                    description=f"Error scanning {service_name}: {str(results)}",
                    status=False,
                    details={},
                    remediation="Check AWS permissions and try again"
                )]
            )
        
        issues = []
        for resource in results:
            for issue in resource.get('SecurityIssues', []):
                issues.append(SecurityCheckResult(
                    check_id=str(uuid.uuid4()),
                    resource_id=resource.get('Id', resource.get('Name', 'Unknown')),
                    resource_type=ResourceType[service_name.upper().replace(" ", "_")],
                    severity=SeverityLevel[issue['severity']],
                    description=issue['issue'],
                    status=False,
                    details=resource,
                    remediation=issue['recommendation']
                ))
        
        # Calculate score based on issues
        total_checks = max(len(results), 1)
        failed_checks = len(issues)
        score = int(((total_checks - failed_checks) / total_checks) * 100)
        
        return ServiceStatus(
            name=service_name,
            score=score,
            total=100,
            issues_count=failed_checks,
            checks_performed=issues
        )
