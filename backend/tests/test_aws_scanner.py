import pytest
from unittest.mock import Mock, patch, MagicMock
from src.services.aws_scanner import AWSScanner
from src.config.aws_config import AWSConfig
from botocore.exceptions import ClientError
from datetime import datetime, timedelta

@pytest.fixture
def aws_scanner():
    """Fixture for creating an AWSScanner instance with mocked AWS clients"""
    with patch('src.config.aws_config.AWSConfig.create_client') as mock_create_client:
        # Mock EC2 client
        mock_ec2 = Mock()
        mock_ec2.get_paginator.return_value.paginate.return_value = [{
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'SecurityGroups': [{'GroupId': 'sg-1234567890'}],
                    'Tags': [{'Key': 'Name', 'Value': 'test-instance'}],
                    'PublicIpAddress': '1.2.3.4',
                    'BlockDeviceMappings': [{
                        'Ebs': {'Encrypted': False}
                    }]
                }]
            }]
        }]
        
        # Mock S3 client
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {
            'Buckets': [{
                'Name': 'test-bucket',
                'CreationDate': '2023-01-01'
            }]
        }
        mock_s3.get_bucket_policy.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchBucketPolicy', 'Message': 'No policy'}},
            'GetBucketPolicy'
        )
        mock_s3.get_bucket_encryption.side_effect = ClientError(
            {'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError', 'Message': 'No encryption'}},
            'GetBucketEncryption'
        )
        mock_s3.get_public_access_block.return_value = {
            'PublicAccessBlockConfiguration': {
                'BlockPublicAcls': False,
                'IgnorePublicAcls': False,
                'BlockPublicPolicy': False,
                'RestrictPublicBuckets': False
            }
        }
        
        # Mock IAM client
        mock_iam = Mock()
        mock_iam.get_paginator.return_value.paginate.return_value = [{
            'Users': [{
                'UserName': 'test-user',
                'CreateDate': '2023-01-01'
            }]
        }]
        mock_iam.list_mfa_devices.return_value = {'MFADevices': []}
        mock_iam.list_access_keys.return_value = {
            'AccessKeyMetadata': [{
                'AccessKeyId': 'AKIA1234567890',
                'Status': 'Active',
                'CreateDate': datetime.now() - timedelta(days=100)
            }]
        }
        
        # Configure mock client to return our mocked services
        def mock_client_factory(service_name):
            if service_name == 'ec2':
                return mock_ec2
            elif service_name == 's3':
                return mock_s3
            elif service_name == 'iam':
                return mock_iam
            return Mock()
            
        mock_create_client.side_effect = mock_client_factory
        
        scanner = AWSScanner()
        yield scanner

def test_scan_ec2_instances(aws_scanner):
    """Test EC2 instance scanning functionality"""
    instances = aws_scanner.scan_ec2_instances()
    assert len(instances) == 1
    instance = instances[0]
    assert instance['InstanceId'] == 'i-1234567890abcdef0'
    assert len(instance['SecurityIssues']) == 2  # Public IP and unencrypted volume
    assert any(issue['issue'] == 'Public IP assigned' for issue in instance['SecurityIssues'])
    assert any(issue['issue'] == 'Unencrypted EBS volume' for issue in instance['SecurityIssues'])

def test_scan_s3_buckets(aws_scanner):
    """Test S3 bucket scanning functionality"""
    buckets = aws_scanner.scan_s3_buckets()
    assert len(buckets) == 1
    bucket = buckets[0]
    assert bucket['Name'] == 'test-bucket'
    assert len(bucket['SecurityIssues']) == 2  # No encryption and public access not blocked
    assert any(issue['issue'] == 'Bucket encryption not enabled' for issue in bucket['SecurityIssues'])
    assert any(issue['issue'] == 'Public access not fully blocked' for issue in bucket['SecurityIssues'])

def test_scan_iam_users(aws_scanner):
    """Test IAM user scanning functionality"""
    users = aws_scanner.scan_iam_users()
    assert len(users) == 1
    user = users[0]
    assert user['UserName'] == 'test-user'
    assert len(user['SecurityIssues']) == 2  # No MFA and old access key
    assert any(issue['issue'] == 'MFA not enabled' for issue in user['SecurityIssues'])
    assert any('Access key' in issue['issue'] and 'days old' in issue['issue'] for issue in user['SecurityIssues'])

def test_scan_security_groups(aws_scanner):
    """Test security group scanning functionality"""
    with patch('src.config.aws_config.AWSConfig.create_client') as mock_create_client:
        mock_ec2 = Mock()
        mock_ec2.get_paginator.return_value.paginate.return_value = [{
            'SecurityGroups': [{
                'GroupId': 'sg-1234567890',
                'GroupName': 'test-sg',
                'IpPermissions': [{
                    'FromPort': 22,
                    'ToPort': 22,
                    'IpRanges': [{'CidrIp': '0.0.0.0/0'}]
                }]
            }]
        }]
        mock_create_client.return_value = mock_ec2
        
        scanner = AWSScanner()
        security_groups = scanner.scan_security_groups()
        
        assert len(security_groups) == 1
        sg = security_groups[0]
        assert sg['GroupId'] == 'sg-1234567890'
        assert len(sg['SecurityIssues']) == 1
        assert 'Open to internet on port' in sg['SecurityIssues'][0]['issue']

@pytest.mark.asyncio
async def test_get_service_overview(aws_scanner):
    """Test getting comprehensive service overview"""
    with patch('src.config.aws_config.AWSConfig.create_client') as mock_create_client:
        # Mock EC2 client
        mock_ec2 = Mock()
        mock_ec2.describe_instances.return_value = {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'State': {'Name': 'running'},
                    'SecurityGroups': [{'GroupId': 'sg-1234'}]
                }]
            }]
        }
        
        # Mock S3 client
        mock_s3 = Mock()
        mock_s3.list_buckets.return_value = {
            'Buckets': [{
                'Name': 'test-bucket',
                'CreationDate': '2023-01-01'
            }]
        }
        
        # Mock IAM client
        mock_iam = Mock()
        mock_iam.list_users.return_value = {
            'Users': [{
                'UserName': 'test-user',
                'PasswordLastUsed': '2023-01-01'
            }]
        }
        
        # Configure mock client to return our mocked services
        def mock_client_factory(service_name):
            if service_name == 'ec2':
                return mock_ec2
            elif service_name == 's3':
                return mock_s3
            elif service_name == 'iam':
                return mock_iam
            return Mock()
            
        mock_create_client.side_effect = mock_client_factory
        
        overview = await aws_scanner.get_service_overview()
        assert overview.compute_services.name == "EC2"
        assert overview.storage_services.name == "S3"
        assert overview.iam_services.name == "IAM"
        assert overview.network_services.name == "Security Groups"
        assert overview.database_services.name == "RDS"
        assert isinstance(overview.last_scan_time, str)
