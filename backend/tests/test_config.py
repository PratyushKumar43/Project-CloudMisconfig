import pytest
from unittest.mock import Mock, patch
from src.config.aws_config import AWSConfig
from botocore.exceptions import ClientError

@pytest.fixture
def aws_config():
    """Fixture for creating an AWSConfig instance"""
    with patch('boto3.Session') as mock_session:
        mock_session.return_value.region_name = 'us-east-1'
        mock_ec2 = Mock()
        mock_ec2.describe_regions.return_value = {'Regions': [{'RegionName': 'us-east-1'}]}
        mock_session.return_value.client.return_value = mock_ec2
        
        config = AWSConfig()
        yield config

def test_aws_config_initialization(aws_config):
    """Test AWS config initialization"""
    assert aws_config.region_name == 'us-east-1'
    assert aws_config.profile_name is None

def test_client_creation():
    """Test client creation"""
    with patch('boto3.Session') as mock_session:
        mock_session.return_value.region_name = 'us-east-1'
        mock_ec2 = Mock()
        mock_ec2.describe_regions.return_value = {'Regions': [{'RegionName': 'us-east-1'}]}
        mock_session.return_value.client.return_value = mock_ec2
        
        config = AWSConfig()
        client = config.create_client('s3')
        assert client is not None

def test_invalid_service():
    """Test invalid service name"""
    with patch('boto3.Session') as mock_session:
        mock_session.return_value.region_name = 'us-east-1'
        mock_session.return_value.client.side_effect = Exception('Invalid service')
        
        with pytest.raises(Exception, match='Invalid service'):
            AWSConfig()

def test_region_validation():
    """Test region validation"""
    with patch('boto3.Session') as mock_session:
        mock_session.return_value.region_name = 'us-east-1'
        mock_ec2 = Mock()
        mock_ec2.describe_regions.return_value = {'Regions': [{'RegionName': 'us-east-1'}]}
        mock_session.return_value.client.return_value = mock_ec2
        
        config = AWSConfig()
        assert config.region_name == 'us-east-1'

def test_credentials_validation():
    """Test successful credentials validation"""
    with patch('boto3.Session') as mock_session:
        # Mock EC2 for region validation
        mock_ec2 = Mock()
        mock_ec2.describe_regions.return_value = {'Regions': [{'RegionName': 'us-east-1'}]}
        
        # Mock STS for credentials validation
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {
            'Account': '123456789012',
            'Arn': 'arn:aws:iam::123456789012:user/test',
            'UserId': 'AIDAJQABLZS4A3QDU576Q'
        }
        
        def get_client(service_name, **kwargs):
            if service_name == 'ec2':
                return mock_ec2
            elif service_name == 'sts':
                return mock_sts
            return Mock()
        
        mock_session.return_value.client.side_effect = get_client
        mock_session.return_value.region_name = 'us-east-1'
        
        config = AWSConfig()
        assert config.validate_credentials() is True

def test_failed_credentials_validation():
    """Test failed credentials validation"""
    with patch('boto3.Session') as mock_session:
        # Mock EC2 for region validation
        mock_ec2 = Mock()
        mock_ec2.describe_regions.return_value = {'Regions': [{'RegionName': 'us-east-1'}]}
        
        # Mock STS for credentials validation
        mock_sts = Mock()
        mock_sts.get_caller_identity.side_effect = ClientError(
            error_response={'Error': {'Code': 'InvalidClientTokenId', 'Message': 'Invalid credentials'}},
            operation_name='GetCallerIdentity'
        )
        
        def get_client(service_name, **kwargs):
            if service_name == 'ec2':
                return mock_ec2
            elif service_name == 'sts':
                return mock_sts
            return Mock()
        
        mock_session.return_value.client.side_effect = get_client
        mock_session.return_value.region_name = 'us-east-1'
        
        config = AWSConfig()
        assert config.validate_credentials() is False
