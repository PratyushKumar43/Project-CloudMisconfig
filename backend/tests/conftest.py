import pytest
from unittest.mock import Mock, patch
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from src.database.database import Base
from src.database.config import get_database_settings

settings = get_database_settings()

# Create test database engine
test_engine = create_engine(settings.TEST_DATABASE_URL)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)

@pytest.fixture(scope="session")
def db_engine():
    Base.metadata.create_all(bind=test_engine)
    yield test_engine
    Base.metadata.drop_all(bind=test_engine)

@pytest.fixture
def db_session(db_engine):
    connection = db_engine.connect()
    transaction = connection.begin()
    session = TestingSessionLocal(bind=connection)
    
    yield session
    
    session.close()
    transaction.rollback()
    connection.close()

@pytest.fixture(autouse=True)
def mock_aws_environment():
    """Global fixture to mock AWS environment for all tests"""
    with patch('boto3.client') as mock_client:
        mock_client.return_value = Mock()
        yield mock_client

@pytest.fixture
def mock_aws_responses():
    """Fixture providing common AWS API response structures"""
    return {
        'ec2_instances': {
            'Reservations': [{
                'Instances': [{
                    'InstanceId': 'i-1234567890abcdef0',
                    'SecurityGroups': [{'GroupId': 'sg-1234567890'}],
                    'Tags': [{'Key': 'Name', 'Value': 'test-instance'}]
                }]
            }]
        },
        's3_buckets': {
            'Buckets': [{
                'Name': 'test-bucket',
                'CreationDate': '2023-01-01'
            }]
        },
        'iam_users': {
            'Users': [{
                'UserName': 'test-user',
                'CreateDate': '2023-01-01'
            }]
        }
    }

@pytest.fixture
def mock_aws_errors():
    """Fixture providing common AWS API error responses"""
    return {
        'access_denied': {
            'Error': {
                'Code': 'AccessDenied',
                'Message': 'Access Denied'
            }
        },
        'not_found': {
            'Error': {
                'Code': 'ResourceNotFoundException',
                'Message': 'Resource not found'
            }
        },
        'throttling': {
            'Error': {
                'Code': 'ThrottlingException',
                'Message': 'Rate exceeded'
            }
        }
    }
