import boto3
from botocore.exceptions import ClientError
from typing import Dict, Optional, List

class AWSConfig:
    def __init__(self, profile_name: Optional[str] = None):
        """Initialize AWS configuration"""
        self.profile_name = profile_name
        self.session = boto3.Session(profile_name=profile_name)
        self.region_name = self.session.region_name or 'us-east-1'
        self.account_id = None
        self._validate_region()

    def create_client(self, service_name: str):
        """Create a boto3 client for the specified service"""
        try:
            return self.session.client(service_name, region_name=self.region_name)
        except Exception as e:
            print(f"Error creating {service_name} client: {str(e)}")
            raise

    def validate_credentials(self) -> bool:
        """Validate AWS credentials"""
        try:
            sts = self.create_client('sts')
            response = sts.get_caller_identity()
            self.account_id = response['Account']
            print(f"Successfully initialized AWS session for account {self.account_id} in region {self.region_name}")
            return True
        except ClientError as e:
            error_code = e.response['Error']['Code']
            if error_code in ['InvalidClientTokenId', 'AccessDenied']:
                print(f"Invalid AWS credentials: {str(e)}")
                return False
            raise
        except Exception as e:
            print(f"Error validating credentials: {str(e)}")
            return False

    def _validate_region(self):
        """Validate AWS region"""
        try:
            ec2 = self.create_client('ec2')
            ec2.describe_regions()
        except Exception as e:
            print(f"Error validating region: {str(e)}")
            raise

    def get_available_regions(self, service: str) -> List[str]:
        """Get available regions for a service"""
        try:
            session = boto3.Session()
            return session.get_available_regions(service)
        except Exception as e:
            print(f"Error getting available regions: {str(e)}")
            return []

    @property
    def credentials(self) -> Dict:
        """Get AWS credentials"""
        try:
            creds = self.session.get_credentials()
            return {
                'access_key': creds.access_key,
                'secret_key': '********',  # Masked for security
                'profile': self.profile_name,
                'region': self.region_name,
                'account_id': self.account_id
            }
        except Exception as e:
            print(f"Error getting credentials: {str(e)}")
            return {}

# Create a singleton instance
aws_config = AWSConfig()
