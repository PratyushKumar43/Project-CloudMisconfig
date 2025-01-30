import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.database.database import SessionLocal, engine
from src.database.models import Base, ScanResult, SecurityFinding, ComplianceResult, RiskTrend
from datetime import datetime
import json
import uuid

def generate_uuid():
    return str(uuid.uuid4())

def create_sample_data():
    db = SessionLocal()
    try:
        # Create sample scan result for EC2
        ec2_scan = ScanResult(
            id=generate_uuid(),
            service_type="EC2",
            resource_id="i-0123456789abcdef0",
            configuration=json.dumps({
                "InstanceType": "t2.micro",
                "SecurityGroups": ["default"],
                "PublicIpEnabled": True
            }),
            security_score=75
        )
        db.add(ec2_scan)
        db.flush()

        # Add security findings for EC2
        ec2_finding = SecurityFinding(
            id=generate_uuid(),
            scan_id=ec2_scan.id,
            severity="HIGH",
            finding_type="SECURITY_GROUP",
            description="Instance has public IP enabled with open security group",
            remediation_steps="Restrict security group rules and use private subnets"
        )
        db.add(ec2_finding)

        # Add compliance result for EC2
        ec2_compliance = ComplianceResult(
            id=generate_uuid(),
            scan_id=ec2_scan.id,
            standard_type="PCI-DSS",
            compliance_status=False,
            findings=json.dumps({
                "requirement": "1.2",
                "details": "Firewall configuration does not meet PCI requirements"
            })
        )
        db.add(ec2_compliance)

        # Create sample scan result for S3
        s3_scan = ScanResult(
            id=generate_uuid(),
            service_type="S3",
            resource_id="my-test-bucket",
            configuration=json.dumps({
                "Versioning": "Enabled",
                "PublicAccess": "Blocked",
                "Encryption": "AES256"
            }),
            security_score=90
        )
        db.add(s3_scan)
        db.flush()

        # Add security findings for S3
        s3_finding = SecurityFinding(
            id=generate_uuid(),
            scan_id=s3_scan.id,
            severity="LOW",
            finding_type="ENCRYPTION",
            description="Server-side encryption using AWS managed keys",
            remediation_steps="Consider using customer managed KMS keys for enhanced security"
        )
        db.add(s3_finding)

        # Add compliance result for S3
        s3_compliance = ComplianceResult(
            id=generate_uuid(),
            scan_id=s3_scan.id,
            standard_type="PCI-DSS",
            compliance_status=True,
            findings=json.dumps({
                "requirement": "3.4",
                "details": "Data encryption meets PCI requirements"
            })
        )
        db.add(s3_compliance)

        # Add risk trends
        risk_trends = [
            RiskTrend(
                service_type="EC2",
                risk_score=75,
                affected_resources=1,
                trend_data=json.dumps({
                    "previous_scores": [80, 78, 75],
                    "trend": "decreasing"
                })
            ),
            RiskTrend(
                service_type="S3",
                risk_score=90,
                affected_resources=1,
                trend_data=json.dumps({
                    "previous_scores": [85, 88, 90],
                    "trend": "improving"
                })
            )
        ]
        for trend in risk_trends:
            db.add(trend)

        db.commit()
        print("Sample data created successfully!")

    except Exception as e:
        print(f"Error creating sample data: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    # Ensure tables are created
    Base.metadata.create_all(bind=engine)
    create_sample_data()
