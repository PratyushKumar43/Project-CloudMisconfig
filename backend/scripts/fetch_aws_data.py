import sys
import os
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import boto3
from src.database.database import SessionLocal, engine
from src.database.models import Base, ScanResult, SecurityFinding, ComplianceResult, RiskTrend
import json
import uuid
from datetime import datetime

def generate_uuid():
    return str(uuid.uuid4())

def check_ec2_security(ec2_client, instance):
    findings = []
    security_score = 100

    # Check for public IP
    if instance.get('PublicIpAddress'):
        security_score -= 20
        findings.append({
            "severity": "HIGH",
            "finding_type": "PUBLIC_IP",
            "description": f"Instance {instance['InstanceId']} has a public IP address",
            "remediation_steps": "Consider using private subnets with NAT Gateway"
        })

    # Check security groups
    for sg in instance['SecurityGroups']:
        sg_id = sg['GroupId']
        sg_info = ec2_client.describe_security_groups(GroupIds=[sg_id])['SecurityGroups'][0]
        
        # Check for open ports
        for permission in sg_info['IpPermissions']:
            for ip_range in permission.get('IpRanges', []):
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    security_score -= 15
                    findings.append({
                        "severity": "HIGH",
                        "finding_type": "OPEN_SECURITY_GROUP",
                        "description": f"Security group {sg_id} has inbound rule open to the world",
                        "remediation_steps": "Restrict security group rules to specific IP ranges"
                    })

    return findings, security_score

def check_s3_security(s3_client, bucket_name):
    findings = []
    security_score = 100

    # Check bucket policy
    try:
        policy = s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_json = json.loads(policy['Policy'])
        # Check for public access in policy
        if any("*" in str(statement) for statement in policy_json.get('Statement', [])):
            security_score -= 30
            findings.append({
                "severity": "HIGH",
                "finding_type": "PUBLIC_ACCESS",
                "description": f"Bucket {bucket_name} has public access in bucket policy",
                "remediation_steps": "Remove public access from bucket policy"
            })
    except s3_client.exceptions.NoSuchBucketPolicy:
        pass

    # Check encryption
    try:
        encryption = s3_client.get_bucket_encryption(Bucket=bucket_name)
        if 'aws:kms' not in str(encryption):
            security_score -= 10
            findings.append({
                "severity": "MEDIUM",
                "finding_type": "ENCRYPTION",
                "description": f"Bucket {bucket_name} not using KMS encryption",
                "remediation_steps": "Enable KMS encryption for the bucket"
            })
    except s3_client.exceptions.ClientError:
        security_score -= 20
        findings.append({
            "severity": "HIGH",
            "finding_type": "NO_ENCRYPTION",
            "description": f"Bucket {bucket_name} does not have default encryption",
            "remediation_steps": "Enable default encryption for the bucket"
        })

    return findings, security_score

def fetch_and_store_aws_data():
    session = boto3.Session()
    ec2_client = session.client('ec2')
    s3_client = session.client('s3')
    
    db = SessionLocal()
    try:
        # Fetch EC2 instances
        instances = ec2_client.describe_instances()
        for reservation in instances['Reservations']:
            for instance in reservation['Instances']:
                findings, security_score = check_ec2_security(ec2_client, instance)
                
                # Store scan result
                scan_result = ScanResult(
                    id=generate_uuid(),
                    service_type="EC2",
                    resource_id=instance['InstanceId'],
                    configuration=json.dumps(instance, default=str),
                    security_score=security_score
                )
                db.add(scan_result)
                db.flush()

                # Store findings
                for finding in findings:
                    security_finding = SecurityFinding(
                        id=generate_uuid(),
                        scan_id=scan_result.id,
                        **finding
                    )
                    db.add(security_finding)

                # Store compliance result
                compliance_result = ComplianceResult(
                    id=generate_uuid(),
                    scan_id=scan_result.id,
                    standard_type="PCI-DSS",
                    compliance_status=security_score >= 80,
                    findings=json.dumps({
                        "requirement": "1.2",
                        "details": "Instance security configuration assessment"
                    })
                )
                db.add(compliance_result)

        # Fetch S3 buckets
        buckets = s3_client.list_buckets()
        for bucket in buckets['Buckets']:
            findings, security_score = check_s3_security(s3_client, bucket['Name'])
            
            # Store scan result
            scan_result = ScanResult(
                id=generate_uuid(),
                service_type="S3",
                resource_id=bucket['Name'],
                configuration=json.dumps(bucket, default=str),
                security_score=security_score
            )
            db.add(scan_result)
            db.flush()

            # Store findings
            for finding in findings:
                security_finding = SecurityFinding(
                    id=generate_uuid(),
                    scan_id=scan_result.id,
                    **finding
                )
                db.add(security_finding)

            # Store compliance result
            compliance_result = ComplianceResult(
                id=generate_uuid(),
                scan_id=scan_result.id,
                standard_type="PCI-DSS",
                compliance_status=security_score >= 80,
                findings=json.dumps({
                    "requirement": "3.4",
                    "details": "Bucket encryption and access control assessment"
                })
            )
            db.add(compliance_result)

        db.commit()
        print("Successfully fetched and stored AWS data!")

    except Exception as e:
        print(f"Error fetching AWS data: {e}")
        db.rollback()
    finally:
        db.close()

if __name__ == "__main__":
    # Ensure tables are created
    Base.metadata.create_all(bind=engine)
    fetch_and_store_aws_data()
