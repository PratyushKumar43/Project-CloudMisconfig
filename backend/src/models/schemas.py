from enum import Enum
from pydantic import BaseModel
from typing import List, Dict, Optional
from datetime import datetime

class SeverityLevel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"

class ResourceType(str, Enum):
    UNKNOWN = "UNKNOWN"
    EC2 = "EC2"
    S3 = "S3"
    RDS = "RDS"
    IAM = "IAM"
    LAMBDA = "LAMBDA"
    CLOUDWATCH = "CLOUDWATCH"
    VPC = "VPC"
    SECURITY_GROUP = "SECURITY_GROUP"
    KMS = "KMS"
    CLOUDTRAIL = "CLOUDTRAIL"

class SecurityCheckResult(BaseModel):
    check_id: str
    resource_id: str
    resource_type: ResourceType
    severity: SeverityLevel
    description: str
    status: bool
    details: Dict
    remediation: str

class ServiceStatus(BaseModel):
    name: str
    score: int
    total: int
    issues_count: int
    checks_performed: Optional[List[SecurityCheckResult]] = []

class ServiceOverview(BaseModel):
    compute_services: ServiceStatus
    storage_services: ServiceStatus
    database_services: ServiceStatus
    network_services: ServiceStatus
    iam_services: ServiceStatus
    serverless_services: Optional[ServiceStatus] = None
    security_services: Optional[ServiceStatus] = None
    monitoring_services: Optional[ServiceStatus] = None
    last_scan_time: str

class Vulnerability(BaseModel):
    id: str
    title: str
    resource_id: str
    resource_type: ResourceType
    severity: SeverityLevel
    description: str
    impact: str
    remediation: str
    detection_time: datetime

class VulnerabilityReport(BaseModel):
    total_count: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    vulnerabilities: List[Vulnerability]

class ComplianceStandard(BaseModel):
    name: str
    status: bool
    passing_controls: int
    total_controls: int
    failed_controls: List[str]

class ComplianceStatus(BaseModel):
    standards: List[ComplianceStandard]
    overall_compliance_score: float

class SecurityGroup(BaseModel):
    id: str
    name: str
    vpc_id: str
    inbound_rules: List[Dict]
    outbound_rules: List[Dict]
    instances: List[str]

class IAMUserSummary(BaseModel):
    username: str
    access_keys_active: int
    mfa_enabled: bool
    groups: List[str]
    policies: List[str]
    password_last_used: Optional[str]

class KMSKeySummary(BaseModel):
    key_id: str
    alias: str
    state: str
    rotation_enabled: bool
    managed_by: str

class CloudTrailStatus(BaseModel):
    name: str
    is_logging: bool
    multi_region: bool
    log_file_validation: bool
    kms_encrypted: bool

class ResourceSummary(BaseModel):
    ec2_instances: List[Dict]
    s3_buckets: List[Dict]
    rds_instances: List[Dict]
    lambda_functions: List[Dict]
    security_groups: List[SecurityGroup]
    iam_users: List[IAMUserSummary]
    kms_keys: List[KMSKeySummary]
    cloudtrail_trails: List[CloudTrailStatus]
