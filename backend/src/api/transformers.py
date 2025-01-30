from typing import List, Dict, Any
from src.database.models import ScanResult, SecurityFinding, ComplianceResult, RiskTrend
from datetime import datetime
import json

def transform_overview(scan_results: List[ScanResult], findings: List[SecurityFinding]) -> Dict[str, Any]:
    """Transform raw database data into frontend Overview format"""
    total_resources = len(scan_results)
    critical_issues = sum(1 for f in findings if f.severity == 'CRITICAL')
    high_issues = sum(1 for f in findings if f.severity == 'HIGH')
    medium_issues = sum(1 for f in findings if f.severity == 'MEDIUM')
    low_issues = sum(1 for f in findings if f.severity == 'LOW')
    
    # Calculate compliance score
    total_findings = len(findings)
    if total_findings > 0:
        severity_weights = {'CRITICAL': 1.0, 'HIGH': 0.7, 'MEDIUM': 0.4, 'LOW': 0.1}
        weighted_score = sum(severity_weights[f.severity] for f in findings)
        compliance_score = max(0, 100 - (weighted_score * 100 / total_findings))
    else:
        compliance_score = 100

    return {
        "totalResources": total_resources,
        "criticalIssues": critical_issues,
        "highIssues": high_issues,
        "mediumIssues": medium_issues,
        "lowIssues": low_issues,
        "complianceScore": round(compliance_score, 2)
    }

def transform_service_data(
    scans: List[ScanResult], 
    findings: List[SecurityFinding]
) -> Dict[str, Any]:
    """Transform service-specific data into frontend format"""
    total = len(scans)
    critical = sum(1 for f in findings if f.severity == 'CRITICAL')
    high = sum(1 for f in findings if f.severity == 'HIGH')
    medium = sum(1 for f in findings if f.severity == 'MEDIUM')
    low = sum(1 for f in findings if f.severity == 'LOW')
    
    resources = []
    for scan in scans:
        config = json.loads(scan.configuration) if isinstance(scan.configuration, str) else scan.configuration
        scan_findings = [f for f in findings if f.scan_id == scan.id]
        
        resource = {
            "id": scan.resource_id,
            "name": config.get("Name", scan.resource_id),
            "type": scan.service_type,
            "region": config.get("Region", "us-east-1"),
            "status": config.get("State", "unknown"),
            "SecurityIssues": [
                {
                    "issue": f.description,
                    "severity": f.severity,
                    "recommendation": f.remediation_steps
                }
                for f in scan_findings
            ]
        }
        resources.append(resource)

    return {
        "total": total,
        "critical": critical,
        "high": high,
        "medium": medium,
        "low": low,
        "instances" if scans[0].service_type == "EC2" else
        "buckets" if scans[0].service_type == "S3" else
        "users" if scans[0].service_type == "IAM" else
        "databases" if scans[0].service_type == "RDS" else
        "resources": resources
    }

def transform_trends(trends: List[RiskTrend]) -> List[Dict[str, Any]]:
    """Transform risk trends into frontend format"""
    return [
        {
            "date": trend.timestamp.strftime("%Y-%m-%d"),
            "Critical Issues": json.loads(trend.trend_data).get("critical", 0),
            "High Issues": json.loads(trend.trend_data).get("high", 0),
            "Medium Issues": json.loads(trend.trend_data).get("medium", 0),
            "Low Issues": json.loads(trend.trend_data).get("low", 0)
        }
        for trend in trends
    ]
