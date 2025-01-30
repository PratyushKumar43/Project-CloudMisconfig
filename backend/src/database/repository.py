from typing import List, Optional, Dict, Any
from datetime import datetime, timedelta
from sqlalchemy.orm import Session
from sqlalchemy import desc, func
from . import models

class DatabaseRepository:
    def __init__(self, db: Session):
        self.db = db

    async def store_scan_result(self, scan_result: Dict[str, Any]) -> models.ScanResult:
        db_scan = models.ScanResult(**scan_result)
        self.db.add(db_scan)
        self.db.commit()
        self.db.refresh(db_scan)
        return db_scan

    async def store_security_finding(self, finding: Dict[str, Any]) -> models.SecurityFinding:
        db_finding = models.SecurityFinding(**finding)
        self.db.add(db_finding)
        self.db.commit()
        self.db.refresh(db_finding)
        return db_finding

    async def store_compliance_result(self, compliance: Dict[str, Any]) -> models.ComplianceResult:
        db_compliance = models.ComplianceResult(**compliance)
        self.db.add(db_compliance)
        self.db.commit()
        self.db.refresh(db_compliance)
        return db_compliance

    async def store_risk_trend(self, risk_trend: Dict[str, Any]) -> models.RiskTrend:
        db_risk = models.RiskTrend(**risk_trend)
        self.db.add(db_risk)
        self.db.commit()
        self.db.refresh(db_risk)
        return db_risk

    async def get_recent_scans(self, limit: int = 10) -> List[models.ScanResult]:
        return self.db.query(models.ScanResult)\
            .order_by(desc(models.ScanResult.created_at))\
            .limit(limit)\
            .all()

    async def get_findings_by_scan(self, scan_id: str) -> List[models.SecurityFinding]:
        return self.db.query(models.SecurityFinding)\
            .filter(models.SecurityFinding.scan_id == scan_id)\
            .all()

    async def get_compliance_by_scan(self, scan_id: str) -> List[models.ComplianceResult]:
        return self.db.query(models.ComplianceResult)\
            .filter(models.ComplianceResult.scan_id == scan_id)\
            .all()

    async def get_risk_trends(self, service_type: str, days: int = 30) -> List[models.RiskTrend]:
        cutoff_date = datetime.utcnow() - timedelta(days=days)
        return self.db.query(models.RiskTrend)\
            .filter(models.RiskTrend.service_type == service_type)\
            .filter(models.RiskTrend.timestamp >= cutoff_date)\
            .all()

    async def get_service_statistics(self, service_type: str) -> Dict[str, Any]:
        stats = self.db.query(
            func.count(models.ScanResult.id).label('total_scans'),
            func.avg(models.ScanResult.security_score).label('average_score')
        ).filter(models.ScanResult.service_type == service_type).first()

        return {
            'total_scans': stats.total_scans if stats else 0,
            'average_score': float(stats.average_score) if stats and stats.average_score else 0
        }

    async def get_compliance_summary(self) -> Dict[str, Any]:
        results = self.db.query(
            models.ComplianceResult.standard_type,
            models.ComplianceResult.compliance_status,
            func.count(models.ComplianceResult.id).label('count')
        ).group_by(
            models.ComplianceResult.standard_type,
            models.ComplianceResult.compliance_status
        ).all()

        summary = {}
        for r in results:
            if r.standard_type not in summary:
                summary[r.standard_type] = {'total': 0, 'compliant': 0}
            summary[r.standard_type]['total'] += r.count
            if r.compliance_status:
                summary[r.standard_type]['compliant'] += r.count

        return summary
