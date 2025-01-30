from datetime import datetime
import uuid
from sqlalchemy import Column, String, Integer, Boolean, DateTime, JSON, ForeignKey
from sqlalchemy.dialects.sqlite import JSON as SQLiteJSON
from sqlalchemy.orm import relationship
from .database import Base

def generate_uuid():
    return str(uuid.uuid4())

class ScanResult(Base):
    __tablename__ = "scan_results"

    id = Column(String, primary_key=True, default=generate_uuid)
    scan_timestamp = Column(DateTime, default=datetime.utcnow)
    service_type = Column(String, nullable=False)
    resource_id = Column(String, nullable=False)
    configuration = Column(SQLiteJSON)
    security_score = Column(Integer)
    created_at = Column(DateTime, default=datetime.utcnow)

    security_findings = relationship("SecurityFinding", back_populates="scan_result")
    compliance_results = relationship("ComplianceResult", back_populates="scan_result")

class SecurityFinding(Base):
    __tablename__ = "security_findings"

    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scan_results.id"))
    severity = Column(String, nullable=False)
    finding_type = Column(String, nullable=False)
    description = Column(String)
    remediation_steps = Column(String)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_result = relationship("ScanResult", back_populates="security_findings")

class ComplianceResult(Base):
    __tablename__ = "compliance_results"

    id = Column(String, primary_key=True, default=generate_uuid)
    scan_id = Column(String, ForeignKey("scan_results.id"))
    standard_type = Column(String, nullable=False)
    compliance_status = Column(Boolean)
    findings = Column(SQLiteJSON)
    created_at = Column(DateTime, default=datetime.utcnow)

    scan_result = relationship("ScanResult", back_populates="compliance_results")

class RiskTrend(Base):
    __tablename__ = "risk_trends"

    id = Column(String, primary_key=True, default=generate_uuid)
    timestamp = Column(DateTime, default=datetime.utcnow)
    service_type = Column(String, nullable=False)
    risk_score = Column(Integer)
    affected_resources = Column(Integer)
    trend_data = Column(SQLiteJSON)
