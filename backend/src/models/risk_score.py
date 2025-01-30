from typing import List
from pydantic import BaseModel

class RiskFactor(BaseModel):
    name: str
    impact: float  # 0-10
    likelihood: float  # 0-10
    description: str

class SecurityFinding(BaseModel):
    finding_id: str
    severity: float
    finding_type: str
    resource_type: str
    description: str
    created_at: str

class RiskTrendPoint(BaseModel):
    timestamp: str
    risk_score: float

class RiskScore(BaseModel):
    overall_score: float  # 0-100
    risk_factors: List[RiskFactor]
    timestamp: str
