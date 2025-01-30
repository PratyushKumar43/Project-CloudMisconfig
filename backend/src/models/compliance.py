from typing import List
from pydantic import BaseModel
from datetime import datetime

class ComplianceStandard(BaseModel):
    name: str
    status: bool
    passing_controls: int
    total_controls: int
    failed_controls: List[str]
    timestamp: datetime

class ComplianceStatus(BaseModel):
    standards: List[ComplianceStandard]
    overall_compliance_score: float
