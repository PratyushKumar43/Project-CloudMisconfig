from fastapi import APIRouter, HTTPException
from typing import Dict, Any, List
from ..services.risk_analyzer import RiskAnalyzer
from ..services.compliance_checker import ComplianceChecker

router = APIRouter()

@router.get("/api/trends/risk")
async def get_risk_trends(days: int = 7) -> Dict[str, Any]:
    """Get risk score trends"""
    try:
        analyzer = RiskAnalyzer()
        trends = await analyzer.get_risk_trends(days)
        
        return {
            "trends": [t.dict() for t in trends]
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/api/trends/compliance")
async def get_compliance_trends() -> Dict[str, List[Dict[str, Any]]]:
    """Get compliance trends"""
    try:
        checker = ComplianceChecker()
        
        # Get current compliance status
        compliance_status = await checker.get_overall_compliance()
        
        # Get current timestamp for the data point and format it as ISO string
        current_time = compliance_status.standards[0].timestamp.isoformat() if compliance_status.standards else None
        
        def calculate_score(standard_name: str) -> float:
            for standard in compliance_status.standards:
                if standard.name == standard_name:
                    return (standard.passing_controls / standard.total_controls * 100) if standard.total_controls > 0 else 100.0
            return 100.0  # Default to 100% if standard not found
        
        return {
            "cis_compliance": [{
                "timestamp": current_time,
                "score": calculate_score("CIS AWS Foundations Benchmark")
            }],
            "pci_compliance": [{
                "timestamp": current_time,
                "score": calculate_score("PCI DSS")
            }],
            "overall_compliance": [{
                "timestamp": current_time,
                "score": compliance_status.overall_compliance_score
            }]
        }
    except Exception as e:
        print(f"Error getting compliance trends: {str(e)}")
        raise HTTPException(
            status_code=500,
            detail=f"Failed to get compliance trends: {str(e)}"
        )
