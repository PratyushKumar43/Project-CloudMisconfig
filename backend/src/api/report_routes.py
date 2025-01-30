from fastapi import APIRouter, HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
from datetime import datetime, UTC
import json
import csv
import io
from typing import Any
from ..services.risk_analyzer import RiskAnalyzer
from ..services.compliance_checker import ComplianceChecker

class DateTimeEncoder(json.JSONEncoder):
    def default(self, obj: Any) -> Any:
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)

router = APIRouter(prefix="/api/reports")

@router.get("/security")
async def get_security_report():
    """Generate security report"""
    try:
        risk_analyzer = RiskAnalyzer()
        compliance_checker = ComplianceChecker()
        
        # Get risk score and findings
        risk_score = await risk_analyzer.calculate_risk_score()
        security_findings = await risk_analyzer.analyze_security_findings()
        compliance_status = await compliance_checker.get_overall_compliance()
        
        return {
            "overview": {
                "risk_score": risk_score.overall_score,
                "compliance_score": compliance_status.overall_compliance_score,
                "total_findings": len(security_findings),
                "timestamp": datetime.now(UTC)
            },
            "compliance": {
                "standards": [s.model_dump() for s in compliance_status.standards],
                "overall_score": compliance_status.overall_compliance_score
            },
            "risks": {
                "score": risk_score.model_dump(),
                "findings": [f.model_dump() for f in security_findings]
            },
            "recommendations": [
                finding.remediation for finding in security_findings if finding.severity >= 7.0
            ]
        }
    except Exception as e:
        print(f"Error generating security report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/compliance")
async def get_compliance_report():
    """Generate compliance report"""
    try:
        checker = ComplianceChecker()
        compliance_status = await checker.get_overall_compliance()
        
        return {
            "standards": [s.model_dump() for s in compliance_status.standards],
            "overall_score": compliance_status.overall_compliance_score
        }
    except Exception as e:
        print(f"Error generating compliance report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/export")
async def export_report(format: str = "json"):
    """Export security and compliance report"""
    # Validate format first
    if format.lower() not in ["json", "csv"]:
        raise HTTPException(status_code=400, detail="Unsupported export format. Use 'json' or 'csv'.")
        
    try:
        # Get report data
        security_report = await get_security_report()
        compliance_report = await get_compliance_report()
        
        report_data = {
            "security": security_report,
            "compliance": compliance_report,
            "generated_at": datetime.now(UTC)
        }
        
        if format.lower() == "json":
            # Use custom encoder for datetime objects
            return JSONResponse(
                content=json.loads(
                    json.dumps(report_data, cls=DateTimeEncoder)
                )
            )
        else:  # format is "csv"
            # Create CSV file in memory
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write headers
            writer.writerow(["Report Type", "Category", "Metric", "Value"])
            
            # Write security data
            writer.writerow(["Security", "Overview", "Risk Score", security_report["overview"]["risk_score"]])
            writer.writerow(["Security", "Overview", "Compliance Score", security_report["overview"]["compliance_score"]])
            writer.writerow(["Security", "Overview", "Total Findings", security_report["overview"]["total_findings"]])
            
            # Write findings
            for finding in security_report["risks"]["findings"]:
                writer.writerow([
                    "Security",
                    "Finding",
                    finding["finding_type"],
                    f"Severity: {finding['severity']}"
                ])
            
            # Write compliance data
            for standard in compliance_report["standards"]:
                writer.writerow([
                    "Compliance",
                    "Standard",
                    standard["name"],
                    f"{standard['passing_controls']}/{standard['total_controls']} controls passing"
                ])
            
            # Prepare the response
            output.seek(0)
            return StreamingResponse(
                iter([output.getvalue()]),
                media_type="text/csv; charset=utf-8",
                headers={
                    "Content-Disposition": f"attachment; filename=security_report_{datetime.now(UTC).strftime('%Y%m%d_%H%M%S')}.csv",
                    "Content-Type": "text/csv"
                }
            )
            
    except HTTPException:
        raise
    except Exception as e:
        print(f"Error exporting report: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))
