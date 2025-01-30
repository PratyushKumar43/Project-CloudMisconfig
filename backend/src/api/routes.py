from fastapi import APIRouter, WebSocket, WebSocketDisconnect, HTTPException, Depends
from sqlalchemy.orm import Session
from datetime import datetime
from typing import List, Dict, Any
from src.database.database import get_db
from src.database.models import ScanResult, SecurityFinding, ComplianceResult, RiskTrend
from src.api.transformers import transform_overview, transform_service_data, transform_trends
import logging
import json

# Configure logging
logger = logging.getLogger(__name__)

router = APIRouter()
websocket_connections: List[WebSocket] = []

@router.websocket("/ws/scan-updates")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    websocket_connections.append(websocket)
    try:
        while True:
            # Wait for any messages (can be used for client requests)
            data = await websocket.receive_text()
            # Echo back for now
            await websocket.send_text(f"Message received: {data}")
    except WebSocketDisconnect:
        websocket_connections.remove(websocket)

async def broadcast_scan_update(data: dict):
    """Broadcast updates to all connected clients"""
    for connection in websocket_connections:
        try:
            await connection.send_text(json.dumps(data))
        except:
            websocket_connections.remove(connection)

@router.get("/overview")
def get_service_overview(db: Session = Depends(get_db)):
    """Get overview of all AWS services and their security status"""
    try:
        scan_results = db.query(ScanResult).all()
        findings = db.query(SecurityFinding).all()
        return transform_overview(scan_results, findings)
    except Exception as e:
        logger.error(f"Error in get_service_overview: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/trends/compliance")
def get_compliance_trends(db: Session = Depends(get_db)):
    """Get compliance trends over time"""
    try:
        trends = db.query(RiskTrend).order_by(RiskTrend.timestamp.desc()).limit(7).all()
        return transform_trends(trends)
    except Exception as e:
        logger.error(f"Error in get_compliance_trends: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/services/{service}")
def get_service_data(service: str, db: Session = Depends(get_db)):
    """Get detailed data for a specific service"""
    try:
        service = service.upper()
        if service not in ["EC2", "S3", "RDS", "IAM"]:
            raise HTTPException(status_code=400, detail=f"Invalid service: {service}")
            
        scans = db.query(ScanResult).filter(ScanResult.service_type == service).all()
        if not scans:
            return {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "resources": []
            }
            
        findings = []
        for scan in scans:
            scan_findings = db.query(SecurityFinding).filter(SecurityFinding.scan_id == scan.id).all()
            findings.extend(scan_findings)
            
        return transform_service_data(scans, findings)
    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Error in get_service_data for {service}: {str(e)}", exc_info=True)
        raise HTTPException(status_code=500, detail=str(e))

@router.get("/overview-new")
def get_overview_new(db: Session = Depends(get_db)):
    # Get total resources
    total_resources = db.query(ScanResult).count()
    
    # Get issues by severity
    findings = db.query(SecurityFinding).all()
    critical_issues = sum(1 for f in findings if f.severity == "CRITICAL")
    high_issues = sum(1 for f in findings if f.severity == "HIGH")
    medium_issues = sum(1 for f in findings if f.severity == "MEDIUM")
    low_issues = sum(1 for f in findings if f.severity == "LOW")
    
    # Calculate compliance score (simplified)
    total_issues = critical_issues + high_issues + medium_issues + low_issues
    if total_issues == 0:
        compliance_score = 100.0
    else:
        weighted_sum = (critical_issues * 1.0 + 
                       high_issues * 0.7 + 
                       medium_issues * 0.4 + 
                       low_issues * 0.1)
        compliance_score = max(0, 100 - (weighted_sum / total_resources) * 100)
    
    return {
        "totalResources": total_resources,
        "criticalIssues": critical_issues,
        "highIssues": high_issues,
        "mediumIssues": medium_issues,
        "lowIssues": low_issues,
        "complianceScore": round(compliance_score, 1)
    }
