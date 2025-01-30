from fastapi import WebSocket, WebSocketDisconnect, APIRouter
from typing import Dict, List
import json
import asyncio
from datetime import datetime
from src.services.aws_scanner import AWSScanner
import os
import logging
import uuid

logger = logging.getLogger(__name__)

router = APIRouter()  

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, WebSocket] = {}
        self.scan_tasks: Dict[str, asyncio.Task] = {}
        self.aws_scanner = AWSScanner()
        self.scan_interval = int(os.getenv('AWS_SCAN_INTERVAL', '60'))

    async def connect(self, websocket: WebSocket, client_id: str):
        """Connect a new client"""
        self.active_connections[client_id] = websocket
        logger.info(f"Client {client_id} connected. Active connections: {len(self.active_connections)}")

    def disconnect(self, client_id: str):
        """Disconnect a client"""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        if client_id in self.scan_tasks:
            self.scan_tasks[client_id].cancel()
            del self.scan_tasks[client_id]
        logger.info(f"Client {client_id} disconnected. Active connections: {len(self.active_connections)}")

    async def send_message(self, message: dict, client_id: str):
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json(message)
            except Exception as e:
                logger.error(f"Error sending message to client {client_id}: {str(e)}")
                await self.disconnect(client_id)

    async def broadcast(self, message: dict):
        for connection in self.active_connections.values():
            try:
                await connection.send_json(message)
            except Exception as e:
                logger.error(f"Error broadcasting message: {str(e)}")

    async def _send_scan_updates(self, client_id: str):
        """Send periodic scan updates to a specific client"""
        while True:
            try:
                if client_id not in self.active_connections:
                    break

                # Get AWS service status
                service_status = await self.aws_scanner.get_service_status()
                await self.send_message(service_status, client_id)
                
                # Wait for next scan interval
                await asyncio.sleep(self.scan_interval)
                
            except Exception as e:
                logger.error(f"Error in scan update loop for client {client_id}: {str(e)}")
                break

    async def start_scan_updates(self, client_id: str):
        """Start sending periodic scan updates to the client"""
        if client_id in self.scan_tasks:
            self.scan_tasks[client_id].cancel()
        
        self.scan_tasks[client_id] = asyncio.create_task(
            self._send_scan_updates(client_id)
        )

    def calculate_severity_counts(self, resources: List[Dict]):
        critical = high = medium = low = 0
        for resource in resources:
            for issue in resource.get('SecurityIssues', []):
                severity = issue.get('severity', '').upper()
                if severity == 'CRITICAL':
                    critical += 1
                elif severity == 'HIGH':
                    high += 1
                elif severity == 'MEDIUM':
                    medium += 1
                elif severity == 'LOW':
                    low += 1
        return critical, high, medium, low

    def calculate_compliance_score(self, critical: int, high: int, medium: int, low: int) -> float:
        max_score = 100
        deduction_per_critical = 10
        deduction_per_high = 5
        deduction_per_medium = 2
        deduction_per_low = 1
        
        total_deduction = (critical * deduction_per_critical +
                         high * deduction_per_high +
                         medium * deduction_per_medium +
                         low * deduction_per_low)
        
        return max(0, max_score - total_deduction)

manager = ConnectionManager()

@router.websocket("/scan-updates")
async def websocket_endpoint(websocket: WebSocket):
    client_id = str(uuid.uuid4())
    logger.info(f"New WebSocket connection request from client {client_id}")
    
    try:
        # Accept the connection first
        await websocket.accept()
        logger.info(f"WebSocket connection accepted for client {client_id}")
        
        # Then connect to the manager
        await manager.connect(websocket, client_id)
        
        # Send initial connection success message
        await websocket.send_json({
            "type": "connection_status",
            "status": "connected",
            "client_id": client_id,
            "message": "Successfully connected to AWS scanner"
        })
        
        # Start sending scan updates
        await manager.start_scan_updates(client_id)
        logger.info(f"Started scan updates for client {client_id}")
        
        # Keep the connection alive and handle incoming messages
        while True:
            try:
                data = await websocket.receive_json()
                logger.debug(f"Received message from client {client_id}: {data}")
                if data.get("type") == "start_scan":
                    await manager.start_scan_updates(client_id)
            except Exception as e:
                logger.error(f"Error processing message from client {client_id}: {str(e)}")
                break
                
    except WebSocketDisconnect:
        logger.info(f"Client {client_id} disconnected")
        manager.disconnect(client_id)
    except Exception as e:
        logger.error(f"WebSocket error for client {client_id}: {str(e)}")
        try:
            if websocket.client_state != WebSocket.State.DISCONNECTED:
                await websocket.send_json({
                    "type": "error",
                    "message": f"Server error: {str(e)}"
                })
        except:
            pass
        manager.disconnect(client_id)
    finally:
        logger.info(f"Cleaning up connection for client {client_id}")
        if client_id in manager.active_connections:
            manager.disconnect(client_id)
