import asyncio
import websockets
import json
from datetime import datetime
import logging
import sys
from websockets.exceptions import WebSocketException
import time

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

async def connect_with_retry(uri, max_retries=3, retry_delay=2):
    for attempt in range(max_retries):
        try:
            return await websockets.connect(uri, ping_interval=20, ping_timeout=20)
        except Exception as e:
            if attempt == max_retries - 1:
                logger.error(f"Failed to connect after {max_retries} attempts: {str(e)}")
                raise
            logger.warning(f"Connection attempt {attempt + 1} failed, retrying in {retry_delay} seconds...")
            await asyncio.sleep(retry_delay)

async def test_services():
    uri = "ws://localhost:8000/ws/scan-updates?client_id=test_client"
    logger.info(f"Connecting to {uri}...")
    
    try:
        websocket = await connect_with_retry(uri)
        logger.info("Connected to WebSocket server")
        
        while True:
            try:
                message = await websocket.recv()
                data = json.loads(message)
                
                if data["type"] == "scan_update":
                    logger.info("\n=== AWS Services Status ===")
                    logger.info(f"Timestamp: {data['timestamp']}")
                    
                    overview = data["overview"]
                    logger.info("\nOverview:")
                    logger.info(f"Total Resources: {overview['totalResources']}")
                    logger.info(f"Compliance Score: {overview['complianceScore']}%")
                    logger.info(f"Critical Issues: {overview['criticalIssues']}")
                    logger.info(f"High Issues: {overview['highIssues']}")
                    logger.info(f"Medium Issues: {overview['mediumIssues']}")
                    logger.info(f"Low Issues: {overview['lowIssues']}")
                    
                    services = data["services"]
                    for service_name, service_data in services.items():
                        logger.info(f"\n{service_name.upper()} Service:")
                        logger.info(f"Total Resources: {service_data['total']}")
                        logger.info(f"Issues: Critical={service_data['critical']}, High={service_data['high']}, Medium={service_data['medium']}, Low={service_data['low']}")
                
                elif data["type"] == "error":
                    logger.error(f"Server Error: {data['message']}")
                    if "AWS credentials" in data['message']:
                        logger.error("Please check your AWS credentials in the .env file")
                        break
                
            except websockets.exceptions.ConnectionClosed:
                logger.warning("Connection closed by server, attempting to reconnect...")
                websocket = await connect_with_retry(uri)
            except json.JSONDecodeError as e:
                logger.error(f"Invalid JSON received: {str(e)}")
            except Exception as e:
                logger.error(f"Error processing message: {str(e)}")
                break
                
    except KeyboardInterrupt:
        logger.info("Shutting down client...")
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
    finally:
        if 'websocket' in locals():
            await websocket.close()

if __name__ == "__main__":
    logger.info("Starting WebSocket test client...")
    try:
        asyncio.run(test_services())
    except KeyboardInterrupt:
        logger.info("Client stopped by user")
    except Exception as e:
        logger.error(f"Fatal error: {str(e)}")
        sys.exit(1)
