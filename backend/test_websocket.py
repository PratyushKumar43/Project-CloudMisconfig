import asyncio
import websockets
import json
import logging
import sys

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger(__name__)

async def test_websocket():
    uri = "ws://127.0.0.1:8000/ws/scan-updates"
    logger.info(f"Connecting to {uri}...")
    
    try:
        async with websockets.connect(uri) as websocket:
            logger.info("Connected to WebSocket server")
            
            try:
                while True:
                    message = await websocket.recv()
                    data = json.loads(message)
                    logger.info(f"Received message type: {data.get('type', 'unknown')}")
                    logger.info(f"Message content: {json.dumps(data, indent=2)}")
            except websockets.exceptions.ConnectionClosed as e:
                logger.error(f"Connection closed: {e}")
            except json.JSONDecodeError as e:
                logger.error(f"Failed to parse message: {e}")
            except Exception as e:
                logger.error(f"Unexpected error: {e}")
    except websockets.exceptions.InvalidStatusCode as e:
        logger.error(f"Failed to connect (Invalid status code): {e}")
    except websockets.exceptions.InvalidURI as e:
        logger.error(f"Invalid URI: {e}")
    except ConnectionRefusedError:
        logger.error("Connection refused. Make sure the server is running.")
    except Exception as e:
        logger.error(f"Failed to connect: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(test_websocket())
    except KeyboardInterrupt:
        logger.info("Test client stopped by user")
    except Exception as e:
        logger.error(f"Test client error: {e}")
