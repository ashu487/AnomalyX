"""
Main entry point for the Network Traffic Analyzer backend.
Starts both the packet capture thread and the Flask API.
"""
import threading
import logging
import sys

import config
import database
import capture
from api import start_api

# Setup basic logging to standard output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def packet_handler(parsed_data: dict):
    """
    Callback function that receives parsed packet data and inserts it into the database.
    This is called from the capture thread for every valid packet.
    """
    try:
        database.insert_packet(parsed_data)
    except Exception as e:
        logger.error(f"Failed to insert packet into database: {e}")

def main():
    logger.info("Initializing Network Traffic Analyzer...")

    # 1. Initialize Database
    try:
        database.create_database()
        logger.info(f"Database initialized at {config.DB_FILENAME}")
    except Exception as e:
        logger.error(f"Database initialization failed: {e}")
        sys.exit(1)

    # 2. Start Packet Capture in a background thread
    # We pass the packet_handler callback to the capture module
    capture_thread = threading.Thread(target=capture.start_capture, args=(packet_handler,), daemon=True)
    capture_thread.start()
    logger.info("Packet capture thread started.")

    # 3. Start Flask API in the main thread
    logger.info(f"Starting Flask API on http://{config.FLASK_HOST}:{config.FLASK_PORT}...")
    try:
        # Blocks until Flask is shut down (e.g. via KeyboardInterrupt)
        start_api(host=config.FLASK_HOST, port=config.FLASK_PORT)
    except KeyboardInterrupt:
        logger.info("Keyboard interrupt received. Shutting down...")
    except Exception as e:
        logger.error(f"Failed to start Flask API: {e}")
    finally:
        # 4. Clean shutdown path
        logger.info("Stopping packet capture...")
        capture.stop_capture()
        # Wait a short time for the capture thread to exit gracefully
        capture_thread.join(timeout=2.0)
        logger.info("Shutdown complete.")

if __name__ == "__main__":
    main()
