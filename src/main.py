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
from detector import AnomalyDetector

# Instantiate the detector globally
detector = AnomalyDetector()

# Setup basic logging to standard output
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def packet_handler(parsed_data: dict):
    """
    Callback function that receives parsed packet data, inserts it into the database,
    and runs it through the anomaly detector.
    """
    try:
        database.insert_packet(parsed_data)
        
        # Detector logic
        src_ip = parsed_data.get("src_ip")
        if not src_ip:
            return
            
        alerts = []
        
        # Traffic spike applies to all
        spike_alert = detector.detect_traffic_spike()
        if spike_alert:
            alerts.append(spike_alert)
            
        protocol = parsed_data.get("protocol")
        if protocol == "TCP":
            dst_port = parsed_data.get("dst_port")
            if dst_port:
                scan_alert = detector.detect_port_scan(src_ip, dst_port)
                if scan_alert:
                    alerts.append(scan_alert)
            
            tcp_flags = parsed_data.get("tcp_flags")
            if tcp_flags and "S" in tcp_flags:
                syn_alert = detector.detect_syn_flood(src_ip)
                if syn_alert:
                    alerts.append(syn_alert)
                    
        elif protocol == "ICMP":
            icmp_alert = detector.detect_icmp_flood(src_ip)
            if icmp_alert:
                alerts.append(icmp_alert)
                
        # Process alerts
        import datetime
        for alert in alerts:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            print(f"\n[{timestamp}] 🚨 ANOMALY DETECTED: {alert.get('attack')} (Severity: {alert.get('severity')})")
            print(f"   Source IP: {src_ip}")
            print(f"   Details: {alert.get('message')}\n")
            database.insert_alert(alert, src_ip)
            
    except Exception as e:
        logger.error(f"Failed to process packet: {e}")

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
