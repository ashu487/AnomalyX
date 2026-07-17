"""
Packet capture module using Scapy.
Note: Raw packet sniffing requires elevated privileges (sudo/root/admin).
"""
import logging
from scapy.all import sniff
from parser import parse_packet
import config

logger = logging.getLogger(__name__)

# Global flag to control the sniffing loop
_is_capturing = False

def _process_packet(packet, callback):
    """
    Internal callback for Scapy's sniff function.
    Parses the packet and passes the result to the main callback.
    """
    parsed_data = parse_packet(packet)
    if parsed_data:
        try:
            callback(parsed_data)
        except Exception as e:
            logger.error(f"Error in callback: {e}")

def _stop_filter(packet):
    """
    Condition function evaluated by Scapy to determine when to stop sniffing.
    Returns True when capture should stop.
    """
    return not _is_capturing

def start_capture(callback):
    """
    Starts sniffing packets continuously on the configured interface.
    Calls the provided callback with parsed packet data.
    """
    global _is_capturing
    _is_capturing = True
    
    iface_str = config.INTERFACE if config.INTERFACE else "default (all/auto)"
    logger.info(f"Starting packet capture on interface: {iface_str}")
    
    try:
        # sniff() is a blocking call, it will run until stop_filter returns True.
        # store=False ensures we don't keep packets in memory to prevent OOM.
        sniff(
            iface=config.INTERFACE,
            filter=config.CAPTURE_FILTER,
            prn=lambda pkt: _process_packet(pkt, callback),
            stop_filter=_stop_filter,
            store=False 
        )
    except PermissionError:
        logger.error("Permission denied. Packet sniffing requires root/administrator privileges.")
    except Exception as e:
        logger.error(f"Error during packet capture: {e}")

def stop_capture():
    """
    Signals the packet capture loop to stop.
    """
    global _is_capturing
    _is_capturing = False
    logger.info("Packet capture stop requested.")
