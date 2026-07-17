"""
Flask API to serve packet data and statistics.
"""
from flask import Flask, jsonify, request
from flask_cors import CORS
import database
import logging

# Suppress noisy Flask logging for cleaner output in standard usage
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

app = Flask(__name__)
# Enable CORS for all domains so a frontend on a different port can access it
CORS(app) 

@app.route('/packets', methods=['GET'])
def api_get_packets():
    """
    Endpoint to retrieve all packets.
    Note: For large datasets, this might be slow and return a lot of data.
    """
    try:
        packets = database.get_all_packets()
        return jsonify(packets)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/packets/latest', methods=['GET'])
def api_get_latest_packets():
    """
    Endpoint to retrieve the latest packets.
    Optional 'limit' query parameter can be provided (default: 100).
    """
    try:
        limit = request.args.get('limit', default=100, type=int)
        packets = database.get_latest_packets(limit=limit)
        return jsonify(packets)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/stats/protocols', methods=['GET'])
def api_get_protocol_stats():
    """
    Endpoint to retrieve protocol counts.
    """
    try:
        stats = database.get_protocol_counts()
        return jsonify(stats)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/stats/total', methods=['GET'])
def api_get_total_stats():
    """
    Endpoint to retrieve total packet count.
    """
    try:
        total = database.get_total_count()
        return jsonify({"total": total})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

def start_api(host, port):
    """
    Helper function to start the Flask application.
    Runs without the reloader to prevent creating multiple capture threads accidentally.
    """
    app.run(host=host, port=port, debug=False, use_reloader=False)
