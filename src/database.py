import sqlite3
from pathlib import Path
DB_PATH = Path(__file__).parent.parent / "database" / "network.db"
def connect_db():
    return sqlite3.connect(DB_PATH)
def create_database():
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packets (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     timestamp REAL,
     src_ip TEXT,
     dst_ip TEXT,
     src_port INTEGER,
     dst_port INTEGER,
     protocol TEXT,
     packet_size INTEGER,
     tcp_flags TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp REAL,
    alert_type TEXT,
    src_ip TEXT,
    confidence TEXT,
    risk_score INTEGER,
    details TEXT
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS risk_scores (
    src_ip TEXT PRIMARY KEY,
    risk_score INTEGER,
    status TEXT,
    last_updated REAL
    )
    """)
def insert_packet(packet):
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("""
    INSERT INTO packets (
        timestamp,
        src_ip,
        dst_ip,
        src_port,
        dst_port,
        protocol,
        packet_size,
        tcp_flags
    )
    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        packet["timestamp"],
        packet["src_ip"],
        packet["dst_ip"],
        packet["src_port"],
        packet["dst_port"],
        packet["protocol"],
        packet["packet_size"],
        packet["tcp_flags"]
    ))

    conn.commit()
    conn.close()

def get_packets():
    conn = connect_db()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM packets")

    packets = cursor.fetchall()

    conn.close()

    return packets

def get_latest_packets(limit=100):
    conn = connect_db()
    conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM packets ORDER BY id DESC LIMIT ?', (limit,))
    res = cursor.fetchall()
    conn.close()
    return res

def get_protocol_counts():
    conn = connect_db()
    conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor = conn.cursor()
    cursor.execute('SELECT protocol, COUNT(*) as count FROM packets GROUP BY protocol')
    res = cursor.fetchall()
    conn.close()
    return res

def get_total_count():
    conn = connect_db()
    conn.row_factory = lambda c, r: dict(zip([col[0] for col in c.description], r))
    cursor = conn.cursor()
    cursor.execute('SELECT COUNT(*) as total FROM packets')
    result = cursor.fetchone()
    conn.close()
    return result['total'] if result else 0

if __name__ == "__main__":
    create_database()
    
    print("Database initialized successfully!")