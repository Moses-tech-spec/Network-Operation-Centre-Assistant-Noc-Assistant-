import os
import sqlite3

# ==========================================================
# Database Location
# ==========================================================

BASE_DIR = os.path.dirname(
    os.path.dirname(
        os.path.dirname(__file__)
    )
)

DB_PATH = os.path.join(
    BASE_DIR,
    "hyperwave.db"
)


# ==========================================================
# Database Engine
# ==========================================================

class Database:

    def __init__(self):

        self.conn = sqlite3.connect(
            DB_PATH,
            check_same_thread=False
        )

        self.conn.row_factory = sqlite3.Row

        self.conn.execute(
            "PRAGMA foreign_keys = ON;"
        )

        self.conn.execute(
            "PRAGMA journal_mode=WAL;"
        )

        self.conn.execute(
            "PRAGMA synchronous=NORMAL;"
        )

    # ======================================================
    # Execute Single Query
    # ======================================================

    def execute(self, sql, params=()):

        cursor = self.conn.cursor()

        cursor.execute(sql, params)

        self.conn.commit()

        return cursor

    # ======================================================
    # Execute Many
    # ======================================================

    def executemany(self, sql, rows):

        cursor = self.conn.cursor()

        cursor.executemany(sql, rows)

        self.conn.commit()

        return cursor

    # ======================================================
    # Fetch One
    # ======================================================

    def fetchone(self, sql, params=()):

        cursor = self.conn.cursor()

        cursor.execute(sql, params)

        row = cursor.fetchone()

        if row:

            return dict(row)

        return None

    # ======================================================
    # Fetch All
    # ======================================================

    def fetchall(self, sql, params=()):

        cursor = self.conn.cursor()

        cursor.execute(sql, params)

        return [

            dict(row)

            for row in cursor.fetchall()

        ]

    # ======================================================
    # Raw Cursor
    # ======================================================

    def cursor(self):

        return self.conn.cursor()


# ==========================================================
# Router Inventory
# ==========================================================

def create_router_inventory_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS router_inventory(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        router TEXT,

        identity TEXT,

        model TEXT,

        board_name TEXT,

        serial_number TEXT,

        version TEXT,

        architecture TEXT,

        cpu TEXT,

        cpu_count INTEGER,

        total_memory INTEGER,

        total_storage INTEGER,

        license TEXT,

        uptime TEXT,

        collected_at DATETIME DEFAULT CURRENT_TIMESTAMP

    )

    """)


# ==========================================================
# Router Health
# ==========================================================

def create_router_health_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS router_health(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        router TEXT,

        cpu_load INTEGER,

        memory_used INTEGER,

        memory_total INTEGER,

        uptime TEXT,

        temperature INTEGER,

        collected_at DATETIME DEFAULT CURRENT_TIMESTAMP

    )

    """)


# ==========================================================
# PPPoE Sessions
# ==========================================================

def create_pppoe_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS pppoe_sessions(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        router TEXT,

        username TEXT,

        service TEXT,

        caller_id TEXT,

        address TEXT,

        uptime TEXT,

        session_id TEXT,

        encoding TEXT,

        collected_at DATETIME DEFAULT CURRENT_TIMESTAMP

    )

    """)


# ==========================================================
# Interfaces
# ==========================================================

def create_interfaces_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS interfaces(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        router TEXT,

        interface_name TEXT,

        interface_type TEXT,

        mac_address TEXT,

        mtu INTEGER,

        running INTEGER,

        disabled INTEGER,

        rx_rate INTEGER,

        tx_rate INTEGER,

        rx_packets INTEGER,

        tx_packets INTEGER,

        rx_errors INTEGER,

        tx_errors INTEGER,

        comment TEXT,

        collected_at DATETIME DEFAULT CURRENT_TIMESTAMP

    )

    """)


# ==========================================================
# Firewall Rules
# ==========================================================

def create_firewall_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS firewall_rules(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        router TEXT,

        chain TEXT,

        action TEXT,

        protocol TEXT,

        src_address TEXT,

        dst_address TEXT,

        src_port TEXT,

        dst_port TEXT,

        disabled INTEGER,

        comment TEXT,

        collected_at DATETIME DEFAULT CURRENT_TIMESTAMP

    )

    """)


# ==========================================================
# Queue Statistics
# ==========================================================

def create_queue_statistics_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS queue_statistics(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        router TEXT,

        queue_name TEXT,

        target TEXT,

        max_limit TEXT,

        upload_bytes INTEGER,

        download_bytes INTEGER,

        upload_rate INTEGER,

        download_rate INTEGER,

        upload_packets INTEGER,

        download_packets INTEGER,

        upload_dropped INTEGER,

        download_dropped INTEGER,

        priority TEXT,

        parent TEXT,

        queue_type TEXT,

        disabled INTEGER,

        collected_at DATETIME DEFAULT CURRENT_TIMESTAMP

    )

    """)


# ==========================================================
# BGP Peers
# ==========================================================

def create_bgp_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS bgp_peers(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        router TEXT,

        peer_name TEXT,

        remote_address TEXT,

        remote_as TEXT,

        local_address TEXT,

        local_as TEXT,

        state TEXT,

        uptime TEXT,

        prefixes_received INTEGER,

        prefixes_advertised INTEGER,

        input_messages INTEGER,

        output_messages INTEGER,

        collected_at DATETIME DEFAULT CURRENT_TIMESTAMP

    )

    """)


# ==========================================================
# OSPF Neighbors
# ==========================================================

def create_ospf_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS ospf_neighbors(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        router TEXT,

        neighbor_id TEXT,

        address TEXT,

        interface TEXT,

        state TEXT,

        priority INTEGER,

        dead_time TEXT,

        collected_at DATETIME DEFAULT CURRENT_TIMESTAMP

    )

    """)


# ==========================================================
# Routing Table
# ==========================================================

def create_routes_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS routing_table(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        router TEXT,

        destination TEXT,

        gateway TEXT,

        distance INTEGER,

        routing_table TEXT,

        route_type TEXT,

        active INTEGER,

        disabled INTEGER,

        collected_at DATETIME DEFAULT CURRENT_TIMESTAMP

    )

    """)


# ==========================================================
# Customer Last Seen (persistent, upsert-only, never wiped)
# ==========================================================

def create_customer_last_seen_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS customer_last_seen(

        router TEXT,

        username TEXT,

        last_ip TEXT,

        last_uptime TEXT,

        last_seen_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        PRIMARY KEY (router, username)

    )

    """)


# ==========================================================
# Incidents
# ==========================================================

def create_incidents_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS incidents(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        router TEXT,

        severity TEXT,

        category TEXT,

        title TEXT,

        description TEXT,

        source TEXT,

        status TEXT DEFAULT 'OPEN',

        acknowledged_by TEXT,

        resolved_by TEXT,

        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,

        acknowledged_at DATETIME,

        resolved_at DATETIME

    )

    """)


# ==========================================================
# Audit Log
# ==========================================================

def create_audit_log_table():

    db.execute("""

    CREATE TABLE IF NOT EXISTS audit_log(

        id INTEGER PRIMARY KEY AUTOINCREMENT,

        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,

        method TEXT,

        path TEXT,

        status_code INTEGER,

        duration_ms INTEGER,

        source_ip TEXT,

        identity TEXT,

        request_body TEXT

    )

    """)


# ==========================================================
# Database Initialization
# ==========================================================

def migrate_interfaces_rate_columns():
    """
    Adds rx_rate/tx_rate columns to the interfaces table if they
    don't already exist (SQLite has no ADD COLUMN IF NOT EXISTS).
    """
    for column in ["rx_rate INTEGER DEFAULT 0", "tx_rate INTEGER DEFAULT 0"]:
        try:
            db.execute(f"ALTER TABLE interfaces ADD COLUMN {column}")
        except Exception:
            pass  # column already exists


def initialize_database():

    print("=" * 50)
    print("Initializing Hyperwave Database...")
    print("=" * 50)

    print("Creating Router Inventory table...")
    create_router_inventory_table()

    print("Creating Router Health table...")
    create_router_health_table()

    print("Creating PPPoE Sessions table...")
    create_pppoe_table()

    print("Creating Interfaces table...")
    create_interfaces_table()

    print("Creating Firewall Rules table...")
    create_firewall_table()

    print("Creating Queue Statistics table...")
    create_queue_statistics_table()

    print("Creating BGP Peers table...")
    create_bgp_table()

    print("Creating OSPF Neighbors table...")
    create_ospf_table()

    print("Creating Routing Table...")
    create_routes_table()

    print("Creating Incidents table...")
    create_incidents_table()

    print("Creating Customer Last Seen table...")
    create_customer_last_seen_table()

    print("Migrating interfaces table for traffic rate columns...")
    migrate_interfaces_rate_columns()

    print("Creating Audit Log table...")
    create_audit_log_table()

    print("=" * 50)
    print("Database initialization completed successfully.")
    print("=" * 50)


# ==========================================================
# Global Database Object
# ==========================================================

db = Database()
