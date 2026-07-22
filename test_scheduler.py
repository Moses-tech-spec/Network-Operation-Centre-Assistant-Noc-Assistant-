from app.database.database import db

tables = [
    "router_inventory",
    "router_health",
    "pppoe_sessions",
    "interfaces",
    "incidents",
]

for table in tables:
    rows = db.fetchall(f"SELECT * FROM {table}")

    print(f"\n{table}")
    print("-" * 40)
    print(f"Rows: {len(rows)}")
