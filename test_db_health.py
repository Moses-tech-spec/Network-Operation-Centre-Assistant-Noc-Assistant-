from app.database.database import db

rows = db.fetchall(
    """
    SELECT *
    FROM router_health
    ORDER BY id DESC
    LIMIT 5
    """
)

print(rows)
