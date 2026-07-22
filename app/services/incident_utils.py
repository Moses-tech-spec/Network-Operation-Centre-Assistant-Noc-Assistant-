from app.database.database import db


def raise_incident(router, category, severity, title, description, source="Monitoring"):
    """
    Creates an incident, but only if one of the same router+category
    is not already OPEN — prevents flooding on every poll cycle while
    a condition persists (e.g. router still offline 30s later).
    """

    existing = db.fetchone(
        """
        SELECT id FROM incidents
        WHERE router=? AND category=? AND status='OPEN'
        ORDER BY created_at DESC
        LIMIT 1
        """,
        (router, category)
    )

    if existing:
        return None

    db.execute(
        """
        INSERT INTO incidents(
            router, severity, category, title, description, source, status
        )
        VALUES(?,?,?,?,?,?,'OPEN')
        """,
        (router, severity, category, title, description, source)
    )

    return True


def resolve_incidents(router, category):
    """
    Marks any OPEN incident of this router+category as resolved —
    called when the underlying condition clears (e.g. router reachable
    again, interface running again).
    """

    db.execute(
        """
        UPDATE incidents
        SET status='RESOLVED', resolved_at=CURRENT_TIMESTAMP
        WHERE router=? AND category=? AND status='OPEN'
        """,
        (router, category)
    )


def log_point_event(router, category, severity, title, description, source="Monitoring"):
    """
    Logs a one-off event that isn't an ongoing condition to track/resolve
    (e.g. a customer's PPP session dropped) — recorded immediately as
    resolved, since there's nothing further to clear.
    """

    db.execute(
        """
        INSERT INTO incidents(
            router, severity, category, title, description, source, status, resolved_at
        )
        VALUES(?,?,?,?,?,?,'RESOLVED',CURRENT_TIMESTAMP)
        """,
        (router, severity, category, title, description, source)
    )
