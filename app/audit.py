import hashlib
from sqlalchemy.orm import Session
from app.models import AuditLog, now

GENESIS = "0" * 64


def _compute_hash(prev_hash, time, user_id, action, document_id, allowed, detail, ip):
    payload = f"{prev_hash}|{time.isoformat()}|{user_id}|{action}|{document_id}|{allowed}|{detail}|{ip}"
    return hashlib.sha256(payload.encode()).hexdigest()


def log_event(db: Session, user_id, action, document_id=None, allowed=True, detail=None, ip=None):
    last = db.query(AuditLog).order_by(AuditLog.id.desc()).first()
    prev_hash = last.hash if last else GENESIS
    t = now().replace(tzinfo=None)
    h = _compute_hash(prev_hash, t, user_id, action, document_id, allowed, detail, ip)
    entry = AuditLog(
        time=t, user_id=user_id, action=action, document_id=document_id,
        allowed=allowed, detail=detail, ip=ip, prev_hash=prev_hash, hash=h,
    )
    db.add(entry)
    db.commit()
    return entry


def verify_chain(db: Session):
    """Returns (True, None) if intact, else (False, id_of_first_bad_row)."""
    prev = GENESIS
    for e in db.query(AuditLog).order_by(AuditLog.id.asc()).all():
        expected = _compute_hash(prev, e.time, e.user_id, e.action, e.document_id, e.allowed, e.detail, e.ip)
        if e.prev_hash != prev or e.hash != expected:
            return False, e.id
        prev = e.hash
    return True, None
