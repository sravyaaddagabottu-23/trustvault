from fastapi import HTTPException, Request
from sqlalchemy.orm import Session

from app.models import Document, Grant, User
from app.audit import log_event


def can_access(db: Session, user: User, document: Document, action: str) -> bool:
    """THE single authorization decision. Every document route calls this.

    Rules:
      - Deleted documents are unreachable.
      - Owner can do everything on own documents.
      - Anyone else needs an ACTIVE (not revoked) grant:
          read action -> 'read' or 'edit' grant
          edit action -> 'edit' grant
          delete/share -> owner only
      - Admin gets NO special access to document content.
    """
    if document is None or document.deleted_at is not None:
        return False
    if not user.is_active:
        return False

    if document.owner_id == user.id:
        return True

    if action in ("delete", "grant", "revoke"):
        return False

    grant = (
        db.query(Grant)
        .filter(
            Grant.document_id == document.id,
            Grant.user_id == user.id,
            Grant.revoked_at.is_(None),
        )
        .first()
    )
    if grant is None:
        return False
    if action in ("read", "download"):
        return grant.permission in ("read", "edit")
    if action == "edit":
        return grant.permission == "edit"
    return False


def authorize(db: Session, user: User, document, action: str, request: Request):
    """Calls can_access, logs the decision (allowed or refused), raises 404 if refused.

    404 (not 403) so outsiders cannot learn whether a document ID exists.
    """
    ok = can_access(db, user, document, action)
    log_event(
        db, user.id, action,
        document_id=document.id if document is not None else None,
        allowed=ok, ip=request.client.host if request.client else None,
    )
    if not ok:
        raise HTTPException(status_code=404, detail="Not found")
    return document
