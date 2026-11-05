import os
import uuid
from contextlib import asynccontextmanager
from datetime import datetime

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy import or_
from sqlalchemy.orm import Session

from app.audit import log_event, verify_chain
from app.auth import (client_ip, create_token, get_current_user, hash_password,
                      require_role, verify_password)
from app.models import AuditLog, Document, Grant, User, get_db, init_db, now
from app.permissions import authorize

DEV_DEFAULTS = {
    "SEED_ADMIN_PW": "ChangeMe-Admin1",
    "SEED_OWNER_PW": "ChangeMe-Owner1",
    "SEED_VIEWER_PW": "ChangeMe-Viewer1",
}


def seed_demo_users():
    """Creates demo accounts if missing.

    Passwords MUST come from environment variables. Insecure defaults are allowed
    only when TRUSTVAULT_ENV=dev (local development).
    """
    from app.models import SessionLocal
    dev = os.environ.get("TRUSTVAULT_ENV") == "dev"
    accounts = [
        ("admin@trustvault.test", "SEED_ADMIN_PW", "admin"),
        ("owner@trustvault.test", "SEED_OWNER_PW", "owner"),
        ("viewer@trustvault.test", "SEED_VIEWER_PW", "viewer"),
    ]
    passwords = {}
    for _, env, _ in accounts:
        value = os.environ.get(env)
        if not value:
            if not dev:
                raise RuntimeError(
                    f"{env} is not set. Refusing to start with a default password. "
                    "Set it, or set TRUSTVAULT_ENV=dev for local development."
                )
            value = DEV_DEFAULTS[env]
        passwords[env] = value

    db = SessionLocal()
    try:
        for email, env, role in accounts:
            if not db.query(User).filter(User.email == email).first():
                db.add(User(email=email, password_hash=hash_password(passwords[env]), role=role))
        db.commit()
    finally:
        db.close()

UPLOAD_DIR = os.environ.get("TRUSTVAULT_UPLOADS", "uploads")
MAX_BYTES = 5 * 1024 * 1024
ALLOWED_TYPES = {
    ".pdf": "application/pdf",
    ".txt": "text/plain",
    ".csv": "text/csv",
    ".png": "image/png",
    ".jpg": "image/jpeg",
}


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(UPLOAD_DIR, exist_ok=True)
    init_db()
    seed_demo_users()
    yield


app = FastAPI(title="TrustVault", lifespan=lifespan)


# ---------- schemas ----------
class RegisterIn(BaseModel):
    email: str
    password: str
    role: str = "viewer" # "owner" or "viewer" only; admin is never self-registered


class GrantIn(BaseModel):
    email: str
    permission: str # "read" | "edit"


# ---------- helpers ----------
def validate_upload(filename: str, data: bytes):
    ext = os.path.splitext(os.path.basename(filename or ""))[1].lower()
    if ext not in ALLOWED_TYPES:
        raise HTTPException(400, f"File type not allowed. Allowed: {sorted(ALLOWED_TYPES)}")
    if len(data) == 0:
        raise HTTPException(400, "Empty file")
    if len(data) > MAX_BYTES:
        raise HTTPException(413, "File too large (max 5 MB)")
    return ext


def file_path(doc: Document) -> str:
    return os.path.join(UPLOAD_DIR, doc.stored_name) # stored_name is a server-made uuid


# ---------- auth ----------
@app.post("/auth/register", status_code=201)
def register(body: RegisterIn, request: Request, db: Session = Depends(get_db)):
    email = body.email.strip().lower()
    if "@" not in email or len(body.password) < 8:
        raise HTTPException(400, "Valid email and password of 8+ characters required")
    if body.role not in ("owner", "viewer"):
        raise HTTPException(400, "Role must be owner or viewer")
    if db.query(User).filter(User.email == email).first():
        raise HTTPException(409, "Email already registered")
    user = User(email=email, password_hash=hash_password(body.password), role=body.role)
    db.add(user)
    db.commit()
    log_event(db, user.id, "register", ip=client_ip(request))
    return {"id": user.id, "email": user.email, "role": user.role}


@app.post("/auth/login")
def login(request: Request, form: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    email = form.username.strip().lower()
    user = db.query(User).filter(User.email == email).first()
    if user is None or not user.is_active or not verify_password(form.password, user.password_hash):
        log_event(db, user.id if user else None, "login", allowed=False,
                  detail=f"email={email}", ip=client_ip(request))
        raise HTTPException(401, "Wrong email or password")
    log_event(db, user.id, "login", ip=client_ip(request))
    return {"access_token": create_token(user.id), "token_type": "bearer"}


@app.get("/me")
def me(user: User = Depends(get_current_user)):
    return {"id": user.id, "email": user.email, "role": user.role}


# ---------- documents ----------
@app.post("/documents", status_code=201)
async def upload(request: Request, file: UploadFile = File(...), category: str = Form(None),
                 user: User = Depends(require_role("owner")), db: Session = Depends(get_db)):
    data = await file.read(MAX_BYTES + 1)
    try:
        ext = validate_upload(file.filename, data)
    except HTTPException as e:
        log_event(db, user.id, "upload", allowed=False, detail=str(e.detail), ip=client_ip(request))
        raise
    stored = uuid.uuid4().hex
    with open(os.path.join(UPLOAD_DIR, stored), "wb") as f:
        f.write(data)
    doc = Document(owner_id=user.id, name=os.path.basename(file.filename), category=category,
                   stored_name=stored, size_bytes=len(data), content_type=ALLOWED_TYPES[ext])
    db.add(doc)
    db.commit()
    log_event(db, user.id, "upload", document_id=doc.id, ip=client_ip(request))
    return {"id": doc.id, "name": doc.name}


@app.get("/documents")
def list_documents(q: str = None, category: str = None, owner: str = None,
                   date_from: str = None, date_to: str = None,
                   user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Only documents the caller owns or holds an active grant for. Filters narrow, never widen."""
    granted = db.query(Grant.document_id).filter(
        Grant.user_id == user.id, Grant.revoked_at.is_(None))
    query = (db.query(Document, User.email)
             .join(User, Document.owner_id == User.id)
             .filter(Document.deleted_at.is_(None))
             .filter(or_(Document.owner_id == user.id, Document.id.in_(granted))))
    if q:
        query = query.filter(Document.name.ilike(f"%{q}%"))
    if category:
        query = query.filter(Document.category == category)
    if owner:
        query = query.filter(User.email.ilike(f"%{owner}%"))
    try:
        if date_from:
            query = query.filter(Document.created_at >= datetime.fromisoformat(date_from))
        if date_to:
            query = query.filter(Document.created_at <= datetime.fromisoformat(date_to))
    except ValueError:
        raise HTTPException(400, "Dates must look like 2026-11-05")
    return [{"id": d.id, "name": d.name, "category": d.category, "owner": email,
             "size": d.size_bytes, "created_at": d.created_at} for d, email in query.all()]


@app.get("/documents/{doc_id}/download")
def download(doc_id: int, request: Request, user: User = Depends(get_current_user),
             db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    authorize(db, user, doc, "download", request) # <-- THE authorization decision for downloads
    path = file_path(doc)
    if not os.path.exists(path):
        raise HTTPException(404, "Not found")
    return FileResponse(path, filename=doc.name, media_type=doc.content_type,
                        headers={"X-Content-Type-Options": "nosniff"})


@app.put("/documents/{doc_id}/content")
async def replace_content(doc_id: int, request: Request, file: UploadFile = File(...),
                          user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    authorize(db, user, doc, "edit", request)
    data = await file.read(MAX_BYTES + 1)
    ext = validate_upload(file.filename, data)
    with open(file_path(doc), "wb") as f:
        f.write(data)
    doc.size_bytes = len(data)
    doc.content_type = ALLOWED_TYPES[ext]
    db.commit()
    return {"id": doc.id, "size": doc.size_bytes}


@app.delete("/documents/{doc_id}")
def delete_document(doc_id: int, request: Request, user: User = Depends(get_current_user),
                    db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    authorize(db, user, doc, "delete", request)
    doc.deleted_at = now()
    db.commit()
    return {"deleted": doc_id}


# ---------- sharing ----------
@app.post("/documents/{doc_id}/grants")
def grant_access(doc_id: int, body: GrantIn, request: Request,
                 user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    authorize(db, user, doc, "grant", request) # owner only
    if body.permission not in ("read", "edit"):
        raise HTTPException(400, "Permission must be read or edit")
    target = db.query(User).filter(User.email == body.email.strip().lower()).first()
    if target is None or not target.is_active or target.id == user.id:
        raise HTTPException(400, "Invalid target user")
    g = db.query(Grant).filter(Grant.document_id == doc.id, Grant.user_id == target.id).first()
    if g: # re-activate / change an old row (UniqueConstraint allows only one row per pair)
        g.permission, g.revoked_at, g.granted_by = body.permission, None, user.id
    else:
        g = Grant(document_id=doc.id, user_id=target.id, permission=body.permission, granted_by=user.id)
        db.add(g)
    db.commit()
    log_event(db, user.id, "grant_given", document_id=doc.id,
              detail=f"to={target.id} perm={body.permission}", ip=client_ip(request))
    return {"document": doc.id, "user": target.id, "permission": g.permission}


@app.delete("/documents/{doc_id}/grants/{target_id}")
def revoke_access(doc_id: int, target_id: int, request: Request,
                  user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    authorize(db, user, doc, "revoke", request)
    g = db.query(Grant).filter(Grant.document_id == doc.id, Grant.user_id == target_id,
                               Grant.revoked_at.is_(None)).first()
    if g is None:
        raise HTTPException(404, "No active grant")
    g.revoked_at = now()
    db.commit()
    log_event(db, user.id, "grant_revoked", document_id=doc.id,
              detail=f"from={target_id}", ip=client_ip(request))
    return {"revoked": target_id}


@app.get("/documents/{doc_id}/grants")
def list_grants(doc_id: int, request: Request, user: User = Depends(get_current_user),
                db: Session = Depends(get_db)):
    doc = db.get(Document, doc_id)
    authorize(db, user, doc, "grant", request)
    rows = db.query(Grant).filter(Grant.document_id == doc.id, Grant.revoked_at.is_(None)).all()
    return [{"user_id": g.user_id, "permission": g.permission} for g in rows]


# ---------- admin (activity only, never document content) ----------
@app.get("/admin/audit")
def admin_audit(only_denied: bool = False, limit: int = 100,
                admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    q = db.query(AuditLog)
    if only_denied:
        q = q.filter(AuditLog.allowed.is_(False))
    rows = q.order_by(AuditLog.id.desc()).limit(min(limit, 500)).all()
    return [{"id": r.id, "time": r.time, "user_id": r.user_id, "action": r.action,
             "document_id": r.document_id, "allowed": r.allowed, "detail": r.detail,
             "ip": r.ip} for r in rows]


@app.get("/admin/audit/verify")
def admin_verify(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    ok, bad_id = verify_chain(db)
    return {"intact": ok, "first_bad_row": bad_id}


@app.get("/admin/users")
def admin_users(admin: User = Depends(require_role("admin")), db: Session = Depends(get_db)):
    return [{"id": u.id, "email": u.email, "role": u.role, "is_active": u.is_active}
            for u in db.query(User).all()]


@app.post("/admin/users/{user_id}/disable")
def admin_disable(user_id: int, request: Request, admin: User = Depends(require_role("admin")),
                  db: Session = Depends(get_db)):
    target = db.get(User, user_id)
    if target is None or target.id == admin.id:
        raise HTTPException(400, "Invalid user")
    target.is_active = False
    db.commit()
    log_event(db, admin.id, "user_disabled", detail=f"user={user_id}", ip=client_ip(request))
    return {"disabled": user_id}
