from datetime import datetime, timezone
from sqlalchemy import (
    create_engine, Column, Integer, String, DateTime, Boolean,
    ForeignKey, UniqueConstraint,
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship

DATABASE_URL = "sqlite:///./trustvault.db"

engine = create_engine(DATABASE_URL, connect_args={"check_same_thread": False})
SessionLocal = sessionmaker(bind=engine, autoflush=False)
Base = declarative_base()


def now():
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    email = Column(String, unique=True, nullable=False, index=True)
    password_hash = Column(String, nullable=False)
    role = Column(String, nullable=False) # "admin" | "owner" | "viewer"
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=now)


class Document(Base):
    __tablename__ = "documents"
    id = Column(Integer, primary_key=True)
    owner_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    name = Column(String, nullable=False)
    category = Column(String, nullable=True)
    stored_name = Column(String, nullable=False, unique=True) # random name on disk
    size_bytes = Column(Integer, nullable=False)
    content_type = Column(String, nullable=False)
    created_at = Column(DateTime, default=now)
    deleted_at = Column(DateTime, nullable=True) # soft delete

    owner = relationship("User")


class Grant(Base):
    __tablename__ = "grants"
    id = Column(Integer, primary_key=True)
    document_id = Column(Integer, ForeignKey("documents.id"), nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False, index=True)
    permission = Column(String, nullable=False) # "read" | "edit"
    granted_by = Column(Integer, ForeignKey("users.id"), nullable=False)
    created_at = Column(DateTime, default=now)
    revoked_at = Column(DateTime, nullable=True) # None = active

    __table_args__ = (UniqueConstraint("document_id", "user_id", name="uq_doc_user"),)


class AuditLog(Base):
    __tablename__ = "audit_log"
    id = Column(Integer, primary_key=True)
    time = Column(DateTime, default=now, nullable=False)
    user_id = Column(Integer, nullable=True) # null if login failed for unknown user
    action = Column(String, nullable=False) # upload/download/edit/delete/grant/revoke/login...
    document_id = Column(Integer, nullable=True)
    allowed = Column(Boolean, nullable=False) # refused attempts are logged too
    detail = Column(String, nullable=True)
    ip = Column(String, nullable=True)
    prev_hash = Column(String, nullable=False)
    hash = Column(String, nullable=False)


def init_db():
    Base.metadata.create_all(engine)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()