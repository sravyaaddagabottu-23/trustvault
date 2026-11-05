import os
os.environ.setdefault("TRUSTVAULT_ENV", "dev")
import tempfile

os.environ["TRUSTVAULT_UPLOADS"] = tempfile.mkdtemp()

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app import main as app_main
from app.models import Base, User, get_db
from app.auth import hash_password


@pytest.fixture()
def client():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    db = Session()
    for email, role in [("admin@t.test", "admin"), ("owner@t.test", "owner"),
                        ("other@t.test", "owner"), ("viewer@t.test", "viewer")]:
        db.add(User(email=email, password_hash=hash_password("Password-123"), role=role))
    db.commit()
    db.close()

    def override():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    app_main.app.dependency_overrides[get_db] = override
    yield TestClient(app_main.app)
    app_main.app.dependency_overrides.clear()


def login(c, email):
    r = c.post("/auth/login", data={"username": email, "password": "Password-123"})
    assert r.status_code == 200
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def upload(c, headers):
    r = c.post("/documents", headers=headers, files={"file": ("a.txt", b"secret", "text/plain")})
    assert r.status_code == 201
    return r.json()["id"]


def test_stranger_cannot_download(client):
    doc = upload(client, login(client, "owner@t.test"))
    assert client.get(f"/documents/{doc}/download", headers=login(client, "viewer@t.test")).status_code == 404
    assert client.get(f"/documents/{doc}/download", headers=login(client, "other@t.test")).status_code == 404


def test_admin_cannot_read_content(client):
    doc = upload(client, login(client, "owner@t.test"))
    assert client.get(f"/documents/{doc}/download", headers=login(client, "admin@t.test")).status_code == 404


def test_grant_then_revoke_is_immediate(client):
    owner = login(client, "owner@t.test")
    viewer = login(client, "viewer@t.test")
    doc = upload(client, owner)
    r = client.post(f"/documents/{doc}/grants", headers=owner,
                    json={"email": "viewer@t.test", "permission": "read"})
    assert r.status_code == 200
    assert client.get(f"/documents/{doc}/download", headers=viewer).status_code == 200
    uid = r.json()["user"]
    assert client.delete(f"/documents/{doc}/grants/{uid}", headers=owner).status_code == 200
    assert client.get(f"/documents/{doc}/download", headers=viewer).status_code == 404


def test_read_grant_cannot_edit_or_delete(client):
    owner = login(client, "owner@t.test")
    viewer = login(client, "viewer@t.test")
    doc = upload(client, owner)
    client.post(f"/documents/{doc}/grants", headers=owner,
                json={"email": "viewer@t.test", "permission": "read"})
    assert client.delete(f"/documents/{doc}", headers=viewer).status_code == 404
    r = client.put(f"/documents/{doc}/content", headers=viewer,
                   files={"file": ("a.txt", b"x", "text/plain")})
    assert r.status_code == 404


def test_listing_hides_other_users_documents(client):
    upload(client, login(client, "owner@t.test"))
    assert client.get("/documents", headers=login(client, "other@t.test")).json() == []


def test_denied_attempts_are_audited(client):
    doc = upload(client, login(client, "owner@t.test"))
    client.get(f"/documents/{doc}/download", headers=login(client, "viewer@t.test"))
    admin = login(client, "admin@t.test")
    rows = client.get("/admin/audit?only_denied=true", headers=admin).json()
    assert any(r["action"] == "download" and r["allowed"] is False for r in rows)
    assert client.get("/admin/audit/verify", headers=admin).json()["intact"] is True


def test_bad_uploads_rejected(client):
    owner = login(client, "owner@t.test")
    bad = client.post("/documents", headers=owner, files={"file": ("x.exe", b"MZ", "application/octet-stream")})
    empty = client.post("/documents", headers=owner, files={"file": ("e.txt", b"", "text/plain")})
    assert bad.status_code == 400 and empty.status_code == 400
