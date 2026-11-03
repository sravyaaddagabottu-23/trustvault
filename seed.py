from app.models import SessionLocal, User, init_db
from app.auth import hash_password

init_db()
db = SessionLocal()
for email, pw, role in [
    ("admin@trustvault.test", "ChangeMe-Admin1", "admin"),
    ("owner@trustvault.test", "ChangeMe-Owner1", "owner"),
    ("viewer@trustvault.test", "ChangeMe-Viewer1", "viewer"),
]:
    if not db.query(User).filter(User.email == email).first():
        db.add(User(email=email, password_hash=hash_password(pw), role=role))
db.commit()
print("seeded")