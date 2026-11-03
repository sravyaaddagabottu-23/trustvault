import os
from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from app.models import User, get_db
from app.audit import log_event

SECRET_KEY = os.environ.get("TRUSTVAULT_SECRET", "dev-only-change-me")
ALGORITHM = "HS256"
TOKEN_MINUTES = 60

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


def client_ip(request: Request):
    return request.client.host if request.client else None


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)


def create_token(user_id: int) -> str:
    exp = datetime.now(timezone.utc) + timedelta(minutes=TOKEN_MINUTES)
    return jwt.encode({"sub": str(user_id), "exp": exp}, SECRET_KEY, algorithm=ALGORITHM)


def get_current_user(
    request: Request,
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        user_id = int(payload["sub"])
    except (JWTError, KeyError, ValueError):
        raise HTTPException(status_code=401, detail="Invalid token")

    # Always re-read the user from the DB: role and is_active are NOT trusted from the token.
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        log_event(db, user_id, "auth_rejected", allowed=False, ip=client_ip(request))
        raise HTTPException(status_code=401, detail="Invalid token")
    return user


def require_role(*roles: str):
    def checker(request: Request, user: User = Depends(get_current_user), db: Session = Depends(get_db)):
        if user.role not in roles:
            log_event(db, user.id, "role_denied", allowed=False,
                      detail=f"needs {roles}", ip=client_ip(request))
            raise HTTPException(status_code=403, detail="Forbidden")
        return user
    return checker
