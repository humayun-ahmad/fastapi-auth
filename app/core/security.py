import re
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Dict

import jwt
from passlib.context import CryptContext
from fastapi import HTTPException, status
from app.core.config import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

PASSWORD_RE = re.compile(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.{8,})")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def validate_password_rules(password: str):
    if not PASSWORD_RE.match(password):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"code": "weak_password", "message": "Password must be at least 8 chars, include upper, lower, and digit."},
        )

def _now() -> datetime:
    return datetime.now(timezone.utc)

def create_jwt_token(subject: str, token_type: str, minutes: int | None = None, days: int | None = None, extra_claims: Dict[str, Any] | None = None) -> dict:
    iat = _now()
    exp = iat + (timedelta(minutes=minutes) if minutes else timedelta(days=days or 0))
    jti = uuid.uuid4().hex
    payload = {
        "sub": subject,
        "jti": jti,
        "type": token_type,
        "aud": settings.SECURITY_TOKEN_AUDIENCE,
        "iat": int(iat.timestamp()),
        "nbf": int(iat.timestamp()),
        "exp": int(exp.timestamp()),
    }
    if extra_claims:
        payload.update(extra_claims)
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return {"token": token, "jti": jti, "exp": exp}

def decode_jwt(token: str) -> dict:
    return jwt.decode(
        token,
        settings.JWT_SECRET_KEY,
        algorithms=[settings.JWT_ALGORITHM],
        audience=settings.SECURITY_TOKEN_AUDIENCE
    )
