import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import hash_password, verify_password, validate_password_rules, create_jwt_token, decode_jwt, _now
from app.models.user import User, Role
from app.models.token import RefreshToken, TokenBlacklist
from app.models.email_token import EmailToken, EmailTokenPurpose
from app.core.config import settings

def register_user(db: Session, email: str, password: str, full_name: Optional[str]) -> User:
    validate_password_rules(password)
    existing = db.query(User).filter(User.email == email).first()
    if existing:
        raise HTTPException(status_code=409, detail={"code": "email_taken", "message": "Email already registered."})
    u = User(email=email, hashed_password=hash_password(password), full_name=full_name, role=Role.user)
    db.add(u)
    db.commit()
    db.refresh(u)
    return u

def issue_tokens(db: Session, user: User, parent_refresh_jti: Optional[str] = None) -> dict:
    access = create_jwt_token(str(user.id), "access", minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES, extra_claims={"role": user.role.value})
    refresh = create_jwt_token(str(user.id), "refresh", days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    # store refresh token for rotation
    rt = RefreshToken(
        jti=refresh["jti"],
        user_id=user.id,
        parent_jti=parent_refresh_jti,
        revoked=False,
        expires_at=refresh["exp"],
    )
    db.add(rt)
    db.commit()
    return {
        "access_token": access["token"],
        "refresh_token": refresh["token"],
        "access_jti": access["jti"],
        "refresh_jti": refresh["jti"],
        "access_exp": access["exp"],
    }

def login(db: Session, email: str, password: str) -> dict:
    user = db.query(User).filter(User.email == email).first()
    if not user or not verify_password(password, user.hashed_password):
        raise HTTPException(status_code=401, detail={"code": "invalid_credentials", "message": "Invalid email or password."})
    if not user.is_active:
        raise HTTPException(status_code=403, detail={"code": "inactive_user", "message": "User is inactive."})
    return issue_tokens(db, user)

def refresh_tokens(db: Session, token_str: str) -> dict:
    payload = decode_jwt(token_str)
    if payload.get("type") != "refresh":
        raise HTTPException(status_code=400, detail={"code": "wrong_token_type", "message": "Expected refresh token."})
    jti = payload.get("jti")
    user_id = payload.get("sub")

    rt = db.query(RefreshToken).filter(RefreshToken.jti == jti).first()
    if not rt or rt.revoked:
        raise HTTPException(status_code=401, detail={"code": "refresh_revoked", "message": "Refresh token is invalidated."})
    if rt.expires_at < _now():
        raise HTTPException(status_code=401, detail={"code": "refresh_expired", "message": "Refresh token expired."})

    user = db.query(User).get(uuid.UUID(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail={"code": "inactive_user", "message": "User is inactive."})

    # rotate: revoke current, issue new
    rt.revoked = True
    db.add(rt)
    db.commit()
    return issue_tokens(db, user, parent_refresh_jti=jti)

def logout(db: Session, access_token: str | None, refresh_token: str | None):
    # blacklist access token if provided
    if access_token:
        payload = decode_jwt(access_token)
        if payload.get("type") == "access":
            db.add(TokenBlacklist(jti=payload["jti"], expires_at=datetime.fromtimestamp(payload["exp"], tz=timezone.utc), reason="logout"))
            db.commit()
    # revoke refresh token if provided
    if refresh_token:
        payload = decode_jwt(refresh_token)
        if payload.get("type") == "refresh":
            rt = db.query(RefreshToken).filter(RefreshToken.jti == payload["jti"]).first()
            if rt and not rt.revoked:
                rt.revoked = True
                db.add(rt)
                db.commit()

def create_email_token(db: Session, user: User, purpose: EmailTokenPurpose, expires_in_minutes: int = 60) -> str:
    tok = create_jwt_token(str(user.id), "email", minutes=expires_in_minutes, extra_claims={"purpose": purpose.value})
    et = EmailToken(
        jti=tok["jti"],
        user_id=user.id,
        purpose=purpose,
        expires_at=tok["exp"],
        used=False
    )
    db.add(et)
    db.commit()
    # In a real app, send email here. For the tutorial we return the token so you can test.
    return tok["token"]

def use_email_token(db: Session, token_str: str, expected_purpose: EmailTokenPurpose) -> User:
    payload = decode_jwt(token_str)
    if payload.get("type") != "email" or payload.get("purpose") != expected_purpose.value:
        raise HTTPException(status_code=400, detail={"code": "invalid_email_token", "message": "Bad email token."})
    et = db.query(EmailToken).filter(EmailToken.jti == payload["jti"]).first()
    if not et or et.used or et.expires_at < _now():
        raise HTTPException(status_code=400, detail={"code": "email_token_used_or_expired", "message": "Token invalid or expired."})
    user = db.query(User).get(uuid.UUID(payload["sub"]))
    if not user:
        raise HTTPException(status_code=404, detail={"code": "user_not_found", "message": "User not found."})
    et.used = True
    db.add(et)
    db.commit()
    return user
