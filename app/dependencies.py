from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer, HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
import uuid

from app.db.session import get_db
from app.core.security import decode_jwt
from app.models.user import User, Role
from app.models.token import TokenBlacklist

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login", auto_error=False)
bearer_scheme = HTTPBearer(auto_error=False)  # for refresh via header too

def get_current_user(db: Session = Depends(get_db), token: str | None = Depends(oauth2_scheme)) -> User:
    if not token:
        raise HTTPException(status_code=401, detail={"code": "not_authenticated", "message": "Missing token."})
    payload = decode_jwt(token)
    if payload.get("type") != "access":
        raise HTTPException(status_code=401, detail={"code": "wrong_token_type", "message": "Access token required."})
    # blacklist check
    black = db.query(TokenBlacklist).filter(TokenBlacklist.jti == payload["jti"]).first()
    if black:
        raise HTTPException(status_code=401, detail={"code": "token_revoked", "message": "Token revoked."})
    user_id = payload.get("sub")
    user = db.query(User).get(uuid.UUID(user_id))
    if not user or not user.is_active:
        raise HTTPException(status_code=403, detail={"code": "inactive_user", "message": "User is inactive."})
    return user

def require_roles(*roles: Role):
    def _dep(user: User = Depends(get_current_user)):
        if user.role not in roles:
            raise HTTPException(status_code=403, detail={"code": "insufficient_role", "message": "Insufficient permissions."})
        return user
    return _dep
