from fastapi import APIRouter, Depends, Header, Request, HTTPException, status
from sqlalchemy.orm import Session
from typing import Optional

from app.db.session import get_db
from app.schemas.auth import RegisterIn, LoginIn, TokenOut, RefreshIn, ChangePasswordIn, ForgotPasswordIn, ResetPasswordIn, VerifyEmailIn
from app.schemas.user import UserOut
from app.services.auth import register_user, login, refresh_tokens, logout, create_email_token, use_email_token
from app.core.security import validate_password_rules, hash_password, verify_password
from app.models.email_token import EmailTokenPurpose
from app.dependencies import bearer_scheme

router = APIRouter(prefix="/auth", tags=["auth"])

@router.post("/register", response_model=UserOut, status_code=201)
def register(payload: RegisterIn, db: Session = Depends(get_db)):
    user = register_user(db, payload.email, payload.password, payload.full_name)
    # auto-issue a verification email token (print/return via logs)
    token = create_email_token(db, user, EmailTokenPurpose.verify_email)
    print(f"[DEV ONLY] Email verification token for {user.email}:\n{token}")
    return UserOut.from_orm_user(user)

@router.post("/login", response_model=TokenOut)
def login_route(payload: LoginIn, db: Session = Depends(get_db)):
    t = login(db, payload.email, payload.password)
    return {
        "access_token": t["access_token"],
        "refresh_token": t["refresh_token"],
        "token_type": "bearer",
        "expires_in": 60 *  settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    }

@router.post("/refresh", response_model=TokenOut)
def refresh_route(
    payload: RefreshIn,
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None, alias="Authorization")
):
    token = payload.refresh_token
    if (not token) and authorization and authorization.lower().startswith("bearer "):
        token = authorization.split(" ", 1)[1]
    if not token:
        raise HTTPException(status_code=400, detail={"code": "missing_refresh", "message": "Provide refresh token in body or Authorization header."})

    t = refresh_tokens(db, token)
    return {
        "access_token": t["access_token"],
        "refresh_token": t["refresh_token"],
        "token_type": "bearer",
        "expires_in": 60 * settings.ACCESS_TOKEN_EXPIRE_MINUTES,
    }

@router.post("/logout", status_code=204)
def logout_route(
    db: Session = Depends(get_db),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    refresh_auth: Optional[str] = Header(default=None, alias="X-Refresh-Token")
):
    access_token = None
    refresh_token = None
    if authorization and authorization.lower().startswith("bearer "):
        access_token = authorization.split(" ", 1)[1]
    if refresh_auth and refresh_auth.lower().startswith("bearer "):
        refresh_token = refresh_auth.split(" ", 1)[1]
    logout(db, access_token, refresh_token)
    return

@router.post("/change-password", status_code=204)
def change_password(
    payload: ChangePasswordIn,
    db: Session = Depends(get_db),
    # use current access token to identify user
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail={"code": "not_authenticated", "message": "Missing access token."})
    access_token = authorization.split(" ", 1)[1]
    from app.core.security import decode_jwt
    p = decode_jwt(access_token)
    if p.get("type") != "access":
        raise HTTPException(status_code=401, detail={"code": "wrong_token_type", "message": "Use access token."})
    import uuid
    from app.models.user import User
    user = db.query(User).get(uuid.UUID(p["sub"]))
    if not user:
        raise HTTPException(status_code=404, detail={"code": "user_not_found", "message": "User not found."})
    if not verify_password(payload.old_password, user.hashed_password):
        raise HTTPException(status_code=400, detail={"code": "bad_old_password", "message": "Old password incorrect."})
    validate_password_rules(payload.new_password)
    user.hashed_password = hash_password(payload.new_password)
    db.add(user)
    db.commit()
    return

@router.post("/forgot-password", status_code=200)
def forgot_password(payload: ForgotPasswordIn, db: Session = Depends(get_db)):
    from app.models.user import User
    user = db.query(User).filter(User.email == payload.email).first()
    # Do not leak user existence. Still generate a token if exists.
    if user:
        token = create_email_token(db, user, EmailTokenPurpose.reset_password)
        print(f"[DEV ONLY] Password reset token for {user.email}:\n{token}")
    return {"detail": "If the email exists, a reset link was issued."}

@router.post("/reset-password", status_code=204)
def reset_password(payload: ResetPasswordIn, db: Session = Depends(get_db)):
    validate_password_rules(payload.new_password)
    user = use_email_token(db, payload.token, EmailTokenPurpose.reset_password)
    user.hashed_password = hash_password(payload.new_password)
    db.add(user)
    db.commit()
    return

@router.post("/verify-email", status_code=204)
def verify_email(payload: VerifyEmailIn, db: Session = Depends(get_db)):
    user = use_email_token(db, payload.token, EmailTokenPurpose.verify_email)
    from datetime import datetime
    user.email_verified_at = datetime.utcnow()
    db.add(user)
    db.commit()
    return
