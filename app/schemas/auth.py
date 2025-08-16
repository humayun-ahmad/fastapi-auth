from pydantic import BaseModel, EmailStr

class RegisterIn(BaseModel):
    email: EmailStr
    full_name: str | None = None
    password: str

class LoginIn(BaseModel):
    email: EmailStr
    password: str

class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # seconds for access token

class RefreshIn(BaseModel):
    refresh_token: str | None = None  # allow body or header

class ChangePasswordIn(BaseModel):
    old_password: str
    new_password: str

class ForgotPasswordIn(BaseModel):
    email: EmailStr

class ResetPasswordIn(BaseModel):
    token: str
    new_password: str

class VerifyEmailIn(BaseModel):
    token: str
