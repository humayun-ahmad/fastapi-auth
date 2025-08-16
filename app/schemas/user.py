from pydantic import BaseModel, EmailStr
from typing import Optional
from enum import Enum

class Role(str, Enum):
    user = "user"
    admin = "admin"

class UserBase(BaseModel):
    email: EmailStr
    full_name: Optional[str] = None

class UserCreate(UserBase):
    password: str

class UserOut(UserBase):
    id: str
    is_active: bool
    role: Role
    email_verified: bool

    @classmethod
    def from_orm_user(cls, u):
        return cls(
            id=str(u.id),
            email=u.email,
            full_name=u.full_name,
            is_active=u.is_active,
            role=u.role.value,
            email_verified=bool(u.email_verified_at),
        )
