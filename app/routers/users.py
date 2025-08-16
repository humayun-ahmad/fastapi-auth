from fastapi import APIRouter, Depends
from app.dependencies import get_current_user, require_roles
from app.schemas.user import UserOut
from app.models.user import Role, User

router = APIRouter(prefix="/users", tags=["users"])

@router.get("/me", response_model=UserOut)
def me(current: User = Depends(get_current_user)):
    return UserOut.from_orm_user(current)

# Example RBAC-protected route (admin only)
@router.get("/admin/secret")
def admin_secret(current: User = Depends(require_roles(Role.admin))):
    return {"message": f"Hello admin {current.email}!"}
