from fastapi import Depends, HTTPException
from join_org_routes import get_current_org

ROLE_PERMISSIONS = {
    "admin": {
        "org:read",
        "org:invite",
        "org:update",
        "org:delete",
        "member:read",
        "member:remove",
    },
    "member": {
        "org:read",
        "member:read",
    },
}

def require_permissions(permission: str):
    def permission_checker(context = Depends(get_current_org)):
        role = context["role"]
        
        allowed_permissions = ROLE_PERMISSIONS.get(role, set())
        if permission not in allowed_permissions:
            raise HTTPException(status_code=403, detail="Forbidden: Insufficient permissions")

        return context
    return permission_checker