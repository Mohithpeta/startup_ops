from fastapi import APIRouter, Depends, HTTPException
from rbac import require_permission
from database import organizations_collection

router = APIRouter(tags=["orgs"])

# -------------------------------------------------
# INVITE MEMBER (ADMIN ONLY)
# -------------------------------------------------

@router.post("/orgs/{org_id}/invite")
async def invite_member(
    context: dict = Depends(require_permission("org:invite"))
):
    org_id = context["org_id"]
    user_id = context["user_id"]

    # Invitation logic placeholder (email / token / DB record)

    return {
        "message": "Invitation sent successfully",
        "organization_id": org_id,
        "invited_by": user_id,
    }

# -------------------------------------------------
# READ ORGANIZATION (ADMIN + MEMBER)
# -------------------------------------------------

@router.get("/orgs/{org_id}")
async def get_org(
    context: dict = Depends(require_permission("org:read"))
):
    org_id = context["org_id"]
    user_id = context["user_id"]

    org = await organizations_collection.find_one({"_id": org_id})
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")

    return {
        "organization_id": org_id,
        "name": org.get("name"),
        "requested_by": user_id,
    }

# -------------------------------------------------
# DELETE ORGANIZATION (ADMIN ONLY)
# -------------------------------------------------

@router.delete("/orgs/{org_id}")
async def delete_org(
    context: dict = Depends(require_permission("org:delete"))
):
    org_id = context["org_id"]
    user_id = context["user_id"]

    result = await organizations_collection.delete_one({"_id": org_id})

    if result.deleted_count == 0:
        raise HTTPException(status_code=404, detail="Organization not found")

    return {
        "message": "Organization deleted successfully",
        "organization_id": org_id,
        "deleted_by": user_id,
    }