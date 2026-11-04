"""Top-level pages."""

from fastapi import APIRouter, Depends, Request
from fastapi.responses import Response

from rajdoll.api.deps import current_session
from rajdoll.api.render import respond
from rajdoll.services.auth import ActiveSession

router = APIRouter()


@router.get("/")
def home(request: Request, _: ActiveSession = Depends(current_session)) -> Response:
    # The engagement list arrives in F2; until then the home page explains what exists.
    return respond(request, "home.html", {"active_nav": "engagements"}, data={"engagements": []})
