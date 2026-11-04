"""Reading request input the same way for HTML forms, htmx, and JSON clients."""

from typing import Any

from fastapi import Request


async def read_fields(request: Request) -> dict[str, Any]:
    """Merge query parameters with a JSON or form body (htmx 2 sends DELETE params in the URL)."""
    fields: dict[str, Any] = dict(request.query_params)
    content_type = request.headers.get("content-type", "")
    if content_type.startswith("application/json"):
        body = await request.json()
        if isinstance(body, dict):
            fields.update(body)
    elif content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
        form = await request.form()
        fields.update({key: value for key, value in form.items() if isinstance(value, str)})
    fields.pop("csrf_token", None)
    return fields
