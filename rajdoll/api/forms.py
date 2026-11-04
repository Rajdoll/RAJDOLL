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
        for key in form:
            values = [value for value in form.getlist(key) if isinstance(value, str)]
            if values:
                # A repeated key (checkboxes with one name) becomes a list.
                fields[key] = values[0] if len(values) == 1 else values
    fields.pop("csrf_token", None)
    return fields


def as_list(value: Any) -> list[str]:
    """A field that may hold one value or several (checkboxes, JSON arrays)."""
    if value is None or value == "":
        return []
    if isinstance(value, list | tuple):
        return [str(item) for item in value]
    return [str(value)]
