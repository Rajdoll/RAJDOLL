"""Errors raised by the service layer. Messages are Indonesian and safe to show the user."""

from dataclasses import dataclass


@dataclass(frozen=True)
class FieldError:
    field: str
    message: str


class ServiceError(Exception):
    """Base class; `status_code` and `code` map onto the BSD 10.1 error format."""

    status_code = 400
    code = "invalid_request"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ValidationFailed(ServiceError):
    status_code = 422
    code = "validation_failed"

    def __init__(self, errors: list[FieldError]) -> None:
        super().__init__("; ".join(e.message for e in errors))
        self.field_errors = errors

    @property
    def errors(self) -> list[str]:
        return [e.message for e in self.field_errors]

    @classmethod
    def one(cls, field: str, message: str) -> "ValidationFailed":
        return cls([FieldError(field, message)])


class NotFound(ServiceError):
    status_code = 404
    code = "not_found"


class Conflict(ServiceError):
    status_code = 409
    code = "conflict"
