"""
Custom Exceptions for Admin Panel

This module contains custom exceptions for the admin panel,
providing clear error handling and better error messages.
"""

import logging

from objects.utils import klogging


class AdminPanelError(Exception):
    """Base exception for admin panel errors."""
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        klogging.log(
            f"AdminPanelError raised: {message} (status: {status_code})",
            start_color=klogging.Ansi.LYELLOW,
            level=klogging.logLevel.WARNING,
            extra={"status_code": status_code, "error_type": "AdminPanelError"}
        )
        super().__init__(self.message)


class AuthenticationError(AdminPanelError):
    """Raised when authentication fails."""
    def __init__(self, message: str = "Please login first."):
        klogging.log(
            f"Authentication failed: {message}",
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "AuthenticationError"}
        )
        super().__init__(message, 401)


class AuthorizationError(AdminPanelError):
    """Raised when user lacks required permissions."""
    def __init__(self, message: str = "You have insufficient privileges."):
        klogging.log(
            f"Authorization failed: {message}",
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "AuthorizationError"}
        )
        super().__init__(message, 403)


class ValidationError(AdminPanelError):
    """Raised when input validation fails."""
    def __init__(self, message: str, field: str | None = None):
        self.field = field
        klogging.log(
            f"Validation failed: {message}" + (f" (field: {field})" if field else ""),
            start_color=klogging.Ansi.LYELLOW,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "ValidationError", "field": field}
        )
        super().__init__(message, 400)


class ResourceNotFoundError(AdminPanelError):
    """Raised when a requested resource is not found."""
    def __init__(self, resource_type: str, resource_id: int):
        self.resource_type = resource_type
        self.resource_id = resource_id
        message = f"{resource_type} with ID {resource_id} does not exist."
        klogging.log(
            f"Resource not found: {resource_type} (ID: {resource_id})",
            start_color=klogging.Ansi.LYELLOW,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "ResourceNotFoundError", "resource_type": resource_type, "resource_id": resource_id}
        )
        super().__init__(message, 404)


class AlreadyExistsError(AdminPanelError):
    """Raised when trying to create a resource that already exists."""
    def __init__(self, resource_type: str, identifier: str):
        message = f"{resource_type} with identifier '{identifier}' already exists."
        klogging.log(
            f"Resource already exists: {resource_type} (identifier: {identifier})",
            start_color=klogging.Ansi.LYELLOW,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "AlreadyExistsError", "resource_type": resource_type, "identifier": identifier}
        )
        super().__init__(message, 400)


class InvalidActionError(AdminPanelError):
    """Raised when an invalid action is requested."""
    def __init__(self, action: str):
        message = f"Invalid action: {action}"
        klogging.log(
            f"Invalid action requested: {action}",
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "InvalidActionError", "action": action}
        )
        super().__init__(message, 400)


class StateConflictError(AdminPanelError):
    """Raised when an action conflicts with the current state."""
    def __init__(self, message: str):
        klogging.log(
            f"State conflict: {message}",
            start_color=klogging.Ansi.LYELLOW,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "StateConflictError"}
        )
        super().__init__(message, 400)


class DatabaseError(AdminPanelError):
    """Raised when a database operation fails."""
    def __init__(self, message: str, original_error: Exception | None = None):
        self.original_error = original_error
        klogging.log(
            f"Database error: {message}",
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.ERROR,
            extra={"error_type": "DatabaseError", "original_error": str(original_error) if original_error else None}
        )
        super().__init__(message, 500)


class ExternalServiceError(AdminPanelError):
    """Raised when an external service call fails."""
    def __init__(self, service: str, message: str):
        self.service = service
        error_msg = f"Failed to communicate with {service}: {message}"
        klogging.log(
            error_msg,
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.ERROR,
            extra={"error_type": "ExternalServiceError", "service": service}
        )
        super().__init__(error_msg, 502)


class PasswordValidationError(AdminPanelError):
    """Raised when password validation fails."""
    def __init__(self, message: str):
        klogging.log(
            f"Password validation failed: {message}",
            start_color=klogging.Ansi.LYELLOW,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "PasswordValidationError"}
        )
        super().__init__(message, 400)


class PrivilegeError(AdminPanelError):
    """Raised when privilege checks fail."""
    def __init__(self, message: str):
        klogging.log(
            f"Privilege error: {message}",
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "PrivilegeError"}
        )
        super().__init__(message, 403)


class FormValidationError(AdminPanelError):
    """Raised when form data is missing or invalid."""
    def __init__(self, message: str, missing_fields: list[str] | None = None):
        self.missing_fields = missing_fields or []
        klogging.log(
            f"Form validation failed: {message}" + (f" (missing: {', '.join(missing_fields)})" if missing_fields else ""),
            start_color=klogging.Ansi.LYELLOW,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "FormValidationError", "missing_fields": missing_fields}
        )
        super().__init__(message, 400)


class MapStatusError(AdminPanelError):
    """Raised when map status operations fail."""
    def __init__(self, message: str):
        klogging.log(
            f"Map status error: {message}",
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "MapStatusError"}
        )
        super().__init__(message, 400)


class ScoreError(AdminPanelError):
    """Raised when score operations fail."""
    def __init__(self, message: str):
        klogging.log(
            f"Score error: {message}",
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "ScoreError"}
        )
        super().__init__(message, 400)


class BadgeError(AdminPanelError):
    """Raised when badge operations fail."""
    def __init__(self, message: str):
        klogging.log(
            f"Badge error: {message}",
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "BadgeError"}
        )
        super().__init__(message, 400)


class UserAccountError(AdminPanelError):
    """Raised when user account operations fail."""
    def __init__(self, message: str):
        klogging.log(
            f"User account error: {message}",
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "UserAccountError"}
        )
        super().__init__(message, 400)


class RateLimitError(AdminPanelError):
    """Raised when rate limiting is triggered."""
    def __init__(self, message: str = "Too many requests. Please try again later."):
        klogging.log(
            f"Rate limit exceeded: {message}",
            start_color=klogging.Ansi.LYELLOW,
            level=klogging.logLevel.WARNING,
            extra={"error_type": "RateLimitError"}
        )
        super().__init__(message, 429)


class ConfigurationError(AdminPanelError):
    """Raised when configuration is missing or invalid."""
    def __init__(self, message: str):
        klogging.log(
            f"Configuration error: {message}",
            start_color=klogging.Ansi.LRED,
            level=klogging.logLevel.ERROR,
            extra={"error_type": "ConfigurationError"}
        )
        super().__init__(message, 500)


def handle_admin_error(error: AdminPanelError) -> tuple:
    """
    Convert an AdminPanelError to a response tuple.

    Args:
        error: The AdminPanelError to handle

    Returns:
        tuple: (response_dict, status_code)
    """
    response = {
        "status": "error",
        "message": error.message
    }

    # Add additional context for specific error types
    if isinstance(error, ValidationError) and error.field:
        response["field"] = error.field

    if isinstance(error, FormValidationError) and error.missing_fields:
        response["missing_fields"] = error.missing_fields

    if isinstance(error, ResourceNotFoundError):
        response["resource_type"] = error.resource_type

    return response, error.status_code


__all__ = [
    'AdminPanelError',
    'AuthenticationError',
    'AuthorizationError',
    'ValidationError',
    'ResourceNotFoundError',
    'AlreadyExistsError',
    'InvalidActionError',
    'StateConflictError',
    'DatabaseError',
    'ExternalServiceError',
    'PasswordValidationError',
    'PrivilegeError',
    'FormValidationError',
    'MapStatusError',
    'ScoreError',
    'BadgeError',
    'UserAccountError',
    'RateLimitError',
    'ConfigurationError',
    'handle_admin_error',
]
