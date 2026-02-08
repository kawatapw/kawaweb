# -*- coding: utf-8 -*-
"""
Custom Exceptions for Admin Panel

This module contains custom exceptions for the admin panel,
providing clear error handling and better error messages.
"""

from typing import Optional, List


class AdminPanelError(Exception):
    """Base exception for admin panel errors."""
    def __init__(self, message: str, status_code: int = 400):
        self.message = message
        self.status_code = status_code
        super().__init__(self.message)


class AuthenticationError(AdminPanelError):
    """Raised when authentication fails."""
    def __init__(self, message: str = "Please login first."):
        super().__init__(message, 401)


class AuthorizationError(AdminPanelError):
    """Raised when user lacks required permissions."""
    def __init__(self, message: str = "You have insufficient privileges."):
        super().__init__(message, 403)


class ValidationError(AdminPanelError):
    """Raised when input validation fails."""
    def __init__(self, message: str, field: Optional[str] = None):
        self.field = field
        super().__init__(message, 400)


class ResourceNotFoundError(AdminPanelError):
    """Raised when a requested resource is not found."""
    def __init__(self, resource_type: str, resource_id: int):
        message = f"{resource_type} with ID {resource_id} does not exist."
        super().__init__(message, 404)


class AlreadyExistsError(AdminPanelError):
    """Raised when trying to create a resource that already exists."""
    def __init__(self, resource_type: str, identifier: str):
        message = f"{resource_type} with identifier '{identifier}' already exists."
        super().__init__(message, 400)


class InvalidActionError(AdminPanelError):
    """Raised when an invalid action is requested."""
    def __init__(self, action: str):
        message = f"Invalid action: {action}"
        super().__init__(message, 400)


class StateConflictError(AdminPanelError):
    """Raised when an action conflicts with the current state."""
    def __init__(self, message: str):
        super().__init__(message, 400)


class DatabaseError(AdminPanelError):
    """Raised when a database operation fails."""
    def __init__(self, message: str, original_error: Optional[Exception] = None):
        self.original_error = original_error
        super().__init__(message, 500)


class ExternalServiceError(AdminPanelError):
    """Raised when an external service call fails."""
    def __init__(self, service: str, message: str):
        self.service = service
        super().__init__(f"Failed to communicate with {service}: {message}", 502)


class PasswordValidationError(AdminPanelError):
    """Raised when password validation fails."""
    def __init__(self, message: str):
        super().__init__(message, 400)


class PrivilegeError(AdminPanelError):
    """Raised when privilege checks fail."""
    def __init__(self, message: str):
        super().__init__(message, 403)


class FormValidationError(AdminPanelError):
    """Raised when form data is missing or invalid."""
    def __init__(self, message: str, missing_fields: Optional[List[str]] = None):
        self.missing_fields = missing_fields or []
        super().__init__(message, 400)


class MapStatusError(AdminPanelError):
    """Raised when map status operations fail."""
    def __init__(self, message: str):
        super().__init__(message, 400)


class ScoreError(AdminPanelError):
    """Raised when score operations fail."""
    def __init__(self, message: str):
        super().__init__(message, 400)


class BadgeError(AdminPanelError):
    """Raised when badge operations fail."""
    def __init__(self, message: str):
        super().__init__(message, 400)


class UserAccountError(AdminPanelError):
    """Raised when user account operations fail."""
    def __init__(self, message: str):
        super().__init__(message, 400)


class RateLimitError(AdminPanelError):
    """Raised when rate limiting is triggered."""
    def __init__(self, message: str = "Too many requests. Please try again later."):
        super().__init__(message, 429)


class ConfigurationError(AdminPanelError):
    """Raised when configuration is missing or invalid."""
    def __init__(self, message: str):
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
        response["resource_type"] = error.__class__.__name__.replace("Error", "").replace("Resource", "")
    
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
