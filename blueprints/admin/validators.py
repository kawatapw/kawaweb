"""
Input Validation for Admin Panel

This module provides validation functions for admin panel inputs,
ensuring data integrity and security.
"""

import logging
import re
from typing import Any

from objects.utils import klogging

from .exceptions import FormValidationError, ValidationError
from .models import ActionRequest, ActionType, BadgeRequest, MapRequest, UserListRequest


class Validator:
    """Base validator class with common validation methods."""

    @staticmethod
    def validate_required(value: Any, field_name: str) -> None:
        """Validate that a required field is present."""
        if value is None or (isinstance(value, str) and not value.strip()):
            klogging.log(f"Validation failed: {field_name} is required", level=logging.WARNING, extra={"field": field_name, "validation_type": "required"})
            raise ValidationError(f"{field_name} is required", field_name)

    @staticmethod
    def validate_string(value: Any, field_name: str, min_length: int = 1, max_length: int = 255) -> None:
        """Validate string field."""
        if not isinstance(value, str):
            klogging.log(f"Validation failed: {field_name} must be a string", level=logging.WARNING, extra={"field": field_name, "validation_type": "type_check", "expected_type": "str"})
            raise ValidationError(f"{field_name} must be a string", field_name)

        if len(value) < min_length:
            klogging.log(f"Validation failed: {field_name} too short (length={len(value)}, min={min_length})", level=logging.WARNING, extra={"field": field_name, "validation_type": "min_length", "actual_length": len(value), "min_length": min_length})
            raise ValidationError(f"{field_name} must be at least {min_length} characters", field_name)

        if len(value) > max_length:
            klogging.log(f"Validation failed: {field_name} too long (length={len(value)}, max={max_length})", level=logging.WARNING, extra={"field": field_name, "validation_type": "max_length", "actual_length": len(value), "max_length": max_length})
            raise ValidationError(f"{field_name} must be at most {max_length} characters", field_name)

    @staticmethod
    def validate_integer(value: Any, field_name: str, min_value: int | None = None, max_value: int | None = None) -> None:
        """Validate integer field."""
        if not isinstance(value, int):
            klogging.log(f"Validation failed: {field_name} must be an integer", level=logging.WARNING, extra={"field": field_name, "validation_type": "type_check", "expected_type": "int"})
            raise ValidationError(f"{field_name} must be an integer", field_name)

        if min_value is not None and value < min_value:
            klogging.log(f"Validation failed: {field_name} below minimum (value={value}, min={min_value})", level=logging.WARNING, extra={"field": field_name, "validation_type": "min_value", "actual_value": value, "min_value": min_value})
            raise ValidationError(f"{field_name} must be at least {min_value}", field_name)

        if max_value is not None and value > max_value:
            klogging.log(f"Validation failed: {field_name} above maximum (value={value}, max={max_value})", level=logging.WARNING, extra={"field": field_name, "validation_type": "max_value", "actual_value": value, "max_value": max_value})
            raise ValidationError(f"{field_name} must be at most {max_value}", field_name)

    @staticmethod
    def validate_email(value: str, field_name: str = "email") -> None:
        """Validate email format."""
        if not isinstance(value, str):
            klogging.log(f"Validation failed: {field_name} must be a string", level=logging.WARNING, extra={"field": field_name, "validation_type": "type_check"})
            raise ValidationError(f"{field_name} must be a string", field_name)

        # Basic email regex pattern
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        if not re.match(email_pattern, value):
            klogging.log(f"Validation failed: {field_name} is not a valid email address", level=logging.WARNING, extra={"field": field_name, "validation_type": "email_format", "value": value})
            raise ValidationError(f"{field_name} is not a valid email address", field_name)

    @staticmethod
    def validate_country_code(value: str, field_name: str = "country") -> None:
        """Validate country code (2-letter ISO code)."""
        if not isinstance(value, str):
            klogging.log(f"Validation failed: {field_name} must be a string", level=logging.WARNING, extra={"field": field_name, "validation_type": "type_check"})
            raise ValidationError(f"{field_name} must be a string", field_name)

        if len(value) != 2:
            klogging.log(f"Validation failed: {field_name} must be 2 characters (got {len(value)})", level=logging.WARNING, extra={"field": field_name, "validation_type": "length", "actual_length": len(value), "expected_length": 2})
            raise ValidationError(f"{field_name} must be a 2-letter country code", field_name)

        if not value.isalpha():
            klogging.log(f"Validation failed: {field_name} must contain only letters", level=logging.WARNING, extra={"field": field_name, "validation_type": "alpha_check", "value": value})
            raise ValidationError(f"{field_name} must contain only letters", field_name)

    @staticmethod
    def validate_password(value: str, field_name: str = "password") -> None:
        """Validate password strength."""
        if not isinstance(value, str):
            klogging.log(f"Validation failed: {field_name} must be a string", level=logging.WARNING, extra={"field": field_name, "validation_type": "type_check"})
            raise ValidationError(f"{field_name} must be a string", field_name)

        if len(value) < 8:
            klogging.log(f"Validation failed: {field_name} too short (length={len(value)}, min=8)", level=logging.WARNING, extra={"field": field_name, "validation_type": "min_length", "actual_length": len(value)})
            raise ValidationError(f"{field_name} must be at least 8 characters", field_name)

        if len(value) > 32:
            klogging.log(f"Validation failed: {field_name} too long (length={len(value)}, max=32)", level=logging.WARNING, extra={"field": field_name, "validation_type": "max_length", "actual_length": len(value)})
            raise ValidationError(f"{field_name} must be at most 32 characters", field_name)

    @staticmethod
    def validate_privileges(value: int, field_name: str = "privs") -> None:
        """Validate privilege value."""
        if not isinstance(value, int):
            klogging.log(f"Validation failed: {field_name} must be an integer", level=logging.WARNING, extra={"field": field_name, "validation_type": "type_check"})
            raise ValidationError(f"{field_name} must be an integer", field_name)

        if value < 0:
            klogging.log(f"Validation failed: {field_name} must be non-negative (got {value})", level=logging.WARNING, extra={"field": field_name, "validation_type": "range_check", "value": value})
            raise ValidationError(f"{field_name} must be a non-negative integer", field_name)

    @staticmethod
    def validate_duration(value: int, field_name: str = "duration") -> None:
        """Validate duration in hours."""
        if not isinstance(value, int):
            klogging.log(f"Validation failed: {field_name} must be an integer", level=logging.WARNING, extra={"field": field_name, "validation_type": "type_check"})
            raise ValidationError(f"{field_name} must be an integer", field_name)

        if value < 1:
            klogging.log(f"Validation failed: {field_name} must be at least 1 hour (got {value})", level=logging.WARNING, extra={"field": field_name, "validation_type": "min_value", "value": value})
            raise ValidationError(f"{field_name} must be at least 1 hour", field_name)

        if value > 8760:  # 1 year in hours
            klogging.log(f"Validation failed: {field_name} exceeds maximum (value={value}, max=8760)", level=logging.WARNING, extra={"field": field_name, "validation_type": "max_value", "value": value})
            raise ValidationError(f"{field_name} must be at most 8760 hours (1 year)", field_name)

    @staticmethod
    def validate_id(value: int, field_name: str = "id") -> None:
        """Validate ID value."""
        if not isinstance(value, int):
            klogging.log(f"Validation failed: {field_name} must be an integer", level=logging.WARNING, extra={"field": field_name, "validation_type": "type_check"})
            raise ValidationError(f"{field_name} must be an integer", field_name)

        if value < 1:
            klogging.log(f"Validation failed: {field_name} must be positive (got {value})", level=logging.WARNING, extra={"field": field_name, "validation_type": "range_check", "value": value})
            raise ValidationError(f"{field_name} must be a positive integer", field_name)

    @staticmethod
    def validate_sort_field(value: str, field_name: str = "sort") -> None:
        """Validate sort field."""
        valid_fields = ['id', 'name', 'creation_time', 'latest_activity', 'priv']
        if value not in valid_fields:
            klogging.log(f"Validation failed: {field_name} must be one of {valid_fields} (got '{value}')", level=logging.WARNING, extra={"field": field_name, "validation_type": "choice_check", "value": value, "valid_choices": valid_fields})
            raise ValidationError(
                f"{field_name} must be one of: {', '.join(valid_fields)}",
                field_name
            )

    @staticmethod
    def validate_sort_order(value: str, field_name: str = "order") -> None:
        """Validate sort order."""
        valid_orders = ['ASC', 'DESC']
        if value not in valid_orders:
            klogging.log(f"Validation failed: {field_name} must be one of {valid_orders} (got '{value}')", level=logging.WARNING, extra={"field": field_name, "validation_type": "choice_check", "value": value, "valid_choices": valid_orders})
            raise ValidationError(
                f"{field_name} must be one of: {', '.join(valid_orders)}",
                field_name
            )

    @staticmethod
    def validate_page(value: int, field_name: str = "page") -> None:
        """Validate page number."""
        if not isinstance(value, int):
            klogging.log(f"Validation failed: {field_name} must be an integer", level=logging.WARNING, extra={"field": field_name, "validation_type": "type_check"})
            raise ValidationError(f"{field_name} must be an integer", field_name)

        if value < 1:
            klogging.log(f"Validation failed: {field_name} must be at least 1 (got {value})", level=logging.WARNING, extra={"field": field_name, "validation_type": "range_check", "value": value})
            raise ValidationError(f"{field_name} must be at least 1", field_name)


class ActionRequestValidator:
    """Validator for action requests."""

    @staticmethod
    def validate(request: ActionRequest) -> None:
        """Validate action request."""
        errors = []

        # Validate action type
        if not request.action:
            errors.append("Action is required")

        # Validate based on action type
        if request.action in [
            ActionType.WIPE, ActionType.RESTRICT, ActionType.UNRESTRICT,
            ActionType.SILENCE, ActionType.UNSILENCE, ActionType.CHANGE_PASSWORD,
            ActionType.CHANGE_PRIVILEGES, ActionType.EDIT_ACCOUNT, ActionType.ADD_BADGE,
            ActionType.REMOVE_BADGE, ActionType.REMOVE_SCORE
        ]:
            if not request.user_id:
                errors.append("User ID is required for this action")
            else:
                try:
                    Validator.validate_id(request.user_id, "user_id")
                except ValidationError as e:
                    errors.append(str(e))

        if request.action in [
            ActionType.RANK, ActionType.APPROVE, ActionType.QUALIFY,
            ActionType.LOVE, ActionType.UNRANK, ActionType.COMPLETE_REQUEST
        ]:
            if not request.map_id:
                errors.append("Map ID is required for this action")
            else:
                try:
                    Validator.validate_id(request.map_id, "map_id")
                except ValidationError as e:
                    errors.append(str(e))

        if request.action == ActionType.SILENCE:
            if not request.duration:
                errors.append("Duration is required for silence action")
            else:
                try:
                    Validator.validate_duration(request.duration, "duration")
                except ValidationError as e:
                    errors.append(str(e))

        if request.action == ActionType.CHANGE_PASSWORD:
            if not request.password:
                errors.append("Password is required for changepassword action")
            else:
                try:
                    Validator.validate_password(request.password, "password")
                except ValidationError as e:
                    errors.append(str(e))

        if request.action == ActionType.CHANGE_PRIVILEGES:
            if request.privs is None:
                errors.append("Privileges are required for changeprivileges action")
            else:
                try:
                    Validator.validate_privileges(request.privs, "privs")
                except ValidationError as e:
                    errors.append(str(e))

        if request.action == ActionType.EDIT_ACCOUNT:
            required_fields = ['username', 'email', 'country', 'userpage_content']
            for field in required_fields:
                if not getattr(request, field):
                    errors.append(f"{field} is required for editaccount action")

            if request.username:
                try:
                    Validator.validate_string(request.username, "username", min_length=1, max_length=32)
                except ValidationError as e:
                    errors.append(str(e))

            if request.email:
                try:
                    Validator.validate_email(request.email, "email")
                except ValidationError as e:
                    errors.append(str(e))

            if request.country:
                try:
                    Validator.validate_country_code(request.country, "country")
                except ValidationError as e:
                    errors.append(str(e))

        if request.action in [ActionType.ADD_BADGE, ActionType.REMOVE_BADGE]:
            if not request.badge_id:
                errors.append("Badge ID is required for this action")
            else:
                try:
                    Validator.validate_id(request.badge_id, "badge_id")
                except ValidationError as e:
                    errors.append(str(e))

        if request.action == ActionType.REMOVE_SCORE:
            if not request.score_id:
                errors.append("Score ID is required for removescore action")
            else:
                try:
                    Validator.validate_id(request.score_id, "score_id")
                except ValidationError as e:
                    errors.append(str(e))

        if errors:
            raise FormValidationError("Validation failed", errors)


class UserListRequestValidator:
    """Validator for user list requests."""

    @staticmethod
    def validate(request: UserListRequest) -> None:
        """Validate user list request."""
        errors = []

        # Validate page
        try:
            Validator.validate_page(request.page, "page")
        except ValidationError as e:
            errors.append(str(e))

        # Validate sort field
        try:
            Validator.validate_sort_field(request.sort_by, "sort")
        except ValidationError as e:
            errors.append(str(e))

        # Validate sort order
        try:
            Validator.validate_sort_order(request.sort_order, "order")
        except ValidationError as e:
            errors.append(str(e))

        # Validate search (optional)
        if request.search is not None:
            try:
                Validator.validate_string(request.search, "search", min_length=0, max_length=100)
            except ValidationError as e:
                errors.append(str(e))

        # Validate filter_priv (optional)
        if request.filter_priv is not None:
            valid_filters = ['normal', 'supporter', 'mod', 'admin', 'restricted']
            if request.filter_priv not in valid_filters:
                errors.append(f"filter_priv must be one of: {', '.join(valid_filters)}")

        # Validate filter_country (optional)
        if request.filter_country is not None:
            try:
                Validator.validate_country_code(request.filter_country, "country")
            except ValidationError as e:
                errors.append(str(e))

        if errors:
            raise FormValidationError("Validation failed", errors)


class BadgeRequestValidator:
    """Validator for badge requests."""

    @staticmethod
    def validate(request: BadgeRequest, is_update: bool = False) -> None:
        """Validate badge request."""
        errors = []

        # For create requests, all fields are required
        if not is_update:
            if not request.name:
                errors.append("Name is required")
            if not request.description:
                errors.append("Description is required")
            if request.priority is None:
                errors.append("Priority is required")
            if not request.styles:
                errors.append("Styles are required")

        # Validate name if provided
        if request.name:
            try:
                Validator.validate_string(request.name, "name", min_length=1, max_length=100)
            except ValidationError as e:
                errors.append(str(e))

        # Validate description if provided
        if request.description:
            try:
                Validator.validate_string(request.description, "description", min_length=1, max_length=500)
            except ValidationError as e:
                errors.append(str(e))

        # Validate priority if provided
        if request.priority is not None:
            try:
                Validator.validate_integer(request.priority, "priority", min_value=0, max_value=1000)
            except ValidationError as e:
                errors.append(str(e))

        # Validate styles if provided
        if request.styles:
            if not isinstance(request.styles, list):
                errors.append("Styles must be a list")
            else:
                for i, style in enumerate(request.styles):
                    if not isinstance(style, dict):
                        errors.append(f"Style at index {i} must be a dictionary")
                    else:
                        if 'type' not in style:
                            errors.append(f"Style at index {i} is missing 'type' field")
                        if 'value' not in style:
                            errors.append(f"Style at index {i} is missing 'value' field")

        if errors:
            raise FormValidationError("Validation failed", errors)


class MapRequestValidator:
    """Validator for map request."""

    @staticmethod
    def validate(request: MapRequest) -> None:
        """Validate map request."""
        errors = []

        # Validate page
        try:
            Validator.validate_page(request.page, "page")
        except ValidationError as e:
            errors.append(str(e))

        if errors:
            raise FormValidationError("Validation failed", errors)


class FormValidator:
    """Validator for form data."""

    @staticmethod
    def validate_form_data(form_data: dict[str, Any], required_fields: list[str]) -> None:
        """Validate that all required fields are present in form data."""
        missing_fields = []

        for field in required_fields:
            if field not in form_data or not form_data[field]:
                missing_fields.append(field)

        if missing_fields:
            raise FormValidationError(
                f"Missing required fields: {', '.join(missing_fields)}",
                missing_fields
            )

    @staticmethod
    def validate_content_type(content_type: str) -> None:
        """Validate request content type."""
        if content_type != "application/x-www-form-urlencoded":
            raise ValidationError(
                "Invalid content type. Use application/x-www-form-urlencoded.",
                "content_type"
            )


__all__ = [
    'Validator',
    'ActionRequestValidator',
    'UserListRequestValidator',
    'BadgeRequestValidator',
    'MapRequestValidator',
    'FormValidator',
]
