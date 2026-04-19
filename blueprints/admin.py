# -*- coding: utf-8 -*-
"""
Admin Blueprint - Refactored Version

This is the main entry point for the admin blueprint.
It imports the modular structure from the admin package.

The new structure provides:
- Better separation of concerns
- Type safety with dataclasses
- Comprehensive error handling
- Improved maintainability
- Clear documentation

Structure:
- admin/__init__.py: Blueprint initialization
- admin/models.py: Data models and DTOs
- admin/exceptions.py: Custom exceptions
- admin/validators.py: Input validation
- admin/repositories.py: Database operations
- admin/services.py: Business logic
- admin/routes.py: Route definitions
- admin/utils.py: Utility functions
"""

# Import the admin blueprint from the new modular structure
from .admin import admin

__all__ = ['admin']
