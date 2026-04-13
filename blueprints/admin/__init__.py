"""
Admin Blueprint Module

This module provides a refactored, modular admin panel with improved:
- Separation of concerns
- Type safety
- Error handling
- Maintainability
- Documentation

Structure:
- models.py: Data models and DTOs
- exceptions.py: Custom exceptions
- validators.py: Input validation
- repositories.py: Database operations
- services.py: Business logic
- actions.py: Action handlers
- routes.py: Route definitions
- utils.py: Utility functions
"""

from quart import Blueprint

# Create the admin blueprint
admin = Blueprint('admin', __name__)

# Import routes to register them
from . import routes #noqa

__all__ = ['admin', 'routes']
