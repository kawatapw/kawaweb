"""
Blueprints package initialization.

This package contains all the blueprints for the application.
"""

from .admin import admin
from .frontend import frontend

__all__ = ['admin', 'frontend']
