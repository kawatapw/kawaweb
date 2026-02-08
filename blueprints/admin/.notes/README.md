# Admin Blueprint - Refactored Structure

## Overview

This is a refactored version of the admin blueprint with improved code organization, maintainability, and type safety.

## Key Improvements

### 1. Modular Structure
The admin blueprint has been reorganized into a modular structure with separate concerns:

```
kawaweb/blueprints/admin/
├── __init__.py          # Blueprint initialization
├── models.py            # Data models and DTOs
├── exceptions.py        # Custom exceptions
├── validators.py        # Input validation
├── repositories.py      # Database operations
├── services.py          # Business logic
├── routes.py            # Route definitions
├── utils.py             # Utility functions
└── README.md            # This file
```

### 2. Type Safety
- All data structures use Python dataclasses
- Type hints throughout the codebase
- Clear separation between DTOs and domain models

### 3. Error Handling
- Custom exception hierarchy for different error types
- Consistent error responses
- Proper error propagation and handling

### 4. Separation of Concerns
- **Models**: Data structures and DTOs
- **Repositories**: Database operations (CRUD)
- **Services**: Business logic and orchestration
- **Validators**: Input validation
- **Routes**: HTTP request handling
- **Utils**: Common utilities

### 5. Documentation
- Comprehensive docstrings for all classes and methods
- Clear module-level documentation
- Type hints for better IDE support

## Module Descriptions

### models.py
Contains data models and data transfer objects:
- `ActionType`: Enum for action types
- `TargetType`: Enum for target types
- `User`, `Map`, `Badge`: Domain models
- `Action`: Action model
- `ActionRequest`: Request DTO
- `ActionResponse`: Response DTO
- Various validation and request DTOs

### exceptions.py
Custom exception hierarchy:
- `AdminPanelError`: Base exception
- `AuthenticationError`: Authentication failures
- `AuthorizationError`: Permission failures
- `ValidationError`: Input validation failures
- `ResourceNotFoundError`: Resource not found
- `AlreadyExistsError`: Duplicate resource
- `InvalidActionError`: Invalid action type
- `StateConflictError`: State conflicts
- `DatabaseError`: Database failures
- `ExternalServiceError`: External service failures
- And more...

### validators.py
Input validation:
- `Validator`: Base validation methods
- `ActionRequestValidator`: Validates action requests
- `UserListRequestValidator`: Validates user list requests
- `BadgeRequestValidator`: Validates badge requests
- `MapRequestValidator`: Validates map requests
- `FormValidator`: Form data validation

### repositories.py
Database operations:
- `UserRepository`: User CRUD operations
- `MapRepository`: Map CRUD operations
- `BadgeRepository`: Badge CRUD operations
- `UserBadgeRepository`: User-badge relationships
- `ScoreRepository`: Score operations
- `StatsRepository`: Stats operations
- `MapRequestRepository`: Map request operations
- `LogRepository`: Log operations
- `ClientHashRepository`: Client hash operations
- `NewlyRankedRepository`: Newly ranked maps
- `ServerDataRepository`: Server data operations

### services.py
Business logic and orchestration:
- `PermissionService`: Permission checks
- `ActionService`: Action execution
- `DashboardService`: Dashboard operations
- `UserService`: User operations
- `BadgeService`: Badge operations
- `MapRequestService`: Map request operations
- `ServerDataService`: Server data operations

### routes.py
HTTP route definitions:
- `/action/<action_type>`: Execute admin actions
- `/`, `/home`, `/dashboard`: Dashboard
- `/users`, `/users/<page>`: User management
- `/user/<userid>`: User details
- `/badges`: Badge management
- `/badge/<badgeid>`: Badge details
- `/badge/<badgeid>/update`: Update badge
- `/badge/create`: Create badge
- `/beatmaps`, `/beatmaps/<page>`: Map request management
- `/stuffbroke`: Debug endpoint
- `/test`: Test endpoint

### utils.py
Utility functions:
- `SessionManager`: Session management
- `RequestValidator`: Request validation
- `DiscordLogger`: Discord webhook logging
- `ResponseFormatter`: Response formatting
- `PasswordManager`: Password operations
- `PrivilegeChecker`: Privilege checks
- `MapStatusUpdater`: Map status updates
- `ScoreManager`: Score operations
- `StatsManager`: Stats operations
- `FormValidator`: Form validation
- `ErrorCatcher`: Error handling decorator

## Usage

### Importing the Blueprint

```python
from blueprints.admin import admin
```

### Using Services

```python
from blueprints.admin.services import ActionService, UserService
from blueprints.admin.repositories import UserRepository

# Initialize repositories
user_repo = UserRepository()

# Initialize services
action_service = ActionService(user_repo, ...)
user_service = UserService(user_repo, ...)
```

### Handling Errors

```python
from blueprints.admin.exceptions import AdminPanelError, ValidationError

try:
    # Your code here
    pass
except ValidationError as e:
    # Handle validation error
    return jsonify({"status": "error", "message": e.message}), e.status_code
except AdminPanelError as e:
    # Handle admin panel error
    return jsonify({"status": "error", "message": e.message}), e.status_code
```

### Creating Actions

```python
from blueprints.admin.models import ActionRequest, ActionType
from blueprints.admin.services import ActionService

# Create action request
request = ActionRequest(
    action=ActionType.WIPE,
    reason="Test reason",
    user_id=123,
    # ... other fields
)

# Create and execute action
action_service = ActionService(...)
action = await action_service.create_action(request, mod_id=456)
response = await action_service.execute_action(action, request)
```

## Benefits

### Before (Monolithic Structure)
- Single 2492-line file
- Repetitive code patterns
- Inconsistent error handling
- Hard to maintain
- Difficult to test
- Poor type safety

### After (Modular Structure)
- Multiple focused files
- DRY (Don't Repeat Yourself) principles
- Consistent error handling
- Easy to maintain
- Easy to test
- Full type safety
- Clear separation of concerns

## Testing

The modular structure makes testing easier:

```python
# Test a service in isolation
from blueprints.admin.services import UserService
from blueprints.admin.repositories import MockUserRepository

mock_repo = MockUserRepository()
user_service = UserService(mock_repo)

# Test the service
result = await user_service.get_user_detail(123)
```

## Migration Guide

To migrate from the old structure:

1. Update imports:
   ```python
   # Old
   from blueprints.admin import admin
   
   # New (same, but now uses modular structure)
   from blueprints.admin import admin
   ```

2. Use services instead of direct database calls:
   ```python
   # Old
   user = await glob.db.fetch("SELECT * FROM users WHERE id = %s", [user_id])
   
   # New
   from blueprints.admin.repositories import UserRepository
   user_repo = UserRepository()
   user = await user_repo.get_by_id(user_id)
   ```

3. Use exceptions instead of manual error handling:
   ```python
   # Old
   if not user:
       return jsonify({"status": "error", "message": "User not found"}), 404
   
   # New
   from blueprints.admin.exceptions import ResourceNotFoundError
   if not user:
       raise ResourceNotFoundError("User", user_id)
   ```

## Future Improvements

- Add unit tests for each module
- Add integration tests
- Add caching layer
- Add rate limiting
- Add audit logging
- Add API documentation (OpenAPI/Swagger)
- Add GraphQL support
- Add WebSocket support for real-time updates

## Contributing

When contributing to this module:

1. Follow the existing structure
2. Add type hints to all new code
3. Add docstrings to all new classes and methods
4. Add unit tests for new functionality
5. Update this README if adding new modules

## License

This module is part of the Kawata project and follows the same license.
