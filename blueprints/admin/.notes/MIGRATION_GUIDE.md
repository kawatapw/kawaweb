# Migration Guide: Old Admin Blueprint to New Modular Structure

## Overview

This guide explains how to migrate from the old monolithic admin blueprint to the new modular structure.

## What Changed?

### Old Structure (Monolithic)
```
kawaweb/blueprints/admin.py (2492 lines)
```

### New Structure (Modular)
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
└── README.md            # Documentation
```

## Key Changes

### 1. Import Changes

#### Old Way
```python
from blueprints.admin import admin
```

#### New Way (Same, but uses modular structure)
```python
from blueprints.admin import admin
```

The import is the same, but now it imports from the modular structure.

### 2. Database Operations

#### Old Way
```python
# Direct database calls scattered throughout
user = await glob.db.fetch("SELECT * FROM users WHERE id = %s", [user_id])
await glob.db.execute("UPDATE users SET priv = 0 WHERE id = %s", [user_id])
```

#### New Way
```python
from blueprints.admin.repositories import UserRepository

user_repo = UserRepository()
user = await user_repo.get_by_id(user_id)
await user_repo.restrict(user_id)
```

### 3. Error Handling

#### Old Way
```python
# Manual error handling
if not user:
    return jsonify({"status": "error", "message": "User not found"}), 404

try:
    # Some code
except Exception as e:
    return jsonify({"status": "error", "message": str(e)}), 400
```

#### New Way
```python
from blueprints.admin.exceptions import ResourceNotFoundError, ValidationError

# Exceptions are raised and handled automatically
if not user:
    raise ResourceNotFoundError("User", user_id)

# Validation is centralized
from blueprints.admin.validators import ActionRequestValidator
ActionRequestValidator.validate(request)
```

### 4. Action Execution

#### Old Way
```python
# Large if-elif chain in main action function
if a == "wipe":
    # ... 100+ lines of code
elif a == "restrict":
    # ... 100+ lines of code
# ... and so on
```

#### New Way
```python
from blueprints.admin.services import ActionService
from blueprints.admin.models import ActionRequest, ActionType

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

### 5. Type Safety

#### Old Way
```python
# No type hints
def some_function(data):
    # What type is data?
    # What does this function return?
    pass
```

#### New Way
```python
from typing import Optional
from blueprints.admin.models import User

# Full type hints
async def get_user(user_id: int) -> Optional[User]:
    """Get user by ID."""
    pass
```

### 6. Validation

#### Old Way
```python
# Manual validation scattered throughout
if form.get("user") is None:
    return jsonify({"status": "error", "message": "No user specified."}), 400

if not 8 < len(password) <= 32:
    return jsonify({"status": "error", "message": "Password must be between 8 and 32 characters."}), 400
```

#### New Way
```python
from blueprints.admin.validators import ActionRequestValidator, Validator
from blueprints.admin.models import ActionRequest

# Centralized validation
request = ActionRequest(...)
ActionRequestValidator.validate(request)

# Or individual field validation
Validator.validate_password(password, "password")
Validator.validate_email(email, "email")
```

### 7. Logging

#### Old Way
```python
# Manual logging
await log(action)  # Global function
```

#### New Way
```python
from blueprints.admin.repositories import LogRepository

log_repo = LogRepository()
await log_repo.create(
    action_id=action.id,
    action=action.action.value,
    reason=action.reason,
    mod_id=action.mod_id,
    target_id=action.target_id,
    target_type=action.target_type
)
```

### 8. Discord Webhooks

#### Old Way
```python
# Manual webhook creation
webhook = DiscordWebhook(glob.config.ADMIN_WEBHOOK_URL)
embed = DiscordEmbed(...)
webhook.add_embed(embed)
webhook.execute()
```

#### New Way
```python
from blueprints.admin.utils import DiscordLogger

discord_logger = DiscordLogger(
    glob.config.ADMIN_WEBHOOK_URL,
    glob.config.RANKED_WEBHOOK_URL
)

discord_logger.log_user_action(action, mod_name, mod_id, user_name, user_id)
```

## Migration Steps

### Step 1: Update Imports

Update your imports to use the new structure:

```python
# Old imports (remove these)
# from blueprints.admin import admin  # This still works!

# New imports (add these)
from blueprints.admin.repositories import (
    UserRepository, MapRepository, BadgeRepository,
    UserBadgeRepository, ScoreRepository, StatsRepository,
    MapRequestRepository, LogRepository, ClientHashRepository,
    NewlyRankedRepository, ServerDataRepository
)

from blueprints.admin.services import (
    PermissionService, ActionService, DashboardService,
    UserService, BadgeService, MapRequestService, ServerDataService
)

from blueprints.admin.models import (
    ActionType, TargetType, User, Map, Badge, Action,
    ActionRequest, ActionResponse, UserListRequest, BadgeRequest, MapRequest
)

from blueprints.admin.exceptions import (
    AdminPanelError, AuthenticationError, AuthorizationError,
    ValidationError, ResourceNotFoundError, AlreadyExistsError,
    InvalidActionError, StateConflictError, DatabaseError,
    ExternalServiceError, PasswordValidationError, PrivilegeError,
    FormValidationError, MapStatusError, ScoreError, BadgeError,
    UserAccountError, RateLimitError, ConfigurationError
)

from blueprints.admin.validators import (
    Validator, ActionRequestValidator, UserListRequestValidator,
    BadgeRequestValidator, MapRequestValidator, FormValidator
)

from blueprints.admin.utils import (
    SessionManager, RequestValidator, DiscordLogger,
    ResponseFormatter, PasswordManager, PrivilegeChecker,
    MapStatusUpdater, ScoreManager, StatsManager, FormValidator,
    ErrorCatcher
)
```

### Step 2: Replace Database Calls

Replace direct database calls with repository methods:

```python
# Old
user = await glob.db.fetch("SELECT * FROM users WHERE id = %s", [user_id])

# New
user_repo = UserRepository()
user = await user_repo.get_by_id(user_id)
```

### Step 3: Replace Error Handling

Replace manual error handling with exceptions:

```python
# Old
if not user:
    return jsonify({"status": "error", "message": "User not found"}), 404

# New
if not user:
    raise ResourceNotFoundError("User", user_id)
```

### Step 4: Replace Action Logic

Replace the large if-elif chain with service calls:

```python
# Old
if a == "wipe":
    # ... 100+ lines of code
elif a == "restrict":
    # ... 100+ lines of code

# New
from blueprints.admin.services import ActionService
from blueprints.admin.models import ActionRequest, ActionType

action_service = ActionService(...)
request = ActionRequest(action=ActionType.WIPE, ...)
action = await action_service.create_action(request, mod_id)
response = await action_service.execute_action(action, request)
```

### Step 5: Replace Validation

Replace manual validation with validator classes:

```python
# Old
if form.get("user") is None:
    return jsonify({"status": "error", "message": "No user specified."}), 400

# New
from blueprints.admin.validators import ActionRequestValidator
from blueprints.admin.models import ActionRequest

request = ActionRequest(...)
ActionRequestValidator.validate(request)
```

### Step 6: Replace Logging

Replace manual logging with repository methods:

```python
# Old
await log(action)

# New
from blueprints.admin.repositories import LogRepository

log_repo = LogRepository()
await log_repo.create(
    action_id=action.id,
    action=action.action.value,
    reason=action.reason,
    mod_id=action.mod_id,
    target_id=action.target_id,
    target_type=action.target_type
)
```

### Step 7: Replace Discord Webhooks

Replace manual webhook creation with DiscordLogger:

```python
# Old
webhook = DiscordWebhook(glob.config.ADMIN_WEBHOOK_URL)
embed = DiscordEmbed(...)
webhook.add_embed(embed)
webhook.execute()

# New
from blueprints.admin.utils import DiscordLogger

discord_logger = DiscordLogger(
    glob.config.ADMIN_WEBHOOK_URL,
    glob.config.RANKED_WEBHOOK_URL
)

discord_logger.log_user_action(action, mod_name, mod_id, user_name, user_id)
```

## Example: Complete Migration

### Before (Old Code)
```python
@admin.route("/action/<a>", methods=["POST"])
@error_catcher
async def action(a: str):
    if not "authenticated" in session:
        return jsonify({"status": "error", "message": "Please login first."}), 401
    
    form = await request.form
    if not form:
        return jsonify({"status": "error", "message": "No form data provided."}), 400
    
    if form.get("user") is None:
        return jsonify({"status": "error", "message": "No user specified."}), 400
    
    try:
        action = await Action.create(a, form.get("reason"), form.get("user"))
    except ValueError as e:
        return jsonify({"status": "error", "message": str(e)}), 400
    
    try:
        if Privileges.WipeUsers not in GetPriv(action.mod.priv):
            return jsonify({"status": "error", "message": "You do not have permission to wipe users."}), 403
        
        # ... 100+ lines of database operations
        
        await log(action)
        
        return jsonify({"status": "success", "message": f"Successfully wiped {action.user.name}."}), 200
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 400
```

### After (New Code)
```python
@admin.route("/action/<action_type>", methods=["POST"])
@error_catcher
async def action(action_type: str):
    # Validate authentication
    SessionManager.require_authentication()
    
    # Validate content type
    RequestValidator.validate_content_type()
    
    # Get form data
    form = await RequestValidator.get_form_data()
    
    # Parse action type
    try:
        action_enum = ActionType(action_type)
    except ValueError:
        raise InvalidActionError(action_type)
    
    # Build action request
    request_data = ActionRequest(
        action=action_enum,
        reason=form.get("reason"),
        user_id=int(form.get("user")) if form.get("user") else None,
        # ... other fields
    )
    
    # Get current user ID
    mod_id = SessionManager.get_user_id()
    
    # Create and execute action
    action_service = ActionService(...)
    action_obj = await action_service.create_action(request_data, mod_id)
    response = await action_service.execute_action(action_obj, request_data)
    
    # Log to Discord
    discord_logger.log_user_action(
        action_obj,
        action_obj.mod.name,
        action_obj.mod.id,
        action_obj.user.name,
        action_obj.user.id
    )
    
    return jsonify(ResponseFormatter.success(
        response.message,
        response.action_id
    )), 200
```

## Benefits of Migration

### Code Quality
- **Reduced complexity**: 2492 lines → ~200 lines per module
- **Better organization**: Clear separation of concerns
- **Easier to understand**: Each module has a single responsibility
- **Easier to maintain**: Changes are isolated to specific modules

### Type Safety
- **Full type hints**: Better IDE support and error detection
- **Dataclasses**: Clear data structures
- **DTOs**: Clear separation between internal and external data

### Error Handling
- **Consistent errors**: All errors follow the same pattern
- **Better messages**: Clear, actionable error messages
- **Proper status codes**: Correct HTTP status codes

### Testing
- **Isolated components**: Easy to test services independently
- **Mock repositories**: Easy to mock database operations
- **Clear contracts**: Type hints define clear interfaces

### Documentation
- **Comprehensive docstrings**: All classes and methods documented
- **Type hints**: Self-documenting code
- **README**: Complete documentation of the structure

## Testing the Migration

### Unit Tests
```python
# Test a service in isolation
from blueprints.admin.services import UserService
from blueprints.admin.repositories import MockUserRepository

mock_repo = MockUserRepository()
user_service = UserService(mock_repo)

# Test the service
result = await user_service.get_user_detail(123)
assert result is not None
```

### Integration Tests
```python
# Test the full flow
from blueprints.admin.routes import action
from blueprints.admin.models import ActionType

# Simulate a request
response = await action(ActionType.WIPE.value)
assert response.status_code == 200
```

## Rollback Plan

If you need to rollback:

1. Restore the old `admin.py` file from backup
2. Remove the `admin/` directory
3. Update imports to use the old structure

## Support

For questions or issues with the migration:
1. Check the README.md for detailed documentation
2. Review the examples in this guide
3. Test in a development environment first
4. Use version control to track changes

## Timeline

Recommended migration timeline:
1. **Week 1**: Set up new structure and test basic functionality
2. **Week 2**: Migrate user management endpoints
3. **Week 3**: Migrate map management endpoints
4. **Week 4**: Migrate badge and score management
5. **Week 5**: Testing and bug fixes
6. **Week 6**: Deploy to production

## Conclusion

The new modular structure provides significant improvements in:
- Code organization and maintainability
- Type safety and error handling
- Testing capabilities
- Documentation

While the migration requires some effort, the long-term benefits far outweigh the initial cost.
