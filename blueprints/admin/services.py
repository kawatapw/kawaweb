"""
Services for Admin Panel

This module contains service classes that orchestrate business logic,
coordinating between repositories, validators, and external services.
"""

import hashlib
import logging
from datetime import datetime
from typing import Any

import bcrypt

from objects import glob
from objects.privileges import ComparePrivs, GetPriv, Privileges
from objects.utils import get_safe_name, klogging

from .exceptions import (
    AdminPanelError,
    AlreadyExistsError,
    AuthorizationError,
    BadgeError,
    DatabaseError,
    ExternalServiceError,
    InvalidActionError,
    ResourceNotFoundError,
    StateConflictError,
)
from .models import (
    Action,
    ActionRequest,
    ActionResponse,
    ActionType,
    BadgeDetail,
    DashboardData,
    PermissionCheck,
    TargetType,
    UserDetail,
)
from .repositories import (
    BadgeRepository,
    ClientHashRepository,
    LogRepository,
    MapRepository,
    MapRequestRepository,
    NewlyRankedRepository,
    ScoreRepository,
    StatsRepository,
    UserBadgeRepository,
    UserRepository,
)
from .validators import ActionRequestValidator, Validator


class PermissionService:
    """Service for permission checks."""

    @staticmethod
    def check_user_permission(user_priv: int, required_privilege: str) -> PermissionCheck:
        """Check if user has required privilege."""
        try:
            priv_enum = getattr(Privileges, required_privilege)
            has_permission = bool(user_priv) and priv_enum in GetPriv(user_priv)  # ty:ignore[unsupported-operator]

            if not has_permission:
                return PermissionCheck(
                    has_permission=False,
                    required_privilege=required_privilege,
                    user_privilege=user_priv,
                    error_message="You do not have permission to perform this action.",
                    status_code=403
                )

            return PermissionCheck(has_permission=True)
        except AttributeError:
            return PermissionCheck(
                has_permission=False,
                required_privilege=required_privilege,
                user_privilege=user_priv,
                error_message=f"Invalid privilege: {required_privilege}",
                status_code=403
            )

    @staticmethod
    def check_privilege_hierarchy(mod_priv: int, target_priv: int, new_priv: int | None = None) -> PermissionCheck:
        """Check privilege hierarchy for privilege modification."""
        # Check if mod can modify target (target must be subset of mod's privs)
        if target_priv and not ComparePrivs(mod_priv, target_priv):
            return PermissionCheck(
                has_permission=False,
                error_message="You cannot modify people with privileges that you don't possess.",
                status_code=403
            )

        # Check if mod can grant new privileges (new privs must be subset of mod's privs)
        if new_priv is not None and new_priv and not ComparePrivs(mod_priv, new_priv):
            return PermissionCheck(
                has_permission=False,
                error_message="You cannot grant privileges that you don't possess.",
                status_code=403
            )

        return PermissionCheck(has_permission=True)


class ActionService:
    """Service for action execution."""

    def __init__(self, user_repository: UserRepository, map_repository: MapRepository,
                 badge_repository: BadgeRepository, user_badge_repository: UserBadgeRepository,
                 score_repository: ScoreRepository, stats_repository: StatsRepository,
                 map_request_repository: MapRequestRepository, log_repository: LogRepository,
                 newly_ranked_repository: NewlyRankedRepository):
        self.user_repo = user_repository
        self.map_repo = map_repository
        self.badge_repo = badge_repository
        self.user_badge_repo = user_badge_repository
        self.score_repo = score_repository
        self.stats_repo = stats_repository
        self.map_request_repo = map_request_repository
        self.log_repo = log_repository
        self.newly_ranked_repo = newly_ranked_repository

    @staticmethod
    def generate_action_id() -> str:
        """Generate a unique action ID."""
        timestamp = str(int(datetime.now().timestamp()))
        action_md5 = hashlib.md5(timestamp.encode()).hexdigest().encode()
        action_bcrypt = bcrypt.hashpw(action_md5, bcrypt.gensalt())
        return action_bcrypt[29:].decode('utf-8')

    async def create_action(self, request: ActionRequest, mod_id: int) -> Action:
        """Create an action instance."""
        # Validate request
        ActionRequestValidator.validate(request)

        # Generate action ID
        action_id = self.generate_action_id()

        # Determine target type and text
        if request.action in [
            ActionType.WIPE, ActionType.RESTRICT, ActionType.UNRESTRICT,
            ActionType.SILENCE, ActionType.UNSILENCE, ActionType.CHANGE_PASSWORD,
            ActionType.CHANGE_PRIVILEGES, ActionType.EDIT_ACCOUNT, ActionType.ADD_BADGE,
            ActionType.REMOVE_BADGE, ActionType.REMOVE_SCORE
        ]:
            target_type = TargetType.USER
            text = self._get_user_action_text(request.action)
        elif request.action in [
            ActionType.RANK, ActionType.APPROVE, ActionType.QUALIFY,
            ActionType.LOVE, ActionType.UNRANK, ActionType.COMPLETE_REQUEST
        ]:
            target_type = TargetType.MAP
            text = self._get_map_action_text(request.action)
        else:
            raise InvalidActionError(request.action.value)

        # Create action
        action = Action(
            id=action_id,
            action=request.action,
            reason=request.reason or "No reason specified.",
            mod_id=mod_id,
            target_id=request.user_id or request.map_id,  # ty:ignore[invalid-argument-type]
            target_type=target_type,
            text=text,
            duration=request.duration,
            badge=None
        )

        return action

    @staticmethod
    def _get_user_action_text(action: ActionType) -> str:
        """Get display text for user actions."""
        action_texts = {
            ActionType.WIPE: "Wiped",
            ActionType.RESTRICT: "Restricted",
            ActionType.UNRESTRICT: "Unrestricted",
            ActionType.SILENCE: "Silenced",
            ActionType.UNSILENCE: "Unsilenced",
            ActionType.CHANGE_PASSWORD: "Changed password",
            ActionType.CHANGE_PRIVILEGES: "Modified Privileges",
            ActionType.EDIT_ACCOUNT: "Edited Account",
            ActionType.ADD_BADGE: "Given Badge",
            ActionType.REMOVE_BADGE: "Revoked Badge",
            ActionType.REMOVE_SCORE: "Removed Score",
        }
        return action_texts.get(action, "Unknown")

    @staticmethod
    def _get_map_action_text(action: ActionType) -> str:
        """Get display text for map actions."""
        action_texts = {
            ActionType.RANK: "Ranked",
            ActionType.APPROVE: "Approved",
            ActionType.QUALIFY: "Qualified",
            ActionType.LOVE: "Loved",
            ActionType.UNRANK: "Unranked",
            ActionType.COMPLETE_REQUEST: "Completed Request",
        }
        return action_texts.get(action, "Unknown")

    async def execute_action(self, action: Action, request: ActionRequest) -> ActionResponse:
        """Execute an action."""
        try:
            klogging.log(f"Executing action {action.id} (type: {action.action.value}, target: {action.target_id})", level=klogging.logLevel.INFO, extra={"action_id": action.id, "action_type": action.action.value, "target_id": action.target_id, "operation": "execute_action"})

            # Get mod user
            mod = await self.user_repo.get_by_id(action.mod_id)
            if not mod:
                klogging.log(f"Mod user not found for action {action.id}: mod_id={action.mod_id}", level=klogging.logLevel.ERROR, extra={"action_id": action.id, "mod_id": action.mod_id})
                raise ResourceNotFoundError("User", action.mod_id)

            action.mod = mod  # type: ignore
            klogging.log(f"Executing action {action.id} as mod {mod.name} ({mod.id})", level=klogging.logLevel.INFO, extra={"action_id": action.id, "mod_name": mod.name, "mod_id": mod.id})

            # Execute based on action type
            if action.is_user_action:
                await self._execute_user_action(action, request)
            elif action.is_map_action:
                await self._execute_map_action(action, request)
            elif action.is_badge_action:
                await self._execute_badge_action(action, request)

            # Log the action (best-effort — action already succeeded)
            try:
                await self.log_repo.create(
                    action_id=action.id,
                    action=action.action.value,
                    reason=action.reason,
                    mod_id=action.mod_id,
                    target_id=action.target_id,
                    target_type=action.target_type
                )
            except Exception as log_err:
                klogging.log(f"Audit log failed (action still succeeded): {log_err}", klogging.Ansi.LYELLOW)

            klogging.log(f"Action {action.id} completed successfully", level=klogging.logLevel.INFO, extra={"action_id": action.id})
            return ActionResponse(
                status="success",
                message=f"Successfully {action.text.lower()} {self._get_target_description(action)}.",
                action_id=action.id
            )

        except AdminPanelError:
            raise
        except Exception as e:
            klogging.log(f"Failed to execute action {action.id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"action_id": action.id, "error": str(e)})
            raise DatabaseError(f"Failed to execute action: {str(e)}") from e

    async def _execute_user_action(self, action: Action, request: ActionRequest) -> None:
        """Execute user-specific actions."""
        # Get target user
        user = await self.user_repo.get_by_id(action.target_id)
        if not user:
            raise ResourceNotFoundError("User", action.target_id)

        action.user = user  # type: ignore

        # Hierarchy guard: mod must outrank target
        if action.user.priv and not ComparePrivs(action.mod.priv, action.user.priv):  # ty:ignore[unresolved-attribute]
            raise AuthorizationError("You cannot modify people with privileges that you don't possess.")

        # Execute specific action
        if action.action == ActionType.WIPE:
            await self._execute_wipe(action)
        elif action.action == ActionType.RESTRICT:
            await self._execute_restrict(action)
        elif action.action == ActionType.UNRESTRICT:
            await self._execute_unrestrict(action)
        elif action.action == ActionType.SILENCE:
            await self._execute_silence(action)
        elif action.action == ActionType.UNSILENCE:
            await self._execute_unsilence(action)
        elif action.action == ActionType.CHANGE_PASSWORD:
            await self._execute_change_password(action, request.password)  # ty:ignore[invalid-argument-type]
        elif action.action == ActionType.CHANGE_PRIVILEGES:
            await self._execute_change_privileges(action, request.privs)  # ty:ignore[invalid-argument-type]
        elif action.action == ActionType.EDIT_ACCOUNT:
            await self._execute_edit_account(action, request)
        elif action.action == ActionType.ADD_BADGE:
            await self._execute_add_badge(action, request.badge_id)  # ty:ignore[invalid-argument-type]
        elif action.action == ActionType.REMOVE_BADGE:
            await self._execute_remove_badge(action, request.badge_id)  # ty:ignore[invalid-argument-type]
        elif action.action == ActionType.REMOVE_SCORE:
            await self._execute_remove_score(action, request.score_id)  # ty:ignore[invalid-argument-type]

    async def _execute_map_action(self, action: Action, request: ActionRequest) -> None:
        """Execute map-specific actions."""
        # Get target map
        map_obj = await self.map_repo.get_by_id(action.target_id)
        if not map_obj:
            raise ResourceNotFoundError("Map", action.target_id)

        action.map = map_obj  # type: ignore

        # Execute specific action
        if action.action == ActionType.RANK:
            await self._execute_rank(action)
        elif action.action == ActionType.APPROVE:
            await self._execute_approve(action)
        elif action.action == ActionType.QUALIFY:
            await self._execute_qualify(action)
        elif action.action == ActionType.LOVE:
            await self._execute_love(action)
        elif action.action == ActionType.UNRANK:
            await self._execute_unrank(action)
        elif action.action == ActionType.COMPLETE_REQUEST:
            await self._execute_complete_request(action)

    async def _execute_badge_action(self, action: Action, request: ActionRequest) -> None:
        """Execute badge-specific actions."""
        # Get target user
        user = await self.user_repo.get_by_id(action.target_id)
        if not user:
            raise ResourceNotFoundError("User", action.target_id)

        action.user = user  # type: ignore

        # Get badge
        badge = await self.badge_repo.get_by_id(request.badge_id)  # ty:ignore[invalid-argument-type]
        if not badge:
            raise ResourceNotFoundError("Badge", request.badge_id)  # ty:ignore[invalid-argument-type]

        action.badge = badge

        # Execute specific action
        if action.action == ActionType.ADD_BADGE:
            await self._execute_add_badge(action, request.badge_id)  # ty:ignore[invalid-argument-type]
        elif action.action == ActionType.REMOVE_BADGE:
            await self._execute_remove_badge(action, request.badge_id)  # ty:ignore[invalid-argument-type]

    async def _execute_wipe(self, action: Action) -> None:
        """Execute wipe action."""
        klogging.log(f"Wiping user {action.user.id} ({action.user.name})", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "user_name": action.user.name, "mod_id": action.mod_id, "operation": "wipe"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "WipeUsers"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Wipe permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Wipe scores
        klogging.log(f"Wiping scores for user {action.user.id}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id})  # ty:ignore[unresolved-attribute]
        await self.score_repo.wipe_user_scores(action.user.id)  # ty:ignore[unresolved-attribute]

        # Reset stats
        modes = [0, 1, 2, 3, 4, 5, 6, 7, 8]
        klogging.log(f"Resetting stats for user {action.user.id} across {len(modes)} modes", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "modes": modes})  # ty:ignore[unresolved-attribute]
        await self.stats_repo.reset_user_stats(action.user.id, modes)  # ty:ignore[unresolved-attribute]

        # Remove from leaderboards
        klogging.log(f"Removing user {action.user.id} from leaderboards", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id})  # ty:ignore[unresolved-attribute]
        for mode in modes:
            await glob.redis.zrem(f"bancho:leaderboard:{mode}", action.user.id)  # ty:ignore[unresolved-attribute]
            await glob.redis.zrem(
                f"bancho:leaderboard:{mode}:{action.user.country}",  # ty:ignore[unresolved-attribute]
                action.user.id  # ty:ignore[unresolved-attribute]
            )

        klogging.log(f"Successfully wiped user {action.user.id}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_restrict(self, action: Action) -> None:
        """Execute restrict action."""
        klogging.log(f"Restricting user {action.user.id} ({action.user.name})", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "user_name": action.user.name, "mod_id": action.mod_id, "operation": "restrict"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "RestrictUsers"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Restrict permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if already restricted
        if action.user.priv == 0:  # ty:ignore[unresolved-attribute]
            klogging.log(f"User {action.user.id} is already restricted", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("User is already restricted.")

        # Restrict user
        klogging.log(f"Restricting user {action.user.id} in database", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id})  # ty:ignore[unresolved-attribute]
        await self.user_repo.restrict(action.user.id)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully restricted user {action.user.id}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_unrestrict(self, action: Action) -> None:
        """Execute unrestrict action."""
        klogging.log(f"Unrestricting user {action.user.id} ({action.user.name})", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "user_name": action.user.name, "mod_id": action.mod_id, "operation": "unrestrict"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "RestrictUsers"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Unrestrict permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if already unrestricted
        if action.user.priv != 0:  # ty:ignore[unresolved-attribute]
            klogging.log(f"User {action.user.id} is not restricted", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("User is not restricted.")

        # Unrestrict user
        klogging.log(f"Unrestricting user {action.user.id} in database", level=klogging.logLevel.INFO, extra={"user_id": action.user.id})  # ty:ignore[unresolved-attribute]
        await self.user_repo.unrestrict(action.user.id)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully unrestricted user {action.user.id}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_silence(self, action: Action) -> None:
        """Execute silence action."""
        klogging.log(f"Silencing user {action.user.id} ({action.user.name}) for {action.duration} hours", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "user_name": action.user.name, "duration": action.duration, "mod_id": action.mod_id, "operation": "silence"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "SilenceUsers"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Silence permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if already silenced
        if action.user.silence_end != 0:  # ty:ignore[unresolved-attribute]
            klogging.log(f"User {action.user.id} is already silenced until {action.user.silence_end}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "silence_end": action.user.silence_end})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("User is already silenced.")

        # Calculate silence end time
        silence_end = int(datetime.now().timestamp()) + action.duration * 3600  # ty:ignore[unsupported-operator]
        klogging.log(f"Setting silence end to {silence_end} for user {action.user.id}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "silence_end": silence_end})  # ty:ignore[unresolved-attribute]

        # Update user
        await self.user_repo.update_silence(action.user.id, silence_end)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully silenced user {action.user.id}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id, "silence_end": silence_end})  # ty:ignore[unresolved-attribute]

    async def _execute_unsilence(self, action: Action) -> None:
        """Execute unsilence action."""
        klogging.log(f"Unsilencing user {action.user.id} ({action.user.name})", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "user_name": action.user.name, "mod_id": action.mod_id, "operation": "unsilence"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "SilenceUsers"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Unsilence permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if not silenced
        if action.user.silence_end == 0:  # ty:ignore[unresolved-attribute]
            klogging.log(f"User {action.user.id} is not silenced", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("User is not silenced.")

        # Update user
        klogging.log(f"Unsilencing user {action.user.id} in database", level=klogging.logLevel.INFO, extra={"user_id": action.user.id})  # ty:ignore[unresolved-attribute]
        await self.user_repo.update_silence(action.user.id, 0)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully unrestricted user {action.user.id}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_change_password(self, action: Action, password: str) -> None:
        """Execute change password action."""
        klogging.log(f"Changing password for user {action.user.id} ({action.user.name})", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "user_name": action.user.name, "mod_id": action.mod_id, "operation": "change_password"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageUsers"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Change password permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Validate password
        Validator.validate_password(password, "password")

        # Get current password hash
        bcrypt_cache = glob.cache['bcrypt']
        old_pw_bcrypt = (await glob.db.fetch(
            'SELECT pw_bcrypt FROM users WHERE id = %s',
            [action.user.id]  # ty:ignore[unresolved-attribute]
        ))['pw_bcrypt'].encode()  # ty:ignore[invalid-argument-type, not-subscriptable]

        # Calculate new password hash
        pw_md5 = hashlib.md5(password.encode()).hexdigest().encode()
        pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())

        # DB write FIRST — cache update only after success
        klogging.log(f"Updating password in database for user {action.user.id}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id})  # ty:ignore[unresolved-attribute]
        await self.user_repo.update_password(action.user.id, pw_bcrypt, action.user.safe_name)  # ty:ignore[unresolved-attribute]

        # Update cache
        if old_pw_bcrypt in bcrypt_cache:
            del bcrypt_cache[old_pw_bcrypt]
        bcrypt_cache[pw_bcrypt] = pw_md5

        klogging.log(f"Successfully changed password for user {action.user.id}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_change_privileges(self, action: Action, new_priv: int) -> None:
        """Execute change privileges action."""
        klogging.log(f"Changing privileges for user {action.user.id} ({action.user.name}): old={action.user.priv}, new={new_priv}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "user_name": action.user.name, "old_priv": action.user.priv, "new_priv": new_priv, "mod_id": action.mod_id, "operation": "change_privileges"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManagePrivs"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"ManagePrivs permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check privilege hierarchy
        hierarchy_check = PermissionService.check_privilege_hierarchy(
            action.mod.priv, action.user.priv, new_priv  # ty:ignore[unresolved-attribute]
        )
        if not hierarchy_check.has_permission:
            klogging.log(f"Privilege hierarchy check failed for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id, "new_priv": new_priv})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(hierarchy_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if privileges are already set
        if action.user.priv == new_priv:  # ty:ignore[unresolved-attribute]
            klogging.log(f"Privileges already set to {new_priv} for user {action.user.id}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "new_priv": new_priv})  # ty:ignore[unresolved-attribute]
            raise StateConflictError(f"Privileges are already set to {new_priv}.")

        # Update privileges
        klogging.log(f"Updating privileges in database for user {action.user.id}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "new_priv": new_priv})  # ty:ignore[unresolved-attribute]
        await self.user_repo.update_privileges(action.user.id, new_priv)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully changed privileges for user {action.user.id}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "mod_id": action.mod_id, "new_priv": new_priv})  # ty:ignore[unresolved-attribute]

    async def _execute_edit_account(self, action: Action, request: ActionRequest) -> None:
        """Execute edit account action."""
        klogging.log(f"Editing account for user {action.user.id} ({action.user.name})", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "user_name": action.user.name, "mod_id": action.mod_id, "operation": "edit_account"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageUsers"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Edit account permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Validate inputs
        Validator.validate_string(request.username, "username", min_length=1, max_length=32)
        Validator.validate_email(request.email, "email")  # ty:ignore[invalid-argument-type]
        Validator.validate_country_code(request.country, "country")  # ty:ignore[invalid-argument-type]

        # Check username availability
        if action.user.name != request.username:  # ty:ignore[unresolved-attribute]
            safe_name = get_safe_name(request.username)  # ty:ignore[invalid-argument-type]
            klogging.log(f"Checking username availability: {request.username}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "new_username": request.username})  # ty:ignore[unresolved-attribute]
            existing_user = await self.user_repo.get_by_safe_name(safe_name)
            if existing_user:
                klogging.log(f"Username already exists (safe_name): {request.username}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "username": request.username})  # ty:ignore[unresolved-attribute]
                raise AlreadyExistsError("Username", request.username)  # ty:ignore[invalid-argument-type]

            existing_user_by_name = await self.user_repo.get_by_name(request.username)  # ty:ignore[invalid-argument-type]
            if existing_user_by_name:
                klogging.log(f"Username already exists (name): {request.username}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "username": request.username})  # ty:ignore[unresolved-attribute]
                raise AlreadyExistsError("Username", request.username)  # ty:ignore[invalid-argument-type]

        # Check email availability
        if action.user.email != request.email:  # ty:ignore[unresolved-attribute]
            klogging.log(f"Checking email availability: {request.email}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "new_email": request.email})  # ty:ignore[unresolved-attribute]
            existing_user = await self.user_repo.get_by_email(request.email)  # ty:ignore[invalid-argument-type]
            if existing_user:
                klogging.log(f"Email already exists: {request.email}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "email": request.email})  # ty:ignore[unresolved-attribute]
                raise AlreadyExistsError("Email", request.email)  # ty:ignore[invalid-argument-type]

        # Update account
        klogging.log(f"Updating account in database for user {action.user.id}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "new_username": request.username, "new_email": request.email, "new_country": request.country})  # ty:ignore[unresolved-attribute]
        safe_name = get_safe_name(request.username)  # ty:ignore[invalid-argument-type]
        await self.user_repo.update_account(
            action.user.id,  # ty:ignore[unresolved-attribute]
            request.username,  # ty:ignore[invalid-argument-type]
            safe_name,
            request.email,  # ty:ignore[invalid-argument-type]
            request.country,  # ty:ignore[invalid-argument-type]
            request.userpage_content  # ty:ignore[invalid-argument-type]
        )
        klogging.log(f"Successfully edited account for user {action.user.id}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_add_badge(self, action: Action, badge_id: int) -> None:
        """Execute add badge action."""
        klogging.log(f"Adding badge {badge_id} to user {action.user.id} ({action.user.name})", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "user_name": action.user.name, "badge_id": badge_id, "mod_id": action.mod_id, "operation": "add_badge"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBadges"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Add badge permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id, "badge_id": badge_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if user already has badge
        has_badge = await self.user_badge_repo.has_badge(action.user.id, badge_id)  # ty:ignore[unresolved-attribute]
        if has_badge:
            klogging.log(f"User {action.user.id} already has badge {badge_id}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "badge_id": badge_id})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("User already has this badge.")

        # Add badge
        klogging.log(f"Adding badge {badge_id} to user {action.user.id} in database", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "badge_id": badge_id})  # ty:ignore[unresolved-attribute]
        await self.user_badge_repo.add_badge(action.user.id, badge_id)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully added badge {badge_id} to user {action.user.id}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "badge_id": badge_id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_remove_badge(self, action: Action, badge_id: int) -> None:
        """Execute remove badge action."""
        klogging.log(f"Removing badge {badge_id} from user {action.user.id} ({action.user.name})", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "user_name": action.user.name, "badge_id": badge_id, "mod_id": action.mod_id, "operation": "remove_badge"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBadges"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Remove badge permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id, "badge_id": badge_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if user has badge
        has_badge = await self.user_badge_repo.has_badge(action.user.id, badge_id)  # ty:ignore[unresolved-attribute]
        if not has_badge:
            klogging.log(f"User {action.user.id} does not have badge {badge_id}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "badge_id": badge_id})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("User does not have this badge.")

        # Remove badge
        klogging.log(f"Removing badge {badge_id} from user {action.user.id} in database", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "badge_id": badge_id})  # ty:ignore[unresolved-attribute]
        await self.user_badge_repo.remove_badge(action.user.id, badge_id)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully removed badge {badge_id} from user {action.user.id}", level=klogging.logLevel.INFO, extra={"user_id": action.user.id, "badge_id": badge_id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_remove_score(self, action: Action, score_id: int) -> None:
        """Execute remove score action."""
        klogging.log(f"Removing score {score_id} for user {action.user.id} ({action.user.name})", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "user_name": action.user.name, "score_id": score_id, "mod_id": action.mod_id, "operation": "remove_score"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageUsers"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Remove score permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"user_id": action.user.id, "mod_id": action.mod_id, "score_id": score_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if score exists
        klogging.log(f"Checking if score {score_id} exists", level=klogging.logLevel.INFO, extra={"score_id": score_id})
        score_exists = await self.score_repo.exists(score_id)
        if not score_exists:
            klogging.log(f"Score {score_id} not found", level=klogging.logLevel.WARNING, extra={"score_id": score_id})
            raise ResourceNotFoundError("Score", score_id)

        # Remove score
        klogging.log(f"Removing score {score_id} from database", level=klogging.logLevel.WARNING, extra={"score_id": score_id})
        await self.score_repo.remove_score(score_id)
        klogging.log(f"Successfully removed score {score_id}", level=klogging.logLevel.WARNING, extra={"score_id": score_id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_rank(self, action: Action) -> None:
        """Execute rank action."""
        klogging.log(f"Ranking map {action.map.id} ({action.map.artist} - {action.map.title} [{action.map.version}])", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "map_title": f"{action.map.artist} - {action.map.title}", "mod_id": action.mod_id, "operation": "rank"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Rank permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if already ranked
        if action.map.status == 2:  # ty:ignore[unresolved-attribute]
            klogging.log(f"Map {action.map.id} is already ranked", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "current_status": action.map.status})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("Map is already ranked.")

        # Update map status via API
        klogging.log(f"Updating map {action.map.id} status to ranked via API", level=klogging.logLevel.INFO, extra={"map_id": action.map.id})  # ty:ignore[unresolved-attribute]
        await self._update_map_status_via_api(action.map.id, 2)  # ty:ignore[unresolved-attribute]

        # Deactivate map request
        await self.map_request_repo.deactivate_request(action.map.id)  # ty:ignore[unresolved-attribute]

        # Add to newly ranked
        klogging.log(f"Adding map {action.map.id} to newly ranked", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
        await self.newly_ranked_repo.add(action.map.id, action.mod_id)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully ranked map {action.map.id}", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_approve(self, action: Action) -> None:
        """Execute approve action."""
        klogging.log(f"Approving map {action.map.id} ({action.map.artist} - {action.map.title} [{action.map.version}])", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "map_title": f"{action.map.artist} - {action.map.title}", "mod_id": action.mod_id, "operation": "approve"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Approve permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if already approved
        if action.map.status == 3:  # ty:ignore[unresolved-attribute]
            klogging.log(f"Map {action.map.id} is already approved", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "current_status": action.map.status})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("Map is already approved.")

        # Update map status via API
        klogging.log(f"Updating map {action.map.id} status to approved via API", level=klogging.logLevel.INFO, extra={"map_id": action.map.id})  # ty:ignore[unresolved-attribute]
        await self._update_map_status_via_api(action.map.id, 3)  # ty:ignore[unresolved-attribute]

        # Deactivate map request
        await self.map_request_repo.deactivate_request(action.map.id)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully approved map {action.map.id}", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_qualify(self, action: Action) -> None:
        """Execute qualify action."""
        klogging.log(f"Qualifying map {action.map.id} ({action.map.artist} - {action.map.title} [{action.map.version}])", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "map_title": f"{action.map.artist} - {action.map.title}", "mod_id": action.mod_id, "operation": "qualify"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Qualify permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if already qualified
        if action.map.status == 4:  # ty:ignore[unresolved-attribute]
            klogging.log(f"Map {action.map.id} is already qualified", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "current_status": action.map.status})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("Map is already qualified.")

        # Update map status via API
        klogging.log(f"Updating map {action.map.id} status to qualified via API", level=klogging.logLevel.INFO, extra={"map_id": action.map.id})  # ty:ignore[unresolved-attribute]
        await self._update_map_status_via_api(action.map.id, 4)  # ty:ignore[unresolved-attribute]

        # Deactivate map request
        await self.map_request_repo.deactivate_request(action.map.id)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully qualified map {action.map.id}", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_love(self, action: Action) -> None:
        """Execute love action."""
        klogging.log(f"Loving map {action.map.id} ({action.map.artist} - {action.map.title} [{action.map.version}])", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "map_title": f"{action.map.artist} - {action.map.title}", "mod_id": action.mod_id, "operation": "love"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Love permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if already loved
        if action.map.status == 5:  # ty:ignore[unresolved-attribute]
            klogging.log(f"Map {action.map.id} is already loved", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "current_status": action.map.status})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("Map is already loved.")

        # Update map status via API
        klogging.log(f"Updating map {action.map.id} status to loved via API", level=klogging.logLevel.INFO, extra={"map_id": action.map.id})  # ty:ignore[unresolved-attribute]
        await self._update_map_status_via_api(action.map.id, 5)  # ty:ignore[unresolved-attribute]

        # Deactivate map request
        await self.map_request_repo.deactivate_request(action.map.id)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully loved map {action.map.id}", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_unrank(self, action: Action) -> None:
        """Execute unrank action."""
        klogging.log(f"Unranking map {action.map.id} ({action.map.artist} - {action.map.title} [{action.map.version}])", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "map_title": f"{action.map.artist} - {action.map.title}", "mod_id": action.mod_id, "operation": "unrank"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Unrank permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Check if not ranked
        if action.map.status == 0:  # ty:ignore[unresolved-attribute]
            klogging.log(f"Map {action.map.id} is not ranked", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "current_status": action.map.status})  # ty:ignore[unresolved-attribute]
            raise StateConflictError("Map is not ranked.")

        # Update map status via API
        klogging.log(f"Updating map {action.map.id} status to unranked via API", level=klogging.logLevel.INFO, extra={"map_id": action.map.id})  # ty:ignore[unresolved-attribute]
        await self._update_map_status_via_api(action.map.id, 0)  # ty:ignore[unresolved-attribute]

        # Deactivate and freeze map request
        klogging.log(f"Deactivating and freezing map request for {action.map.id}", level=klogging.logLevel.INFO, extra={"map_id": action.map.id})  # ty:ignore[unresolved-attribute]
        await self.map_request_repo.deactivate_and_freeze_request(action.map.id)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully unranked map {action.map.id}", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _execute_complete_request(self, action: Action) -> None:
        """Execute complete request action."""
        klogging.log(f"Completing map request for {action.map.id}", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "mod_id": action.mod_id, "operation": "complete_request"})  # ty:ignore[unresolved-attribute]

        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"  # ty:ignore[unresolved-attribute]
        )
        if not permission_check.has_permission:
            klogging.log(f"Complete request permission denied for mod {action.mod.name}", level=klogging.logLevel.WARNING, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]
            raise AuthorizationError(permission_check.error_message)  # ty:ignore[invalid-argument-type]

        # Deactivate map request
        klogging.log(f"Deactivating map request for {action.map.id}", level=klogging.logLevel.INFO, extra={"map_id": action.map.id})  # ty:ignore[unresolved-attribute]
        await self.map_request_repo.deactivate_request(action.map.id)  # ty:ignore[unresolved-attribute]
        klogging.log(f"Successfully completed map request for {action.map.id}", level=klogging.logLevel.INFO, extra={"map_id": action.map.id, "mod_id": action.mod_id})  # ty:ignore[unresolved-attribute]

    async def _update_map_status_via_api(self, map_id: int, status: int) -> None:
        """Update map status via external API."""
        try:
            klogging.log(f"Calling map status API for map {map_id} with status {status}", level=klogging.logLevel.INFO, extra={"map_id": map_id, "status": status, "operation": "update_map_status_api"})
            url = "http://bancho:10000/v1/update_map_status"
            headers = {
                "Authorization": f"Bearer {glob.config.api_key}",
                "Host": f"api.{glob.config.domain}",
            }
            params = {
                "id": map_id,
                "s": status,
            }

            async with glob.http.post(url, headers=headers, params=params, timeout=15) as response:
                json_response = await response.json(content_type=None)

            if json_response.get("status") != "success":
                klogging.log(f"Map status API failed for map {map_id}: {json_response.get('status')}", level=klogging.logLevel.ERROR, extra={"map_id": map_id, "api_response": json_response})
                raise ExternalServiceError(
                    "Map Status API",
                    f"Failed to update map status: {json_response.get('status')}"
                )

            klogging.log(f"Map status API call successful for map {map_id}", level=klogging.logLevel.INFO, extra={"map_id": map_id, "status": status})
        except ExternalServiceError:
            raise
        except Exception as e:
            klogging.log(f"Error calling map status API for map {map_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"map_id": map_id, "error": str(e)})
            raise ExternalServiceError("Map Status API", str(e)) from e

    def _get_target_description(self, action: Action) -> str:
        """Get description of action target."""
        if action.is_user_action and hasattr(action, 'user'):
            return f"{action.user.name} ({action.user.id})"  # ty:ignore[unresolved-attribute]
        elif action.is_map_action and hasattr(action, 'map'):
            return f"{action.map.artist} - {action.map.title} [{action.map.version}] ({action.map.id})"  # ty:ignore[unresolved-attribute]
        elif action.is_badge_action and hasattr(action, 'badge'):
            return f"badge {action.badge.id}"  # ty:ignore[unresolved-attribute]
        return "unknown target"


class DashboardService:
    """Service for dashboard operations."""

    def __init__(self, user_repository: UserRepository):
        self.user_repo = user_repository

    async def get_dashboard_data(self) -> DashboardData:
        """Get dashboard statistics."""
        try:
            klogging.log("Fetching dashboard data", level=klogging.logLevel.INFO, extra={"operation": "get_dashboard_data"})

            # Get total user count
            total_users = await self.user_repo.get_count()
            klogging.log(f"Total users: {total_users}", level=klogging.logLevel.DEBUG, extra={"total_users": total_users})

            # Get latest user
            latest_user_data = await glob.db.fetch(
                "SELECT name FROM users ORDER BY id DESC LIMIT 1"
            )
            latest_user = latest_user_data['name'] if latest_user_data else "N/A"  # ty:ignore[invalid-argument-type]
            klogging.log(f"Latest user: {latest_user}", level=klogging.logLevel.DEBUG, extra={"latest_user": latest_user})

            # Get banned user count
            banned_data = await glob.db.fetch(
                "SELECT COUNT(id) as banned FROM users WHERE NOT priv & 1"
            )
            banned_users = banned_data['banned'] if banned_data else 0  # ty:ignore[invalid-argument-type]
            klogging.log(f"Banned users: {banned_users}", level=klogging.logLevel.DEBUG, extra={"banned_users": banned_users})

            # Get recent users
            recent_users = await glob.db.fetchall(
                "SELECT * FROM users ORDER BY id DESC LIMIT 5"
            )
            klogging.log(f"Retrieved {len(recent_users)} recent users", level=klogging.logLevel.DEBUG, extra={"recent_users_count": len(recent_users)})

            # Get recent scores
            recent_scores = await glob.db.fetchall(
                """
                SELECT scores.*, maps.artist, maps.title, maps.set_id, maps.creator, maps.version
                FROM scores JOIN maps ON scores.map_md5 = maps.md5
                ORDER BY scores.id DESC LIMIT 5
                """
            )
            klogging.log(f"Retrieved {len(recent_scores)} recent scores", level=klogging.logLevel.DEBUG, extra={"recent_scores_count": len(recent_scores)})

            klogging.log("Dashboard data fetched successfully", level=klogging.logLevel.INFO, extra={"operation": "get_dashboard_data"})
            return DashboardData(
                total_users=total_users,
                latest_user=latest_user,
                banned_users=banned_users,
                recent_users=recent_users,  # ty:ignore[invalid-argument-type]
                recent_scores=recent_scores  # ty:ignore[invalid-argument-type]
            )
        except Exception as e:
            klogging.log(f"Failed to get dashboard data: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"error": str(e), "operation": "get_dashboard_data"})
            raise DatabaseError(f"Failed to get dashboard data: {str(e)}") from e


class UserService:
    """Service for user operations."""

    def __init__(self, user_repository: UserRepository, badge_repository: BadgeRepository,
                 user_badge_repository: UserBadgeRepository, log_repository: LogRepository,
                 client_hash_repository: ClientHashRepository):
        self.user_repo = user_repository
        self.badge_repo = badge_repository
        self.user_badge_repo = user_badge_repository
        self.log_repo = log_repository
        self.client_hash_repo = client_hash_repository

    async def get_user_detail(self, user_id: int) -> UserDetail:
        """Get detailed user information."""
        try:
            klogging.log(f"Getting user detail for user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "operation": "get_user_detail"})

            # Get user
            user = await self.user_repo.get_by_id(user_id)
            if not user:
                klogging.log(f"User {user_id} not found", level=klogging.logLevel.WARNING, extra={"user_id": user_id})
                raise ResourceNotFoundError("User", user_id)

            # Get user badges
            user_badges_data = await self.user_badge_repo.get_user_badges(user_id)
            klogging.log(f"Found {len(user_badges_data)} badges for user {user_id}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "badge_count": len(user_badges_data)})

            badges = []
            for user_badge in user_badges_data:
                badge_id = user_badge["badge_id"]
                badge = await self.badge_repo.get_by_id(badge_id)
                if badge:
                    badge_styles = await self.badge_repo.get_styles(badge_id)
                    badge_dict = {
                        "id": badge.id,
                        "name": badge.name,
                        "description": badge.description,
                        "priority": badge.priority,
                        "styles": {style["type"]: style["value"] for style in badge_styles}
                    }
                    badges.append(badge_dict)

            # Sort badges by priority
            badges.sort(key=lambda x: x['priority'], reverse=True)

            # Get logs
            hashes = await self.client_hash_repo.get_by_user(user_id)
            admin_logs = await self.log_repo.get_by_target(user_id)
            klogging.log(f"Retrieved {len(hashes)} hashes and {len(admin_logs)} admin logs for user {user_id}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "hash_count": len(hashes), "log_count": len(admin_logs)})

            # Enrich admin logs with mod info
            for admin_log in admin_logs:
                mod = await self.user_repo.get_by_id(admin_log['from_id'])
                if mod:
                    admin_log['mod'] = {
                        'id': mod.id,
                        'name': mod.name,
                        'country': mod.country,
                        'priv': mod.priv,
                        'safe_name': mod.safe_name
                    }

            logs = {
                'hashes': hashes,
                'admin_logs': admin_logs
            }

            # Convert user to dict
            user_dict = {
                'id': user.id,
                'name': user.name,
                'safe_name': user.safe_name,
                'email': user.email,
                'priv': user.priv,
                'country': user.country,
                'silence_end': user.silence_end,
                'donor_end': user.donor_end,
                'creation_time': user.creation_time,
                'latest_activity': user.latest_activity,
                'clan_id': user.clan_id,
                'clan_priv': user.clan_priv,
                'preferred_mode': user.preferred_mode,
                'play_style': user.play_style,
                'custom_badge_name': user.custom_badge_name,
                'custom_badge_icon': user.custom_badge_icon,
                'userpage_content': user.userpage_content,
                'badges': badges,
                'logs': logs
            }

            klogging.log(f"Successfully retrieved user detail for user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id})
            return UserDetail(user=user_dict, badges=badges, logs=logs)
        except AdminPanelError:
            raise
        except Exception as e:
            klogging.log(f"Failed to get user detail for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "error": str(e)})
            raise DatabaseError(f"Failed to get user detail: {str(e)}") from e


class BadgeService:
    """Service for badge operations."""

    def __init__(self, badge_repository: BadgeRepository):
        self.badge_repo = badge_repository

    async def get_all_badges(self) -> list[dict[str, Any]]:
        """Get all badges."""
        try:
            klogging.log("Fetching all badges", level=klogging.logLevel.INFO, extra={"operation": "get_all_badges"})
            badges = await self.badge_repo.get_all()
            result = []

            for badge in badges:
                badge_styles = await self.badge_repo.get_styles(badge.id)
                badge_dict = {
                    'id': badge.id,
                    'name': badge.name,
                    'description': badge.description,
                    'priority': badge.priority,
                    'styles': {style['type']: style['value'] for style in badge_styles}
                }
                result.append(badge_dict)

            klogging.log(f"Successfully retrieved {len(result)} badges", level=klogging.logLevel.INFO, extra={"badge_count": len(result)})
            return result
        except Exception as e:
            klogging.log(f"Failed to get badges: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"error": str(e)})
            raise DatabaseError(f"Failed to get badges: {str(e)}") from e

    async def get_badge_detail(self, badge_id: int) -> BadgeDetail:
        """Get detailed badge information."""
        try:
            klogging.log(f"Getting badge detail for badge {badge_id}", level=klogging.logLevel.INFO, extra={"badge_id": badge_id, "operation": "get_badge_detail"})
            badge = await self.badge_repo.get_by_id(badge_id)
            if not badge:
                klogging.log(f"Badge {badge_id} not found", level=klogging.logLevel.WARNING, extra={"badge_id": badge_id})
                raise ResourceNotFoundError("Badge", badge_id)

            badge_styles = await self.badge_repo.get_styles(badge_id)

            badge_dict = {
                'id': badge.id,
                'name': badge.name,
                'description': badge.description,
                'priority': badge.priority,
                'styles': badge_styles
            }

            klogging.log(f"Successfully retrieved badge detail for badge {badge_id}", level=klogging.logLevel.INFO, extra={"badge_id": badge_id})
            return BadgeDetail(badge=badge_dict, styles=badge_styles)
        except AdminPanelError:
            raise
        except Exception as e:
            klogging.log(f"Failed to get badge detail for badge {badge_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"badge_id": badge_id, "error": str(e)})
            raise DatabaseError(f"Failed to get badge detail: {str(e)}") from e

    async def create_badge(self, name: str, description: str, priority: int, styles: list[dict[str, str]]) -> None:
        """Create a new badge."""
        try:
            klogging.log(f"Creating badge: {name}", level=klogging.logLevel.INFO, extra={"name": name, "priority": priority, "operation": "create_badge"})

            # Check if badge already exists
            existing_badge = await self.badge_repo.get_by_name(name)
            if existing_badge:
                klogging.log(f"Badge with name '{name}' already exists", level=klogging.logLevel.WARNING, extra={"name": name})
                raise AlreadyExistsError("Badge", name)

            # Create badge
            badge_id = await self.badge_repo.create(name, description, priority)
            if not badge_id:
                klogging.log(f"Failed to create badge: {name}", level=klogging.logLevel.ERROR, extra={"name": name})
                raise BadgeError("Failed to create badge")

            # Add styles
            for style in styles:
                await self.badge_repo.update_style(badge_id, style['type'], style['value'])

            klogging.log(f"Successfully created badge {badge_id}: {name}", level=klogging.logLevel.INFO, extra={"badge_id": badge_id, "name": name})
        except AdminPanelError:
            raise
        except Exception as e:
            klogging.log(f"Failed to create badge {name}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"name": name, "error": str(e)})
            raise DatabaseError(f"Failed to create badge: {str(e)}") from e

    async def update_badge(self, badge_id: int, name: str, description: str, priority: int, styles: list[dict[str, str]]) -> None:
        """Update an existing badge."""
        try:
            klogging.log(f"Updating badge {badge_id}: {name}", level=klogging.logLevel.INFO, extra={"badge_id": badge_id, "name": name, "priority": priority, "operation": "update_badge"})

            # Check if badge exists
            badge = await self.badge_repo.get_by_id(badge_id)
            if not badge:
                klogging.log(f"Badge {badge_id} not found", level=klogging.logLevel.WARNING, extra={"badge_id": badge_id})
                raise ResourceNotFoundError("Badge", badge_id)

            # Check for duplicate name on rename
            if badge.name != name:
                existing = await self.badge_repo.get_by_name(name)
                if existing and existing.id != badge_id:
                    klogging.log(f"Badge name '{name}' already exists", level=klogging.logLevel.WARNING, extra={"name": name, "badge_id": badge_id})
                    raise AlreadyExistsError("Badge", name)

            # Update badge
            await self.badge_repo.update(badge_id, name, description, priority)

            # Update styles
            for style in styles:
                await self.badge_repo.update_style(badge_id, style['type'], style['value'])

            klogging.log(f"Successfully updated badge {badge_id}", level=klogging.logLevel.INFO, extra={"badge_id": badge_id})
        except AdminPanelError:
            raise
        except Exception as e:
            klogging.log(f"Failed to update badge {badge_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"badge_id": badge_id, "error": str(e)})
            raise DatabaseError(f"Failed to update badge: {str(e)}") from e


class MapRequestService:
    """Service for map request operations."""

    def __init__(self, map_request_repository: MapRequestRepository, user_repository: UserRepository,
                 badge_repository: BadgeRepository, user_badge_repository: UserBadgeRepository,
                 map_repository: MapRepository):
        self.map_request_repo = map_request_repository
        self.user_repo = user_repository
        self.badge_repo = badge_repository
        self.user_badge_repo = user_badge_repository
        self.map_repo = map_repository

    async def get_active_requests(self, page: int, items_per_page: int = 50) -> list[dict[str, Any]]:
        """Get active map requests."""
        try:
            klogging.log(f"Fetching active map requests (page={page}, items_per_page={items_per_page})", level=klogging.logLevel.INFO, extra={"page": page, "items_per_page": items_per_page, "operation": "get_active_requests"})
            offset = (page - 1) * items_per_page
            requests = await self.map_request_repo.get_active_requests(items_per_page, offset)

            result = []
            for request in requests:
                # Get player info
                player = await self.user_repo.get_by_id(request['player_id'])
                if not player:
                    klogging.log(f"Player not found for map request: player_id={request['player_id']}", level=klogging.logLevel.WARNING, extra={"player_id": request['player_id'], "request_id": request['id']})
                    continue

                # Get player badges
                user_badges_data = await self.user_badge_repo.get_user_badges(request['player_id'])
                badges = []
                for user_badge in user_badges_data:
                    badge_id = user_badge["badge_id"]
                    badge = await self.badge_repo.get_by_id(badge_id)
                    if badge:
                        badge_styles = await self.badge_repo.get_styles(badge_id)
                        badge_dict = {
                            "id": badge.id,
                            "name": badge.name,
                            "description": badge.description,
                            "priority": badge.priority,
                            "styles": {style["type"]: style["value"] for style in badge_styles}
                        }
                        badges.append(badge_dict)

                # Sort badges by priority
                badges.sort(key=lambda x: x['priority'], reverse=True)

                # Get map info
                map_info_and_diffs = await glob.db.fetchall(
                    """
                    SELECT *
                    FROM maps
                    WHERE id = %s OR set_id = (
                        SELECT set_id FROM maps WHERE id = %s
                    )
                    """,
                    [request['map_id'], request['map_id']]
                )

                map_info = None
                map_diffs = []

                for map_row in map_info_and_diffs:
                    if map_row['id'] == request['map_id']:  # ty:ignore[invalid-argument-type, not-subscriptable]
                        map_info = map_row
                    else:
                        map_diffs.append(map_row)

                if not map_info:
                    # Delete invalid request
                    klogging.log(f"Deleting invalid map request: map_id={request['map_id']}", level=klogging.logLevel.WARNING, extra={"request_id": request['id'], "map_id": request['map_id']})
                    await glob.db.execute(
                        "DELETE FROM map_requests WHERE id = %s",
                        [request['id']]
                    )
                    continue

                # Format dates
                request['datetime'] = request['datetime'].strftime('%Y-%m-%d %H:%M:%S')
                map_info['last_update'] = map_info['last_update'].strftime('%Y-%m-%d %H:%M:%S')  # ty:ignore[invalid-argument-type, invalid-assignment]
                for diff in map_diffs:
                    diff['last_update'] = diff['last_update'].strftime('%Y-%m-%d %H:%M:%S')

                result.append({
                    'request': request,
                    'player': {
                        'id': player.id,
                        'name': player.name,
                        'country': player.country,
                        'badges': badges
                    },
                    'map_info': map_info,
                    'map_diffs': map_diffs
                })

            klogging.log(f"Successfully retrieved {len(result)} active map requests", level=klogging.logLevel.INFO, extra={"result_count": len(result)})
            return result
        except Exception as e:
            klogging.log(f"Failed to get map requests: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"error": str(e), "page": page})
            raise DatabaseError(f"Failed to get map requests: {str(e)}") from e


class ServerDataService:
    """Service for server data operations."""

    def __init__(self, server_data_repository):
        self.server_data_repo = server_data_repository

    async def trigger_break_event(self) -> None:
        """Trigger a break event."""
        try:
            timestamp = int(datetime.now().timestamp())
            klogging.log(f"Triggering break event at timestamp {timestamp}", level=klogging.logLevel.INFO, extra={"timestamp": timestamp, "operation": "trigger_break_event"})
            await self.server_data_repo.set_breakevent(timestamp)
            klogging.log("Break event triggered successfully", level=klogging.logLevel.INFO, extra={"timestamp": timestamp})
        except Exception as e:
            klogging.log(f"Failed to trigger break event: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"error": str(e)})
            raise DatabaseError(f"Failed to trigger break event: {str(e)}") from e


__all__ = [
    'PermissionService',
    'ActionService',
    'DashboardService',
    'UserService',
    'BadgeService',
    'MapRequestService',
    'ServerDataService',
]
