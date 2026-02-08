# -*- coding: utf-8 -*-
"""
Services for Admin Panel

This module contains service classes that orchestrate business logic,
coordinating between repositories, validators, and external services.
"""

import hashlib
import bcrypt
import requests
from typing import Optional, List, Dict, Any
from datetime import datetime

from objects import glob
from objects.utils import get_safe_name
from objects.privileges import Privileges, ComparePrivs, GetPriv

from .models import (
    ActionType, TargetType, User, Map, Badge, Action, ActionRequest,
    ActionResponse, PermissionCheck, DashboardData, UserDetail, BadgeDetail
)
from .exceptions import (
    AdminPanelError, AuthenticationError, AuthorizationError, ValidationError,
    ResourceNotFoundError, AlreadyExistsError, InvalidActionError,
    StateConflictError, DatabaseError, ExternalServiceError,
    PasswordValidationError, PrivilegeError, MapStatusError, ScoreError,
    BadgeError, UserAccountError
)
from .repositories import (
    UserRepository, MapRepository, BadgeRepository, UserBadgeRepository,
    ScoreRepository, StatsRepository, MapRequestRepository, LogRepository,
    ClientHashRepository, NewlyRankedRepository
)
from .validators import ActionRequestValidator, Validator


class PermissionService:
    """Service for permission checks."""
    
    @staticmethod
    def check_user_permission(user_priv: int, required_privilege: str) -> PermissionCheck:
        """Check if user has required privilege."""
        try:
            priv_enum = getattr(Privileges, required_privilege)
            has_permission = priv_enum in GetPriv(user_priv)
            
            if not has_permission:
                return PermissionCheck(
                    has_permission=False,
                    required_privilege=required_privilege,
                    user_privilege=user_priv,
                    error_message=f"You do not have permission to perform this action.",
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
    def check_privilege_hierarchy(mod_priv: int, target_priv: int, new_priv: Optional[int] = None) -> PermissionCheck:
        """Check privilege hierarchy for privilege modification."""
        # Check if mod can modify target
        if ComparePrivs(mod_priv, target_priv):
            return PermissionCheck(
                has_permission=False,
                error_message="You cannot modify people with privileges that you don't possess.",
                status_code=403
            )
        
        # Check if mod can grant new privileges
        if new_priv is not None and ComparePrivs(new_priv, mod_priv):
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
            target_id=request.user_id or request.map_id,
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
            # Get mod user
            mod = await self.user_repo.get_by_id(action.mod_id)
            if not mod:
                raise ResourceNotFoundError("User", action.mod_id)
            
            action.mod = mod  # type: ignore
            
            # Execute based on action type
            if action.is_user_action:
                await self._execute_user_action(action, request)
            elif action.is_map_action:
                await self._execute_map_action(action, request)
            elif action.is_badge_action:
                await self._execute_badge_action(action, request)
            
            # Log the action
            await self.log_repo.create(
                action_id=action.id,
                action=action.action.value,
                reason=action.reason,
                mod_id=action.mod_id,
                target_id=action.target_id,
                target_type=action.target_type
            )
            
            return ActionResponse(
                status="success",
                message=f"Successfully {action.text.lower()} {self._get_target_description(action)}.",
                action_id=action.id
            )
            
        except AdminPanelError:
            raise
        except Exception as e:
            raise DatabaseError(f"Failed to execute action: {str(e)}", e)
    
    async def _execute_user_action(self, action: Action, request: ActionRequest) -> None:
        """Execute user-specific actions."""
        # Get target user
        user = await self.user_repo.get_by_id(action.target_id)
        if not user:
            raise ResourceNotFoundError("User", action.target_id)
        
        action.user = user  # type: ignore
        
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
            await self._execute_change_password(action, request.password)
        elif action.action == ActionType.CHANGE_PRIVILEGES:
            await self._execute_change_privileges(action, request.privs)
        elif action.action == ActionType.EDIT_ACCOUNT:
            await self._execute_edit_account(action, request)
        elif action.action == ActionType.ADD_BADGE:
            await self._execute_add_badge(action, request.badge_id)
        elif action.action == ActionType.REMOVE_BADGE:
            await self._execute_remove_badge(action, request.badge_id)
        elif action.action == ActionType.REMOVE_SCORE:
            await self._execute_remove_score(action, request.score_id)
    
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
        badge = await self.badge_repo.get_by_id(request.badge_id)
        if not badge:
            raise ResourceNotFoundError("Badge", request.badge_id)
        
        action.badge = badge  # type: ignore
        
        # Execute specific action
        if action.action == ActionType.ADD_BADGE:
            await self._execute_add_badge(action, request.badge_id)
        elif action.action == ActionType.REMOVE_BADGE:
            await self._execute_remove_badge(action, request.badge_id)
    
    async def _execute_wipe(self, action: Action) -> None:
        """Execute wipe action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "WipeUsers"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Wipe scores
        await self.score_repo.wipe_user_scores(action.user.id)
        
        # Reset stats
        modes = [0, 1, 2, 3, 4, 5, 6, 7, 8]
        await self.stats_repo.reset_user_stats(action.user.id, modes)
        
        # Remove from leaderboards
        for mode in modes:
            await glob.redis.zrem(f"bancho:leaderboard:{mode}", action.user.id)
            await glob.redis.zrem(
                f"bancho:leaderboard:{mode}:{action.user.country}",
                action.user.id
            )
    
    async def _execute_restrict(self, action: Action) -> None:
        """Execute restrict action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "RestrictUsers"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if already restricted
        if action.user.priv == 0:
            raise StateConflictError("User is already restricted.")
        
        # Restrict user
        await self.user_repo.restrict(action.user.id)
    
    async def _execute_unrestrict(self, action: Action) -> None:
        """Execute unrestrict action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "RestrictUsers"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if already unrestricted
        if action.user.priv != 0:
            raise StateConflictError("User is not restricted.")
        
        # Unrestrict user
        await self.user_repo.unrestrict(action.user.id)
    
    async def _execute_silence(self, action: Action) -> None:
        """Execute silence action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "SilenceUsers"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if already silenced
        if action.user.silence_end != 0:
            raise StateConflictError("User is already silenced.")
        
        # Calculate silence end time
        silence_end = int(datetime.now().timestamp()) + action.duration * 3600
        
        # Update user
        await self.user_repo.update_silence(action.user.id, silence_end)
    
    async def _execute_unsilence(self, action: Action) -> None:
        """Execute unsilence action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "SilenceUsers"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if not silenced
        if action.user.silence_end == 0:
            raise StateConflictError("User is not silenced.")
        
        # Update user
        await self.user_repo.update_silence(action.user.id, 0)
    
    async def _execute_change_password(self, action: Action, password: str) -> None:
        """Execute change password action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageUsers"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Validate password
        Validator.validate_password(password, "password")
        
        # Get current password hash
        bcrypt_cache = glob.cache['bcrypt']
        pw_bcrypt = (await glob.db.fetch(
            'SELECT pw_bcrypt FROM users WHERE id = %s',
            [action.user.id]
        ))['pw_bcrypt'].encode()
        
        # Remove from cache if exists
        if pw_bcrypt in bcrypt_cache:
            del bcrypt_cache[pw_bcrypt]
        
        # Calculate new password hash
        pw_md5 = hashlib.md5(password.encode()).hexdigest().encode()
        pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())
        
        # Update cache and database
        bcrypt_cache[pw_bcrypt] = pw_md5
        await self.user_repo.update_password(action.user.id, pw_bcrypt, action.user.safe_name)
    
    async def _execute_change_privileges(self, action: Action, new_priv: int) -> None:
        """Execute change privileges action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManagePrivs"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check privilege hierarchy
        hierarchy_check = PermissionService.check_privilege_hierarchy(
            action.mod.priv, action.user.priv, new_priv
        )
        if not hierarchy_check.has_permission:
            raise AuthorizationError(hierarchy_check.error_message)
        
        # Check if privileges are already set
        if ComparePrivs(action.user.priv, new_priv):
            raise StateConflictError(f"Privileges are already set to {action.user.priv}.")
        
        # Update privileges
        await self.user_repo.update_privileges(action.user.id, new_priv)
    
    async def _execute_edit_account(self, action: Action, request: ActionRequest) -> None:
        """Execute edit account action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageUsers"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Validate inputs
        Validator.validate_string(request.username, "username", min_length=1, max_length=32)
        Validator.validate_email(request.email, "email")
        Validator.validate_country_code(request.country, "country")
        
        # Check username availability
        if action.user.name != request.username:
            safe_name = get_safe_name(request.username)
            existing_user = await self.user_repo.get_by_safe_name(safe_name)
            if existing_user:
                raise AlreadyExistsError("Username", request.username)
            
            existing_user_by_name = await self.user_repo.get_by_name(request.username)
            if existing_user_by_name:
                raise AlreadyExistsError("Username", request.username)
        
        # Check email availability
        if action.user.email != request.email:
            existing_user = await self.user_repo.get_by_email(request.email)
            if existing_user:
                raise AlreadyExistsError("Email", request.email)
        
        # Update account
        safe_name = get_safe_name(request.username)
        await self.user_repo.update_account(
            action.user.id,
            request.username,
            safe_name,
            request.email,
            request.country,
            request.userpage_content
        )
    
    async def _execute_add_badge(self, action: Action, badge_id: int) -> None:
        """Execute add badge action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBadges"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if user already has badge
        has_badge = await self.user_badge_repo.has_badge(action.user.id, badge_id)
        if has_badge:
            raise StateConflictError("User already has this badge.")
        
        # Add badge
        await self.user_badge_repo.add_badge(action.user.id, badge_id)
    
    async def _execute_remove_badge(self, action: Action, badge_id: int) -> None:
        """Execute remove badge action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBadges"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if user has badge
        has_badge = await self.user_badge_repo.has_badge(action.user.id, badge_id)
        if not has_badge:
            raise StateConflictError("User does not have this badge.")
        
        # Remove badge
        await self.user_badge_repo.remove_badge(action.user.id, badge_id)
    
    async def _execute_remove_score(self, action: Action, score_id: int) -> None:
        """Execute remove score action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageScores"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if score exists
        score_exists = await self.score_repo.exists(score_id)
        if not score_exists:
            raise ResourceNotFoundError("Score", score_id)
        
        # Remove score
        await self.score_repo.remove_score(score_id)
    
    async def _execute_rank(self, action: Action) -> None:
        """Execute rank action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if already ranked
        if action.map.status == 2:
            raise StateConflictError("Map is already ranked.")
        
        # Update map status via API
        await self._update_map_status_via_api(action.map.id, 2)
        
        # Deactivate map request
        await self.map_request_repo.deactivate_request(action.map.id)
        
        # Add to newly ranked
        await self.newly_ranked_repo.add(action.map.id, action.mod_id)
    
    async def _execute_approve(self, action: Action) -> None:
        """Execute approve action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if already approved
        if action.map.status == 3:
            raise StateConflictError("Map is already approved.")
        
        # Update map status via API
        await self._update_map_status_via_api(action.map.id, 3)
        
        # Deactivate map request
        await self.map_request_repo.deactivate_request(action.map.id)
    
    async def _execute_qualify(self, action: Action) -> None:
        """Execute qualify action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if already qualified
        if action.map.status == 4:
            raise StateConflictError("Map is already qualified.")
        
        # Update map status via API
        await self._update_map_status_via_api(action.map.id, 4)
        
        # Deactivate map request
        await self.map_request_repo.deactivate_request(action.map.id)
    
    async def _execute_love(self, action: Action) -> None:
        """Execute love action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if already loved
        if action.map.status == 5:
            raise StateConflictError("Map is already loved.")
        
        # Update map status via API
        await self._update_map_status_via_api(action.map.id, 5)
        
        # Deactivate map request
        await self.map_request_repo.deactivate_request(action.map.id)
    
    async def _execute_unrank(self, action: Action) -> None:
        """Execute unrank action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Check if not ranked
        if action.map.status == 0:
            raise StateConflictError("Map is not ranked.")
        
        # Update map status via API
        await self._update_map_status_via_api(action.map.id, 0)
        
        # Deactivate and freeze map request
        await self.map_request_repo.deactivate_and_freeze_request(action.map.id)
    
    async def _execute_complete_request(self, action: Action) -> None:
        """Execute complete request action."""
        # Check permission
        permission_check = PermissionService.check_user_permission(
            action.mod.priv, "ManageBeatmaps"
        )
        if not permission_check.has_permission:
            raise AuthorizationError(permission_check.error_message)
        
        # Deactivate map request
        await self.map_request_repo.deactivate_request(action.map.id)
    
    async def _update_map_status_via_api(self, map_id: int, status: int) -> None:
        """Update map status via external API."""
        try:
            status_update_url = f"https://api.{glob.config.domain}/v1/update_map_status"
            headers = {
                "Authorization": f"Bearer {glob.config.api_key}"
            }
            params = {
                "id": map_id,
                "s": status
            }
            
            response = requests.post(status_update_url, headers=headers, params=params)
            json_response = response.json()
            
            if json_response.get("status") != "success":
                raise ExternalServiceError(
                    "Map Status API",
                    f"Failed to update map status: {json_response.get('status')}"
                )
        except requests.RequestException as e:
            raise ExternalServiceError("Map Status API", str(e))
    
    def _get_target_description(self, action: Action) -> str:
        """Get description of action target."""
        if action.is_user_action and hasattr(action, 'user'):
            return f"{action.user.name} ({action.user.id})"
        elif action.is_map_action and hasattr(action, 'map'):
            return f"{action.map.artist} - {action.map.title} [{action.map.version}] ({action.map.id})"
        elif action.is_badge_action and hasattr(action, 'badge'):
            return f"badge {action.badge.id}"
        return "unknown target"


class DashboardService:
    """Service for dashboard operations."""
    
    def __init__(self, user_repository: UserRepository):
        self.user_repo = user_repository
    
    async def get_dashboard_data(self) -> DashboardData:
        """Get dashboard statistics."""
        try:
            # Get total user count
            total_users = await self.user_repo.get_count()
            
            # Get latest user
            latest_user_data = await glob.db.fetch(
                "SELECT name FROM users ORDER BY id DESC LIMIT 1"
            )
            latest_user = latest_user_data['name'] if latest_user_data else "N/A"
            
            # Get banned user count
            banned_data = await glob.db.fetch(
                "SELECT COUNT(id) as banned FROM users WHERE NOT priv & 1"
            )
            banned_users = banned_data['banned'] if banned_data else 0
            
            # Get recent users
            recent_users = await glob.db.fetchall(
                "SELECT * FROM users ORDER BY id DESC LIMIT 5"
            )
            
            # Get recent scores
            recent_scores = await glob.db.fetchall(
                """
                SELECT scores.*, maps.artist, maps.title, maps.set_id, maps.creator, maps.version
                FROM scores JOIN maps ON scores.map_md5 = maps.md5
                ORDER BY scores.id DESC LIMIT 5
                """
            )
            
            return DashboardData(
                total_users=total_users,
                latest_user=latest_user,
                banned_users=banned_users,
                recent_users=recent_users,
                recent_scores=recent_scores
            )
        except Exception as e:
            raise DatabaseError(f"Failed to get dashboard data: {str(e)}", e)


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
            # Get user
            user = await self.user_repo.get_by_id(user_id)
            if not user:
                raise ResourceNotFoundError("User", user_id)
            
            # Get user badges
            user_badges_data = await self.user_badge_repo.get_user_badges(user_id)
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
            
            # Enrich admin logs with mod info
            for admin_log in admin_logs:
                mod = await self.user_repo.get_by_id(admin_log['mod'])
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
            
            return UserDetail(user=user_dict, badges=badges, logs=logs)
        except Exception as e:
            raise DatabaseError(f"Failed to get user detail: {str(e)}", e)


class BadgeService:
    """Service for badge operations."""
    
    def __init__(self, badge_repository: BadgeRepository):
        self.badge_repo = badge_repository
    
    async def get_all_badges(self) -> List[Dict[str, Any]]:
        """Get all badges."""
        try:
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
            
            return result
        except Exception as e:
            raise DatabaseError(f"Failed to get badges: {str(e)}", e)
    
    async def get_badge_detail(self, badge_id: int) -> BadgeDetail:
        """Get detailed badge information."""
        try:
            badge = await self.badge_repo.get_by_id(badge_id)
            if not badge:
                raise ResourceNotFoundError("Badge", badge_id)
            
            badge_styles = await self.badge_repo.get_styles(badge_id)
            
            badge_dict = {
                'id': badge.id,
                'name': badge.name,
                'description': badge.description,
                'priority': badge.priority,
                'styles': badge_styles
            }
            
            return BadgeDetail(badge=badge_dict, styles=badge_styles)
        except Exception as e:
            raise DatabaseError(f"Failed to get badge detail: {str(e)}", e)
    
    async def create_badge(self, name: str, description: str, priority: int, styles: List[Dict[str, str]]) -> None:
        """Create a new badge."""
        try:
            # Check if badge already exists
            existing_badge = await self.badge_repo.get_by_name(name)
            if existing_badge:
                raise AlreadyExistsError("Badge", name)
            
            # Create badge
            badge_id = await self.badge_repo.create(name, description, priority)
            if not badge_id:
                raise BadgeError("Failed to create badge")
            
            # Add styles
            for style in styles:
                await self.badge_repo.update_style(badge_id, style['type'], style['value'])
        except AdminPanelError:
            raise
        except Exception as e:
            raise DatabaseError(f"Failed to create badge: {str(e)}", e)
    
    async def update_badge(self, badge_id: int, name: str, description: str, priority: int, styles: List[Dict[str, str]]) -> None:
        """Update an existing badge."""
        try:
            # Check if badge exists
            badge = await self.badge_repo.get_by_id(badge_id)
            if not badge:
                raise ResourceNotFoundError("Badge", badge_id)
            
            # Update badge
            await self.badge_repo.update(badge_id, name, description, priority)
            
            # Update styles
            for style in styles:
                await self.badge_repo.update_style(badge_id, style['type'], style['value'])
        except AdminPanelError:
            raise
        except Exception as e:
            raise DatabaseError(f"Failed to update badge: {str(e)}", e)


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
    
    async def get_active_requests(self, page: int, items_per_page: int = 50) -> List[Dict[str, Any]]:
        """Get active map requests."""
        try:
            offset = (page - 1) * items_per_page
            requests = await self.map_request_repo.get_active_requests(items_per_page, offset)
            
            result = []
            for request in requests:
                # Get player info
                player = await self.user_repo.get_by_id(request['player_id'])
                if not player:
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
                    if map_row['id'] == request['map_id']:
                        map_info = map_row
                    else:
                        map_diffs.append(map_row)
                
                if not map_info:
                    # Delete invalid request
                    await glob.db.execute(
                        "DELETE FROM map_requests WHERE id = %s",
                        [request['id']]
                    )
                    continue
                
                # Format dates
                request['datetime'] = request['datetime'].strftime('%Y-%m-%d %H:%M:%S')
                map_info['last_update'] = map_info['last_update'].strftime('%Y-%m-%d %H:%M:%S')
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
            
            return result
        except Exception as e:
            raise DatabaseError(f"Failed to get map requests: {str(e)}", e)


class ServerDataService:
    """Service for server data operations."""
    
    def __init__(self, server_data_repository):
        self.server_data_repo = server_data_repository
    
    async def trigger_break_event(self) -> None:
        """Trigger a break event."""
        try:
            timestamp = int(datetime.now().timestamp())
            await self.server_data_repo.set_breakevent(timestamp)
        except Exception as e:
            raise DatabaseError(f"Failed to trigger break event: {str(e)}", e)


__all__ = [
    'PermissionService',
    'ActionService',
    'DashboardService',
    'UserService',
    'BadgeService',
    'MapRequestService',
    'ServerDataService',
]
