"""
Utility Functions for Admin Panel

This module contains utility functions for the admin panel,
providing common functionality used across different services.
"""

import asyncio
import hashlib
import logging
from datetime import datetime
from typing import Any

import bcrypt
from discord_webhook import DiscordEmbed, DiscordWebhook
from quart import request, session

from objects import glob
from objects.privileges import ComparePrivs, GetPriv, Privileges
from objects.utils import error_catcher, klogging

from .exceptions import (
    AdminPanelError,
    AuthenticationError,
    AuthorizationError,
    ValidationError,
)
from .models import Action, ActionType


class SessionManager:
    """Manage session data for admin panel."""

    @staticmethod
    def is_authenticated() -> bool:
        """Check if user is authenticated."""
        return 'authenticated' in session

    @staticmethod
    def get_user_id() -> int | None:
        """Get current user ID from session."""
        if 'user_data' in session:
            return session['user_data'].get('id')
        return None

    @staticmethod
    def get_user_priv() -> int | None:
        """Get current user privileges from session."""
        if 'user_data' in session:
            return session['user_data'].get('priv')
        return None

    @staticmethod
    def is_staff() -> bool:
        """Check if current user is staff."""
        if 'user_data' in session:
            return session['user_data'].get('is_staff', False)
        return False

    @staticmethod
    def require_authentication() -> None:
        """Require authentication, raise error if not authenticated."""
        if not SessionManager.is_authenticated():
            klogging.log("Authentication required but user not authenticated", level=klogging.logLevel.WARNING, extra={"ip": request.remote_addr, "path": request.path})
            raise AuthenticationError()

    @staticmethod
    def require_staff() -> None:
        """Require staff privileges, raise error if not staff."""
        SessionManager.require_authentication()
        if not SessionManager.is_staff():
            user_id = SessionManager.get_user_id()
            klogging.log(f"Staff privileges required but user {user_id} is not staff", level=klogging.logLevel.WARNING, extra={"user_id": user_id, "path": request.path})
            raise AuthorizationError()


class RequestValidator:
    """Validate request data."""

    @staticmethod
    def validate_content_type(expected: str = "application/x-www-form-urlencoded") -> None:
        """Validate request content type."""
        received = (request.content_type or "").split(";", 1)[0].strip()
        if received != expected:
            klogging.log(f"Invalid content type: received '{received}', expected '{expected}'", level=klogging.logLevel.WARNING, extra={"received_content_type": received, "expected_content_type": expected, "path": request.path})
            raise ValidationError(f"Invalid content type. Use {expected}.")

    @staticmethod
    async def get_form_data() -> dict[str, Any]:
        """Get form data from request."""
        form = await request.form
        if not form:
            klogging.log("No form data provided in request", level=klogging.logLevel.WARNING, extra={"path": request.path, "method": request.method})
            raise ValidationError("No form data provided.")
        return form

    @staticmethod
    async def get_json_data() -> dict[str, Any]:
        """Get JSON data from request."""
        data = await request.get_json()
        if not data:
            klogging.log("No JSON data provided in request", level=klogging.logLevel.WARNING, extra={"path": request.path, "method": request.method})
            raise ValidationError("No JSON data provided.")
        return data

    @staticmethod
    def get_query_param(name: str, default: Any = None) -> Any:
        """Get query parameter from request."""
        return request.args.get(name, default)


class DiscordLogger:
    """Handle Discord webhook logging."""

    def __init__(self, admin_webhook_url: str, ranked_webhook_url: str):
        self.admin_webhook_url = admin_webhook_url
        self.ranked_webhook_url = ranked_webhook_url

    async def log_user_action(self, action: Action, mod_name: str, mod_id: int, user_name: str, user_id: int) -> None:
        """Log user action to Discord."""
        try:
            if action.action == ActionType.CHANGE_PASSWORD:
                # Don't log password changes
                klogging.log("Skipping Discord log for password change", level=klogging.logLevel.DEBUG, extra={"action_id": action.id, "user_id": user_id})
                return

            klogging.log(f"Logging user action to Discord: {action.action.value} on {user_name}", level=klogging.logLevel.INFO, extra={"action_id": action.id, "mod_id": mod_id, "user_id": user_id, "action_type": action.action.value})

            webhook = DiscordWebhook(self.admin_webhook_url)

            embed = DiscordEmbed(
                title=f"{user_name} was {action.text} by {mod_name}",
                description=f"a {action.action.value} was performed.",
                color=5126045,
                timestamp=datetime.now()
            )

            embed.set_author(
                name=f"New Action By {mod_name}",
                icon_url=f"https://a.kawata.pw/{mod_id}"
            )

            embed.add_embed_field(
                name="Information:",
                value=f"Action ID: {action.id}\nAction Moderator: {mod_name} ({mod_id})\nAction User: {user_name} ({user_id})\nAction Type: {action.action.value}\nAction Reason: {action.reason}",
                inline=False
            )

            embed.set_footer(
                text=f"ID: {action.id}",
                icon_url=f"https://a.kawata.pw/{user_id}"
            )

            webhook.add_embed(embed)
            await asyncio.to_thread(webhook.execute)
            klogging.log("Successfully logged user action to Discord", level=klogging.logLevel.INFO, extra={"action_id": action.id})
        except Exception as e:
            klogging.log(f"Failed to log user action to Discord: {e}", start_color=klogging.Ansi.LYELLOW, level=klogging.logLevel.WARNING, extra={"action_id": action.id, "error": str(e)})

    async def log_map_action(self, action: Action, mod_name: str, mod_id: int, map_obj: Any) -> None:
        """Log map action to Discord."""
        try:
            klogging.log(f"Logging map action to Discord: {action.action.value} on {map_obj.title} [{map_obj.version}]", level=klogging.logLevel.INFO, extra={"action_id": action.id, "mod_id": mod_id, "map_id": map_obj.id, "action_type": action.action.value})

            webhook = DiscordWebhook(self.ranked_webhook_url)

            embed = DiscordEmbed(
                title=f"{map_obj.title} [{map_obj.version}] was {action.text} by {mod_name} ({mod_id})",
                description=f"[{map_obj.title} [{map_obj.version}]](https://osu.ppy.sh/b/{map_obj.id}) was {action.text}",
                color=5126045,
                timestamp=datetime.now()
            )

            embed.set_author(
                name=f"Diff {action.text} By {mod_name} ({mod_id})",
                icon_url=f"https://a.kawata.pw/{mod_id}"
            )

            embed.add_embed_field(
                name="Information:",
                value=f"""
                Ranked By: {mod_name} ({mod_id})
                Map: {map_obj.title} [{map_obj.version}] ({map_obj.id})
                Map Stats: CS: {map_obj.cs} AR: {map_obj.ar} OD: {map_obj.od} HP: {map_obj.hp} NM*: {map_obj.diff}
                Action: {action.action.value}
                """,
                inline=False
            )

            embed.set_image(url=f"https://assets.ppy.sh/beatmaps/{map_obj.set_id}/covers/card@2x.jpg")

            embed.set_footer(
                text=f"ID: {action.id}",
                icon_url=f"https://a.kawata.pw/{mod_id}"
            )

            webhook.add_embed(embed)
            await asyncio.to_thread(webhook.execute)
            klogging.log("Successfully logged map action to Discord", level=klogging.logLevel.INFO, extra={"action_id": action.id, "map_id": map_obj.id})
        except Exception as e:
            klogging.log(f"Failed to log map action to Discord: {e}", start_color=klogging.Ansi.LYELLOW, level=klogging.logLevel.WARNING, extra={"action_id": action.id, "map_id": map_obj.id, "error": str(e)})

    async def log_badge_action(self, action: Action, mod_name: str, mod_id: int, user_name: str, user_id: int, badge: Any) -> None:
        """Log badge action to Discord."""
        try:
            klogging.log(f"Logging badge action to Discord: {action.action.value} badge '{badge['name']}' on {user_name}", level=klogging.logLevel.INFO, extra={"action_id": action.id, "mod_id": mod_id, "user_id": user_id, "badge_id": badge['id'], "action_type": action.action.value})

            webhook = DiscordWebhook(self.admin_webhook_url)

            embed = DiscordEmbed(
                title=f"{user_name} was {action.text} {badge['name']} by {mod_name}",
                description="",
                color=5126045,
                timestamp=datetime.now()
            )

            embed.set_author(
                name=f"New Action By {mod_name}",
                icon_url=f"https://a.kawata.pw/{mod_id}"
            )

            embed.add_embed_field(
                name="Information:",
                value=f"""
                Action Moderator: {mod_name} ({mod_id})
                Action User: {user_name} ({user_id})
                Badge: {badge['name']} ({badge['id']})
                Badge Description: {badge['description']}
                """,
                inline=False
            )

            embed.set_footer(
                text=f"ID: {action.id}",
                icon_url=f"https://a.kawata.pw/{user_id}"
            )

            webhook.add_embed(embed)
            await asyncio.to_thread(webhook.execute)
            klogging.log("Successfully logged badge action to Discord", level=klogging.logLevel.INFO, extra={"action_id": action.id, "badge_id": badge['id']})
        except Exception as e:
            klogging.log(f"Failed to log badge action to Discord: {e}", start_color=klogging.Ansi.LYELLOW, level=klogging.logLevel.WARNING, extra={"action_id": action.id, "badge_id": badge['id'], "error": str(e)})


class ResponseFormatter:
    """Format responses for the admin panel."""

    @staticmethod
    def success(message: str, action_id: str | None = None, details: dict[str, Any] | None = None) -> dict[str, Any]:
        """Create a success response."""
        response = {
            "status": "success",
            "message": message
        }

        if action_id:
            response["action_id"] = action_id

        if details:
            response.update(details)

        return response

    @staticmethod
    def error(message: str, field: str | None = None, missing_fields: list | None = None) -> dict[str, Any]:
        """Create an error response."""
        response = {
            "status": "error",
            "message": message
        }

        if field:
            response["field"] = field

        if missing_fields:
            response["missing_fields"] = missing_fields  # ty:ignore[invalid-assignment]

        return response

    @staticmethod
    def validation_error(errors: list) -> dict[str, Any]:
        """Create a validation error response."""
        return {
            "status": "error",
            "message": "Validation failed",
            "errors": errors
        }

    @staticmethod
    def permission_error(action: str) -> dict[str, Any]:
        """Create a permission error response."""
        return ResponseFormatter.error(f"You do not have permission to {action}.")

    @staticmethod
    def not_found_error(resource_type: str, resource_id: int) -> dict[str, Any]:
        """Create a not found error response."""
        return ResponseFormatter.error(f"{resource_type} with ID {resource_id} does not exist.")

    @staticmethod
    def conflict_error(message: str) -> dict[str, Any]:
        """Create a conflict error response."""
        return ResponseFormatter.error(message)


class PasswordManager:
    """Manage password operations."""

    @staticmethod
    def validate_password(password: str) -> None:
        """Validate password strength."""
        if not 8 <= len(password) <= 32:
            raise ValueError("Password must be between 8 and 32 characters.")

    @staticmethod
    def hash_password(password: str) -> tuple:
        """Hash a password."""
        pw_md5 = hashlib.md5(password.encode()).hexdigest().encode()
        pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())
        return pw_md5, pw_bcrypt

    @staticmethod
    async def update_password_cache(user_id: int, pw_bcrypt: bytes, pw_md5: bytes) -> None:
        """Update password in cache."""
        bcrypt_cache = glob.cache['bcrypt']

        # Get old password hash
        old_pw_bcrypt = await glob.db.fetch(
            'SELECT pw_bcrypt FROM users WHERE id = %s',
            [user_id]
        )

        if old_pw_bcrypt and old_pw_bcrypt['pw_bcrypt'].encode() in bcrypt_cache:  # ty:ignore[invalid-argument-type]
            del bcrypt_cache[old_pw_bcrypt['pw_bcrypt'].encode()]  # ty:ignore[invalid-argument-type]

        # Add new password to cache
        bcrypt_cache[pw_bcrypt] = pw_md5


class PrivilegeChecker:
    """Check user privileges."""

    @staticmethod
    def has_privilege(user_priv: int, required_privilege: str) -> bool:
        """Check if user has required privilege."""
        try:
            priv_enum = getattr(Privileges, required_privilege)
            return bool(user_priv) and priv_enum in GetPriv(user_priv)  # ty:ignore[unsupported-operator]
        except AttributeError:
            return False

    @staticmethod
    def can_modify_privileges(mod_priv: int, target_priv: int, new_priv: int | None = None) -> tuple:
        """Check if moderator can modify privileges."""
        # Check if mod can modify target (target must be subset of mod's privs)
        if target_priv and not ComparePrivs(mod_priv, target_priv):
            return False, "You cannot modify people with privileges that you don't possess."

        # Check if mod can grant new privileges (new privs must be subset of mod's privs)
        if new_priv is not None and new_priv and not ComparePrivs(mod_priv, new_priv):
            return False, "You cannot grant privileges that you don't possess."

        return True, None


class MapStatusUpdater:
    """Update map status via API."""

    @staticmethod
    async def update_status(map_id: int, status: int) -> bool:
        """Update map status via external API."""
        try:
            klogging.log(f"Updating map {map_id} status to {status} via API", level=klogging.logLevel.INFO, extra={"map_id": map_id, "status": status, "operation": "update_map_status"})
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

            if json_response.get("status") == "success":
                klogging.log(f"Successfully updated map {map_id} status to {status}", level=klogging.logLevel.INFO, extra={"map_id": map_id, "status": status})
                return True
            else:
                klogging.log(f"Failed to update map status: {json_response.get('status')}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"map_id": map_id, "api_response": json_response})
                return False
        except Exception as e:
            klogging.log(f"Error updating map status: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"map_id": map_id, "error": str(e)})
            return False


class ScoreManager:
    """Manage score operations."""

    @staticmethod
    async def wipe_user_scores(user_id: int) -> None:
        """Wipe all scores for a user."""
        async with glob.db.pool.acquire() as conn:  # ty:ignore[unresolved-attribute]
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO wiped_scores (id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id)
                    SELECT id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id
                    FROM scores
                    WHERE userid = %s
                    """,
                    [user_id]
                )
                await cur.execute(
                    "DELETE FROM scores WHERE userid = %s",
                    [user_id]
                )

    @staticmethod
    async def remove_score(score_id: int) -> None:
        """Remove a specific score."""
        async with glob.db.pool.acquire() as conn:  # ty:ignore[unresolved-attribute]
            async with conn.cursor() as cur:
                await cur.execute(
                    """
                    INSERT INTO wiped_scores (id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id)
                    SELECT id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id
                    FROM scores
                    WHERE id = %s
                    """,
                    [score_id]
                )
                await cur.execute(
                    "DELETE FROM scores WHERE id = %s",
                    [score_id]
                )


class StatsManager:
    """Manage stats operations."""

    @staticmethod
    async def reset_user_stats(user_id: int) -> None:
        """Reset user stats for all modes."""
        modes = [0, 1, 2, 3, 4, 5, 6, 7, 8]

        for mode in modes:
            await glob.db.execute(
                """
                UPDATE stats
                SET tscore = 0, rscore = 0, pp = 0, plays = 0, playtime = 0, acc = 0.000, max_combo = 0, total_hits = 0, replay_views = 0, xh_count = 0, x_count = 0, sh_count = 0, s_count = 0, a_count = 0
                WHERE id = %s AND mode = %s
                """,
                [user_id, mode]
            )

    @staticmethod
    async def remove_from_leaderboards(user_id: int, country: str) -> None:
        """Remove user from leaderboards."""
        modes = [0, 1, 2, 3, 4, 5, 6, 7, 8]

        for mode in modes:
            await glob.redis.zrem(f"bancho:leaderboard:{mode}", user_id)
            await glob.redis.zrem(f"bancho:leaderboard:{mode}:{country}", user_id)


class FormValidator:
    """Validate form data."""

    @staticmethod
    def validate_required_fields(form_data: dict[str, Any], required_fields: list) -> None:
        """Validate that all required fields are present."""
        missing_fields = []

        for field in required_fields:
            if field not in form_data or not form_data[field]:
                missing_fields.append(field)

        if missing_fields:
            raise ValueError(f"Missing required fields: {', '.join(missing_fields)}")

    @staticmethod
    def validate_content_type(content_type: str) -> None:
        """Validate request content type."""
        if content_type != "application/x-www-form-urlencoded":
            raise ValueError("Invalid content type. Use application/x-www-form-urlencoded.")


class ErrorCatcher:
    """Decorator for catching and handling errors."""

    @staticmethod
    def catch(func):
        """Decorator to catch and handle errors."""
        @error_catcher
        async def wrapper(*args, **kwargs):
            try:
                return await func(*args, **kwargs)
            except AdminPanelError:
                # Re-raise admin panel errors
                raise
            except Exception as e:
                # Convert other errors to AdminPanelError
                raise AdminPanelError(f"An unexpected error occurred: {str(e)}") from e
        return wrapper


__all__ = [
    'SessionManager',
    'RequestValidator',
    'DiscordLogger',
    'ResponseFormatter',
    'PasswordManager',
    'PrivilegeChecker',
    'MapStatusUpdater',
    'ScoreManager',
    'StatsManager',
    'FormValidator',
    'ErrorCatcher',
]
