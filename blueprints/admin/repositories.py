"""
Database Repositories for Admin Panel

This module contains repository classes for database operations,
providing a clean separation between business logic and data access.
"""

from datetime import datetime
from typing import Any

from objects import glob
from objects.privileges import Privileges

from .exceptions import DatabaseError
from .models import Badge, Map, TargetType, User


class UserRepository:
    """Repository for user-related database operations."""

    @staticmethod
    async def get_by_id(user_id: int) -> User | None:
        """Get user by ID."""
        try:
            data = await glob.db.fetch(
                "SELECT * FROM users WHERE id = %s",
                [user_id]
            )
            if data is None:
                return None
            return User.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to fetch user {user_id}: {str(e)}") from e

    @staticmethod
    async def get_by_safe_name(safe_name: str) -> User | None:
        """Get user by safe name."""
        try:
            data = await glob.db.fetch(
                "SELECT * FROM users WHERE safe_name = %s",
                [safe_name]
            )
            if data is None:
                return None
            return User.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to fetch user by safe name: {str(e)}") from e

    @staticmethod
    async def get_by_name(name: str) -> User | None:
        """Get user by name."""
        try:
            data = await glob.db.fetch(
                "SELECT * FROM users WHERE name = %s",
                [name]
            )
            if data is None:
                return None
            return User.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to fetch user by name: {str(e)}") from e

    @staticmethod
    async def get_by_email(email: str) -> User | None:
        """Get user by email."""
        try:
            data = await glob.db.fetch(
                "SELECT * FROM users WHERE email = %s",
                [email]
            )
            if data is None:
                return None
            return User.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to fetch user by email: {str(e)}") from e

    @staticmethod
    async def update_privileges(user_id: int, priv: int) -> None:
        """Update user privileges."""
        try:
            await glob.db.execute(
                "UPDATE users SET priv = %s WHERE id = %s",
                [priv, user_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to update privileges for user {user_id}: {str(e)}") from e

    @staticmethod
    async def update_password(user_id: int, pw_bcrypt: bytes, safe_name: str) -> None:
        """Update user password."""
        try:
            await glob.db.execute(
                "UPDATE users SET pw_bcrypt = %s WHERE safe_name = %s",
                [pw_bcrypt, safe_name]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to update password for user {user_id}: {str(e)}") from e

    @staticmethod
    async def update_account(user_id: int, username: str, safe_name: str, email: str, country: str, userpage_content: str) -> None:
        """Update user account details."""
        try:
            await glob.db.execute(
                "UPDATE users SET name = %s, safe_name = %s, email = %s, country = %s, userpage_content = %s WHERE id = %s",
                [username, safe_name, email, country, userpage_content, user_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to update account for user {user_id}: {str(e)}") from e

    @staticmethod
    async def update_silence(user_id: int, silence_end: int) -> None:
        """Update user silence status."""
        try:
            await glob.db.execute(
                "UPDATE users SET silence_end = %s WHERE id = %s",
                [silence_end, user_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to update silence for user {user_id}: {str(e)}") from e

    @staticmethod
    async def restrict(user_id: int) -> None:
        """Restrict user."""
        try:
            await glob.db.execute(
                "UPDATE users SET priv = 0 WHERE id = %s",
                [user_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to restrict user {user_id}: {str(e)}") from e

    @staticmethod
    async def unrestrict(user_id: int) -> None:
        """Unrestrict user."""
        try:
            await glob.db.execute(
                "UPDATE users SET priv = 1 WHERE id = %s",
                [user_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to unrestrict user {user_id}: {str(e)}") from e

    @staticmethod
    async def get_count(filters: dict[str, Any] | None = None) -> int:
        """Get user count with optional filters."""
        try:
            query = "SELECT COUNT(*) as total FROM users"
            params = []

            if filters:
                conditions = []
                if 'search' in filters:
                    search = filters['search']
                    if search.isdigit():
                        conditions.append("id = %s")
                        params.append(int(search))
                    else:
                        conditions.append("name LIKE %s")
                        params.append(f"%{search}%")

                if 'filter_priv' in filters:
                    filter_priv = filters['filter_priv']
                    if filter_priv == 'normal':
                        conditions.append("priv = 1")
                    elif filter_priv == 'supporter':
                        conditions.append("priv & 4 != 0")
                    elif filter_priv == 'mod':
                        conditions.append(f"priv & {int(Privileges.AccessPanel)} != 0 AND NOT priv & {int(Privileges.ManagePrivs)}")
                    elif filter_priv == 'admin':
                        conditions.append(f"priv & {int(Privileges.ManagePrivs)} != 0")
                    elif filter_priv == 'restricted':
                        conditions.append("NOT priv & 1")

                if 'filter_country' in filters:
                    conditions.append("country = %s")
                    params.append(filters['filter_country'].upper())

                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

            result = await glob.db.fetch(query, params)
            return result['total'] if result else 0  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to get user count: {str(e)}") from e

    @staticmethod
    async def get_list(
        limit: int,
        offset: int,
        sort_by: str = "id",
        sort_order: str = "ASC",
        filters: dict[str, Any] | None = None
    ) -> list[dict[str, Any]]:
        """Get list of users with pagination and filtering."""
        try:
            query = "SELECT id, name, priv, country, creation_time, latest_activity FROM users"
            params = []

            if filters:
                conditions = []
                if 'search' in filters:
                    search = filters['search']
                    if search.isdigit():
                        conditions.append("id = %s")
                        params.append(int(search))
                    else:
                        conditions.append("name LIKE %s")
                        params.append(f"%{search}%")

                if 'filter_priv' in filters:
                    filter_priv = filters['filter_priv']
                    if filter_priv == 'normal':
                        conditions.append("priv = 1")
                    elif filter_priv == 'supporter':
                        conditions.append("priv & 4 != 0")
                    elif filter_priv == 'mod':
                        conditions.append(f"priv & {int(Privileges.AccessPanel)} != 0 AND NOT priv & {int(Privileges.ManagePrivs)}")
                    elif filter_priv == 'admin':
                        conditions.append(f"priv & {int(Privileges.ManagePrivs)} != 0")
                    elif filter_priv == 'restricted':
                        conditions.append("NOT priv & 1")

                if 'filter_country' in filters:
                    conditions.append("country = %s")
                    params.append(filters['filter_country'].upper())

                if conditions:
                    query += " WHERE " + " AND ".join(conditions)

            query += f" ORDER BY {sort_by} {sort_order} LIMIT %s OFFSET %s"
            params.extend([limit, offset])

            return await glob.db.fetchall(query, params)  # ty:ignore[invalid-return-type]
        except Exception as e:
            raise DatabaseError(f"Failed to get user list: {str(e)}") from e

    @staticmethod
    async def get_customisations(user_id: int) -> dict[str, Any] | None:
        """Get user customisations."""
        try:
            return await glob.db.fetch(
                "SELECT * FROM user_customisations WHERE userid = %s",
                [user_id]
            )  # ty:ignore[invalid-return-type]
        except Exception as e:
            raise DatabaseError(f"Failed to get customisations for user {user_id}: {str(e)}") from e


class MapRepository:
    """Repository for map-related database operations."""

    @staticmethod
    async def get_by_id(map_id: int) -> Map | None:
        """Get map by ID."""
        try:
            data = await glob.db.fetch(
                "SELECT * FROM maps WHERE id = %s",
                [map_id]
            )
            if data is None:
                return None
            return Map.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to fetch map {map_id}: {str(e)}") from e

    @staticmethod
    async def get_by_set_id(set_id: int) -> list[Map]:
        """Get all maps in a set."""
        try:
            data = await glob.db.fetchall(
                "SELECT * FROM maps WHERE set_id = %s",
                [set_id]
            )
            return [Map.from_dict(row) for row in data]  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to fetch maps for set {set_id}: {str(e)}") from e

    @staticmethod
    async def update_status(map_id: int, status: int, frozen: bool = False) -> None:
        """Update map status."""
        try:
            await glob.db.execute(
                "UPDATE maps SET status = %s, frozen = %s WHERE id = %s",
                [status, frozen, map_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to update status for map {map_id}: {str(e)}") from e

    @staticmethod
    async def get_set_id(map_id: int) -> int | None:
        """Get set ID for a map."""
        try:
            data = await glob.db.fetch(
                "SELECT set_id FROM maps WHERE id = %s",
                [map_id]
            )
            return data['set_id'] if data else None  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to get set ID for map {map_id}: {str(e)}") from e


class BadgeRepository:
    """Repository for badge-related database operations."""

    @staticmethod
    async def get_by_id(badge_id: int) -> Badge | None:
        """Get badge by ID."""
        try:
            data = await glob.db.fetch(
                "SELECT * FROM badges WHERE id = %s",
                [badge_id]
            )
            if data is None:
                return None
            return Badge.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to fetch badge {badge_id}: {str(e)}") from e

    @staticmethod
    async def get_all() -> list[Badge]:
        """Get all badges."""
        try:
            data = await glob.db.fetchall("SELECT * FROM badges ORDER BY priority DESC")
            return [Badge.from_dict(row) for row in data]  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to fetch badges: {str(e)}") from e

    @staticmethod
    async def get_by_name(name: str) -> Badge | None:
        """Get badge by name."""
        try:
            data = await glob.db.fetch(
                "SELECT * FROM badges WHERE name = %s",
                [name]
            )
            if data is None:
                return None
            return Badge.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            raise DatabaseError(f"Failed to fetch badge by name: {str(e)}") from e

    @staticmethod
    async def create(name: str, description: str, priority: int) -> int:
        """Create a new badge."""
        try:
            await glob.db.execute(
                "INSERT INTO badges (name, description, priority) VALUES (%s, %s, %s)",
                [name, description, priority]
            )
            result = await glob.db.fetch(
                "SELECT id FROM badges WHERE name = %s",
                [name]
            )
            return result['id'] if result else None  # ty:ignore[invalid-argument-type, invalid-return-type]
        except Exception as e:
            raise DatabaseError(f"Failed to create badge: {str(e)}") from e

    @staticmethod
    async def update(badge_id: int, name: str, description: str, priority: int) -> None:
        """Update badge."""
        try:
            await glob.db.execute(
                "UPDATE badges SET name = %s, description = %s, priority = %s WHERE id = %s",
                [name, description, priority, badge_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to update badge {badge_id}: {str(e)}") from e

    @staticmethod
    async def get_styles(badge_id: int) -> list[dict[str, Any]]:
        """Get badge styles."""
        try:
            return await glob.db.fetchall(
                "SELECT * FROM badge_styles WHERE badge_id = %s",
                [badge_id]
            )  # ty:ignore[invalid-return-type]
        except Exception as e:
            raise DatabaseError(f"Failed to get styles for badge {badge_id}: {str(e)}") from e

    @staticmethod
    async def update_style(badge_id: int, style_type: str, value: str) -> None:
        """Update or create badge style."""
        try:
            existing = await glob.db.fetch(
                "SELECT * FROM badge_styles WHERE badge_id = %s AND type = %s",
                [badge_id, style_type]
            )

            if existing:
                await glob.db.execute(
                    "UPDATE badge_styles SET value = %s WHERE badge_id = %s AND type = %s",
                    [value, badge_id, style_type]
                )
            else:
                await glob.db.execute(
                    "INSERT INTO badge_styles (badge_id, type, value) VALUES (%s, %s, %s)",
                    [badge_id, style_type, value]
                )
        except Exception as e:
            raise DatabaseError(f"Failed to update style for badge {badge_id}: {str(e)}") from e


class UserBadgeRepository:
    """Repository for user-badge relationships."""

    @staticmethod
    async def has_badge(user_id: int, badge_id: int) -> bool:
        """Check if user has a badge."""
        try:
            data = await glob.db.fetch(
                "SELECT * FROM user_badges WHERE userid = %s AND badge_id = %s",
                [user_id, badge_id]
            )
            return data is not None
        except Exception as e:
            raise DatabaseError(f"Failed to check badge for user {user_id}: {str(e)}") from e

    @staticmethod
    async def add_badge(user_id: int, badge_id: int) -> None:
        """Add badge to user."""
        try:
            await glob.db.execute(
                "INSERT INTO user_badges (userid, badge_id) VALUES (%s, %s)",
                [user_id, badge_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to add badge to user {user_id}: {str(e)}") from e

    @staticmethod
    async def remove_badge(user_id: int, badge_id: int) -> None:
        """Remove badge from user."""
        try:
            await glob.db.execute(
                "DELETE FROM user_badges WHERE userid = %s AND badge_id = %s",
                [user_id, badge_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to remove badge from user {user_id}: {str(e)}") from e

    @staticmethod
    async def get_user_badges(user_id: int) -> list[dict[str, Any]]:
        """Get all badges for a user."""
        try:
            return await glob.db.fetchall(
                "SELECT badge_id FROM user_badges WHERE userid = %s",
                [user_id]
            )  # ty:ignore[invalid-return-type]
        except Exception as e:
            raise DatabaseError(f"Failed to get badges for user {user_id}: {str(e)}") from e


class ScoreRepository:
    """Repository for score-related database operations."""

    @staticmethod
    async def exists(score_id: int) -> bool:
        """Check if score exists."""
        try:
            data = await glob.db.fetch(
                "SELECT id FROM scores WHERE id = %s",
                [score_id]
            )
            return data is not None
        except Exception as e:
            raise DatabaseError(f"Failed to check score {score_id}: {str(e)}") from e

    @staticmethod
    async def wipe_user_scores(user_id: int) -> None:
        """Wipe all scores for a user."""
        try:
            # Move scores to wiped_scores
            await glob.db.execute(
                """
                INSERT INTO wiped_scores (id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id)
                SELECT id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id
                FROM scores
                WHERE userid = %s
                """,
                [user_id]
            )

            # Delete from scores
            await glob.db.execute(
                "DELETE FROM scores WHERE userid = %s",
                [user_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to wipe scores for user {user_id}: {str(e)}") from e

    @staticmethod
    async def remove_score(score_id: int) -> None:
        """Remove a specific score."""
        try:
            # Move to wiped_scores
            await glob.db.execute(
                """
                INSERT INTO wiped_scores (id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id)
                SELECT id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, userid, perfect, online_checksum, r_replay_id
                FROM scores
                WHERE id = %s
                """,
                [score_id]
            )

            # Delete from scores
            await glob.db.execute(
                "DELETE FROM scores WHERE id = %s",
                [score_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to remove score {score_id}: {str(e)}") from e


class StatsRepository:
    """Repository for stats-related database operations."""

    @staticmethod
    async def reset_user_stats(user_id: int, modes: list[int]) -> None:
        """Reset user stats for all modes."""
        try:
            for mode in modes:
                await glob.db.execute(
                    """
                    UPDATE stats
                    SET tscore = 0, rscore = 0, pp = 0, plays = 0, playtime = 0, acc = 0.000, max_combo = 0, total_hits = 0, replay_views = 0, xh_count = 0, x_count = 0, sh_count = 0, s_count = 0, a_count = 0
                    WHERE id = %s AND mode = %s
                    """,
                    [user_id, mode]
                )
        except Exception as e:
            raise DatabaseError(f"Failed to reset stats for user {user_id}: {str(e)}") from e


class MapRequestRepository:
    """Repository for map request-related database operations."""

    @staticmethod
    async def get_active_requests(limit: int, offset: int) -> list[dict[str, Any]]:
        """Get active map requests."""
        try:
            return await glob.db.fetchall(
                "SELECT * FROM map_requests WHERE active = 1 ORDER BY datetime DESC LIMIT %s OFFSET %s",
                [limit, offset]
            )  # ty:ignore[invalid-return-type]
        except Exception as e:
            raise DatabaseError(f"Failed to get active map requests: {str(e)}") from e

    @staticmethod
    async def deactivate_request(map_id: int) -> None:
        """Deactivate a map request."""
        try:
            await glob.db.execute(
                "UPDATE map_requests SET active = 0 WHERE map_id = %s",
                [map_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to deactivate map request for map {map_id}: {str(e)}") from e

    @staticmethod
    async def deactivate_and_freeze_request(map_id: int) -> None:
        """Deactivate and freeze a map request."""
        try:
            await glob.db.execute(
                "UPDATE map_requests SET active = 0, frozen = 1 WHERE map_id = %s",
                [map_id]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to deactivate and freeze map request for map {map_id}: {str(e)}") from e


class LogRepository:
    """Repository for log-related database operations."""

    @staticmethod
    async def create(
        action_id: str,
        action: str,
        reason: str,
        mod_id: int,
        target_id: int,
        target_type: TargetType
    ) -> None:
        """Create a log entry."""
        try:
            await glob.db.execute(
                """
                INSERT INTO logs (id, action, reason, `mod`, target, time, type)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                [action_id, action, reason, mod_id, target_id, datetime.now(), target_type.value]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to create log entry: {str(e)}") from e

    @staticmethod
    async def get_by_target(target_id: int) -> list[dict[str, Any]]:
        """Get logs for a target."""
        try:
            return await glob.db.fetchall(
                "SELECT * FROM logs WHERE `target` = %s ORDER BY `time` DESC",
                [target_id]
            )  # ty:ignore[invalid-return-type]
        except Exception as e:
            raise DatabaseError(f"Failed to get logs for target {target_id}: {str(e)}") from e


class ClientHashRepository:
    """Repository for client hash-related database operations."""

    @staticmethod
    async def get_by_user(user_id: int) -> list[dict[str, Any]]:
        """Get client hashes for a user."""
        try:
            return await glob.db.fetchall(
                "SELECT * FROM client_hashes WHERE userid = %s ORDER BY latest_time DESC",
                [user_id]
            )  # ty:ignore[invalid-return-type]
        except Exception as e:
            raise DatabaseError(f"Failed to get client hashes for user {user_id}: {str(e)}") from e


class NewlyRankedRepository:
    """Repository for newly ranked maps."""

    @staticmethod
    async def add(map_id: int, mod_id: int) -> None:
        """Add a newly ranked map."""
        try:
            await glob.db.execute(
                "INSERT INTO newly_ranked (map_id, mod_id, time) VALUES (%s, %s, %s)",
                [map_id, mod_id, datetime.now()]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to add newly ranked map {map_id}: {str(e)}") from e


class ServerDataRepository:
    """Repository for server data."""

    @staticmethod
    async def set_breakevent(timestamp: int) -> None:
        """Set break event timestamp."""
        try:
            await glob.db.execute(
                """
                INSERT INTO server_data (type, value)
                VALUES ('breakevent', %s)
                ON DUPLICATE KEY UPDATE value = %s
                """,
                [timestamp, timestamp]
            )
        except Exception as e:
            raise DatabaseError(f"Failed to set break event: {str(e)}") from e


__all__ = [
    'UserRepository',
    'MapRepository',
    'BadgeRepository',
    'UserBadgeRepository',
    'ScoreRepository',
    'StatsRepository',
    'MapRequestRepository',
    'LogRepository',
    'ClientHashRepository',
    'NewlyRankedRepository',
    'ServerDataRepository',
]
