"""
Database Repositories for Admin Panel

This module contains repository classes for database operations,
providing a clean separation between business logic and data access.
"""

import logging
from datetime import datetime
from typing import Any

from objects import glob
from objects.privileges import Privileges
from objects.utils import klogging

from .exceptions import DatabaseError
from .models import Badge, Map, TargetType, User


class UserRepository:
    """Repository for user-related database operations."""

    @staticmethod
    async def get_by_id(user_id: int) -> User | None:
        """Get user by ID."""
        try:
            klogging.log(f"Fetching user by ID: {user_id}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "operation": "get_by_id"})
            data = await glob.db.fetch(
                "SELECT * FROM users WHERE id = %s",
                [user_id]
            )
            if data is None:
                klogging.log(f"User not found with ID: {user_id}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id})
                return None
            klogging.log(f"Successfully fetched user: {data.get('name', 'unknown')} (ID: {user_id})", level=klogging.logLevel.DEBUG, extra={"user_id": user_id})  # ty:ignore[unresolved-attribute]
            return User.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            klogging.log(f"Error fetching user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "error": str(e)})
            raise DatabaseError(f"Failed to fetch user {user_id}: {str(e)}") from e

    @staticmethod
    async def get_by_safe_name(safe_name: str) -> User | None:
        """Get user by safe name."""
        try:
            klogging.log(f"Fetching user by safe_name: {safe_name}", level=klogging.logLevel.DEBUG, extra={"safe_name": safe_name, "operation": "get_by_safe_name"})
            data = await glob.db.fetch(
                "SELECT * FROM users WHERE safe_name = %s",
                [safe_name]
            )
            if data is None:
                klogging.log(f"User not found with safe_name: {safe_name}", level=klogging.logLevel.DEBUG, extra={"safe_name": safe_name})
                return None
            klogging.log(f"Successfully fetched user: {data.get('name', 'unknown')} (safe_name: {safe_name})", level=klogging.logLevel.DEBUG, extra={"safe_name": safe_name})  # ty:ignore[unresolved-attribute]
            return User.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            klogging.log(f"Error fetching user by safe_name {safe_name}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"safe_name": safe_name, "error": str(e)})
            raise DatabaseError(f"Failed to fetch user by safe name: {str(e)}") from e

    @staticmethod
    async def get_by_name(name: str) -> User | None:
        """Get user by name."""
        try:
            klogging.log(f"Fetching user by name: {name}", level=klogging.logLevel.DEBUG, extra={"name": name, "operation": "get_by_name"})
            data = await glob.db.fetch(
                "SELECT * FROM users WHERE name = %s",
                [name]
            )
            if data is None:
                klogging.log(f"User not found with name: {name}", level=klogging.logLevel.DEBUG, extra={"name": name})
                return None
            klogging.log(f"Successfully fetched user: {data.get('name', 'unknown')} (name: {name})", level=klogging.logLevel.DEBUG, extra={"name": name})  # ty:ignore[unresolved-attribute]
            return User.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            klogging.log(f"Error fetching user by name {name}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"name": name, "error": str(e)})
            raise DatabaseError(f"Failed to fetch user by name: {str(e)}") from e

    @staticmethod
    async def get_by_email(email: str) -> User | None:
        """Get user by email."""
        try:
            klogging.log(f"Fetching user by email: {email}", level=klogging.logLevel.DEBUG, extra={"email": email, "operation": "get_by_email"})
            data = await glob.db.fetch(
                "SELECT * FROM users WHERE email = %s",
                [email]
            )
            if data is None:
                klogging.log(f"User not found with email: {email}", level=klogging.logLevel.DEBUG, extra={"email": email})
                return None
            klogging.log(f"Successfully fetched user: {data.get('name', 'unknown')} (email: {email})", level=klogging.logLevel.DEBUG, extra={"email": email})  # ty:ignore[unresolved-attribute]
            return User.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            klogging.log(f"Error fetching user by email {email}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"email": email, "error": str(e)})
            raise DatabaseError(f"Failed to fetch user by email: {str(e)}") from e

    @staticmethod
    async def update_privileges(user_id: int, priv: int) -> None:
        """Update user privileges."""
        try:
            klogging.log(f"Updating privileges for user {user_id} to {priv}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "new_priv": priv, "operation": "update_privileges"})
            await glob.db.execute(
                "UPDATE users SET priv = %s WHERE id = %s",
                [priv, user_id]
            )
            klogging.log(f"Successfully updated privileges for user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "new_priv": priv})
        except Exception as e:
            klogging.log(f"Error updating privileges for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "new_priv": priv, "error": str(e)})
            raise DatabaseError(f"Failed to update privileges for user {user_id}: {str(e)}") from e

    @staticmethod
    async def update_password(user_id: int, pw_bcrypt: bytes, safe_name: str) -> None:
        """Update user password."""
        try:
            klogging.log(f"Updating password for user {user_id} (safe_name: {safe_name})", level=klogging.logLevel.INFO, extra={"user_id": user_id, "safe_name": safe_name, "operation": "update_password"})
            await glob.db.execute(
                "UPDATE users SET pw_bcrypt = %s WHERE safe_name = %s",
                [pw_bcrypt, safe_name]
            )
            klogging.log(f"Successfully updated password for user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "safe_name": safe_name})
        except Exception as e:
            klogging.log(f"Error updating password for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "safe_name": safe_name, "error": str(e)})
            raise DatabaseError(f"Failed to update password for user {user_id}: {str(e)}") from e

    @staticmethod
    async def update_account(user_id: int, username: str, safe_name: str, email: str, country: str, userpage_content: str) -> None:
        """Update user account details."""
        try:
            klogging.log(f"Updating account for user {user_id}: username={username}, email={email}, country={country}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "username": username, "email": email, "country": country, "operation": "update_account"})
            await glob.db.execute(
                "UPDATE users SET name = %s, safe_name = %s, email = %s, country = %s, userpage_content = %s WHERE id = %s",
                [username, safe_name, email, country, userpage_content, user_id]
            )
            klogging.log(f"Successfully updated account for user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "username": username})
        except Exception as e:
            klogging.log(f"Error updating account for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "username": username, "error": str(e)})
            raise DatabaseError(f"Failed to update account for user {user_id}: {str(e)}") from e

    @staticmethod
    async def update_silence(user_id: int, silence_end: int) -> None:
        """Update user silence status."""
        try:
            klogging.log(f"Updating silence for user {user_id}: silence_end={silence_end}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "silence_end": silence_end, "operation": "update_silence"})
            await glob.db.execute(
                "UPDATE users SET silence_end = %s WHERE id = %s",
                [silence_end, user_id]
            )
            klogging.log(f"Successfully updated silence for user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "silence_end": silence_end})
        except Exception as e:
            klogging.log(f"Error updating silence for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "silence_end": silence_end, "error": str(e)})
            raise DatabaseError(f"Failed to update silence for user {user_id}: {str(e)}") from e

    @staticmethod
    async def restrict(user_id: int) -> None:
        """Restrict user."""
        try:
            klogging.log(f"Restricting user {user_id}", level=klogging.logLevel.WARNING, extra={"user_id": user_id, "operation": "restrict"})
            await glob.db.execute(
                "UPDATE users SET priv = 0 WHERE id = %s",
                [user_id]
            )
            klogging.log(f"Successfully restricted user {user_id}", level=klogging.logLevel.WARNING, extra={"user_id": user_id})
        except Exception as e:
            klogging.log(f"Error restricting user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "error": str(e)})
            raise DatabaseError(f"Failed to restrict user {user_id}: {str(e)}") from e

    @staticmethod
    async def unrestrict(user_id: int) -> None:
        """Unrestrict user."""
        try:
            klogging.log(f"Unrestricting user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "operation": "unrestrict"})
            await glob.db.execute(
                "UPDATE users SET priv = 1 WHERE id = %s",
                [user_id]
            )
            klogging.log(f"Successfully unrestricted user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id})
        except Exception as e:
            klogging.log(f"Error unrestricting user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "error": str(e)})
            raise DatabaseError(f"Failed to unrestrict user {user_id}: {str(e)}") from e

    @staticmethod
    async def get_count(filters: dict[str, Any] | None = None) -> int:
        """Get user count with optional filters."""
        try:
            klogging.log(f"Getting user count with filters: {filters}", level=klogging.logLevel.DEBUG, extra={"filters": filters, "operation": "get_count"})
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
                        params.append("%" + search + "%")

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

            klogging.log(f"Executing count query: {query} with params: {params}", level=klogging.logLevel.DEBUG, extra={"query": query, "params": params})
            result = await glob.db.fetch(query, params)
            count = result['total'] if result else 0  # ty:ignore[invalid-argument-type]
            klogging.log(f"User count result: {count}", level=klogging.logLevel.DEBUG, extra={"count": count})
            return count
        except Exception as e:
            klogging.log(f"Error getting user count: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"filters": filters, "error": str(e)})
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
            klogging.log(f"Getting user list: limit={limit}, offset={offset}, sort_by={sort_by}, sort_order={sort_order}, filters={filters}", level=klogging.logLevel.DEBUG, extra={"limit": limit, "offset": offset, "sort_by": sort_by, "sort_order": sort_order, "filters": filters, "operation": "get_list"})
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
                        params.append("%" + search + "%")

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

            klogging.log(f"Executing list query: {query} with params: {params}", level=klogging.logLevel.DEBUG, extra={"query": query, "params": params})
            results = await glob.db.fetchall(query, params)
            klogging.log(f"User list query returned {len(results)} results", level=klogging.logLevel.DEBUG, extra={"result_count": len(results)})
            return list(results)  # ty:ignore[invalid-return-type]
        except Exception as e:
            klogging.log(f"Error getting user list: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"limit": limit, "offset": offset, "error": str(e)})
            raise DatabaseError(f"Failed to get user list: {str(e)}") from e

    @staticmethod
    async def get_customisations(user_id: int) -> dict[str, Any] | None:
        """Get user customisations."""
        try:
            klogging.log(f"Getting customisations for user {user_id}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "operation": "get_customisations"})
            result = await glob.db.fetch(
                "SELECT * FROM user_customisations WHERE userid = %s",
                [user_id]
            )
            klogging.log(f"Customisations for user {user_id}: {'found' if result else 'not found'}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "found": result is not None})
            return result  # ty:ignore[invalid-return-type]
        except Exception as e:
            klogging.log(f"Error getting customisations for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "error": str(e)})
            raise DatabaseError(f"Failed to get customisations for user {user_id}: {str(e)}") from e


class MapRepository:
    """Repository for map-related database operations."""

    @staticmethod
    async def get_by_id(map_id: int) -> Map | None:
        """Get map by ID."""
        try:
            klogging.log(f"Fetching map by ID: {map_id}", level=klogging.logLevel.DEBUG, extra={"map_id": map_id, "operation": "get_by_id"})
            data = await glob.db.fetch(
                "SELECT * FROM maps WHERE id = %s",
                [map_id]
            )
            if data is None:
                klogging.log(f"Map not found with ID: {map_id}", level=klogging.logLevel.DEBUG, extra={"map_id": map_id})
                return None
            klogging.log(f"Successfully fetched map: {data.get('title', 'unknown')} (ID: {map_id})", level=klogging.logLevel.DEBUG, extra={"map_id": map_id})  # ty:ignore[unresolved-attribute]
            return Map.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            klogging.log(f"Error fetching map {map_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"map_id": map_id, "error": str(e)})
            raise DatabaseError(f"Failed to fetch map {map_id}: {str(e)}") from e

    @staticmethod
    async def get_by_set_id(set_id: int) -> list[Map]:
        """Get all maps in a set."""
        try:
            klogging.log(f"Fetching maps by set_id: {set_id}", level=klogging.logLevel.DEBUG, extra={"set_id": set_id, "operation": "get_by_set_id"})
            data = await glob.db.fetchall(
                "SELECT * FROM maps WHERE set_id = %s",
                [set_id]
            )
            maps = [Map.from_dict(row) for row in data]  # ty:ignore[invalid-argument-type]
            klogging.log(f"Successfully fetched {len(maps)} maps for set {set_id}", level=klogging.logLevel.DEBUG, extra={"set_id": set_id, "count": len(maps)})
            return maps
        except Exception as e:
            klogging.log(f"Error fetching maps for set {set_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"set_id": set_id, "error": str(e)})
            raise DatabaseError(f"Failed to fetch maps for set {set_id}: {str(e)}") from e

    @staticmethod
    async def update_status(map_id: int, status: int, frozen: bool = False) -> None:
        """Update map status."""
        try:
            klogging.log(f"Updating map {map_id} status to {status} (frozen={frozen})", level=klogging.logLevel.INFO, extra={"map_id": map_id, "status": status, "frozen": frozen, "operation": "update_status"})
            await glob.db.execute(
                "UPDATE maps SET status = %s, frozen = %s WHERE id = %s",
                [status, frozen, map_id]
            )
            klogging.log(f"Successfully updated map {map_id} status to {status}", level=klogging.logLevel.INFO, extra={"map_id": map_id, "status": status})
        except Exception as e:
            klogging.log(f"Error updating map {map_id} status: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"map_id": map_id, "status": status, "error": str(e)})
            raise DatabaseError(f"Failed to update status for map {map_id}: {str(e)}") from e

    @staticmethod
    async def get_set_id(map_id: int) -> int | None:
        """Get set ID for a map."""
        try:
            klogging.log(f"Fetching set_id for map: {map_id}", level=klogging.logLevel.DEBUG, extra={"map_id": map_id, "operation": "get_set_id"})
            data = await glob.db.fetch(
                "SELECT set_id FROM maps WHERE id = %s",
                [map_id]
            )
            set_id = data['set_id'] if data else None  # ty:ignore[invalid-argument-type]
            klogging.log(f"Set ID for map {map_id}: {set_id}", level=klogging.logLevel.DEBUG, extra={"map_id": map_id, "set_id": set_id})
            return set_id
        except Exception as e:
            klogging.log(f"Error fetching set_id for map {map_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"map_id": map_id, "error": str(e)})
            raise DatabaseError(f"Failed to get set ID for map {map_id}: {str(e)}") from e


class BadgeRepository:
    """Repository for badge-related database operations."""

    @staticmethod
    async def get_by_id(badge_id: int) -> Badge | None:
        """Get badge by ID."""
        try:
            klogging.log(f"Fetching badge by ID: {badge_id}", level=klogging.logLevel.DEBUG, extra={"badge_id": badge_id, "operation": "get_by_id"})
            data = await glob.db.fetch(
                "SELECT * FROM badges WHERE id = %s",
                [badge_id]
            )
            if data is None:
                klogging.log(f"Badge not found with ID: {badge_id}", level=klogging.logLevel.DEBUG, extra={"badge_id": badge_id})
                return None
            klogging.log(f"Successfully fetched badge: {data.get('name', 'unknown')} (ID: {badge_id})", level=klogging.logLevel.DEBUG, extra={"badge_id": badge_id})  # ty:ignore[unresolved-attribute]
            return Badge.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            klogging.log(f"Error fetching badge {badge_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"badge_id": badge_id, "error": str(e)})
            raise DatabaseError(f"Failed to fetch badge {badge_id}: {str(e)}") from e

    @staticmethod
    async def get_all() -> list[Badge]:
        """Get all badges."""
        try:
            klogging.log("Fetching all badges", level=klogging.logLevel.DEBUG, extra={"operation": "get_all"})
            data = await glob.db.fetchall("SELECT * FROM badges ORDER BY priority DESC")
            badges = [Badge.from_dict(row) for row in data]  # ty:ignore[invalid-argument-type]
            klogging.log(f"Successfully fetched {len(badges)} badges", level=klogging.logLevel.DEBUG, extra={"count": len(badges)})
            return badges
        except Exception as e:
            klogging.log(f"Error fetching badges: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"error": str(e)})
            raise DatabaseError(f"Failed to fetch badges: {str(e)}") from e

    @staticmethod
    async def get_by_name(name: str) -> Badge | None:
        """Get badge by name."""
        try:
            klogging.log(f"Fetching badge by name: {name}", level=klogging.logLevel.DEBUG, extra={"name": name, "operation": "get_by_name"})
            data = await glob.db.fetch(
                "SELECT * FROM badges WHERE name = %s",
                [name]
            )
            if data is None:
                klogging.log(f"Badge not found with name: {name}", level=klogging.logLevel.DEBUG, extra={"name": name})
                return None
            klogging.log(f"Successfully fetched badge: {data.get('name', 'unknown')} (name: {name})", level=klogging.logLevel.DEBUG, extra={"name": name})  # ty:ignore[unresolved-attribute]
            return Badge.from_dict(data)  # ty:ignore[invalid-argument-type]
        except Exception as e:
            klogging.log(f"Error fetching badge by name {name}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"name": name, "error": str(e)})
            raise DatabaseError(f"Failed to fetch badge by name: {str(e)}") from e

    @staticmethod
    async def create(name: str, description: str, priority: int) -> int:
        """Create a new badge."""
        try:
            klogging.log(f"Creating badge: name={name}, description={description}, priority={priority}", level=klogging.logLevel.INFO, extra={"name": name, "description": description, "priority": priority, "operation": "create"})
            await glob.db.execute(
                "INSERT INTO badges (name, description, priority) VALUES (%s, %s, %s)",
                [name, description, priority]
            )
            result = await glob.db.fetch(
                "SELECT id FROM badges WHERE name = %s",
                [name]
            )
            badge_id = result['id'] if result else None  # ty:ignore[invalid-argument-type]
            klogging.log(f"Successfully created badge with ID: {badge_id}", level=klogging.logLevel.INFO, extra={"badge_id": badge_id, "name": name})
            return badge_id or 0
        except Exception as e:
            klogging.log(f"Error creating badge: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"name": name, "error": str(e)})
            raise DatabaseError(f"Failed to create badge: {str(e)}") from e

    @staticmethod
    async def update(badge_id: int, name: str, description: str, priority: int) -> None:
        """Update badge."""
        try:
            klogging.log(f"Updating badge {badge_id}: name={name}, description={description}, priority={priority}", level=klogging.logLevel.INFO, extra={"badge_id": badge_id, "name": name, "description": description, "priority": priority, "operation": "update"})
            await glob.db.execute(
                "UPDATE badges SET name = %s, description = %s, priority = %s WHERE id = %s",
                [name, description, priority, badge_id]
            )
            klogging.log(f"Successfully updated badge {badge_id}", level=klogging.logLevel.INFO, extra={"badge_id": badge_id})
        except Exception as e:
            klogging.log(f"Error updating badge {badge_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"badge_id": badge_id, "error": str(e)})
            raise DatabaseError(f"Failed to update badge {badge_id}: {str(e)}") from e

    @staticmethod
    async def get_styles(badge_id: int) -> list[dict[str, Any]]:
        """Get badge styles."""
        try:
            klogging.log(f"Fetching styles for badge {badge_id}", level=klogging.logLevel.DEBUG, extra={"badge_id": badge_id, "operation": "get_styles"})
            styles = await glob.db.fetchall(
                "SELECT * FROM badge_styles WHERE badge_id = %s",
                [badge_id]
            )
            klogging.log(f"Found {len(styles)} styles for badge {badge_id}", level=klogging.logLevel.DEBUG, extra={"badge_id": badge_id, "count": len(styles)})
            return list(styles)  # ty:ignore[invalid-return-type]
        except Exception as e:
            klogging.log(f"Error fetching styles for badge {badge_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"badge_id": badge_id, "error": str(e)})
            raise DatabaseError(f"Failed to get styles for badge {badge_id}: {str(e)}") from e

    @staticmethod
    async def update_style(badge_id: int, style_type: str, value: str) -> None:
        """Update or create badge style."""
        try:
            klogging.log(f"Updating style for badge {badge_id}: type={style_type}", level=klogging.logLevel.DEBUG, extra={"badge_id": badge_id, "style_type": style_type, "operation": "update_style"})
            existing = await glob.db.fetch(
                "SELECT * FROM badge_styles WHERE badge_id = %s AND type = %s",
                [badge_id, style_type]
            )

            if existing:
                klogging.log(f"Updating existing style for badge {badge_id}", level=klogging.logLevel.DEBUG, extra={"badge_id": badge_id, "style_type": style_type})
                await glob.db.execute(
                    "UPDATE badge_styles SET value = %s WHERE badge_id = %s AND type = %s",
                    [value, badge_id, style_type]
                )
            else:
                klogging.log(f"Creating new style for badge {badge_id}", level=klogging.logLevel.DEBUG, extra={"badge_id": badge_id, "style_type": style_type})
                await glob.db.execute(
                    "INSERT INTO badge_styles (badge_id, type, value) VALUES (%s, %s, %s)",
                    [badge_id, style_type, value]
                )
            klogging.log(f"Successfully updated style for badge {badge_id}", level=klogging.logLevel.DEBUG, extra={"badge_id": badge_id, "style_type": style_type})
        except Exception as e:
            klogging.log(f"Error updating style for badge {badge_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"badge_id": badge_id, "style_type": style_type, "error": str(e)})
            raise DatabaseError(f"Failed to update style for badge {badge_id}: {str(e)}") from e


class UserBadgeRepository:
    """Repository for user-badge relationships."""

    @staticmethod
    async def has_badge(user_id: int, badge_id: int) -> bool:
        """Check if user has a badge."""
        try:
            klogging.log(f"Checking if user {user_id} has badge {badge_id}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "badge_id": badge_id, "operation": "has_badge"})
            data = await glob.db.fetch(
                "SELECT * FROM user_badges WHERE userid = %s AND badge_id = %s",
                [user_id, badge_id]
            )
            has_badge = data is not None
            klogging.log(f"User {user_id} {'has' if has_badge else 'does not have'} badge {badge_id}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "badge_id": badge_id, "has_badge": has_badge})
            return has_badge
        except Exception as e:
            klogging.log(f"Error checking badge for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "badge_id": badge_id, "error": str(e)})
            raise DatabaseError(f"Failed to check badge for user {user_id}: {str(e)}") from e

    @staticmethod
    async def add_badge(user_id: int, badge_id: int) -> None:
        """Add badge to user."""
        try:
            klogging.log(f"Adding badge {badge_id} to user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "badge_id": badge_id, "operation": "add_badge"})
            await glob.db.execute(
                "INSERT INTO user_badges (userid, badge_id) VALUES (%s, %s)",
                [user_id, badge_id]
            )
            klogging.log(f"Successfully added badge {badge_id} to user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "badge_id": badge_id})
        except Exception as e:
            klogging.log(f"Error adding badge {badge_id} to user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "badge_id": badge_id, "error": str(e)})
            raise DatabaseError(f"Failed to add badge to user {user_id}: {str(e)}") from e

    @staticmethod
    async def remove_badge(user_id: int, badge_id: int) -> None:
        """Remove badge from user."""
        try:
            klogging.log(f"Removing badge {badge_id} from user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "badge_id": badge_id, "operation": "remove_badge"})
            await glob.db.execute(
                "DELETE FROM user_badges WHERE userid = %s AND badge_id = %s",
                [user_id, badge_id]
            )
            klogging.log(f"Successfully removed badge {badge_id} from user {user_id}", level=klogging.logLevel.INFO, extra={"user_id": user_id, "badge_id": badge_id})
        except Exception as e:
            klogging.log(f"Error removing badge {badge_id} from user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "badge_id": badge_id, "error": str(e)})
            raise DatabaseError(f"Failed to remove badge from user {user_id}: {str(e)}") from e

    @staticmethod
    async def get_user_badges(user_id: int) -> list[dict[str, Any]]:
        """Get all badges for a user."""
        try:
            klogging.log(f"Getting badges for user {user_id}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "operation": "get_user_badges"})
            badges = await glob.db.fetchall(
                "SELECT badge_id FROM user_badges WHERE userid = %s",
                [user_id]
            )
            klogging.log(f"User {user_id} has {len(badges)} badges", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "count": len(badges)})
            return list(badges)  # ty:ignore[invalid-return-type]
        except Exception as e:
            klogging.log(f"Error getting badges for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "error": str(e)})
            raise DatabaseError(f"Failed to get badges for user {user_id}: {str(e)}") from e


class ScoreRepository:
    """Repository for score-related database operations."""

    @staticmethod
    async def exists(score_id: int) -> bool:
        """Check if score exists."""
        try:
            klogging.log(f"Checking if score {score_id} exists", level=klogging.logLevel.DEBUG, extra={"score_id": score_id, "operation": "exists"})
            data = await glob.db.fetch(
                "SELECT id FROM scores WHERE id = %s",
                [score_id]
            )
            exists = data is not None
            klogging.log(f"Score {score_id} {'exists' if exists else 'does not exist'}", level=klogging.logLevel.DEBUG, extra={"score_id": score_id, "exists": exists})
            return exists
        except Exception as e:
            klogging.log(f"Error checking score {score_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"score_id": score_id, "error": str(e)})
            raise DatabaseError(f"Failed to check score {score_id}: {str(e)}") from e

    @staticmethod
    async def wipe_user_scores(user_id: int) -> None:
        """Wipe all scores for a user."""
        try:
            klogging.log(f"Wiping all scores for user {user_id}", level=klogging.logLevel.WARNING, extra={"user_id": user_id, "operation": "wipe_user_scores"})
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
            klogging.log(f"Successfully wiped scores for user {user_id}", level=klogging.logLevel.WARNING, extra={"user_id": user_id})
        except Exception as e:
            klogging.log(f"Error wiping scores for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "error": str(e)})
            raise DatabaseError(f"Failed to wipe scores for user {user_id}: {str(e)}") from e

    @staticmethod
    async def remove_score(score_id: int) -> None:
        """Remove a specific score."""
        try:
            klogging.log(f"Removing score {score_id}", level=klogging.logLevel.WARNING, extra={"score_id": score_id, "operation": "remove_score"})
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
            klogging.log(f"Successfully removed score {score_id}", level=klogging.logLevel.WARNING, extra={"score_id": score_id})
        except Exception as e:
            klogging.log(f"Error removing score {score_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"score_id": score_id, "error": str(e)})
            raise DatabaseError(f"Failed to remove score {score_id}: {str(e)}") from e


class StatsRepository:
    """Repository for stats-related database operations."""

    @staticmethod
    async def reset_user_stats(user_id: int, modes: list[int]) -> None:
        """Reset user stats for all modes."""
        try:
            klogging.log(f"Resetting stats for user {user_id} across {len(modes)} modes", level=klogging.logLevel.WARNING, extra={"user_id": user_id, "modes": modes, "operation": "reset_user_stats"})
            for mode in modes:
                await glob.db.execute(
                    """
                    UPDATE stats
                    SET tscore = 0, rscore = 0, pp = 0, plays = 0, playtime = 0, acc = 0.000, max_combo = 0, total_hits = 0, replay_views = 0, xh_count = 0, x_count = 0, sh_count = 0, s_count = 0, a_count = 0
                    WHERE id = %s AND mode = %s
                    """,
                    [user_id, mode]
                )
            klogging.log(f"Successfully reset stats for user {user_id}", level=klogging.logLevel.WARNING, extra={"user_id": user_id, "modes": modes})
        except Exception as e:
            klogging.log(f"Error resetting stats for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "modes": modes, "error": str(e)})
            raise DatabaseError(f"Failed to reset stats for user {user_id}: {str(e)}") from e


class MapRequestRepository:
    """Repository for map request-related database operations."""

    @staticmethod
    async def get_active_requests(limit: int, offset: int) -> list[dict[str, Any]]:
        """Get active map requests."""
        try:
            klogging.log(f"Getting active map requests: limit={limit}, offset={offset}", level=klogging.logLevel.DEBUG, extra={"limit": limit, "offset": offset, "operation": "get_active_requests"})
            requests = await glob.db.fetchall(
                "SELECT * FROM map_requests WHERE active = 1 ORDER BY datetime DESC LIMIT %s OFFSET %s",
                [limit, offset]
            )
            klogging.log(f"Found {len(requests)} active map requests", level=klogging.logLevel.DEBUG, extra={"count": len(requests)})
            return list(requests)  # ty:ignore[invalid-return-type]
        except Exception as e:
            klogging.log(f"Error getting active map requests: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"limit": limit, "offset": offset, "error": str(e)})
            raise DatabaseError(f"Failed to get active map requests: {str(e)}") from e

    @staticmethod
    async def deactivate_request(map_id: int) -> None:
        """Deactivate a map request."""
        try:
            klogging.log(f"Deactivating map request for map {map_id}", level=klogging.logLevel.INFO, extra={"map_id": map_id, "operation": "deactivate_request"})
            await glob.db.execute(
                "UPDATE map_requests SET active = 0 WHERE map_id = %s",
                [map_id]
            )
            klogging.log(f"Successfully deactivated map request for map {map_id}", level=klogging.logLevel.INFO, extra={"map_id": map_id})
        except Exception as e:
            klogging.log(f"Error deactivating map request for map {map_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"map_id": map_id, "error": str(e)})
            raise DatabaseError(f"Failed to deactivate map request for map {map_id}: {str(e)}") from e

    @staticmethod
    async def deactivate_and_freeze_request(map_id: int) -> None:
        """Deactivate and freeze a map request."""
        try:
            klogging.log(f"Deactivating and freezing map request for map {map_id}", level=klogging.logLevel.INFO, extra={"map_id": map_id, "operation": "deactivate_and_freeze_request"})
            await glob.db.execute(
                "UPDATE map_requests SET active = 0, frozen = 1 WHERE map_id = %s",
                [map_id]
            )
            klogging.log(f"Successfully deactivated and froze map request for map {map_id}", level=klogging.logLevel.INFO, extra={"map_id": map_id})
        except Exception as e:
            klogging.log(f"Error deactivating and freezing map request for map {map_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"map_id": map_id, "error": str(e)})
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
            klogging.log(f"Creating log entry: action={action}, mod_id={mod_id}, target_id={target_id}, type={target_type.value}", level=klogging.logLevel.INFO, extra={"action_id": action_id, "action": action, "mod_id": mod_id, "target_id": target_id, "target_type": target_type.value, "operation": "create"})
            await glob.db.execute(
                """
                INSERT INTO logs (id, `from_id`, `to_id`, action, reason, `created_at`, action_type)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                """,
                [action_id, mod_id, target_id, action, reason, datetime.now(), target_type.value]
            )
            klogging.log(f"Successfully created log entry {action_id}", level=klogging.logLevel.INFO, extra={"action_id": action_id})
        except Exception as e:
            klogging.log(f"Error creating log entry: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"action_id": action_id, "error": str(e)})
            raise DatabaseError(f"Failed to create log entry: {str(e)}") from e

    @staticmethod
    async def get_by_target(target_id: int) -> list[dict[str, Any]]:
        """Get logs for a target."""
        try:
            klogging.log(f"Getting logs for target {target_id}", level=klogging.logLevel.DEBUG, extra={"target_id": target_id, "operation": "get_by_target"})
            logs = await glob.db.fetchall(
                "SELECT * FROM logs WHERE `to_id` = %s ORDER BY `created_at` DESC",
                [target_id]
            )
            klogging.log(f"Found {len(logs)} log entries for target {target_id}", level=klogging.logLevel.DEBUG, extra={"target_id": target_id, "count": len(logs)})
            return list(logs)  # ty:ignore[invalid-return-type]
        except Exception as e:
            klogging.log(f"Error getting logs for target {target_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"target_id": target_id, "error": str(e)})
            raise DatabaseError(f"Failed to get logs for target {target_id}: {str(e)}") from e


class ClientHashRepository:
    """Repository for client hash-related database operations."""

    @staticmethod
    async def get_by_user(user_id: int) -> list[dict[str, Any]]:
        """Get client hashes for a user."""
        try:
            klogging.log(f"Getting client hashes for user {user_id}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "operation": "get_by_user"})
            hashes = await glob.db.fetchall(
                "SELECT * FROM client_hashes WHERE userid = %s ORDER BY latest_time DESC",
                [user_id]
            )
            klogging.log(f"Found {len(hashes)} client hashes for user {user_id}", level=klogging.logLevel.DEBUG, extra={"user_id": user_id, "count": len(hashes)})
            return list(hashes)  # ty:ignore[invalid-return-type]
        except Exception as e:
            klogging.log(f"Error getting client hashes for user {user_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"user_id": user_id, "error": str(e)})
            raise DatabaseError(f"Failed to get client hashes for user {user_id}: {str(e)}") from e


class NewlyRankedRepository:
    """Repository for newly ranked maps."""

    @staticmethod
    async def add(map_id: int, mod_id: int) -> None:
        """Add a newly ranked map."""
        try:
            klogging.log(f"Adding newly ranked map {map_id} by mod {mod_id}", level=klogging.logLevel.INFO, extra={"map_id": map_id, "mod_id": mod_id, "operation": "add"})
            await glob.db.execute(
                "INSERT INTO newly_ranked (map_id, mod_id, time) VALUES (%s, %s, %s)",
                [map_id, mod_id, datetime.now()]
            )
            klogging.log(f"Successfully added newly ranked map {map_id}", level=klogging.logLevel.INFO, extra={"map_id": map_id, "mod_id": mod_id})
        except Exception as e:
            klogging.log(f"Error adding newly ranked map {map_id}: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"map_id": map_id, "mod_id": mod_id, "error": str(e)})
            raise DatabaseError(f"Failed to add newly ranked map {map_id}: {str(e)}") from e


class ServerDataRepository:
    """Repository for server data."""

    @staticmethod
    async def set_breakevent(timestamp: int) -> None:
        """Set break event timestamp."""
        try:
            klogging.log(f"Setting break event timestamp: {timestamp}", level=klogging.logLevel.WARNING, extra={"timestamp": timestamp, "operation": "set_breakevent"})
            await glob.db.execute(
                """
                INSERT INTO server_data (type, value)
                VALUES ('breakevent', %s)
                ON DUPLICATE KEY UPDATE value = %s
                """,
                [timestamp, timestamp]
            )
            klogging.log(f"Successfully set break event timestamp: {timestamp}", level=klogging.logLevel.WARNING, extra={"timestamp": timestamp})
        except Exception as e:
            klogging.log(f"Error setting break event: {e}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"timestamp": timestamp, "error": str(e)})
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
