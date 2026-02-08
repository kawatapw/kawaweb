# -*- coding: utf-8 -*-
"""
Data Models and DTOs for Admin Panel

This module contains data models and data transfer objects (DTOs)
for the admin panel, providing type safety and clear data structures.
"""

from dataclasses import dataclass, field
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


class ActionType(Enum):
    """Enum for different types of admin actions."""
    WIPE = "wipe"
    RESTRICT = "restrict"
    UNRESTRICT = "unrestrict"
    SILENCE = "silence"
    UNSILENCE = "unsilence"
    CHANGE_PASSWORD = "changepassword"
    CHANGE_PRIVILEGES = "changeprivileges"
    EDIT_ACCOUNT = "editaccount"
    ADD_BADGE = "addbadge"
    REMOVE_BADGE = "removebadge"
    REMOVE_SCORE = "removescore"
    RANK = "rank"
    APPROVE = "approve"
    QUALIFY = "qualify"
    LOVE = "love"
    UNRANK = "unrank"
    COMPLETE_REQUEST = "completerequest"


class TargetType(Enum):
    """Enum for different types of action targets."""
    USER = 0
    MAP = 1
    BADGE = 2


@dataclass
class User:
    """User data model."""
    id: int
    name: str
    safe_name: str
    email: str
    priv: int
    country: str
    silence_end: int
    donor_end: int
    creation_time: datetime
    latest_activity: datetime
    clan_id: Optional[int]
    clan_priv: Optional[int]
    preferred_mode: Optional[int]
    play_style: Optional[int]
    custom_badge_name: Optional[str]
    custom_badge_icon: Optional[str]
    userpage_content: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'User':
        """Create User instance from database row."""
        return cls(
            id=data['id'],
            name=data['name'],
            safe_name=data['safe_name'],
            email=data['email'],
            priv=data['priv'],
            country=data['country'],
            silence_end=data['silence_end'],
            donor_end=data['donor_end'],
            creation_time=data['creation_time'],
            latest_activity=data['latest_activity'],
            clan_id=data.get('clan_id'),
            clan_priv=data.get('clan_priv'),
            preferred_mode=data.get('preferred_mode'),
            play_style=data.get('play_style'),
            custom_badge_name=data.get('custom_badge_name'),
            custom_badge_icon=data.get('custom_badge_icon'),
            userpage_content=data.get('userpage_content')
        )


@dataclass
class Map:
    """Map data model."""
    id: int
    set_id: int
    status: int
    md5: str
    artist: str
    title: str
    version: str
    creator: str
    last_update: datetime
    total_length: int
    max_combo: int
    frozen: bool
    plays: int
    passes: int
    mode: int
    bpm: float
    cs: float
    ar: float
    od: float
    hp: float
    diff: float

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Map':
        """Create Map instance from database row."""
        return cls(
            id=data['id'],
            set_id=data['set_id'],
            status=data['status'],
            md5=data['md5'],
            artist=data['artist'],
            title=data['title'],
            version=data['version'],
            creator=data['creator'],
            last_update=data['last_update'],
            total_length=data['total_length'],
            max_combo=data['max_combo'],
            frozen=data['frozen'],
            plays=data['plays'],
            passes=data['passes'],
            mode=data['mode'],
            bpm=data['bpm'],
            cs=data['cs'],
            ar=data['ar'],
            od=data['od'],
            hp=data['hp'],
            diff=data['diff']
        )


@dataclass
class Badge:
    """Badge data model."""
    id: int
    name: str
    description: str
    priority: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'Badge':
        """Create Badge instance from database row."""
        return cls(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            priority=data['priority']
        )


@dataclass
class Action:
    """Action data model."""
    id: str
    action: ActionType
    reason: str
    mod_id: int
    target_id: int
    target_type: TargetType
    text: str
    duration: Optional[int] = None
    badge: Optional[Badge] = None
    created_at: datetime = field(default_factory=datetime.now)

    @property
    def is_user_action(self) -> bool:
        """Check if action targets a user."""
        return self.target_type == TargetType.USER

    @property
    def is_map_action(self) -> bool:
        """Check if action targets a map."""
        return self.target_type == TargetType.MAP

    @property
    def is_badge_action(self) -> bool:
        """Check if action targets a badge."""
        return self.target_type == TargetType.BADGE


@dataclass
class ActionRequest:
    """Request data for creating an action."""
    action: ActionType
    reason: Optional[str]
    user_id: Optional[int]
    map_id: Optional[int]
    duration: Optional[int]
    password: Optional[str]
    privs: Optional[int]
    username: Optional[str]
    email: Optional[str]
    country: Optional[str]
    userpage_content: Optional[str]
    badge_id: Optional[int]
    score_id: Optional[int]

    def validate(self) -> List[str]:
        """Validate the request data."""
        errors = []

        if not self.action:
            errors.append("Action is required")

        # Validate based on action type
        if self.action in [ActionType.WIPE, ActionType.RESTRICT, ActionType.UNRESTRICT,
                          ActionType.SILENCE, ActionType.UNSILENCE, ActionType.CHANGE_PASSWORD,
                          ActionType.CHANGE_PRIVILEGES, ActionType.EDIT_ACCOUNT, ActionType.ADD_BADGE,
                          ActionType.REMOVE_BADGE, ActionType.REMOVE_SCORE]:
            if not self.user_id:
                errors.append("User ID is required for this action")

        if self.action in [ActionType.RANK, ActionType.APPROVE, ActionType.QUALIFY,
                          ActionType.LOVE, ActionType.UNRANK, ActionType.COMPLETE_REQUEST]:
            if not self.map_id:
                errors.append("Map ID is required for this action")

        if self.action == ActionType.SILENCE:
            if not self.duration:
                errors.append("Duration is required for silence action")

        if self.action == ActionType.CHANGE_PASSWORD:
            if not self.password:
                errors.append("Password is required for changepassword action")

        if self.action == ActionType.CHANGE_PRIVILEGES:
            if self.privs is None:
                errors.append("Privileges are required for changeprivileges action")

        if self.action == ActionType.EDIT_ACCOUNT:
            if not all([self.username, self.email, self.country, self.userpage_content]):
                errors.append("All fields (username, email, country, userpage_content) are required for editaccount action")

        if self.action in [ActionType.ADD_BADGE, ActionType.REMOVE_BADGE]:
            if not self.badge_id:
                errors.append("Badge ID is required for this action")

        if self.action == ActionType.REMOVE_SCORE:
            if not self.score_id:
                errors.append("Score ID is required for removescore action")

        return errors


@dataclass
class ActionResponse:
    """Response data for action execution."""
    status: str
    message: str
    action_id: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


@dataclass
class ValidationResult:
    """Result of validation."""
    is_valid: bool
    errors: List[str]
    data: Optional[Dict[str, Any]] = None


@dataclass
class PermissionCheck:
    """Result of permission check."""
    has_permission: bool
    required_privilege: Optional[str] = None
    user_privilege: Optional[int] = None
    error_message: Optional[str] = None
    status_code: int = 403


@dataclass
class UserListRequest:
    """Request data for user list."""
    page: int = 1
    search: Optional[str] = None
    sort_by: str = "id"
    sort_order: str = "ASC"
    filter_priv: Optional[str] = None
    filter_country: Optional[str] = None
    update: bool = False

    def validate(self) -> List[str]:
        """Validate the request data."""
        errors = []

        if self.page < 1:
            errors.append("Page must be at least 1")

        valid_sort_fields = ['id', 'name', 'creation_time', 'latest_activity', 'priv']
        if self.sort_by not in valid_sort_fields:
            errors.append(f"Sort field must be one of: {', '.join(valid_sort_fields)}")

        if self.sort_order not in ['ASC', 'DESC']:
            errors.append("Sort order must be either ASC or DESC")

        return errors


@dataclass
class UserListResponse:
    """Response data for user list."""
    users: List[Dict[str, Any]]
    pagination: Dict[str, Any]


@dataclass
class BadgeRequest:
    """Request data for badge operations."""
    name: Optional[str] = None
    description: Optional[str] = None
    priority: Optional[int] = None
    styles: Optional[List[Dict[str, str]]] = None

    def validate(self) -> List[str]:
        """Validate the request data."""
        errors = []

        if not self.name:
            errors.append("Name is required")

        if not self.description:
            errors.append("Description is required")

        if self.priority is None:
            errors.append("Priority is required")

        if not self.styles:
            errors.append("Styles are required")

        return errors


@dataclass
class MapRequest:
    """Request data for map operations."""
    page: int = 1

    def validate(self) -> List[str]:
        """Validate the request data."""
        errors = []

        if self.page < 1:
            errors.append("Page must be at least 1")

        return errors


@dataclass
class DashboardData:
    """Dashboard statistics."""
    total_users: int
    latest_user: str
    banned_users: int
    recent_users: List[Dict[str, Any]]
    recent_scores: List[Dict[str, Any]]


@dataclass
class UserDetail:
    """User detail response."""
    user: Dict[str, Any]
    badges: List[Dict[str, Any]]
    logs: Dict[str, Any]


@dataclass
class BadgeDetail:
    """Badge detail response."""
    badge: Dict[str, Any]
    styles: List[Dict[str, Any]]


@dataclass
class MapRequestDetail:
    """Map request detail."""
    request: Dict[str, Any]
    player: Dict[str, Any]
    map_info: Dict[str, Any]
    map_diffs: List[Dict[str, Any]]


__all__ = [
    'ActionType',
    'TargetType',
    'User',
    'Map',
    'Badge',
    'Action',
    'ActionRequest',
    'ActionResponse',
    'ValidationResult',
    'PermissionCheck',
    'UserListRequest',
    'UserListResponse',
    'BadgeRequest',
    'MapRequest',
    'DashboardData',
    'UserDetail',
    'BadgeDetail',
    'MapRequestDetail',
]
