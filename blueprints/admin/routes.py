"""
Routes for Admin Panel

This module contains all route definitions for the admin panel,
handling HTTP requests and coordinating with services.
"""

import datetime

import timeago
from quart import jsonify, render_template, request

from objects import glob
from objects.utils import error_catcher, flash, klogging

from . import admin
from .exceptions import (
    AdminPanelError,
    InvalidActionError,
    ValidationError,
    handle_admin_error,
)
from .models import (
    ActionRequest,
    ActionType,
    BadgeRequest,
    MapRequest,
    UserListRequest,
    UserListResponse,
)
from .repositories import (
    BadgeRepository,
    ClientHashRepository,
    LogRepository,
    MapRepository,
    MapRequestRepository,
    NewlyRankedRepository,
    ScoreRepository,
    ServerDataRepository,
    StatsRepository,
    UserBadgeRepository,
    UserRepository,
)
from .services import (
    ActionService,
    BadgeService,
    DashboardService,
    MapRequestService,
    ServerDataService,
    UserService,
)
from .utils import (
    DiscordLogger,
    PrivilegeChecker,
    RequestValidator,
    ResponseFormatter,
    SessionManager,
)


def _parse_optional_int(form, field_name: str):
    """Parse an optional integer form field, raising ValidationError on bad input."""
    val = form.get(field_name)
    if not val:
        return None
    try:
        return int(val)
    except (ValueError, TypeError) as e:
        raise ValidationError(f"Invalid value for '{field_name}': must be an integer.") from e


# Initialize services
user_repo = UserRepository()
map_repo = MapRepository()
badge_repo = BadgeRepository()
user_badge_repo = UserBadgeRepository()
score_repo = ScoreRepository()
stats_repo = StatsRepository()
map_request_repo = MapRequestRepository()
log_repo = LogRepository()
client_hash_repo = ClientHashRepository()
newly_ranked_repo = NewlyRankedRepository()
server_data_repo = ServerDataRepository()

action_service = ActionService(
    user_repo, map_repo, badge_repo, user_badge_repo,
    score_repo, stats_repo, map_request_repo, log_repo, newly_ranked_repo
)
dashboard_service = DashboardService(user_repo)
user_service = UserService(user_repo, badge_repo, user_badge_repo, log_repo, client_hash_repo)
badge_service = BadgeService(badge_repo)
map_request_service = MapRequestService(map_request_repo, user_repo, badge_repo, user_badge_repo, map_repo)
server_data_service = ServerDataService(server_data_repo)

discord_logger = DiscordLogger(
    glob.config.ADMIN_WEBHOOK_URL,
    glob.config.RANKED_WEBHOOK_URL
)


@admin.route("/action/<action_type>", methods=["POST"])
async def action(action_type: str):
    """
    Execute an admin action on users or maps.

    This endpoint handles various admin actions including:
    - User management (wipe, restrict, unrestrict, silence, unsilence, etc.)
    - Map management (rank, approve, qualify, love, unrank, etc.)
    - Badge management (add, remove)
    - Score management (remove)

    Args:
        action_type: The type of action to execute

    Returns:
        JSON response with action status and details
    """
    # Validate authentication
    SessionManager.require_authentication()

    # Validate content type
    RequestValidator.validate_content_type()

    # Get form data
    form = await RequestValidator.get_form_data()

    # Parse action type
    try:
        action_enum = ActionType(action_type)
    except ValueError as e:
        raise InvalidActionError(action_type) from e

    # Build action request
    request_data = ActionRequest(
        action=action_enum,
        reason=form.get("reason"),
        user_id=_parse_optional_int(form, "user"),
        map_id=_parse_optional_int(form, "map"),
        duration=_parse_optional_int(form, "duration"),
        password=form.get("password"),
        privs=_parse_optional_int(form, "privs"),
        username=form.get("username"),
        email=form.get("email"),
        country=form.get("country"),
        userpage_content=form.get("userpage_content"),
        badge_id=_parse_optional_int(form, "badge"),
        score_id=_parse_optional_int(form, "score"),
    )

    # Get current user ID
    mod_id = SessionManager.get_user_id()

    # Create and execute action
    action_obj = await action_service.create_action(request_data, mod_id)  # ty:ignore[invalid-argument-type]
    response = await action_service.execute_action(action_obj, request_data)

    # Log to Discord (best-effort — don't fail the request if webhook fails)
    try:
        if action_obj.is_user_action and hasattr(action_obj, 'user'):
            await discord_logger.log_user_action(
                action_obj,
                action_obj.mod.name,  # ty:ignore[unresolved-attribute]
                action_obj.mod.id,  # ty:ignore[unresolved-attribute]
                action_obj.user.name,  # ty:ignore[unresolved-attribute]
                action_obj.user.id  # ty:ignore[unresolved-attribute]
            )
        elif action_obj.is_map_action and hasattr(action_obj, 'map'):
            await discord_logger.log_map_action(
                action_obj,
                action_obj.mod.name,  # ty:ignore[unresolved-attribute]
                action_obj.mod.id,  # ty:ignore[unresolved-attribute]
                action_obj.map
            )
        elif action_obj.is_badge_action and hasattr(action_obj, 'badge'):
            await discord_logger.log_badge_action(
                action_obj,
                action_obj.mod.name,  # ty:ignore[unresolved-attribute]
                action_obj.mod.id,  # ty:ignore[unresolved-attribute]
                action_obj.user.name,  # ty:ignore[unresolved-attribute]
                action_obj.user.id,  # ty:ignore[unresolved-attribute]
                {
                    'id': action_obj.badge.id,  # ty:ignore[unresolved-attribute]
                    'name': action_obj.badge.name,  # ty:ignore[unresolved-attribute]
                    'description': action_obj.badge.description  # ty:ignore[unresolved-attribute]
                }
            )
    except Exception as e:
        klogging.log(f"Discord webhook failed (action still succeeded): {e}", klogging.Ansi.LYELLOW)

    return jsonify(ResponseFormatter.success(
        response.message,
        response.action_id
    )), 200


@admin.route('/')
@admin.route('/home')
@admin.route('/dashboard')
@error_catcher
async def home():
    """Render the admin dashboard."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Get dashboard data
    dashboard_data = await dashboard_service.get_dashboard_data()

    return await render_template(
        'admin/home.html',
        dashdata=dashboard_data,
        recentusers=dashboard_data.recent_users,
        recentscores=dashboard_data.recent_scores,
        datetime=datetime,
        timeago=timeago
    )


@admin.route('/users')
@admin.route('/users/')
@admin.route('/users/<int:page>')
@error_catcher
async def users(page: int | None = None):
    """Render the users management page."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Parse request parameters
    update = request.args.get('update') == 'true'
    search = str(request.args.get('search') or '')
    sort_by = str(request.args.get('sort') or 'id')
    sort_order = str(request.args.get('order') or 'ASC')
    filter_priv = str(request.args.get('priv') or '')
    filter_country = str(request.args.get('country') or '')

    # Build request
    request_data = UserListRequest(
        page=page or 1,
        search=search if search else None,
        sort_by=sort_by,
        sort_order=sort_order,
        filter_priv=filter_priv if filter_priv else None,
        filter_country=filter_country if filter_country else None,
        update=update
    )

    # Validate request
    errors = request_data.validate()
    if errors:
        raise ValidationError(f"Invalid request: {', '.join(errors)}")

    # Calculate pagination
    items_per_page = 50
    offset = items_per_page * (request_data.page - 1)

    # Build filters
    filters = {}
    if request_data.search:
        filters['search'] = request_data.search
    if request_data.filter_priv:
        filters['filter_priv'] = request_data.filter_priv
    if request_data.filter_country:
        filters['filter_country'] = request_data.filter_country

    # Get total count
    total_count = await user_repo.get_count(filters)
    total_pages = (total_count + items_per_page - 1) // items_per_page

    # Get users
    users = await user_repo.get_list(
        limit=items_per_page,
        offset=offset,
        sort_by=request_data.sort_by,
        sort_order=request_data.sort_order,
        filters=filters
    )

    # Get customizations for each user
    for user in users:
        user['customisations'] = await user_repo.get_customisations(user['id'])

    # Return JSON if update request
    if update:
        return jsonify(UserListResponse(
            users=users,
            pagination={
                'current_page': request_data.page,
                'total_pages': total_pages,
                'total_count': total_count,
                'items_per_page': items_per_page
            }
        ))

    # Render template
    return await render_template(
        'admin/users.html',
        users=users,
        page=request_data.page,
        total_pages=total_pages,
        total_count=total_count,
        search=request_data.search or '',
        sort_by=request_data.sort_by,
        sort_order=request_data.sort_order,
        filter_priv=request_data.filter_priv or '',
        filter_country=request_data.filter_country or '',
        datetime=datetime,
        timeago=timeago
    )


@admin.route('/user/<int:userid>')
async def user(userid: int):
    """Get detailed user information."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Get user detail
    user_detail = await user_service.get_user_detail(userid)

    # Strip sensitive data if caller lacks ViewSensitiveInfo
    session_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(session_priv, "ViewSensitiveInfo"):  # ty:ignore[invalid-argument-type]
        user_detail.user.get("logs", {}).pop("hashes", None)

    return jsonify(user_detail.user)


@admin.route('/badges')
@error_catcher
async def badges():
    """Render the badges management page."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Check if JSON response is requested
    is_json = request.args.get('json') == 'true'

    # Get all badges
    badges = await badge_service.get_all_badges()

    # Return JSON if requested
    if is_json:
        return jsonify(badges)

    # Render template
    return await render_template(
        'admin/badges.html',
        badges=badges,
        datetime=datetime,
        timeago=timeago
    )


@admin.route('/badge/<int:badgeid>')
async def badge(badgeid: int):
    """Get detailed badge information."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Get badge detail
    badge_detail = await badge_service.get_badge_detail(badgeid)

    return jsonify(badge_detail.badge)


@admin.route('/badge/<int:badgeid>/update', methods=['POST'])
async def update_badge(badgeid: int):
    """Update an existing badge."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Check permission
    user_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(user_priv, "ManageBadges"):  # ty:ignore[invalid-argument-type]
        return jsonify(ResponseFormatter.permission_error("update badges")), 403

    # Get JSON data
    data = await RequestValidator.get_json_data()

    # Build request
    request_data = BadgeRequest(
        name=data.get('name'),
        description=data.get('description'),
        priority=data.get('priority'),
        styles=data.get('styles')
    )

    # Validate request
    errors = request_data.validate()
    if errors:
        raise ValidationError(f"Invalid request: {', '.join(errors)}")

    # Update badge
    await badge_service.update_badge(
        badgeid,
        request_data.name,  # ty:ignore[invalid-argument-type]
        request_data.description,  # ty:ignore[invalid-argument-type]
        request_data.priority,  # ty:ignore[invalid-argument-type]
        request_data.styles  # ty:ignore[invalid-argument-type]
    )

    return jsonify(ResponseFormatter.success("Badge updated successfully")), 200


@admin.route('/badge/create', methods=['POST'])
async def create_badge():
    """Create a new badge."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Check permission
    user_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(user_priv, "ManageBadges"):  # ty:ignore[invalid-argument-type]
        return jsonify(ResponseFormatter.permission_error("create badges")), 403

    # Get JSON data
    data = await RequestValidator.get_json_data()

    # Build request
    request_data = BadgeRequest(
        name=data.get('name'),
        description=data.get('description'),
        priority=data.get('priority'),
        styles=data.get('styles')
    )

    # Validate request
    errors = request_data.validate()
    if errors:
        raise ValidationError(f"Invalid request: {', '.join(errors)}")

    # Create badge
    await badge_service.create_badge(
        request_data.name,  # ty:ignore[invalid-argument-type]
        request_data.description,  # ty:ignore[invalid-argument-type]
        request_data.priority,  # ty:ignore[invalid-argument-type]
        request_data.styles  # ty:ignore[invalid-argument-type]
    )

    return jsonify(ResponseFormatter.success("Badge created successfully")), 200


@admin.route('/beatmaps/<int:page>')
@admin.route('/beatmaps')
@error_catcher
async def beatmaps(page: int | None = None):
    """Render the beatmaps management page."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Check permission
    user_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(user_priv, "ManageBeatmaps"):  # ty:ignore[invalid-argument-type]
        return await flash('error', 'You have insufficient privileges.', 'home')

    # Build request
    request_data = MapRequest(page=page or 1)

    # Validate request
    errors = request_data.validate()
    if errors:
        raise ValidationError(f"Invalid request: {', '.join(errors)}")

    # Get active map requests
    requests = await map_request_service.get_active_requests(request_data.page)

    # Render template
    return await render_template(
        'admin/beatmaps.html',
        requests=requests,
        datetime=datetime,
        timeago=timeago,
        page=request_data.page
    )


@admin.route('/stuffbroke')
@error_catcher
async def stuffbroke():
    """Trigger a break event (for testing/debugging)."""
    # Validate authentication
    SessionManager.require_authentication()

    # Check permission
    user_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(user_priv, "Dangerous"):  # ty:ignore[invalid-argument-type]
        return await flash('error', 'You have insufficient privileges.', 'home')

    # Trigger break event
    await server_data_service.trigger_break_event()

    return await frontend.home(flash='Successfully broke stuff.', status='success')  # ty:ignore[unresolved-attribute]


@admin.route('/test')
@error_catcher
async def test():
    """Test endpoint for debugging."""
    # Validate authentication
    SessionManager.require_authentication()

    # Check permission
    user_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(user_priv, "Dangerous"):  # ty:ignore[invalid-argument-type]
        return await flash('error', 'You have insufficient privileges.', 'home')

    return await flash('success', 'Successfully tested. Results: ', 'home')


# Error handler for AdminPanelError
@admin.errorhandler(AdminPanelError)
async def handle_admin_panel_error(error: AdminPanelError):
    """Handle AdminPanelError exceptions."""
    response, status_code = handle_admin_error(error)
    return jsonify(response), status_code


@admin.errorhandler(Exception)
async def handle_unexpected_error(error):
    """Handle unexpected exceptions with JSON response."""
    klogging.log(f"Unexpected admin error: {error}", klogging.Ansi.LRED)
    return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500


from blueprints import frontend  # noqa: E402 - Required for stuffbroke endpoint
