"""
Routes for Admin Panel

This module contains all route definitions for the admin panel,
handling HTTP requests and coordinating with services.
"""

import datetime
import logging

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
        klogging.log(f"Invalid action type: {action_type}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.WARNING, extra={"action_type": action_type})
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
    klogging.log(f"Admin action requested: {action_type} by mod {mod_id}", level=klogging.logLevel.INFO, extra={"action_type": action_type, "mod_id": mod_id, "target_user_id": request_data.user_id, "target_map_id": request_data.map_id})

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

    klogging.log(f"Admin action completed: {action_type} (action_id: {response.action_id})", level=klogging.logLevel.INFO, extra={"action_type": action_type, "action_id": response.action_id, "status": response.status})
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

    # Get current admin context
    current_user_id = SessionManager.get_user_id()
    klogging.log(f"Admin dashboard accessed by user {current_user_id}", level=klogging.logLevel.INFO, extra={"user_id": current_user_id, "route": "/dashboard"})

    # Get dashboard data
    dashboard_data = await dashboard_service.get_dashboard_data()

    klogging.log(f"Dashboard data loaded successfully for user {current_user_id}", level=klogging.logLevel.DEBUG, extra={"user_id": current_user_id})
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

    # Get current admin context
    current_user_id = SessionManager.get_user_id()

    # Parse request parameters
    update = request.args.get('update') == 'true'
    search = str(request.args.get('search') or '')
    sort_by = str(request.args.get('sort') or 'id')
    sort_order = str(request.args.get('order') or 'ASC')
    filter_priv = str(request.args.get('priv') or '')
    filter_country = str(request.args.get('country') or '')

    klogging.log(f"Users list requested by user {current_user_id}: page={page}, search='{search}', sort={sort_by} {sort_order}", level=klogging.logLevel.INFO, extra={"user_id": current_user_id, "page": page, "search": search, "sort_by": sort_by, "sort_order": sort_order, "filter_priv": filter_priv, "filter_country": filter_country, "update": update})

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
        klogging.log(f"Invalid users list request: {', '.join(errors)}", level=klogging.logLevel.WARNING, extra={"errors": errors})
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

    klogging.log(f"Retrieved {len(users)} users out of {total_count} total (page {request_data.page}/{total_pages})", level=klogging.logLevel.DEBUG, extra={"returned_count": len(users), "total_count": total_count, "page": request_data.page, "total_pages": total_pages})

    # Get customizations for each user
    for user in users:
        user['customisations'] = await user_repo.get_customisations(user['id'])

    # Return JSON if update request
    if update:
        klogging.log(f"Returning JSON users list for page {request_data.page}", level=klogging.logLevel.DEBUG, extra={"page": request_data.page, "count": len(users)})
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
    klogging.log(f"Rendering users page for page {request_data.page}", level=klogging.logLevel.DEBUG, extra={"page": request_data.page})
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
    # Log route entry
    klogging.log(f"Admin user detail route called for userid: {userid}",
                 extra={"userid": userid, "route": "/user/<int:userid>"})

    try:
        # Validate authentication
        SessionManager.require_authentication()
        SessionManager.require_staff()

        # Get current admin context
        current_user_id = SessionManager.get_user_id()
        session_priv = SessionManager.get_user_priv()
        klogging.log(f"Admin {current_user_id} requesting user {userid} details",
                     extra={"admin_id": current_user_id, "target_userid": userid, "privileges": session_priv})

        # Get user detail
        klogging.log(f"Calling user_service.get_user_detail for userid: {userid}",
                     extra={"userid": userid})
        user_detail = await user_service.get_user_detail(userid)
        klogging.log(f"Successfully retrieved user detail for userid: {userid}",
                     extra={"userid": userid})

        # Strip sensitive data if caller lacks ViewSensitiveInfo
        if not PrivilegeChecker.has_privilege(session_priv, "ViewSensitiveInfo"):  # ty:ignore[invalid-argument-type]
            klogging.log(f"Stripping sensitive data for user {userid} (admin lacks ViewSensitiveInfo)",
                         extra={"userid": userid, "admin_privileges": session_priv},
                         level=klogging.logLevel.WARNING)
            user_detail.user.get("logs", {}).pop("hashes", None)

        klogging.log(f"Successfully completed user detail request for userid: {userid}",
                     extra={"userid": userid})
        return jsonify(user_detail.user)

    except Exception as e:
        klogging.log(f"Error in user detail route for userid {userid}: {e}",
                     start_color=klogging.Ansi.LRED,
                     level=klogging.logLevel.ERROR,
                     extra={"userid": userid, "error": str(e)})
        raise


@admin.route('/badges')
@error_catcher
async def badges():
    """Render the badges management page."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Get current admin context
    current_user_id = SessionManager.get_user_id()

    # Check if JSON response is requested
    is_json = request.args.get('json') == 'true'

    klogging.log(f"Badges page requested by user {current_user_id} (json={is_json})", level=klogging.logLevel.INFO, extra={"user_id": current_user_id, "json_request": is_json})

    # Get all badges
    badges = await badge_service.get_all_badges()

    klogging.log(f"Retrieved {len(badges)} badges", level=klogging.logLevel.DEBUG, extra={"badge_count": len(badges)})

    # Return JSON if requested
    if is_json:
        klogging.log("Returning JSON badges list", level=klogging.logLevel.DEBUG, extra={"count": len(badges)})
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

    # Get current admin context
    current_user_id = SessionManager.get_user_id()

    klogging.log(f"Badge detail requested by user {current_user_id}: badgeid={badgeid}", level=klogging.logLevel.INFO, extra={"user_id": current_user_id, "badge_id": badgeid})

    # Get badge detail
    badge_detail = await badge_service.get_badge_detail(badgeid)

    klogging.log(f"Badge detail retrieved successfully: {badgeid}", level=klogging.logLevel.DEBUG, extra={"badge_id": badgeid})
    return jsonify(badge_detail.badge)


@admin.route('/badge/<int:badgeid>/update', methods=['POST'])
async def update_badge(badgeid: int):
    """Update an existing badge."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Get current admin context
    current_user_id = SessionManager.get_user_id()

    # Check permission
    user_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(user_priv, "ManageBadges"):  # ty:ignore[invalid-argument-type]
        klogging.log(f"Permission denied for badge update: user {current_user_id} lacks ManageBadges", level=klogging.logLevel.WARNING, extra={"user_id": current_user_id, "badge_id": badgeid})
        return jsonify(ResponseFormatter.permission_error("update badges")), 403

    # Get JSON data
    data = await RequestValidator.get_json_data()

    klogging.log(f"Badge update requested by user {current_user_id}: badgeid={badgeid}", level=klogging.logLevel.INFO, extra={"user_id": current_user_id, "badge_id": badgeid, "name": data.get('name'), "priority": data.get('priority')})

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
        klogging.log(f"Invalid badge update request: {', '.join(errors)}", level=klogging.logLevel.WARNING, extra={"errors": errors})
        raise ValidationError(f"Invalid request: {', '.join(errors)}")

    # Update badge
    await badge_service.update_badge(
        badgeid,
        request_data.name,  # ty:ignore[invalid-argument-type]
        request_data.description,  # ty:ignore[invalid-argument-type]
        request_data.priority,  # ty:ignore[invalid-argument-type]
        request_data.styles  # ty:ignore[invalid-argument-type]
    )

    klogging.log(f"Badge updated successfully: {badgeid}", level=klogging.logLevel.INFO, extra={"user_id": current_user_id, "badge_id": badgeid})
    return jsonify(ResponseFormatter.success("Badge updated successfully")), 200


@admin.route('/badge/create', methods=['POST'])
async def create_badge():
    """Create a new badge."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Get current admin context
    current_user_id = SessionManager.get_user_id()

    # Check permission
    user_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(user_priv, "ManageBadges"):  # ty:ignore[invalid-argument-type]
        klogging.log(f"Permission denied for badge creation: user {current_user_id} lacks ManageBadges", level=klogging.logLevel.WARNING, extra={"user_id": current_user_id})
        return jsonify(ResponseFormatter.permission_error("create badges")), 403

    # Get JSON data
    data = await RequestValidator.get_json_data()

    klogging.log(f"Badge creation requested by user {current_user_id}: name={data.get('name')}", level=klogging.logLevel.INFO, extra={"user_id": current_user_id, "name": data.get('name'), "priority": data.get('priority')})

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
        klogging.log(f"Invalid badge creation request: {', '.join(errors)}", level=klogging.logLevel.WARNING, extra={"errors": errors})
        raise ValidationError(f"Invalid request: {', '.join(errors)}")

    # Create badge
    await badge_service.create_badge(
        request_data.name,  # ty:ignore[invalid-argument-type]
        request_data.description,  # ty:ignore[invalid-argument-type]
        request_data.priority,  # ty:ignore[invalid-argument-type]
        request_data.styles  # ty:ignore[invalid-argument-type]
    )

    klogging.log(f"Badge created successfully: {data.get('name')}", level=klogging.logLevel.INFO, extra={"user_id": current_user_id, "name": data.get('name')})
    return jsonify(ResponseFormatter.success("Badge created successfully")), 200


@admin.route('/beatmaps/<int:page>')
@admin.route('/beatmaps')
@error_catcher
async def beatmaps(page: int | None = None):
    """Render the beatmaps management page."""
    # Validate authentication
    SessionManager.require_authentication()
    SessionManager.require_staff()

    # Get current admin context
    current_user_id = SessionManager.get_user_id()

    # Check permission
    user_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(user_priv, "ManageBeatmaps"):  # ty:ignore[invalid-argument-type]
        klogging.log(f"Permission denied for beatmaps page: user {current_user_id} lacks ManageBeatmaps", level=klogging.logLevel.WARNING, extra={"user_id": current_user_id})
        return await flash('error', 'You have insufficient privileges.', 'home')

    klogging.log(f"Beatmaps page requested by user {current_user_id}: page={page}", level=klogging.logLevel.INFO, extra={"user_id": current_user_id, "page": page})

    # Build request
    request_data = MapRequest(page=page or 1)

    # Validate request
    errors = request_data.validate()
    if errors:
        klogging.log(f"Invalid beatmaps request: {', '.join(errors)}", level=klogging.logLevel.WARNING, extra={"errors": errors})
        raise ValidationError(f"Invalid request: {', '.join(errors)}")

    # Get active map requests
    requests = await map_request_service.get_active_requests(request_data.page)

    klogging.log(f"Retrieved {len(requests)} active map requests", level=klogging.logLevel.DEBUG, extra={"count": len(requests), "page": request_data.page})

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

    # Get current admin context
    current_user_id = SessionManager.get_user_id()

    # Check permission
    user_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(user_priv, "Dangerous"):  # ty:ignore[invalid-argument-type]
        klogging.log(f"Permission denied for /stuffbroke: user {current_user_id} lacks Dangerous", level=klogging.logLevel.WARNING, extra={"user_id": current_user_id})
        return await flash('error', 'You have insufficient privileges.', 'home')

    klogging.log(f"Break event triggered by user {current_user_id}", level=klogging.logLevel.WARNING, extra={"user_id": current_user_id, "route": "/stuffbroke"})

    # Trigger break event
    await server_data_service.trigger_break_event()

    return await frontend.home(flash='Successfully broke stuff.', status='success')  # ty:ignore[unresolved-attribute]


@admin.route('/test')
@error_catcher
async def test():
    """Test endpoint for debugging."""
    # Validate authentication
    SessionManager.require_authentication()

    # Get current admin context
    current_user_id = SessionManager.get_user_id()

    # Check permission
    user_priv = SessionManager.get_user_priv()
    if not PrivilegeChecker.has_privilege(user_priv, "Dangerous"):  # ty:ignore[invalid-argument-type]
        klogging.log(f"Permission denied for /test: user {current_user_id} lacks Dangerous", level=klogging.logLevel.WARNING, extra={"user_id": current_user_id})
        return await flash('error', 'You have insufficient privileges.', 'home')

    klogging.log(f"Test endpoint accessed by user {current_user_id}", level=klogging.logLevel.INFO, extra={"user_id": current_user_id, "route": "/test"})

    return await flash('success', 'Successfully tested. Results: ', 'home')


# Error handler for AdminPanelError
@admin.errorhandler(AdminPanelError)
async def handle_admin_panel_error(error: AdminPanelError):
    """Handle AdminPanelError exceptions."""
    klogging.log(f"Admin panel error: {error.message}", start_color=klogging.Ansi.LYELLOW, level=klogging.logLevel.WARNING, extra={"error_type": type(error).__name__, "status_code": error.status_code, "message": error.message})
    response, status_code = handle_admin_error(error)
    return jsonify(response), status_code


@admin.errorhandler(Exception)
async def handle_unexpected_error(error):
    """Handle unexpected exceptions with JSON response."""
    klogging.log(f"Unexpected admin error: {error}", start_color=klogging.Ansi.LRED, level=klogging.logLevel.ERROR, extra={"error_type": type(error).__name__, "error_message": str(error)})
    return jsonify({"status": "error", "message": "An unexpected error occurred."}), 500


from blueprints import frontend  # noqa: E402 - Required for stuffbroke endpoint
