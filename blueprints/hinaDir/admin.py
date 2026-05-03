"""hinaDir: Admin V2 — Independent admin panel SPA."""

import datetime
import hashlib
import json
from functools import wraps

import bcrypt
from quart import (
    Blueprint,
    g,
    jsonify,
    redirect,
    render_template,
    request,
    session,
)

import config as cfg
from constants import regexes
from objects import glob
from objects.privileges import ComparePrivs, GetPriv, Privileges
from objects.utils import error_catcher, get_safe_name

hina_admin = Blueprint('hina_admin', __name__)

DEFAULT_CHECKLIST = json.dumps({
    "timing": False, "hitsounds": False, "difficulty_spread": False,
    "metadata": False, "background": False, "no_abuse": False
})

# ─── Decorators ────────────────────────────────────────────────────────

def staff_required(func):
    """Require login + is_staff for admin-v2 API routes. Returns JSON errors."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        if 'authenticated' not in session:
            return jsonify({'status': 'error', 'message': 'Not logged in.'}), 401
        if not session['user_data'].get('is_staff'):
            return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403
        return await func(*args, **kwargs)
    return wrapper


def staff_required_page(func):
    """Require login + is_staff for page routes. Redirects on failure."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        if 'authenticated' not in session:
            return redirect('/login')
        if not session['user_data'].get('is_staff'):
            return redirect('/')
        return await func(*args, **kwargs)
    return wrapper


# ─── Helpers ───────────────────────────────────────────────────────────

def _gen_action_id():
    t = str(int(datetime.datetime.now().timestamp()))
    md5 = hashlib.md5(t.encode()).hexdigest().encode()
    hashed = bcrypt.hashpw(md5, bcrypt.gensalt())
    return hashed[29:].decode('utf-8')


async def _log_action(mod_id, mod_name, target_id, action_name, action_text,
                       reason, action_type, badge=None, map_obj=None):
    """Insert into logs table and post to Discord webhook."""
    action_id = _gen_action_id()
    reason = reason or 'No reason specified.'
    now = datetime.datetime.now()

    await glob.db.execute(
        "INSERT INTO logs (from_id, to_id, action, msg, created_at, action_type) "
        "VALUES (%s, %s, %s, %s, %s, %s)",
        [mod_id, target_id, action_name, reason, now, action_type]
    )

    # Discord webhook (best-effort, don't fail the action)
    try:
        from discord_webhook import DiscordEmbed, DiscordWebhook

        if action_type == 0:
            # User action
            target_user = await glob.db.fetch("SELECT name FROM users WHERE id = %s", [target_id])
            target_name = target_user['name'] if target_user else str(target_id)  # type: ignore

            webhook = DiscordWebhook(url=glob.config.ADMIN_WEBHOOK_URL)
            if action_name != 'changepassword':
                embed = DiscordEmbed(
                    title=f"{target_name} was {action_text} by {mod_name}",
                    description=f"a {action_name} was performed.",
                    color=5126045, timestamp=now
                )
            else:
                embed = DiscordEmbed(
                    title=f"{target_name} was {action_text} by {mod_name}",
                    description=f"a {action_text} was performed.",
                    color=5126045, timestamp=now
                )
            embed.set_author(name=f"New Action By {mod_name}",
                             icon_url=f"https://a.kawata.pw/{mod_id}")
            embed.add_embed_field(
                name="Information:",
                value=(f"Action ID: {action_id}\nAction Moderator: {mod_name} ({mod_id})\n"
                       f"Action User: {target_name} ({target_id})\n"
                       f"Action Type: {action_name}\nAction Reason: {reason}"),
                inline=False
            )
            embed.set_footer(text=f"ID: {action_id}",
                             icon_url=f"https://a.kawata.pw/{target_id}")
            webhook.add_embed(embed)
            webhook.execute()

        elif action_type == 1 and map_obj:
            # Map action
            webhook = DiscordWebhook(url=glob.config.RANKED_WEBHOOK_URL)
            embed = DiscordEmbed(
                title=f"{map_obj['title']} [{map_obj.get('version','')}] was {action_text} by {mod_name}",
                description=f"[{map_obj['title']} [{map_obj.get('version','')}]](https://osu.ppy.sh/b/{map_obj['id']}) was {action_text}",
                color=5126045, timestamp=now
            )
            embed.set_author(name=f"Diff {action_text} By {mod_name} ({mod_id})",
                             icon_url=f"https://a.kawata.pw/{mod_id}")
            embed.add_embed_field(
                name="Information:",
                value=(f"Ranked By: {mod_name} ({mod_id})\n"
                       f"Map: {map_obj['title']} [{map_obj.get('version','')}] ({map_obj['id']})\n"
                       f"Action: {action_name}"),
                inline=False
            )
            if map_obj.get('set_id'):
                embed.set_image(url=f"https://assets.ppy.sh/beatmaps/{map_obj['set_id']}/covers/card@2x.jpg")
            embed.set_footer(text=f"ID: {action_id}",
                             icon_url=f"https://a.kawata.pw/{mod_id}")
            webhook.add_embed(embed)
            webhook.execute()

        elif action_type == 2 and badge:
            # Badge action
            target_user = await glob.db.fetch("SELECT name FROM users WHERE id = %s", [target_id])
            target_name = target_user['name'] if target_user else str(target_id)  # type: ignore

            webhook = DiscordWebhook(url=glob.config.ADMIN_WEBHOOK_URL)
            embed = DiscordEmbed(
                title=f"{target_name} was {action_text} {badge['name']} by {mod_name}",
                description="", color=5126045, timestamp=now
            )
            embed.set_author(name=f"New Action By {mod_name}",
                             icon_url=f"https://a.kawata.pw/{mod_id}")
            embed.add_embed_field(
                name="Information:",
                value=(f"Action Moderator: {mod_name} ({mod_id})\n"
                       f"Action User: {target_name} ({target_id})\n"
                       f"Badge: {badge['name']} ({badge['id']})\n"
                       f"Badge Description: {badge.get('description','')}"),
                inline=False
            )
            embed.set_footer(text=f"ID: {action_id}",
                             icon_url=f"https://a.kawata.pw/{target_id}")
            webhook.add_embed(embed)
            webhook.execute()
    except Exception:
        pass  # Discord webhook failure should never break admin actions


def _get_mod_info():
    """Get current moderator info from session."""
    ud = session['user_data']
    return ud['id'], ud['name'], ud['priv']


def _check_priv(mod_priv, required):
    """Check if moderator has a required privilege."""
    return required in GetPriv(mod_priv)  # ty:ignore[unsupported-operator]


# Map status codes for reference:
# 0 = not submitted, 1 = pending, 2 = ranked, 3 = approved, 4 = qualified, 5 = loved

async def _update_map_status(map_id=None, new_status=None, set_id=None):
    """Proxy map status update to kawata.py API.

    Uses internal Docker URL with Host header for host-based routing.
    Pass set_id to update all diffs in a set at once (?sid=),
    or map_id to update a single diff (?id=).
    """
    url = 'http://bancho:10000/v1/update_map_status'
    headers = {
        'Host': f'api.{cfg.domain}',
        'Authorization': f'Bearer {glob.config.api_key}',
    }
    params = {"s": str(new_status)}
    if map_id is not None:
        params["id"] = str(map_id)
    if set_id is not None:
        params["sid"] = str(set_id)
    try:
        async with glob.http.post(url, headers=headers, params=params) as resp:
            return await resp.json(content_type=None)
    except Exception as e:
        return {"status": "error", "message": str(e)}


# ─── Page Routes ───────────────────────────────────────────────────────

@hina_admin.route('/')
@hina_admin.route('/<path:subpath>')
@error_catcher
@staff_required_page
async def admin_spa(subpath=None):
    """Render the admin V2 SPA shell."""
    return await render_template('admin/admin_v2.html', globalNotice=g.globalNotice)


# ─── Dashboard API ─────────────────────────────────────────────────────

# Whitelist of log actions to show in the staff actions feed.
_STAFF_ACTION_WHITELIST = (
    'restrict', 'unrestrict', 'silence', 'unsilence',
    'wipe', 'changepassword', 'removescore',
    'changeprivileges', 'editaccount',
    'addbadge', 'removebadge',
)


async def _get_online_count() -> int:
    """Fetch online player count from kawata.py API (best-effort)."""
    try:
        async with glob.http.get(
            'http://bancho:10000/v1/get_player_count',
            headers={'Host': f'api.{cfg.domain}'},
        ) as resp:
            if resp.status == 200:
                data = await resp.json()
                return data.get('counts', {}).get('online', 0)
    except Exception:
        pass
    return 0


@hina_admin.route('/api/dashboard')
@error_catcher
@staff_required
async def api_dashboard():
    # ── KPIs ──────────────────────────────────────────────
    kpi_data = await glob.db.fetch(
        'SELECT '
        '  COUNT(id) AS total_users, '
        '  (SELECT COUNT(id) FROM users WHERE NOT priv & 1) AS restricted, '
        '  (SELECT COUNT(id) FROM users WHERE creation_time > UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 7 DAY))) AS new_users_7d, '
        '  (SELECT COUNT(id) FROM users WHERE creation_time > UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 14 DAY)) '
        '    AND creation_time <= UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 7 DAY))) AS new_users_prev_7d, '
        '  (SELECT COUNT(id) FROM users WHERE NOT priv & 1 '
        '    AND creation_time <= UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 7 DAY))) AS restricted_7d_ago, '
        '  (SELECT COUNT(id) FROM scores WHERE play_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)) AS scores_1h, '
        '  (SELECT COUNT(id) FROM scores WHERE play_time > DATE_SUB(NOW(), INTERVAL 1 DAY)) AS scores_24h '
        'FROM users'
    )

    online_count = await _get_online_count()

    kpis = {
        'total_users': kpi_data['total_users'] if kpi_data else 0,  # type: ignore
        'new_users_7d': kpi_data['new_users_7d'] if kpi_data else 0,  # type: ignore
        'new_users_prev_7d': kpi_data['new_users_prev_7d'] if kpi_data else 0,  # type: ignore
        'restricted': kpi_data['restricted'] if kpi_data else 0,  # type: ignore
        'restricted_7d_ago': kpi_data['restricted_7d_ago'] if kpi_data else 0,  # type: ignore
        'online': online_count,
        'scores_1h': kpi_data['scores_1h'] if kpi_data else 0,  # type: ignore
        'scores_24h': kpi_data['scores_24h'] if kpi_data else 0,  # type: ignore
    }

    # ── Top countries (new users, 7d) ─────────────────────
    top_countries = await glob.db.fetchall(
        'SELECT country, COUNT(*) AS count FROM users '
        'WHERE creation_time > UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 7 DAY)) '
        'GROUP BY country ORDER BY count DESC LIMIT 5'
    )

    action_placeholders = ', '.join(['%s'] * len(_STAFF_ACTION_WHITELIST))
    whitelist = list(_STAFF_ACTION_WHITELIST)
    raw_actions = await glob.db.fetchall(
        'SELECT CAST(l.id AS CHAR) AS id, '
        '  CONVERT(l.action USING utf8mb4) AS action, '
        '  CONVERT(l.msg USING utf8mb4) AS msg, '
        '  l.created_at AS time, l.from_id AS mod_id, l.to_id AS target_id '
        f'FROM logs l WHERE l.action IN ({action_placeholders}) '
        'ORDER BY time DESC LIMIT 10',
        whitelist
    )

    recent_actions = []
    for a in (raw_actions or []):
        mod_user = await glob.db.fetch(
            'SELECT id, name FROM users WHERE id = %s', [a['mod_id']]  # type: ignore
        )
        target_user = await glob.db.fetch(
            'SELECT id, name FROM users WHERE id = %s', [a['target_id']]  # type: ignore
        )
        recent_actions.append({
            'id': a['id'],  # ty:ignore[invalid-argument-type, not-subscriptable]
            'action': a['action'],  # ty:ignore[invalid-argument-type, not-subscriptable]
            'reason': a['msg'] or '',  # ty:ignore[invalid-argument-type, not-subscriptable]
            'time': int(a['time'].timestamp()) if isinstance(a['time'], datetime.datetime) else a['time'],  # ty:ignore[invalid-argument-type, not-subscriptable]
            'mod': {'id': mod_user['id'], 'name': mod_user['name']} if mod_user else {'id': a['mod_id'], 'name': str(a['mod_id'])},  # ty:ignore[invalid-argument-type, not-subscriptable]
            'target': {'id': target_user['id'], 'name': target_user['name']} if target_user else {'id': a['target_id'], 'name': str(a['target_id'])},  # ty:ignore[invalid-argument-type, not-subscriptable]
        })

    # ── Recent users with shared hardware count ───────────
    recent_users = await glob.db.fetchall(
        'SELECT u.id, u.name, u.priv, u.country, u.creation_time, u.latest_activity, '
        '  (SELECT COUNT(DISTINCT ch2.userid) FROM client_hashes ch '
        '   JOIN client_hashes ch2 ON (ch2.osupath = ch.osupath OR ch2.adapters = ch.adapters '
        '     OR ch2.disk_serial = ch.disk_serial) AND ch2.userid != ch.userid '
        '   WHERE ch.userid = u.id) AS shared_hardware '
        'FROM users u WHERE u.id > 1 ORDER BY u.id DESC LIMIT 10'
    )

    # ── Recent scores ─────────────────────────────────────
    recent_scores = await glob.db.fetchall(
        'SELECT scores.id, scores.userid, scores.pp, scores.acc, scores.grade, '
        'scores.mode, UNIX_TIMESTAMP(scores.play_time) AS play_time, scores.max_combo, scores.mods, '
        'scores.client_flags, '
        'maps.artist, maps.title, maps.set_id, maps.creator, maps.version, '
        'users.name AS player_name '
        'FROM scores '
        'JOIN maps ON scores.map_md5 = maps.md5 '
        'JOIN users ON scores.userid = users.id '
        'ORDER BY scores.id DESC LIMIT 10'
    )

    return jsonify({
        'kpis': kpis,
        'top_countries': top_countries or [],
        'recent_actions': recent_actions,
        'recent_users': recent_users or [],
        'recent_scores': recent_scores or [],
    })


@hina_admin.route('/api/dashboard/flagged-scores')
@error_catcher
@staff_required
async def api_dashboard_flagged_scores():
    """Return scores with non-zero client_flags."""
    page = max(1, int(request.args.get('page', 1)))
    limit = min(50, max(1, int(request.args.get('limit', 20))))
    offset = (page - 1) * limit

    scores = await glob.db.fetchall(
        'SELECT scores.id, scores.userid, scores.pp, scores.acc, scores.grade, '
        'scores.mode, UNIX_TIMESTAMP(scores.play_time) AS play_time, scores.max_combo, scores.mods, '
        'scores.client_flags, '
        'maps.artist, maps.title, maps.set_id, maps.creator, maps.version, '
        'users.name AS player_name '
        'FROM scores '
        'JOIN maps ON scores.map_md5 = maps.md5 '
        'JOIN users ON scores.userid = users.id '
        'WHERE scores.client_flags != 0 '
        'ORDER BY scores.id DESC '
        'LIMIT %s OFFSET %s',
        [limit, offset]
    )

    total = await glob.db.fetch(
        'SELECT COUNT(*) AS count FROM scores WHERE client_flags != 0'
    )

    return jsonify({
        'scores': scores or [],
        'total': total['count'] if total else 0,  # ty:ignore[invalid-argument-type]
        'page': page,
    })


@hina_admin.route('/api/dashboard/search')
@error_catcher
@staff_required
async def api_dashboard_search():
    """Global search: users and maps."""
    query = str(request.args.get('q', '')).strip()
    scope = str(request.args.get('scope', 'all'))  # all, users, maps

    if len(query) < 2:
        return jsonify({'users': [], 'maps': []})

    users = []
    maps = []

    if scope in ('all', 'users'):
        if query.isdigit():
            users = await glob.db.fetchall(
                'SELECT id, name, priv, country FROM users WHERE id = %s LIMIT 10',
                [int(query)]
            )
        else:
            users = await glob.db.fetchall(
                'SELECT id, name, priv, country FROM users WHERE name LIKE %s LIMIT 10',
                [f'%{query}%']
            )

    if scope in ('all', 'maps'):
        if query.isdigit():
            maps = await glob.db.fetchall(
                'SELECT id, set_id, artist, title, version, creator, status '
                'FROM maps WHERE id = %s OR set_id = %s LIMIT 10',
                [int(query), int(query)]
            )
        else:
            maps = await glob.db.fetchall(
                'SELECT id, set_id, artist, title, version, creator, status '
                'FROM maps WHERE title LIKE %s OR artist LIKE %s LIMIT 10',
                [f'%{query}%', f'%{query}%']
            )

    return jsonify({
        'users': users or [],
        'maps': maps or [],
    })


# ─── Users API ─────────────────────────────────────────────────────────

@hina_admin.route('/api/users')
@error_catcher
@staff_required
async def api_users():
    page = max(1, int(request.args.get('page', 1)))
    search = str(request.args.get('search', ''))
    sort_by = str(request.args.get('sort', 'id'))
    sort_order = str(request.args.get('order', 'ASC'))
    filter_priv = str(request.args.get('priv', ''))
    filter_country = str(request.args.get('country', ''))
    filter_active = str(request.args.get('active', ''))
    filter_registered = str(request.args.get('registered', ''))
    filter_risk = str(request.args.get('risk', ''))

    if sort_by not in ('id', 'name', 'creation_time', 'latest_activity', 'priv', 'pp', 'plays'):
        sort_by = 'id'
    if sort_order not in ('ASC', 'DESC'):
        sort_order = 'ASC'

    items_per_page = 50
    offset = items_per_page * (page - 1)

    # JOIN stats for PP/plays columns
    base_query = (
        "SELECT u.id, u.name, u.priv, u.country, u.creation_time, u.latest_activity, "
        "u.silence_end, u.preferred_mode, "
        "COALESCE(s.pp, 0) as pp, COALESCE(s.plays, 0) as plays "
        "FROM users u "
        "LEFT JOIN stats s ON s.id = u.id AND s.mode = u.preferred_mode AND s.season_id = 0"
    )
    count_query = "SELECT COUNT(*) as total FROM users u"
    conditions = []
    params = []

    if search and search.strip():
        if search.isdigit():
            conditions.append("u.id = %s")
            params.append(int(search))
        else:
            conditions.append("u.name LIKE %s")
            params.append(f"%{search}%")

    if filter_priv:
        if filter_priv == 'normal':
            conditions.append("u.priv = 1")
        elif filter_priv == 'supporter':
            conditions.append("u.priv & 4 != 0")
        elif filter_priv == 'mod':
            conditions.append(f"u.priv & {int(Privileges.AccessPanel)} != 0 AND NOT u.priv & {int(Privileges.ManagePrivs)}")
        elif filter_priv == 'admin':
            conditions.append(f"u.priv & {int(Privileges.ManagePrivs)} != 0")
        elif filter_priv == 'restricted':
            conditions.append("NOT u.priv & 1")

    if filter_country and filter_country.strip():
        conditions.append("u.country = %s")
        params.append(filter_country.upper())

    # Advanced filters: last active
    if filter_active:
        import time
        now_ts = int(time.time())
        active_map = {
            'today': now_ts - 86400,
            'week': now_ts - 604800,
            'month': now_ts - 2592000,
        }
        if filter_active in active_map:
            conditions.append("u.latest_activity > %s")
            params.append(active_map[filter_active])
        elif filter_active == 'inactive30':
            conditions.append("u.latest_activity < %s")
            params.append(now_ts - 2592000)
        elif filter_active == 'inactive90':
            conditions.append("u.latest_activity < %s")
            params.append(now_ts - 7776000)

    # Advanced filters: registered
    if filter_registered:
        registered_map = {
            '24h': "u.creation_time > UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 1 DAY))",
            '7d': "u.creation_time > UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 7 DAY))",
            '30d': "u.creation_time > UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 30 DAY))",
            '90d': "u.creation_time > UNIX_TIMESTAMP(DATE_SUB(NOW(), INTERVAL 90 DAY))",
        }
        if filter_registered in registered_map:
            conditions.append(registered_map[filter_registered])

    # Advanced filters: risk (expensive subqueries, only when active)
    if filter_risk:
        shared_hw_exists = (
            "EXISTS (SELECT 1 FROM client_hashes ch1 "
            "JOIN client_hashes ch2 ON (ch1.osupath = ch2.osupath "
            "OR ch1.adapters = ch2.adapters OR ch1.disk_serial = ch2.disk_serial) "
            "AND ch1.userid != ch2.userid WHERE ch1.userid = u.id)"
        )
        flagged_scores_exists = (
            "EXISTS (SELECT 1 FROM scores sc WHERE sc.userid = u.id AND sc.client_flags != 0)"
        )
        if filter_risk == 'shared_hw':
            conditions.append(shared_hw_exists)
        elif filter_risk == 'flagged_scores':
            conditions.append(flagged_scores_exists)
        elif filter_risk == 'either':
            conditions.append(f"({shared_hw_exists} OR {flagged_scores_exists})")

    where = ""
    if conditions:
        where = " WHERE " + " AND ".join(conditions)

    # For count query, we only need users table conditions (no JOIN)
    # But since risk filters reference u.id, we need the alias
    total = await glob.db.fetch(count_query + where, params)
    total_count = total['total'] if total else 0  # ty:ignore[invalid-argument-type]
    total_pages = max(1, (total_count + items_per_page - 1) // items_per_page)

    # Sort: pp and plays come from the JOIN
    sort_col = sort_by
    if sort_by in ('pp', 'plays'):
        sort_col = sort_by  # already in SELECT via COALESCE
    elif sort_by in ('id', 'name', 'priv', 'country', 'creation_time', 'latest_activity'):
        sort_col = 'u.' + sort_by

    order = f" ORDER BY {sort_col} {sort_order}"
    limit = f" LIMIT {items_per_page} OFFSET {offset}"

    users = await glob.db.fetchall(base_query + where + order + limit, params)

    if not users:
        users = []

    # Batch risk indicator queries for the returned page of users
    user_ids = [u['id'] for u in users]  # ty:ignore[invalid-argument-type, not-subscriptable]
    hw_counts = {}
    flag_counts = {}

    if user_ids:
        placeholders = ', '.join(['%s'] * len(user_ids))

        # Shared hardware counts
        try:
            hw_rows = await glob.db.fetchall(
                "SELECT ch1.userid, COUNT(DISTINCT ch2.userid) as cnt "
                "FROM client_hashes ch1 "
                "JOIN client_hashes ch2 ON (ch1.osupath = ch2.osupath "
                "  OR ch1.adapters = ch2.adapters OR ch1.disk_serial = ch2.disk_serial) "
                "  AND ch1.userid != ch2.userid "
                f"WHERE ch1.userid IN ({placeholders}) "
                "GROUP BY ch1.userid",
                user_ids
            )
            for row in (hw_rows or []):
                hw_counts[row['userid']] = row['cnt']  # ty:ignore[invalid-argument-type, not-subscriptable]
        except Exception:
            pass

        # Flagged score counts
        try:
            flag_rows = await glob.db.fetchall(
                "SELECT userid, COUNT(*) as cnt FROM scores "
                f"WHERE userid IN ({placeholders}) AND client_flags != 0 "
                "GROUP BY userid",
                user_ids
            )
            for row in (flag_rows or []):
                flag_counts[row['userid']] = row['cnt']  # ty:ignore[invalid-argument-type, not-subscriptable]
        except Exception:
            pass

    # Attach risk counts to each user
    for u in users:
        u['shared_hardware'] = hw_counts.get(u['id'], 0)  # ty:ignore[invalid-argument-type, invalid-assignment, not-subscriptable]
        u['flagged_scores'] = flag_counts.get(u['id'], 0)  # ty:ignore[invalid-argument-type, invalid-assignment, not-subscriptable]

    return jsonify({
        'users': users,
        'pagination': {
            'current_page': page,
            'total_pages': total_pages,
            'total_count': total_count,
        }
    })


@hina_admin.route('/api/user/<int:userid>')
@error_catcher
@staff_required
async def api_user_detail(userid):
    user = await glob.db.fetch("SELECT * FROM users WHERE id = %s", [userid])
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    # Badges
    user_badges = await glob.db.fetchall(
        "SELECT badge_id FROM user_badges WHERE userid = %s", [userid]
    )
    badges = []
    for ub in user_badges:
        badge = await glob.db.fetch("SELECT * FROM badges WHERE id = %s", [ub['badge_id']])  # ty:ignore[invalid-argument-type, not-subscriptable]
        if badge:
            styles = await glob.db.fetchall(
                "SELECT * FROM badge_styles WHERE badge_id = %s", [ub['badge_id']]  # ty:ignore[invalid-argument-type, not-subscriptable]
            )
            badge = dict(badge)
            badge['styles'] = {s['type']: s['value'] for s in styles}  # ty:ignore[invalid-argument-type, not-subscriptable]
            badges.append(badge)
    badges.sort(key=lambda x: x.get('priority', 0), reverse=True)

    # Client hashes (if viewer has ViewSensitiveInfo)
    hashes = []
    viewer_priv = session['user_data']['priv']
    if _check_priv(viewer_priv, Privileges.ViewSensitiveInfo):
        hashes = await glob.db.fetchall(
            "SELECT * FROM client_hashes WHERE userid = %s ORDER BY latest_time DESC",
            [userid]
        )

    # Admin logs (logs schema: id, from_id, to_id, action, msg, created_at, action_type)
    admin_logs = await glob.db.fetchall(
        "SELECT id, from_id AS mod_id, to_id AS target_id, action, msg, created_at AS `time` "
        "FROM logs WHERE to_id = %s AND action_type = 0 ORDER BY created_at DESC LIMIT 50",
        [userid]
    )
    for log_entry in (admin_logs or []):
        mod_user = await glob.db.fetch(
            "SELECT id, name, country, priv FROM users WHERE id = %s",
            [log_entry['mod_id']]  # ty:ignore[invalid-argument-type, not-subscriptable]
        )
        log_entry['mod'] = mod_user  # ty:ignore[invalid-assignment]
        if isinstance(log_entry.get('time'), datetime.datetime):  # ty:ignore[unresolved-attribute]
            log_entry['time'] = int(log_entry['time'].timestamp())  # ty:ignore[invalid-argument-type, invalid-assignment, not-subscriptable]

    # ── Overview data (new) ────────────────────────────────────

    # Stats for all modes
    stats = await glob.db.fetchall(
        "SELECT * FROM stats WHERE id = %s", [userid]
    )

    # Recent scores (last 5 with map info)
    recent_scores = await glob.db.fetchall(
        "SELECT s.id, s.map_md5, s.pp, s.acc, s.grade, s.mods, s.mode, "
        "s.client_flags, UNIX_TIMESTAMP(s.play_time) as play_time, "
        "m.artist, m.title, m.version, m.set_id "
        "FROM scores s LEFT JOIN maps m ON s.map_md5 = m.md5 "
        "WHERE s.userid = %s ORDER BY s.id DESC LIMIT 5",
        [userid]
    )

    # Hardware matches (other users sharing hashes)
    hw_matches = []
    try:
        hw_matches = await glob.db.fetchall(
            "SELECT DISTINCT ch2.userid, u2.name "
            "FROM client_hashes ch1 "
            "JOIN client_hashes ch2 ON (ch1.osupath = ch2.osupath "
            "    OR ch1.adapters = ch2.adapters OR ch1.disk_serial = ch2.disk_serial) "
            "    AND ch1.userid != ch2.userid "
            "JOIN users u2 ON ch2.userid = u2.id "
            "WHERE ch1.userid = %s LIMIT 10",
            [userid]
        )
    except Exception:
        pass

    # Flagged score count
    flagged = await glob.db.fetch(
        "SELECT COUNT(*) as cnt FROM scores WHERE userid = %s AND client_flags != 0",
        [userid]
    )

    # Recent logins (last 5)
    recent_logins = []
    try:
        recent_logins = await glob.db.fetchall(
            "SELECT id, userid, ip, osu_ver, osu_stream, datetime "
            "FROM ingame_logins WHERE userid = %s ORDER BY id DESC LIMIT 5",
            [userid]
        )
        # Convert datetime objects to timestamps for JSON
        for login in (recent_logins or []):
            if login.get('datetime') and isinstance(login['datetime'], datetime.datetime):  # ty:ignore[invalid-argument-type, not-subscriptable, unresolved-attribute]
                login['datetime'] = int(login['datetime'].timestamp())  # ty:ignore[invalid-argument-type, invalid-assignment, not-subscriptable]
    except Exception:
        pass

    # Clan info
    clan = None
    if user.get('clan_id') and user['clan_id'] > 0:  # ty:ignore[invalid-argument-type, unresolved-attribute]
        clan = await glob.db.fetch(
            "SELECT id, name, tag FROM clans WHERE id = %s", [user['clan_id']]  # ty:ignore[invalid-argument-type]
        )

    user = dict(user)
    user['badges'] = badges
    user['logs'] = {'hashes': hashes, 'admin_logs': admin_logs}
    user['stats'] = stats or []
    user['recent_scores'] = recent_scores or []
    user['hw_matches'] = hw_matches or []
    user['flagged_score_count'] = flagged['cnt'] if flagged else 0  # ty:ignore[invalid-argument-type]
    user['recent_logins'] = recent_logins or []
    user['clan'] = dict(clan) if clan else None

    return jsonify(user)


# ─── User Actions ──────────────────────────────────────────────────────

@hina_admin.route('/api/action/wipe', methods=['POST'])
@error_catcher
@staff_required
async def action_wipe():
    data = await request.get_json()
    if not data or not data.get('user'):
        return jsonify({'status': 'error', 'message': 'No user specified.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.WipeUsers):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    reason = data.get('reason', '')

    user = await glob.db.fetch("SELECT id, name, country, priv FROM users WHERE id = %s", [user_id])
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    if user['priv'] and not ComparePrivs(mod_priv, user['priv']):  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'Cannot modify users with privileges you do not possess.'}), 403

    # Backup scores → wiped_scores
    await glob.db.execute(
        "INSERT INTO wiped_scores "
        "(id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, "
        "ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, "
        "userid, perfect, online_checksum) "
        "SELECT id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, "
        "ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, "
        "userid, perfect, online_checksum "
        "FROM scores WHERE userid = %s",
        [user_id]
    )

    # Delete scores
    await glob.db.execute("DELETE FROM scores WHERE userid = %s", [user_id])

    # Reset stats for all modes
    modes = [0, 1, 2, 3, 4, 5, 6, 7, 8]
    for mode in modes:
        await glob.db.execute(
            "UPDATE stats SET tscore=0, rscore=0, pp=0, plays=0, playtime=0, "
            "acc=0.000, max_combo=0, total_hits=0, replay_views=0, "
            "xh_count=0, x_count=0, sh_count=0, s_count=0, a_count=0 "
            "WHERE id = %s AND mode = %s",
            [user_id, mode]
        )
        await glob.redis.zrem(f"bancho:leaderboard:{mode}", user_id)
        await glob.redis.zrem(f"bancho:leaderboard:{mode}:{user['country']}", user_id)  # ty:ignore[invalid-argument-type]

    await _log_action(mod_id, mod_name, user_id, 'wipe', 'Wiped', reason, 0)

    return jsonify({
        'status': 'success',
        'message': f"Successfully wiped {user['name']} ({user_id})."  # ty:ignore[invalid-argument-type]
    })


@hina_admin.route('/api/action/restrict', methods=['POST'])
@error_catcher
@staff_required
async def action_restrict():
    data = await request.get_json()
    if not data or not data.get('user'):
        return jsonify({'status': 'error', 'message': 'No user specified.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.RestrictUsers):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    reason = data.get('reason', '')

    user = await glob.db.fetch("SELECT id, name, priv FROM users WHERE id = %s", [user_id])
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404
    if user['priv'] and not ComparePrivs(mod_priv, user['priv']):  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'Cannot modify users with privileges you do not possess.'}), 403
    if user['priv'] == 0:  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'User is already restricted.'}), 400

    await glob.db.execute("UPDATE users SET priv = 0 WHERE id = %s", [user_id])
    await _log_action(mod_id, mod_name, user_id, 'restrict', 'Restricted', reason, 0)

    return jsonify({
        'status': 'success',
        'message': f"Successfully restricted {user['name']} ({user_id})."  # ty:ignore[invalid-argument-type]
    })


@hina_admin.route('/api/action/unrestrict', methods=['POST'])
@error_catcher
@staff_required
async def action_unrestrict():
    data = await request.get_json()
    if not data or not data.get('user'):
        return jsonify({'status': 'error', 'message': 'No user specified.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.RestrictUsers):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    reason = data.get('reason', '')

    user = await glob.db.fetch("SELECT id, name, priv FROM users WHERE id = %s", [user_id])
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404
    if user['priv'] and not ComparePrivs(mod_priv, user['priv']):  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'Cannot modify users with privileges you do not possess.'}), 403
    if user['priv'] != 0:  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'User is not restricted.'}), 400

    await glob.db.execute("UPDATE users SET priv = 1 WHERE id = %s", [user_id])
    await _log_action(mod_id, mod_name, user_id, 'unrestrict', 'Unrestricted', reason, 0)

    return jsonify({
        'status': 'success',
        'message': f"Successfully unrestricted {user['name']} ({user_id})."  # ty:ignore[invalid-argument-type]
    })


@hina_admin.route('/api/action/silence', methods=['POST'])
@error_catcher
@staff_required
async def action_silence():
    data = await request.get_json()
    if not data or not data.get('user') or not data.get('duration'):
        return jsonify({'status': 'error', 'message': 'User and duration required.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.SilenceUsers):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    duration_hours = int(data['duration'])
    reason = data.get('reason', '')

    user = await glob.db.fetch("SELECT id, name, priv, silence_end FROM users WHERE id = %s", [user_id])
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404
    if user['priv'] and not ComparePrivs(mod_priv, user['priv']):  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'Cannot modify users with privileges you do not possess.'}), 403
    now_ts = int(datetime.datetime.now().timestamp())
    if user['silence_end'] and user['silence_end'] > now_ts:  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'User is already silenced.'}), 400

    silence_end = int(datetime.datetime.now().timestamp()) + duration_hours * 3600
    await glob.db.execute("UPDATE users SET silence_end = %s WHERE id = %s", [silence_end, user_id])
    await _log_action(mod_id, mod_name, user_id, 'silence', 'Silenced', reason, 0)

    return jsonify({
        'status': 'success',
        'message': f"Successfully silenced {user['name']} ({user_id}) for {duration_hours}h."  # ty:ignore[invalid-argument-type]
    })


@hina_admin.route('/api/action/unsilence', methods=['POST'])
@error_catcher
@staff_required
async def action_unsilence():
    data = await request.get_json()
    if not data or not data.get('user'):
        return jsonify({'status': 'error', 'message': 'No user specified.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.SilenceUsers):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    reason = data.get('reason', '')

    user = await glob.db.fetch("SELECT id, name, priv, silence_end FROM users WHERE id = %s", [user_id])
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404
    if user['priv'] and not ComparePrivs(mod_priv, user['priv']):  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'Cannot modify users with privileges you do not possess.'}), 403
    if user['silence_end'] == 0:  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'User is not silenced.'}), 400

    await glob.db.execute("UPDATE users SET silence_end = 0 WHERE id = %s", [user_id])
    await _log_action(mod_id, mod_name, user_id, 'unsilence', 'Unsilenced', reason, 0)

    return jsonify({
        'status': 'success',
        'message': f"Successfully unsilenced {user['name']} ({user_id})."  # ty:ignore[invalid-argument-type]
    })


@hina_admin.route('/api/action/changepassword', methods=['POST'])
@error_catcher
@staff_required
async def action_changepassword():
    data = await request.get_json()
    if not data or not data.get('user') or not data.get('password'):
        return jsonify({'status': 'error', 'message': 'User and password required.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.ManageUsers):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    password = data['password']
    reason = data.get('reason', '')

    if not (8 < len(password) <= 32):
        return jsonify({'status': 'error', 'message': 'Password must be between 8 and 32 characters.'}), 400

    user = await glob.db.fetch("SELECT id, name, safe_name, priv FROM users WHERE id = %s", [user_id])
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    if user['priv'] and not ComparePrivs(mod_priv, user['priv']):  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'Cannot modify users with privileges you do not possess.'}), 403

    # Invalidate bcrypt cache
    bcrypt_cache = glob.cache['bcrypt']
    old_pw = await glob.db.fetch("SELECT pw_bcrypt FROM users WHERE id = %s", [user_id])
    if old_pw:
        old_hash = old_pw['pw_bcrypt'].encode()  # ty:ignore[invalid-argument-type]
        if old_hash in bcrypt_cache:
            del bcrypt_cache[old_hash]

    # CRITICAL: bcrypt(md5(plaintext))
    pw_md5 = hashlib.md5(password.encode()).hexdigest().encode()
    pw_bcrypt = bcrypt.hashpw(pw_md5, bcrypt.gensalt())

    bcrypt_cache[pw_bcrypt] = pw_md5
    await glob.db.execute(
        "UPDATE users SET pw_bcrypt = %s WHERE safe_name = %s",
        [pw_bcrypt, user['safe_name']]  # ty:ignore[invalid-argument-type]
    )

    await _log_action(mod_id, mod_name, user_id, 'changepassword', 'Changed password', reason, 0)

    return jsonify({
        'status': 'success',
        'message': f"Successfully changed password for {user['name']} ({user_id})."  # ty:ignore[invalid-argument-type]
    })


@hina_admin.route('/api/action/changeprivileges', methods=['POST'])
@error_catcher
@staff_required
async def action_changeprivileges():
    data = await request.get_json()
    if not data or not data.get('user') or data.get('privs') is None:
        return jsonify({'status': 'error', 'message': 'User and privs required.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.ManagePrivs):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    new_priv = int(data['privs'])
    reason = data.get('reason', '')

    user = await glob.db.fetch("SELECT id, name, priv FROM users WHERE id = %s", [user_id])
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    if user['priv'] == new_priv:  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'Privileges are already the same.'}), 400

    # ComparePrivs(a, b) returns True if b ⊆ a
    # Block if new_priv has privs the mod doesn't have
    if not ComparePrivs(mod_priv, new_priv):
        return jsonify({'status': 'error', 'message': 'Cannot grant privileges you do not possess.'}), 403

    # Block if target user has privs the mod doesn't have
    if not ComparePrivs(mod_priv, user['priv']):  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'Cannot modify users with privileges you do not possess.'}), 403

    await glob.db.execute("UPDATE users SET priv = %s WHERE id = %s", [new_priv, user_id])
    await _log_action(mod_id, mod_name, user_id, 'changeprivileges', 'Modified Privileges', reason, 0)

    return jsonify({
        'status': 'success',
        'message': f"Successfully modified privileges for {user['name']} ({user_id})."  # ty:ignore[invalid-argument-type]
    })


@hina_admin.route('/api/action/editaccount', methods=['POST'])
@error_catcher
@staff_required
async def action_editaccount():
    data = await request.get_json()
    if not data or not data.get('user'):
        return jsonify({'status': 'error', 'message': 'No user specified.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.ManageUsers):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    reason = data.get('reason', '')

    user = await glob.db.fetch("SELECT * FROM users WHERE id = %s", [user_id])
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found.'}), 404

    if user['priv'] and not ComparePrivs(mod_priv, user['priv']):  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'Cannot modify users with privileges you do not possess.'}), 403

    # Username change
    username = data.get('username')
    if username and username != user['name']:  # ty:ignore[invalid-argument-type]
        safename = get_safe_name(username)
        existing = await glob.db.fetch(
            "SELECT id FROM users WHERE (safe_name = %s OR name = %s) AND id != %s",
            [safename, username, user_id]
        )
        if existing:
            return jsonify({'status': 'error', 'message': 'Username already taken.'}), 400
        await glob.db.execute(
            "UPDATE users SET name = %s, safe_name = %s WHERE id = %s",
            [username, safename, user_id]
        )

    # Email change
    email = data.get('email')
    if email and email != user['email']:  # ty:ignore[invalid-argument-type]
        if not regexes.email.match(email):
            return jsonify({'status': 'error', 'message': 'Invalid email address.'}), 400
        existing = await glob.db.fetch(
            "SELECT id FROM users WHERE email = %s AND id != %s",
            [email, user_id]
        )
        if existing:
            return jsonify({'status': 'error', 'message': 'Email already taken.'}), 400
        await glob.db.execute("UPDATE users SET email = %s WHERE id = %s", [email, user_id])

    # Country change
    country = data.get('country')
    if country and country != user['country']:  # ty:ignore[invalid-argument-type]
        if len(country) != 2:
            return jsonify({'status': 'error', 'message': 'Invalid country code.'}), 400
        await glob.db.execute("UPDATE users SET country = %s WHERE id = %s", [country, user_id])

    # Userpage change
    userpage = data.get('userpage_content')
    if userpage is not None and userpage != user['userpage_content']:  # ty:ignore[invalid-argument-type]
        await glob.db.execute("UPDATE users SET userpage_content = %s WHERE id = %s", [userpage, user_id])

    await _log_action(mod_id, mod_name, user_id, 'editaccount', 'Edited Account', reason, 0)

    return jsonify({
        'status': 'success',
        'message': f"Successfully edited account for {user['name']} ({user_id})."  # ty:ignore[invalid-argument-type]
    })


@hina_admin.route('/api/action/bulk', methods=['POST'])
@error_catcher
@staff_required
async def action_bulk():
    data = await request.get_json()
    action = data.get('action', '') if data else ''
    user_ids = data.get('users', []) if data else []
    reason = data.get('reason', '') if data else ''

    if action not in ('restrict', 'unrestrict'):
        return jsonify({'status': 'error', 'message': 'Invalid bulk action.'}), 400

    if not user_ids or len(user_ids) > 50:
        return jsonify({'status': 'error', 'message': 'Select 1-50 users.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.RestrictUsers):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    results = []
    for uid in user_ids:
        uid = int(uid)
        user = await glob.db.fetch(
            "SELECT id, name, priv, country FROM users WHERE id = %s", [uid]
        )
        if not user:
            results.append({'id': uid, 'status': 'error', 'message': 'Not found'})
            continue

        if user['priv'] and not ComparePrivs(mod_priv, user['priv']):  # ty:ignore[invalid-argument-type]
            results.append({'id': uid, 'status': 'error', 'message': 'Cannot modify users with higher privileges'})
            continue

        if action == 'restrict':
            if not (user['priv'] & 1):  # ty:ignore[invalid-argument-type]
                results.append({'id': uid, 'status': 'skipped', 'message': 'Already restricted'})
                continue
            await glob.db.execute("UPDATE users SET priv = 0 WHERE id = %s", [uid])
            # Remove from all leaderboards
            for mode in [0, 1, 2, 3, 4, 5, 6, 7, 8]:
                await glob.redis.zrem(f"bancho:leaderboard:{mode}", uid)
                await glob.redis.zrem(f"bancho:leaderboard:{mode}:{user['country']}", uid)  # ty:ignore[invalid-argument-type]
            await _log_action(mod_id, mod_name, uid, 'restrict', 'Restricted (bulk)', reason, 0)

        elif action == 'unrestrict':
            if user['priv'] & 1:  # ty:ignore[invalid-argument-type]
                results.append({'id': uid, 'status': 'skipped', 'message': 'Not restricted'})
                continue
            await glob.db.execute("UPDATE users SET priv = 1 WHERE id = %s", [uid])
            await _log_action(mod_id, mod_name, uid, 'unrestrict', 'Unrestricted (bulk)', reason, 0)

        results.append({'id': uid, 'status': 'success', 'message': f'{action}ed'})

    success_count = len([r for r in results if r['status'] == 'success'])

    # Summary audit log entry
    affected_ids = [r['id'] for r in results if r['status'] == 'success']
    if affected_ids:
        summary_msg = (
            f"Bulk {action}: {success_count}/{len(user_ids)} users. "
            f"IDs: {','.join(str(i) for i in affected_ids[:20])}"
            f"{'...' if len(affected_ids) > 20 else ''}. "
            f"Reason: {reason or 'No reason specified.'}"
        )
        await _log_action(
            mod_id, mod_name, 0,
            f'bulk_{action}', f'Bulk {action}',
            summary_msg, 0
        )

    return jsonify({
        'status': 'success',
        'message': f'Bulk {action}: {success_count}/{len(user_ids)} users processed.',
        'results': results,
    })


@hina_admin.route('/api/action/removescore', methods=['POST'])
@error_catcher
@staff_required
async def action_removescore():
    data = await request.get_json()
    if not data or not data.get('user') or not data.get('score'):
        return jsonify({'status': 'error', 'message': 'User and score required.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.ManageUsers):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    score_id = int(data['score'])
    reason = data.get('reason', '')

    score_owner = await glob.db.fetch("SELECT priv FROM users WHERE id = %s", [user_id])
    if score_owner and score_owner['priv'] and not ComparePrivs(mod_priv, score_owner['priv']):  # ty:ignore[invalid-argument-type]
        return jsonify({'status': 'error', 'message': 'Cannot modify scores of users with privileges you do not possess.'}), 403

    score = await glob.db.fetch("SELECT * FROM scores WHERE id = %s", [score_id])
    if not score:
        return jsonify({'status': 'error', 'message': 'Score not found.'}), 404

    # Backup to wiped_scores
    await glob.db.execute(
        "INSERT INTO wiped_scores "
        "(id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, "
        "ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, "
        "userid, perfect, online_checksum) "
        "SELECT id, map_md5, score, pp, acc, max_combo, mods, n300, n100, n50, nmiss, "
        "ngeki, nkatu, grade, status, mode, play_time, time_elapsed, client_flags, "
        "userid, perfect, online_checksum "
        "FROM scores WHERE id = %s",
        [score_id]
    )

    await glob.db.execute("DELETE FROM scores WHERE id = %s", [score_id])
    await _log_action(mod_id, mod_name, user_id, 'removescore', 'Removed Score', reason, 0)

    return jsonify({
        'status': 'success',
        'message': f"Successfully removed score {score_id}."
    })


# ─── Badges API ────────────────────────────────────────────────────────

@hina_admin.route('/api/badges')
@error_catcher
@staff_required
async def api_badges():
    badges = await glob.db.fetchall("SELECT * FROM badges ORDER BY priority DESC")
    for badge in badges:
        styles = await glob.db.fetchall(
            "SELECT * FROM badge_styles WHERE badge_id = %s", [badge['id']]  # ty:ignore[invalid-argument-type, not-subscriptable]
        )
        badge['styles'] = {s['type']: s['value'] for s in styles}  # ty:ignore[invalid-argument-type, invalid-assignment, not-subscriptable]

    return jsonify(badges)


@hina_admin.route('/api/badge/<int:badge_id>')
@error_catcher
@staff_required
async def api_badge_detail(badge_id):
    badge = await glob.db.fetch("SELECT * FROM badges WHERE id = %s", [badge_id])
    if not badge:
        return jsonify({'status': 'error', 'message': 'Badge not found.'}), 404

    styles = await glob.db.fetchall(
        "SELECT * FROM badge_styles WHERE badge_id = %s", [badge_id]
    )
    badge = dict(badge)
    badge['styles'] = styles
    return jsonify(badge)


@hina_admin.route('/api/badge/create', methods=['POST'])
@error_catcher
@staff_required
async def api_badge_create():
    mod_priv = session['user_data']['priv']
    if not _check_priv(mod_priv, Privileges.ManageBadges):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    data = await request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'No data provided.'}), 400

    await glob.db.execute(
        "INSERT INTO badges (name, description, priority) VALUES (%s, %s, %s)",
        [data.get('name', ''), data.get('description', ''), data.get('priority', 0)]
    )

    result = await glob.db.fetch(
        "SELECT id FROM badges WHERE name = %s ORDER BY id DESC LIMIT 1",
        [data.get('name', '')]
    )
    if not result:
        return jsonify({'status': 'error', 'message': 'Failed to create badge.'}), 500

    new_id = result['id']  # ty:ignore[invalid-argument-type]
    for style in data.get('styles', []):
        await glob.db.execute(
            "INSERT INTO badge_styles (badge_id, type, value) VALUES (%s, %s, %s)",
            [new_id, style['type'], style['value']]
        )

    return jsonify({'status': 'success', 'message': 'Badge created.', 'id': new_id})


@hina_admin.route('/api/badge/<int:badge_id>/update', methods=['POST'])
@error_catcher
@staff_required
async def api_badge_update(badge_id):
    mod_priv = session['user_data']['priv']
    if not _check_priv(mod_priv, Privileges.ManageBadges):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    data = await request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'No data provided.'}), 400

    await glob.db.execute(
        "UPDATE badges SET name = %s, description = %s, priority = %s WHERE id = %s",
        [data['name'], data['description'], data['priority'], badge_id]
    )

    for style in data.get('styles', []):
        existing = await glob.db.fetch(
            "SELECT * FROM badge_styles WHERE badge_id = %s AND type = %s",
            [badge_id, style['type']]
        )
        if existing:
            await glob.db.execute(
                "UPDATE badge_styles SET value = %s WHERE badge_id = %s AND type = %s",
                [style['value'], badge_id, style['type']]
            )
        else:
            await glob.db.execute(
                "INSERT INTO badge_styles (badge_id, type, value) VALUES (%s, %s, %s)",
                [badge_id, style['type'], style['value']]
            )

    return jsonify({'status': 'success', 'message': 'Badge updated.'})


@hina_admin.route('/api/action/addbadge', methods=['POST'])
@error_catcher
@staff_required
async def action_addbadge():
    data = await request.get_json()
    if not data or not data.get('user') or not data.get('badge'):
        return jsonify({'status': 'error', 'message': 'User and badge required.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.ManageBadges):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    badge_id = int(data['badge'])

    badge = await glob.db.fetch("SELECT * FROM badges WHERE id = %s", [badge_id])
    if not badge:
        return jsonify({'status': 'error', 'message': 'Badge not found.'}), 404

    existing = await glob.db.fetch(
        "SELECT * FROM user_badges WHERE userid = %s AND badge_id = %s",
        [user_id, badge_id]
    )
    if existing:
        return jsonify({'status': 'error', 'message': 'User already has this badge.'}), 400

    await glob.db.execute(
        "INSERT INTO user_badges (userid, badge_id) VALUES (%s, %s)",
        [user_id, badge_id]
    )

    await _log_action(mod_id, mod_name, user_id, 'addbadge', 'Given Badge', data.get('reason', ''), 2, badge=badge)

    return jsonify({'status': 'success', 'message': f'Badge {badge_id} added.'})


@hina_admin.route('/api/action/removebadge', methods=['POST'])
@error_catcher
@staff_required
async def action_removebadge():
    data = await request.get_json()
    if not data or not data.get('user') or not data.get('badge'):
        return jsonify({'status': 'error', 'message': 'User and badge required.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.ManageBadges):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    user_id = int(data['user'])
    badge_id = int(data['badge'])

    badge = await glob.db.fetch("SELECT * FROM badges WHERE id = %s", [badge_id])
    if not badge:
        return jsonify({'status': 'error', 'message': 'Badge not found.'}), 404

    existing = await glob.db.fetch(
        "SELECT * FROM user_badges WHERE userid = %s AND badge_id = %s",
        [user_id, badge_id]
    )
    if not existing:
        return jsonify({'status': 'error', 'message': 'User does not have this badge.'}), 400

    await glob.db.execute(
        "DELETE FROM user_badges WHERE userid = %s AND badge_id = %s",
        [user_id, badge_id]
    )

    await _log_action(mod_id, mod_name, user_id, 'removebadge', 'Revoked Badge', data.get('reason', ''), 2, badge=badge)

    return jsonify({'status': 'success', 'message': f'Badge {badge_id} removed.'})


# ─── Beatmaps API ─────────────────────────────────────────────────────


# ─── PP Table ─────────────────────────────────────────────────────────

@hina_admin.route('/api/beatmaps/pp-table')
@error_catcher
@staff_required
async def api_pp_table():
    """Proxy batch PP calculation to kawata.py API."""
    mod_priv = session['user_data']['priv']
    if not _check_priv(mod_priv, Privileges.ManageBeatmaps):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    ids_raw = request.args.get('ids', '')
    mods = request.args.get('mods', '0')

    if not ids_raw:
        return jsonify({'status': 'error', 'message': 'No IDs provided.'}), 400

    # Build query params: repeat id= for each diff
    params = [('acc', '100'), ('acc', '99'), ('acc', '98'), ('acc', '95')]
    params.append(('mods', mods))
    for bid in ids_raw.split(',')[:20]:
        bid = bid.strip()
        if bid.isdigit():
            params.append(('id', bid))

    url = 'http://bancho:10000/v1/calculate_pp_batch'
    headers = {
        'Host': f'api.{cfg.domain}',
        'Authorization': f'Bearer {glob.config.api_key}',
    }
    try:
        async with glob.http.get(url, headers=headers, params=params) as resp:
            data = await resp.json(content_type=None)
            if resp.status != 200:
                return jsonify({'status': 'error', 'message': data.get('status', 'API error')}), resp.status
            return jsonify(data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500

@hina_admin.route('/api/beatmaps')
@error_catcher
@staff_required
async def api_beatmaps():
    mod_priv = session['user_data']['priv']
    if not _check_priv(mod_priv, Privileges.ManageBeatmaps):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    page = max(1, int(request.args.get('page', 1)))
    items_per_page = 50
    offset = (page - 1) * items_per_page

    map_requests = await glob.db.fetchall(
        "SELECT * FROM map_requests WHERE active = 1 ORDER BY datetime DESC "
        "LIMIT %s OFFSET %s",
        [items_per_page, offset]
    )

    results = []
    for req in map_requests:
        # Player info
        player = await glob.db.fetch(
            "SELECT name, id, country FROM users WHERE id = %s",
            [req['player_id']]  # ty:ignore[invalid-argument-type, not-subscriptable]
        )

        # Map info + diffs
        try:
            maps_data = await glob.db.fetchall(
                "SELECT * FROM maps WHERE id = %s OR set_id = "
                "(SELECT set_id FROM maps WHERE id = %s)",
                [req['map_id'], req['map_id']]  # ty:ignore[invalid-argument-type, not-subscriptable]
            )
        except Exception:
            maps_data = []

        map_info = None
        map_diffs = []
        for m in maps_data:
            if m['id'] == req['map_id']:  # ty:ignore[invalid-argument-type, not-subscriptable]
                map_info = dict(m)  # ty:ignore[no-matching-overload]
                # Convert datetime
                if map_info.get('last_update'):
                    map_info['last_update'] = str(map_info['last_update'])
            else:
                d = dict(m)  # ty:ignore[no-matching-overload]
                if d.get('last_update'):
                    d['last_update'] = str(d['last_update'])
                map_diffs.append(d)

        if not map_info:
            continue

        req_dict = dict(req)  # ty:ignore[no-matching-overload]
        req_dict['datetime'] = str(req['datetime'])  # ty:ignore[invalid-argument-type, not-subscriptable]
        req_dict['player'] = player
        req_dict['map_info'] = map_info
        req_dict['map_diffs'] = map_diffs
        results.append(req_dict)

    return jsonify({'requests': results, 'page': page})


def _map_action_handler(action_name, action_text, target_status, status_check_value, status_check_msg):
    """Factory for map status change actions (rank/approve/qualify/love/unrank)."""
    async def handler():
        data = await request.get_json()
        if not data or not data.get('map'):
            return jsonify({'status': 'error', 'message': 'No map specified.'}), 400

        mod_id, mod_name, mod_priv = _get_mod_info()
        if not _check_priv(mod_priv, Privileges.ManageBeatmaps):
            return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

        map_id = int(data['map'])
        reason = data.get('reason', '')

        map_obj = await glob.db.fetch("SELECT * FROM maps WHERE id = %s", [map_id])
        if not map_obj:
            return jsonify({'status': 'error', 'message': 'Map not found.'}), 404

        if map_obj['status'] == status_check_value:  # ty:ignore[invalid-argument-type]
            return jsonify({'status': 'error', 'message': status_check_msg}), 400

        # Proxy to kawata.py API
        api_result = await _update_map_status(map_id, target_status)
        if not api_result or api_result.get('status') not in ('success',):
            error_msg = api_result.get('message', 'Unknown error') if api_result else 'No response'
            return jsonify({'status': 'error', 'message': f'Failed to update map status: {error_msg}'}), 502

        # Deactivate map request
        try:
            await glob.db.execute(
                "UPDATE map_requests SET active = 0 WHERE map_id = %s", [map_id]
            )
        except Exception:
            pass

        # Add to newly_ranked for rank/approve/qualify/love
        if target_status in (2, 3, 4, 5):
            try:
                await glob.db.execute(
                    "INSERT INTO newly_ranked (map_id, mod_id, time) VALUES (%s, %s, %s)",
                    [map_id, mod_id, datetime.datetime.now()]
                )
            except Exception:
                pass

        await _log_action(mod_id, mod_name, map_id, action_name, action_text,
                          reason, 1, map_obj=dict(map_obj))

        return jsonify({
            'status': 'success',
            'message': f"Successfully {action_text.lower()} {map_obj['artist']} - {map_obj['title']} [{map_obj['version']}]."  # ty:ignore[invalid-argument-type]
        })

    handler.__name__ = f'action_{action_name}'
    return handler


# Register map action routes
for _action, _text, _status, _check_val, _check_msg in [
    ('rank', 'Ranked', 2, 2, 'Map is already ranked.'),
    ('approve', 'Approved', 3, 3, 'Map is already approved.'),
    ('qualify', 'Qualified', 4, 4, 'Map is already qualified.'),
    ('love', 'Loved', 5, 5, 'Map is already loved.'),
    ('unrank', 'Unranked', 0, 0, 'Map is not ranked.'),
]:
    _handler = _map_action_handler(_action, _text, _status, _check_val, _check_msg)
    _handler = staff_required(_handler)
    _handler = error_catcher(_handler)
    hina_admin.add_url_rule(
        f'/api/action/{_action}', f'action_{_action}',
        _handler, methods=['POST']
    )


@hina_admin.route('/api/action/completerequest', methods=['POST'])
@error_catcher
@staff_required
async def action_completerequest():
    data = await request.get_json()
    if not data or not data.get('map'):
        return jsonify({'status': 'error', 'message': 'No map specified.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.ManageBeatmaps):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    map_id = int(data['map'])

    await glob.db.execute("UPDATE map_requests SET active = 0 WHERE map_id = %s", [map_id])

    return jsonify({
        'status': 'success',
        'message': f"Request for map {map_id} marked as complete."
    })


# ─── Beatmap Review Work Items ────────────────────────────────────────

@hina_admin.route('/api/beatmaps/work-items')
@error_catcher
@staff_required
async def api_bm_work_items():
    mod_priv = session['user_data']['priv']
    if not _check_priv(mod_priv, Privileges.ManageBeatmaps):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    # ── Auto-sync: create work items from unprocessed active map_requests ──
    unprocessed = await glob.db.fetchall(
        "SELECT mr.id, mr.map_id, mr.player_id, mr.datetime, m.set_id "
        "FROM map_requests mr "
        "JOIN maps m ON mr.map_id = m.id "
        "WHERE mr.active = 1 "
        "AND NOT EXISTS ("
        "  SELECT 1 FROM beatmap_work_items bwi "
        "  WHERE bwi.set_id = m.set_id AND bwi.review_state != 'done'"
        ")"
    )
    seen_sets = set()
    for req in (unprocessed or []):
        if req['set_id'] in seen_sets:  # ty:ignore[invalid-argument-type, not-subscriptable]
            continue
        seen_sets.add(req['set_id'])  # ty:ignore[invalid-argument-type, not-subscriptable]
        await glob.db.execute(
            "INSERT INTO beatmap_work_items "
            "(set_id, request_id, review_state, checklist, created_at) "
            "VALUES (%s, %s, 'pending', %s, %s)",
            [req['set_id'], req['id'], DEFAULT_CHECKLIST, req['datetime']]  # ty:ignore[invalid-argument-type, not-subscriptable]
        )

    # ── Parse filters ──
    page = max(1, int(request.args.get('page', 1)))
    search = str(request.args.get('search', '')).strip()
    filter_status = str(request.args.get('status', ''))
    filter_assigned = str(request.args.get('assigned', ''))
    filter_age = str(request.args.get('age', ''))
    filter_mode = str(request.args.get('mode', ''))
    filter_map_status = str(request.args.get('map_status', ''))
    filter_mapper = str(request.args.get('mapper', '')).strip()
    filter_requester = str(request.args.get('requester', '')).strip()
    sort_by = str(request.args.get('sort', 'created_at'))
    sort_order = str(request.args.get('order', 'DESC'))

    if sort_by not in ('created_at', 'updated_at', 'priority'):
        sort_by = 'created_at'
    if sort_order not in ('ASC', 'DESC'):
        sort_order = 'DESC'

    items_per_page = 30
    offset = (page - 1) * items_per_page

    # ── Build query ──
    base_query = (
        "SELECT bwi.id, bwi.set_id, bwi.request_id, bwi.review_state, "
        "bwi.assigned_to, bwi.checklist, bwi.priority, bwi.resolution, "
        "UNIX_TIMESTAMP(bwi.created_at) as created_at, "
        "UNIX_TIMESTAMP(bwi.updated_at) as updated_at, "
        "UNIX_TIMESTAMP(bwi.resolved_at) as resolved_at, "
        "UNIX_TIMESTAMP(bwi.assigned_at) as assigned_at, "
        "ua.name as assignee_name, "
        "mr.player_id as requester_id, ur.name as requester_name, "
        "UNIX_TIMESTAMP(mr.datetime) as requested_at "
        "FROM beatmap_work_items bwi "
        "LEFT JOIN map_requests mr ON mr.id = bwi.request_id "
        "LEFT JOIN users ua ON ua.id = bwi.assigned_to "
        "LEFT JOIN users ur ON ur.id = mr.player_id"
    )
    conditions = []
    params = []

    if filter_status:
        conditions.append("bwi.review_state = %s")
        params.append(filter_status)
    else:
        conditions.append("bwi.review_state != 'done'")

    if filter_assigned == 'me':
        conditions.append("bwi.assigned_to = %s")
        params.append(session['user_data']['id'])
    elif filter_assigned == 'unassigned':
        conditions.append("bwi.assigned_to IS NULL")

    age_map = {'1d': 1, '3d': 3, '7d': 7, '30d': 30}
    if filter_age in age_map:
        conditions.append("bwi.created_at <= DATE_SUB(NOW(), INTERVAL %s DAY)")
        params.append(age_map[filter_age])

    if search:
        conditions.append(
            "EXISTS (SELECT 1 FROM maps m WHERE m.set_id = bwi.set_id "
            "AND (m.artist LIKE %s OR m.title LIKE %s OR m.creator LIKE %s))"
        )
        like = f"%{search}%"
        params.extend([like, like, like])

    if filter_mapper:
        conditions.append(
            "EXISTS (SELECT 1 FROM maps m WHERE m.set_id = bwi.set_id AND m.creator LIKE %s)"
        )
        params.append(f"%{filter_mapper}%")

    if filter_requester:
        conditions.append("ur.name LIKE %s")
        params.append(f"%{filter_requester}%")

    if filter_mode != '':
        conditions.append(
            "EXISTS (SELECT 1 FROM maps m WHERE m.set_id = bwi.set_id AND m.mode = %s)"
        )
        params.append(int(filter_mode))

    if filter_map_status != '':
        conditions.append(
            "EXISTS (SELECT 1 FROM maps m WHERE m.set_id = bwi.set_id AND m.status = %s)"
        )
        params.append(int(filter_map_status))

    where = " WHERE " + " AND ".join(conditions) if conditions else ""

    # Count
    count_query = (
        "SELECT COUNT(*) as total FROM beatmap_work_items bwi "
        "LEFT JOIN map_requests mr ON mr.id = bwi.request_id "
        "LEFT JOIN users ur ON ur.id = mr.player_id"
    )
    total = await glob.db.fetch(count_query + where, params)
    total_count = total['total'] if total else 0  # ty:ignore[invalid-argument-type]
    total_pages = max(1, (total_count + items_per_page - 1) // items_per_page)

    # Fetch page
    sort_col = 'bwi.' + sort_by
    items = await glob.db.fetchall(
        base_query + where + f" ORDER BY {sort_col} {sort_order} LIMIT {items_per_page} OFFSET {offset}",
        params
    )
    items = [dict(i) for i in (items or [])]  # ty:ignore[no-matching-overload]

    # ── Batch-enrich with set metadata (avoid N+1) ──
    if items:
        set_ids = list({item['set_id'] for item in items})
        placeholders = ','.join(['%s'] * len(set_ids))

        set_meta = await glob.db.fetchall(
            f"SELECT set_id, artist, title, "
            f"creator, mode "
            f"FROM maps WHERE set_id IN ({placeholders}) GROUP BY set_id",
            set_ids
        )
        meta_map = {r['set_id']: r for r in (set_meta or [])}  # ty:ignore[invalid-argument-type, not-subscriptable]

        diff_summary = await glob.db.fetchall(
            f"SELECT set_id, COUNT(*) as diff_count, "
            f"MIN(diff) as min_stars, MAX(diff) as max_stars, "
            f"SUM(plays) as total_plays "
            f"FROM maps WHERE set_id IN ({placeholders}) GROUP BY set_id",
            set_ids
        )
        diff_map = {r['set_id']: r for r in (diff_summary or [])}  # ty:ignore[invalid-argument-type, not-subscriptable]

        item_ids = [item['id'] for item in items]
        ip = ','.join(['%s'] * len(item_ids))
        comment_rows = await glob.db.fetchall(
            f"SELECT work_item_id, COUNT(*) as cnt "
            f"FROM beatmap_review_comments WHERE work_item_id IN ({ip}) "
            f"GROUP BY work_item_id",
            item_ids
        )
        comment_map = {r['work_item_id']: r['cnt'] for r in (comment_rows or [])}  # ty:ignore[invalid-argument-type, not-subscriptable]

        for item in items:
            meta = meta_map.get(item['set_id'], {})
            diffs = diff_map.get(item['set_id'], {})
            item['artist'] = meta.get('artist', '')  # ty:ignore[unresolved-attribute]
            item['title'] = meta.get('title', '')  # ty:ignore[unresolved-attribute]
            item['creator'] = meta.get('creator', '')  # ty:ignore[unresolved-attribute]
            item['mode'] = meta.get('mode', 0)  # ty:ignore[unresolved-attribute]
            item['diff_count'] = diffs.get('diff_count', 0)  # ty:ignore[unresolved-attribute]
            item['min_stars'] = float(diffs.get('min_stars', 0) or 0)  # ty:ignore[unresolved-attribute]
            item['max_stars'] = float(diffs.get('max_stars', 0) or 0)  # ty:ignore[unresolved-attribute]
            item['total_plays'] = diffs.get('total_plays', 0)  # ty:ignore[unresolved-attribute]
            item['comment_count'] = comment_map.get(item['id'], 0)
            if item.get('checklist') and isinstance(item['checklist'], str):
                item['checklist'] = json.loads(item['checklist'])

    return jsonify({
        'items': items,
        'pagination': {
            'current_page': page,
            'total_pages': total_pages,
            'total_count': total_count,
        }
    })


@hina_admin.route('/api/beatmaps/work-items/<int:item_id>')
@error_catcher
@staff_required
async def api_bm_work_item_detail(item_id):
    item = await glob.db.fetch(
        "SELECT bwi.*, ua.name as assignee_name "
        "FROM beatmap_work_items bwi "
        "LEFT JOIN users ua ON ua.id = bwi.assigned_to "
        "WHERE bwi.id = %s", [item_id]
    )
    if not item:
        return jsonify({'status': 'error', 'message': 'Work item not found.'}), 404
    item = dict(item)

    # All diffs in the set
    diffs = await glob.db.fetchall(
        "SELECT id, version, diff, mode, cs, ar, od, hp, bpm, "
        "total_length, max_combo, plays, passes, status "
        "FROM maps WHERE set_id = %s ORDER BY diff ASC",
        [item['set_id']]
    )

    # Set metadata from first diff
    meta = await glob.db.fetch(
        "SELECT artist, title, creator FROM maps WHERE set_id = %s LIMIT 1",
        [item['set_id']]
    )
    item['artist'] = meta['artist'] if meta else ''  # ty:ignore[invalid-argument-type]
    item['title'] = meta['title'] if meta else ''  # ty:ignore[invalid-argument-type]
    item['creator'] = meta['creator'] if meta else ''  # ty:ignore[invalid-argument-type]

    # Requester info
    requester = None
    if item.get('request_id'):
        req_row = await glob.db.fetch(
            "SELECT mr.player_id, mr.datetime, u.name as player_name "
            "FROM map_requests mr JOIN users u ON u.id = mr.player_id "
            "WHERE mr.id = %s", [item['request_id']]
        )
        if req_row:
            requester = {
                'id': req_row['player_id'],  # ty:ignore[invalid-argument-type]
                'name': req_row['player_name'],  # ty:ignore[invalid-argument-type]
                'datetime': int(req_row['datetime'].timestamp())  # ty:ignore[invalid-argument-type]
                    if isinstance(req_row['datetime'], datetime.datetime)  # ty:ignore[invalid-argument-type]
                    else req_row['datetime'],  # ty:ignore[invalid-argument-type]
            }

    # All requests for this set
    all_requests = await glob.db.fetchall(
        "SELECT mr.id, mr.map_id, mr.player_id, mr.active, mr.datetime, u.name "
        "FROM map_requests mr "
        "JOIN maps m ON mr.map_id = m.id "
        "JOIN users u ON u.id = mr.player_id "
        "WHERE m.set_id = %s ORDER BY mr.datetime DESC",
        [item['set_id']]
    )

    # Aggregate stats
    fav_count = await glob.db.fetch(
        "SELECT COUNT(*) as cnt FROM favourites WHERE setid = %s", [item['set_id']]
    )
    total_plays = sum(d.get('plays', 0) for d in (diffs or []))  # ty:ignore[unresolved-attribute]
    total_passes = sum(d.get('passes', 0) for d in (diffs or []))  # ty:ignore[unresolved-attribute]

    # Review comments
    comments = await glob.db.fetchall(
        "SELECT brc.*, u.name as user_name "
        "FROM beatmap_review_comments brc "
        "JOIN users u ON u.id = brc.user_id "
        "WHERE brc.work_item_id = %s ORDER BY brc.created_at ASC",
        [item_id]
    )

    # Action history from logs
    # logs schema: id, from_id, to_id, action, msg, created_at, action_type
    map_ids = [d['id'] for d in (diffs or [])]  # ty:ignore[invalid-argument-type, not-subscriptable]
    history = []
    if map_ids:
        ip = ','.join(['%s'] * len(map_ids))
        history = await glob.db.fetchall(
            f"SELECT l.id, l.from_id as `mod`, l.to_id as target, l.action, "
            f"l.msg as reason, l.created_at as time, u.name as mod_name "
            f"FROM logs l LEFT JOIN users u ON u.id = l.from_id "
            f"WHERE l.to_id IN ({ip}) AND l.action_type = 1 "
            f"ORDER BY l.created_at DESC LIMIT 20",
            map_ids
        )

    # Convert datetimes to unix timestamps for JSON
    for key in ('created_at', 'updated_at', 'resolved_at', 'assigned_at'):
        if item.get(key) and isinstance(item[key], datetime.datetime):
            item[key] = int(item[key].timestamp())
    if isinstance(item.get('checklist'), str):
        item['checklist'] = json.loads(item['checklist'])
    for c in (comments or []):
        if isinstance(c.get('created_at'), datetime.datetime):  # ty:ignore[unresolved-attribute]
            c['created_at'] = int(c['created_at'].timestamp())  # ty:ignore[invalid-argument-type, invalid-assignment, not-subscriptable]
    for r in (all_requests or []):
        if isinstance(r.get('datetime'), datetime.datetime):  # ty:ignore[unresolved-attribute]
            r['datetime'] = int(r['datetime'].timestamp())  # ty:ignore[invalid-argument-type, invalid-assignment, not-subscriptable]
    for h in (history or []):
        if isinstance(h.get('time'), datetime.datetime):  # ty:ignore[unresolved-attribute]
            h['time'] = int(h['time'].timestamp())  # ty:ignore[invalid-argument-type, invalid-assignment, not-subscriptable]

    item['diffs'] = [dict(d) for d in (diffs or [])]  # ty:ignore[no-matching-overload]
    item['requester'] = requester
    item['requests'] = [dict(r) for r in (all_requests or [])]  # ty:ignore[no-matching-overload]
    item['favourite_count'] = fav_count['cnt'] if fav_count else 0  # ty:ignore[invalid-argument-type]
    item['total_plays'] = total_plays
    item['total_passes'] = total_passes
    item['comments'] = [dict(c) for c in (comments or [])]  # ty:ignore[no-matching-overload]
    item['history'] = [dict(h) for h in (history or [])]  # ty:ignore[no-matching-overload]

    return jsonify(item)


@hina_admin.route('/api/beatmaps/work-items', methods=['POST'])
@error_catcher
@staff_required
async def api_bm_create_work_item():
    data = await request.get_json()
    set_id = data.get('set_id')
    if not set_id:
        return jsonify({'status': 'error', 'message': 'set_id required.'}), 400

    mod_priv = session['user_data']['priv']
    if not _check_priv(mod_priv, Privileges.ManageBeatmaps):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    exists = await glob.db.fetch("SELECT id FROM maps WHERE set_id = %s LIMIT 1", [set_id])
    if not exists:
        return jsonify({'status': 'error', 'message': 'No maps found for this set.'}), 404

    active = await glob.db.fetch(
        "SELECT id FROM beatmap_work_items WHERE set_id = %s AND review_state != 'done'",
        [set_id]
    )
    if active:
        return jsonify({'status': 'error', 'message': 'Active work item already exists.', 'existing_id': active['id']}), 409  # ty:ignore[invalid-argument-type]

    await glob.db.execute(
        "INSERT INTO beatmap_work_items (set_id, review_state, checklist) VALUES (%s, 'pending', %s)",
        [set_id, DEFAULT_CHECKLIST]
    )
    return jsonify({'status': 'success', 'message': 'Work item created.'})


@hina_admin.route('/api/beatmaps/work-items/<int:item_id>/assign', methods=['POST'])
@error_catcher
@staff_required
async def api_bm_assign(item_id):
    data = await request.get_json()
    user_id = data.get('user_id')

    item = await glob.db.fetch("SELECT * FROM beatmap_work_items WHERE id = %s", [item_id])
    if not item:
        return jsonify({'status': 'error', 'message': 'Work item not found.'}), 404

    if user_id:
        await glob.db.execute(
            "UPDATE beatmap_work_items "
            "SET assigned_to = %s, assigned_at = NOW(), "
            "    review_state = CASE WHEN review_state = 'pending' THEN 'in_review' ELSE review_state END "
            "WHERE id = %s",
            [int(user_id), item_id]
        )
    else:
        await glob.db.execute(
            "UPDATE beatmap_work_items SET assigned_to = NULL, assigned_at = NULL, "
            "review_state = CASE WHEN review_state = 'in_review' THEN 'pending' ELSE review_state END "
            "WHERE id = %s",
            [item_id]
        )

    return jsonify({'status': 'success'})


@hina_admin.route('/api/beatmaps/work-items/<int:item_id>/checklist', methods=['POST'])
@error_catcher
@staff_required
async def api_bm_checklist(item_id):
    data = await request.get_json()
    if not isinstance(data, dict):
        return jsonify({'status': 'error', 'message': 'Request body must be a JSON object.'}), 400

    item = await glob.db.fetch("SELECT checklist FROM beatmap_work_items WHERE id = %s", [item_id])
    if not item:
        return jsonify({'status': 'error', 'message': 'Work item not found.'}), 404

    current = json.loads(item['checklist']) if item.get('checklist') else {}  # ty:ignore[invalid-argument-type, unresolved-attribute]
    VALID_KEYS = ('timing', 'hitsounds', 'difficulty_spread', 'metadata', 'background', 'no_abuse')
    for key in VALID_KEYS:
        if key in data:
            current[key] = bool(data[key])

    await glob.db.execute(
        "UPDATE beatmap_work_items SET checklist = %s WHERE id = %s",
        [json.dumps(current), item_id]
    )
    return jsonify({'status': 'success', 'checklist': current})


@hina_admin.route('/api/beatmaps/work-items/<int:item_id>/comment', methods=['POST'])
@error_catcher
@staff_required
async def api_bm_comment(item_id):
    data = await request.get_json()
    body = (data.get('body') or '').strip()
    if not body:
        return jsonify({'status': 'error', 'message': 'Comment body required.'}), 400

    item = await glob.db.fetch("SELECT id FROM beatmap_work_items WHERE id = %s", [item_id])
    if not item:
        return jsonify({'status': 'error', 'message': 'Work item not found.'}), 404

    mod_id = session['user_data']['id']
    await glob.db.execute(
        "INSERT INTO beatmap_review_comments (work_item_id, user_id, body) VALUES (%s, %s, %s)",
        [item_id, mod_id, body]
    )
    return jsonify({'status': 'success'})


@hina_admin.route('/api/beatmaps/work-items/<int:item_id>/set-status', methods=['POST'])
@error_catcher
@staff_required
async def api_bm_set_status(item_id):
    """Apply a ranked status to selected difficulties without closing the work item."""
    data = await request.get_json()
    map_ids = data.get('map_ids', [])
    action = data.get('action', '')
    reason = (data.get('reason') or '').strip()

    STATUS_MAP = {'rank': 2, 'approve': 3, 'qualify': 4, 'love': 5, 'unrank': 0}
    if action not in STATUS_MAP:
        return jsonify({'status': 'error', 'message': 'Invalid action.'}), 400

    if not map_ids or not isinstance(map_ids, list):
        return jsonify({'status': 'error', 'message': 'No difficulties selected.'}), 400

    if action == 'unrank' and not reason:
        return jsonify({'status': 'error', 'message': 'Reason required for unranking.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.ManageBeatmaps):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    item = await glob.db.fetch("SELECT * FROM beatmap_work_items WHERE id = %s", [item_id])
    if not item:
        return jsonify({'status': 'error', 'message': 'Work item not found.'}), 404

    set_id = item['set_id']  # ty:ignore[invalid-argument-type]

    # Validate all map_ids belong to this set
    all_diffs = await glob.db.fetchall(
        "SELECT id, version, artist, title, set_id FROM maps WHERE set_id = %s",
        [set_id]
    )
    all_diff_ids = {d['id'] for d in (all_diffs or [])}  # ty:ignore[invalid-argument-type, not-subscriptable]
    for mid in map_ids:
        if int(mid) not in all_diff_ids:
            return jsonify({
                'status': 'error',
                'message': f'Map ID {mid} does not belong to this set.'
            }), 400

    new_status = STATUS_MAP[action]
    ACTION_TEXT = {
        'rank': 'Ranked', 'approve': 'Approved', 'qualify': 'Qualified',
        'love': 'Loved', 'unrank': 'Unranked',
    }

    # Efficient path: if ALL diffs selected, use set_id API call
    # Note: kawata.py always needs a valid map_id for its bmap lookup,
    # even when using set_id, so we pass the first diff's id too.
    if {int(m) for m in map_ids} == all_diff_ids:
        first_id = int(map_ids[0])
        result = await _update_map_status(map_id=first_id, set_id=set_id, new_status=new_status)
        if result.get('status') not in ('success',):
            return jsonify({'status': 'error', 'message': result.get('status') or result.get('message', 'API call failed.')}), 502
    else:
        for mid in map_ids:
            result = await _update_map_status(map_id=int(mid), new_status=new_status)
            if result.get('status') not in ('success',):
                return jsonify({'status': 'error', 'message': result.get('status') or result.get('message', 'API call failed.')}), 502

    # Insert into newly_ranked for non-unrank actions
    if action != 'unrank':
        for mid in map_ids:
            try:
                await glob.db.execute(
                    "INSERT IGNORE INTO newly_ranked (map_id, mod_id, time) "
                    "VALUES (%s, %s, %s)",
                    [int(mid), mod_id, datetime.datetime.now()]
                )
            except Exception:
                pass

    # Log each diff action
    for mid in map_ids:
        diff_row = next((d for d in all_diffs if d['id'] == int(mid)), None)  # ty:ignore[invalid-argument-type, not-subscriptable]
        if diff_row:
            await _log_action(
                mod_id, mod_name, int(mid), action,
                ACTION_TEXT[action],
                reason or f'{ACTION_TEXT[action]} via per-diff review',
                1, map_obj=dict(diff_row)
            )

    # Auto-transition pending → in_review on first status action
    if item['review_state'] == 'pending':  # ty:ignore[invalid-argument-type]
        await glob.db.execute(
            "UPDATE beatmap_work_items SET review_state = 'in_review' WHERE id = %s",
            [item_id]
        )

    # Return refreshed diff list
    refreshed_diffs = await glob.db.fetchall(
        "SELECT id, version, diff, mode, cs, ar, od, hp, bpm, "
        "total_length, max_combo, plays, passes, status "
        "FROM maps WHERE set_id = %s ORDER BY diff ASC",
        [set_id]
    )

    return jsonify({
        'status': 'success',
        'message': f'{ACTION_TEXT[action]} {len(map_ids)} difficulty(ies).',
        'diffs': [dict(d) for d in (refreshed_diffs or [])],  # ty:ignore[no-matching-overload]
        'review_state': 'in_review' if item['review_state'] == 'pending' else item['review_state'],  # ty:ignore[invalid-argument-type]
    })


@hina_admin.route('/api/beatmaps/work-items/<int:item_id>/decide', methods=['POST'])
@error_catcher
@staff_required
async def api_bm_decide(item_id):
    """Resolve a review work item (close it). Does NOT change map statuses.
    Use the set-status endpoint to change diff statuses before resolving."""
    data = await request.get_json()
    action = data.get('action', '')
    reason = (data.get('reason') or '').strip()

    VALID_ACTIONS = ('mark_complete', 'needs_changes', 'dismiss')
    if action not in VALID_ACTIONS:
        return jsonify({'status': 'error', 'message': 'Invalid action.'}), 400

    if action == 'needs_changes' and not reason:
        return jsonify({'status': 'error', 'message': 'Reason required for this action.'}), 400

    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.ManageBeatmaps):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    item = await glob.db.fetch("SELECT * FROM beatmap_work_items WHERE id = %s", [item_id])
    if not item:
        return jsonify({'status': 'error', 'message': 'Work item not found.'}), 404

    set_id = item['set_id']  # ty:ignore[invalid-argument-type]
    map_row = await glob.db.fetch("SELECT * FROM maps WHERE set_id = %s LIMIT 1", [set_id])
    map_id = map_row['id'] if map_row else 0  # ty:ignore[invalid-argument-type]
    map_obj = dict(map_row) if map_row else {}

    # ── Mark Complete ──
    if action == 'mark_complete':
        await glob.db.execute(
            "UPDATE beatmap_work_items "
            "SET review_state = 'done', resolution = 'completed', resolved_at = NOW() "
            "WHERE id = %s",
            [item_id]
        )
        await glob.db.execute(
            "UPDATE map_requests SET active = 0 "
            "WHERE map_id IN (SELECT id FROM maps WHERE set_id = %s)",
            [set_id]
        )
        await _log_action(mod_id, mod_name, map_id, 'mark_complete',
                          'Review completed', reason or 'Completed via review',
                          1, map_obj=map_obj)

    # ── Needs Changes (no map status change) ──
    elif action == 'needs_changes':
        await glob.db.execute(
            "UPDATE beatmap_work_items "
            "SET review_state = 'needs_changes', resolution = 'needs_changes' WHERE id = %s",
            [item_id]
        )
        await glob.db.execute(
            "INSERT INTO beatmap_review_comments (work_item_id, user_id, body) VALUES (%s, %s, %s)",
            [item_id, mod_id, '[Needs Changes] ' + reason]
        )
        await _log_action(mod_id, mod_name, map_id, 'needs_changes',
                          'Requested changes', reason, 1, map_obj=map_obj)

    # ── Dismiss (close without status change) ──
    elif action == 'dismiss':
        await glob.db.execute(
            "UPDATE beatmap_work_items "
            "SET review_state = 'done', resolution = 'dismissed', resolved_at = NOW() WHERE id = %s",
            [item_id]
        )
        await glob.db.execute(
            "UPDATE map_requests SET active = 0 "
            "WHERE map_id IN (SELECT id FROM maps WHERE set_id = %s)",
            [set_id]
        )
        await _log_action(mod_id, mod_name, map_id, 'dismiss',
                          'Request dismissed', reason or 'Dismissed via review',
                          1, map_obj=map_obj)

    return jsonify({'status': 'success', 'message': f'Review resolved: {action}.'})


# ─── Staff Activity Log ──────────────────────────────────────────────

_ACTION_TYPE_LABELS = {0: 'user', 1: 'map', 2: 'badge'}


@hina_admin.route('/api/staff-list')
@error_catcher
@staff_required
async def api_staff_list():
    """Return list of staff members who have logged actions (for filter dropdown)."""
    mod_priv = session['user_data']['priv']
    if not _check_priv(mod_priv, Privileges.ViewPanelLog):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    staff = await glob.db.fetchall(
        "SELECT DISTINCT u.id, u.name FROM users u "
        "INNER JOIN logs l ON u.id = l.from_id "
        "ORDER BY u.name"
    )
    return jsonify({'staff': staff or []})


@hina_admin.route('/api/staff-log')
@error_catcher
@staff_required
async def api_staff_log():
    """Full staff activity log with filtering and pagination."""
    mod_priv = session['user_data']['priv']
    if not _check_priv(mod_priv, Privileges.ViewPanelLog):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    page = max(1, int(request.args.get('page', 1)))
    page_size = min(200, max(1, int(request.args.get('page_size', 50))))
    offset = (page - 1) * page_size

    staff_id = request.args.get('staff_id', '').strip()
    action_type = request.args.get('action_type', '').strip()
    action = request.args.get('action', '').strip()
    from_date = request.args.get('from_date', '').strip()
    to_date = request.args.get('to_date', '').strip()
    search = request.args.get('search', '').strip()

    conditions = []
    params = []

    if staff_id:
        conditions.append("l.from_id = %s")
        params.append(int(staff_id))
    if action_type != '':
        conditions.append("l.action_type = %s")
        params.append(int(action_type))
    if action:
        conditions.append("l.action = %s")
        params.append(action)
    if from_date:
        conditions.append("l.created_at >= %s")
        params.append(from_date)
    if to_date:
        conditions.append("l.created_at <= %s")
        params.append(to_date)
    if search:
        conditions.append("l.msg LIKE %s")
        params.append(f"%{search}%")

    where = ""
    if conditions:
        where = " WHERE " + " AND ".join(conditions)

    # Count
    total_row = await glob.db.fetch(
        "SELECT COUNT(*) as total FROM logs l" + where, params
    )
    total = total_row['total'] if total_row else 0  # ty:ignore[invalid-argument-type]

    # Fetch page
    rows = await glob.db.fetchall(
        "SELECT l.id, l.from_id, l.to_id, l.action, l.action_type, l.msg, l.created_at "
        "FROM logs l" + where +
        " ORDER BY l.created_at DESC LIMIT %s OFFSET %s",
        params + [page_size, offset]
    )

    logs = []
    for row in (rows or []):
        # Resolve staff name
        staff_user = await glob.db.fetch("SELECT name FROM users WHERE id = %s", [row['from_id']])  # ty:ignore[invalid-argument-type, not-subscriptable]
        staff_name = staff_user['name'] if staff_user else str(row['from_id'])  # ty:ignore[invalid-argument-type, not-subscriptable]

        # Resolve target summary based on action_type
        at = row['action_type']  # ty:ignore[invalid-argument-type, not-subscriptable]
        target_summary = ''
        target_set_id = None
        if at == 0:
            target_user = await glob.db.fetch("SELECT name FROM users WHERE id = %s", [row['to_id']])  # ty:ignore[invalid-argument-type, not-subscriptable]
            target_summary = target_user['name'] if target_user else str(row['to_id'])  # ty:ignore[invalid-argument-type, not-subscriptable]
        elif at == 1:
            target_map = await glob.db.fetch(
                "SELECT artist, title, version, set_id FROM maps WHERE id = %s LIMIT 1", [row['to_id']]  # ty:ignore[invalid-argument-type, not-subscriptable]
            )
            if target_map:
                target_summary = f"{target_map['artist']} - {target_map['title']} [{target_map['version']}]"  # ty:ignore[invalid-argument-type]
                target_set_id = target_map['set_id']  # ty:ignore[invalid-argument-type]
            else:
                target_summary = f"Map #{row['to_id']}"  # ty:ignore[invalid-argument-type, not-subscriptable]
        elif at == 2:
            target_badge = await glob.db.fetch("SELECT name FROM badges WHERE id = %s", [row['to_id']])  # ty:ignore[invalid-argument-type, not-subscriptable]
            target_summary = target_badge['name'] if target_badge else f"Badge #{row['to_id']}"  # ty:ignore[invalid-argument-type, not-subscriptable]

        created = row['created_at']  # ty:ignore[invalid-argument-type, not-subscriptable]
        if isinstance(created, datetime.datetime):
            created = int(created.timestamp())

        entry = {
            'id': row['id'],  # ty:ignore[invalid-argument-type, not-subscriptable]
            'staff_id': row['from_id'],  # ty:ignore[invalid-argument-type, not-subscriptable]
            'staff_name': staff_name,
            'action': row['action'],  # ty:ignore[invalid-argument-type, not-subscriptable]
            'action_type': at,
            'target_type': _ACTION_TYPE_LABELS.get(at, 'unknown'),
            'target_id': row['to_id'],  # ty:ignore[invalid-argument-type, not-subscriptable]
            'target_summary': target_summary,
            'msg': row['msg'] or '',  # ty:ignore[invalid-argument-type, not-subscriptable]
            'created_at': created,
        }
        if target_set_id is not None:
            entry['target_set_id'] = target_set_id
        logs.append(entry)

    return jsonify({
        'status': 'success',
        'logs': logs,
        'total': total,
        'page': page,
        'page_size': page_size,
    })


# ─── Manual Beatmap Actions ──────────────────────────────────────────

@hina_admin.route('/api/manual-map-info')
@error_catcher
@staff_required
async def api_manual_map_info():
    """Look up a beatmap set by set_id or map_id for manual actions."""
    mod_priv = session['user_data']['priv']
    if not _check_priv(mod_priv, Privileges.ManageBeatmaps):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    set_id = request.args.get('set_id', '').strip()
    map_id = request.args.get('map_id', '').strip()

    if not set_id and not map_id:
        return jsonify({'status': 'error', 'message': 'set_id or map_id required.'}), 400

    # Resolve set_id from map_id if needed
    if map_id and not set_id:
        row = await glob.db.fetch("SELECT set_id FROM maps WHERE id = %s", [int(map_id)])
        if row:
            set_id = str(row['set_id'])  # ty:ignore[invalid-argument-type]

    # Try local DB first
    diffs = None
    if set_id:
        diffs = await glob.db.fetchall(
            "SELECT id, set_id, artist, title, creator, version, mode, diff, "
            "total_length, cs, ar, od, hp, bpm, max_combo, plays, passes, status "
            "FROM maps WHERE set_id = %s ORDER BY diff ASC",
            [int(set_id)]
        )

    # If not found locally, try to import from osu! via kawata.py
    if not diffs and map_id:
        try:
            url = 'http://bancho:10000/v1/get_map_info'
            headers = {'Host': f'api.{cfg.domain}'}
            async with glob.http.get(url, headers=headers, params={'id': str(map_id)}) as resp:
                api_data = await resp.json(content_type=None)
                if api_data.get('status') == 'success' and api_data.get('map'):
                    imported_set_id = api_data['map'].get('set_id')
                    if imported_set_id:
                        set_id = str(imported_set_id)
                        diffs = await glob.db.fetchall(
                            "SELECT id, set_id, artist, title, creator, version, mode, diff, "
                            "total_length, cs, ar, od, hp, bpm, max_combo, plays, passes, status "
                            "FROM maps WHERE set_id = %s ORDER BY diff ASC",
                            [int(set_id)]
                        )
        except Exception:
            pass

    if not diffs:
        msg = 'No maps found for this set.'
        if not map_id:
            msg += ' Try pasting a full beatmap URL (e.g. https://osu.ppy.sh/beatmapsets/123456#osu/789) to import from osu!'
        return jsonify({'status': 'error', 'message': msg}), 404

    first = diffs[0]
    return jsonify({
        'status': 'success',
        'set_id': int(set_id),
        'artist': first['artist'],  # ty:ignore[invalid-argument-type, not-subscriptable]
        'title': first['title'],  # ty:ignore[invalid-argument-type, not-subscriptable]
        'creator': first['creator'],  # ty:ignore[invalid-argument-type, not-subscriptable]
        'diffs': [dict(d) for d in diffs],  # ty:ignore[no-matching-overload]
    })


@hina_admin.route('/api/manual-map-action', methods=['POST'])
@error_catcher
@staff_required
async def api_manual_map_action():
    """Execute a manual status change on selected diffs of a set."""
    mod_id, mod_name, mod_priv = _get_mod_info()
    if not _check_priv(mod_priv, Privileges.ManageBeatmaps):
        return jsonify({'status': 'error', 'message': 'Insufficient privileges.'}), 403

    data = await request.get_json()
    if not data:
        return jsonify({'status': 'error', 'message': 'No data provided.'}), 400

    set_id = data.get('set_id')
    map_ids = data.get('map_ids', [])
    action = data.get('action', '')
    reason = (data.get('reason') or '').strip()

    STATUS_MAP = {'rank': 2, 'approve': 3, 'qualify': 4, 'love': 5, 'unrank': 0}
    if action not in STATUS_MAP:
        return jsonify({'status': 'error', 'message': 'Invalid action.'}), 400

    if not set_id:
        return jsonify({'status': 'error', 'message': 'set_id required.'}), 400

    if action == 'unrank' and not reason:
        return jsonify({'status': 'error', 'message': 'Reason required for unranking.'}), 400

    # Get all diffs in the set
    all_diffs = await glob.db.fetchall(
        "SELECT id, version, artist, title, set_id FROM maps WHERE set_id = %s",
        [int(set_id)]
    )
    if not all_diffs:
        return jsonify({'status': 'error', 'message': 'No maps found for this set.'}), 404

    all_diff_ids = {d['id'] for d in all_diffs}  # ty:ignore[invalid-argument-type, not-subscriptable]

    # If no map_ids specified, update all diffs
    if not map_ids:
        map_ids = list(all_diff_ids)

    # Validate all map_ids belong to this set
    for mid in map_ids:
        if int(mid) not in all_diff_ids:
            return jsonify({
                'status': 'error',
                'message': f'Map ID {mid} does not belong to set {set_id}.'
            }), 400

    new_status = STATUS_MAP[action]
    ACTION_TEXT = {
        'rank': 'Ranked', 'approve': 'Approved', 'qualify': 'Qualified',
        'love': 'Loved', 'unrank': 'Unranked',
    }

    # If ALL diffs selected, use set_id for efficiency
    if {int(m) for m in map_ids} == all_diff_ids:
        first_id = int(map_ids[0])
        result = await _update_map_status(map_id=first_id, set_id=int(set_id), new_status=new_status)
        if result.get('status') not in ('success',):
            return jsonify({'status': 'error', 'message': result.get('status') or result.get('message', 'API call failed.')}), 502
    else:
        for mid in map_ids:
            result = await _update_map_status(map_id=int(mid), new_status=new_status)
            if result.get('status') not in ('success',):
                return jsonify({'status': 'error', 'message': result.get('status') or result.get('message', 'API call failed.')}), 502

    # Insert into newly_ranked for non-unrank actions
    if action != 'unrank':
        for mid in map_ids:
            try:
                await glob.db.execute(
                    "INSERT IGNORE INTO newly_ranked (map_id, mod_id, time) "
                    "VALUES (%s, %s, %s)",
                    [int(mid), mod_id, datetime.datetime.now()]
                )
            except Exception:
                pass

    # Deactivate related map_requests
    if map_ids:
        placeholders = ', '.join(['%s'] * len(map_ids))
        try:
            await glob.db.execute(
                f"UPDATE map_requests SET active = 0 WHERE map_id IN ({placeholders})",
                [int(m) for m in map_ids]
            )
        except Exception:
            pass

    # Log each diff action
    for mid in map_ids:
        diff_row = next((d for d in all_diffs if d['id'] == int(mid)), None)  # ty:ignore[invalid-argument-type, not-subscriptable]
        if diff_row:
            await _log_action(
                mod_id, mod_name, int(mid), f'manual_{action}',
                ACTION_TEXT[action],
                reason or f'{ACTION_TEXT[action]} via manual action',
                1, map_obj=dict(diff_row)
            )

    return jsonify({
        'status': 'success',
        'message': f'{ACTION_TEXT[action]} {len(map_ids)} difficulty(ies) in set {set_id}.',
        'count': len(map_ids),
    })
