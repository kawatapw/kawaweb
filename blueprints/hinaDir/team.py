"""hinaDir: Staff Team page route."""

import time

from quart import Blueprint, render_template, g

from objects import glob
from objects.utils import error_catcher

hina_team = Blueprint('hina_team', __name__)

# ── Team page structure matching production roles ─────────────────────
# Each section can have one or more sub-groups. Users can appear in
# multiple groups (no exclusivity) — matches production behavior.
# Privilege flags from kawata.py/app/constants/privileges.py.

_TEAM_LAYOUT = [
    {
        'title': 'Owners',
        'slug': 'owners',
        'desc': (
            'They created Kawata, they are the ones who run the server '
            'and manage many things.'
        ),
        'groups': [
            {'db_name': 'Owner', 'flag': 17179869184, 'fallback_color': '#FF69B4'},
        ],
    },
    {
        'title': 'Developers',
        'slug': 'developers',
        'desc': (
            'Developers add new features to the server, squash bugs, '
            'keep the server up and running and take care of its '
            'maintenance. Without them, the server wouldn\'t be running at all!'
        ),
        'groups': [
            {'db_name': 'Developer', 'flag': 17179869184, 'fallback_color': '#8A2BE2'},
        ],
    },
    {
        'title': 'Administrators and Community Managers',
        'slug': 'admin-cm',
        'desc': (
            'Our Community Managers are here to take care of our social '
            'networks. Our Administrators manage the chat, and the game, '
            'making sure the rules are respected, they are in charge of '
            'the Moderator.'
        ),
        'groups': [
            {'db_name': 'Administrator', 'flag': 65536, 'fallback_color': '#FF4444'},
            {'db_name': 'Community Manager', 'flag': 131072, 'fallback_color': '#3498DB'},
        ],
    },
    {
        'title': 'Gestion and Support Team',
        'slug': 'gestion-support',
        'desc': (
            'Our Gestion Team manages the staff team with the help of '
            'the Administration team, they are also part of the Support '
            'team. Our Support Team manage the chat, and the game, making '
            'sure the rules are respected, and take action if necessary.'
        ),
        'groups': [
            {'db_name': 'Gestion Team', 'flag': 8192, 'fallback_color': '#9B59B6'},
            {'db_name': 'Support Team', 'flag': 32, 'fallback_color': '#2ECC71'},
        ],
    },
    {
        'title': 'BATs',
        'slug': 'bats',
        'desc': (
            'BATs play beatmaps in the ranking queue and decide whether '
            'they are good enough to be ranked or not.'
        ),
        'groups': [
            {'db_name': 'BAT', 'flag': 256, 'fallback_color': '#F39C12'},
        ],
    },
]


def _time_ago(ts):
    """Format a unix timestamp as relative time (e.g. '4 years ago')."""
    if not ts:
        return 'Unknown'
    diff = int(time.time()) - ts
    if diff < 60:
        return 'just now'
    if diff < 3600:
        n = diff // 60
        return f'{n} minute{"s" if n != 1 else ""} ago'
    if diff < 86400:
        n = diff // 3600
        return f'about {n} hour{"s" if n != 1 else ""} ago'
    if diff < 2592000:
        n = diff // 86400
        return f'{n} day{"s" if n != 1 else ""} ago'
    if diff < 31536000:
        n = diff // 2592000
        return f'{n} month{"s" if n != 1 else ""} ago'
    n = diff // 31536000
    return f'{n} year{"s" if n != 1 else ""} ago'


@hina_team.route('/team')
@error_catcher
async def team_page():
    # 1. Fetch color map from privileges_groups
    db_groups = await glob.db.fetchall(
        "SELECT name, color FROM privileges_groups"
    )
    color_map = {g['name']: g['color'] for g in (db_groups or [])}

    # 2. Fetch all staff users (AccessPanel + UNRESTRICTED, not BanchoBot)
    staff_users = await glob.db.fetchall(
        "SELECT id, name, country, creation_time, latest_activity, priv "
        "FROM users "
        "WHERE priv & 8 != 0 AND priv & 1 != 0 AND id > 1 "
        "ORDER BY name"
    )

    # 3. Build sections — users can appear in multiple groups
    team_sections = []
    seen_ids = set()

    for layout in _TEAM_LAYOUT:
        section_groups = []
        for grp in layout['groups']:
            members = []
            for user in (staff_users or []):
                if user['priv'] & grp['flag']:
                    members.append({
                        **user,
                        'joined_ago': _time_ago(user['creation_time']),
                        'active_ago': _time_ago(user['latest_activity']),
                    })
                    seen_ids.add(user['id'])
            section_groups.append({
                'name': grp['db_name'],
                'color': color_map.get(grp['db_name'], grp['fallback_color']),
                'members': members,
            })

        has_members = any(g['members'] for g in section_groups)
        if has_members:
            team_sections.append({
                'title': layout['title'],
                'slug': layout['slug'],
                'desc': layout['desc'],
                'groups': section_groups,
                'is_multi': len(layout['groups']) > 1,
                'color': section_groups[0]['color'],
            })

    total = len(seen_ids)

    return await render_template(
        'hinaDir/team.html',
        team_sections=team_sections,
        total_staff=total,
        globalNotice=g.globalNotice,
    )
