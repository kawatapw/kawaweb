"""hinaDir: Staff Team page route."""

from datetime import datetime

from quart import Blueprint, render_template, g

from objects import glob
from objects.utils import error_catcher

hina_team = Blueprint('hina_team', __name__)

# Display order + distinguishing privilege flag for known staff groups.
# Processed in this order so users land in their highest role.
# Groups in the DB that aren't listed here are picked up dynamically
# using their DB privileges column (works on production with distinct values).
# Values from kawata.py/app/constants/privileges.py.
_KNOWN_ROLES = [
    ('Admin',             65536),        # SendAlerts
    ('Developer',         17179869184),  # DEVELOPER
    ('Moderator',         16),           # ManageUsers
    ('Beatmap Nominator', 256),          # ManageBeatmaps
]
_ROLE_FLAG = {name: flag for name, flag in _KNOWN_ROLES}
_ROLE_ORDER = {name: i for i, (name, _) in enumerate(_KNOWN_ROLES)}

_ROLE_DESC = {
    'Admin':             'Server leadership and full administration.',
    'Developer':         'Building and maintaining the server.',
    'Moderator':         'Community moderation and support.',
    'Beatmap Nominator': 'Beatmap quality assurance and ranking.',
    'Staff':             'General server operations.',
}


def _format_joined(timestamp):
    if not timestamp:
        return 'Unknown'
    return datetime.fromtimestamp(timestamp).strftime('%b %Y')


@hina_team.route('/team')
@error_catcher
async def team_page():
    # 1. Fetch role groups from DB for names + colors
    groups = await glob.db.fetchall(
        "SELECT id, name, privileges, color "
        "FROM privileges_groups "
    )

    # 2. Sort groups: known roles in defined display order, then unknown by DB id
    groups = sorted(
        (groups or []),
        key=lambda g: (_ROLE_ORDER.get(g['name'], 100 + g['id']),),
    )

    # 3. Fetch all staff users (has AccessPanel, is unrestricted, not BanchoBot)
    staff_users = await glob.db.fetchall(
        "SELECT id, name, country, creation_time, latest_activity, priv "
        "FROM users "
        "WHERE priv & 8 != 0 AND priv & 1 != 0 AND id > 1 "
        "ORDER BY name"
    )

    # 4. Classify each user into their highest matching group.
    #    Use _ROLE_FLAG for known groups (handles seed data where DB values
    #    aren't distinct). Unknown groups use their DB privileges column.
    assigned = set()
    team_groups = []
    for group in groups:
        flag = _ROLE_FLAG.get(group['name'], group['privileges'])
        if flag < 8:
            continue  # skip non-staff groups (Player=3, Supporter=7)

        members = []
        for user in (staff_users or []):
            if user['id'] not in assigned and (user['priv'] & flag):
                members.append({
                    **user,
                    'joined': _format_joined(user['creation_time']),
                })
                assigned.add(user['id'])
        if members:
            team_groups.append({
                'name': group['name'],
                'color': group['color'],
                'desc': _ROLE_DESC.get(group['name'], ''),
                'slug': group['name'].lower().replace(' ', '-'),
                'members': members,
            })

    # 4. Fallback for unassigned staff (have AccessPanel but no named group match)
    unassigned = [
        {
            **u,
            'joined': _format_joined(u['creation_time']),
        }
        for u in (staff_users or []) if u['id'] not in assigned
    ]
    if unassigned:
        team_groups.append({
            'name': 'Staff',
            'color': '#808080',
            'desc': _ROLE_DESC.get('Staff', ''),
            'slug': 'staff',
            'members': unassigned,
        })

    total = len(staff_users or [])

    return await render_template(
        'hinaDir/team.html',
        team_groups=team_groups,
        total_staff=total,
        globalNotice=g.globalNotice,
    )
