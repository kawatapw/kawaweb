"""hinaDir: Friends page routes."""

from functools import wraps

from quart import Blueprint, g, jsonify, render_template, request, session

from objects import glob
from objects.utils import error_catcher

hina_friends = Blueprint('hina_friends', __name__)


def login_required(func):
    @wraps(func)
    async def wrapper(*args, **kwargs):
        if not session or 'authenticated' not in session:
            from objects.utils import flash
            return await flash('error', 'You must be logged in to access that page.', 'login')
        return await func(*args, **kwargs)
    return wrapper


@hina_friends.route('/friends')
@error_catcher
@login_required
async def friends():
    return await render_template('friends.html', globalNotice=g.globalNotice)


@hina_friends.route('/friends/leaderboard')
@error_catcher
@login_required
async def friends_leaderboard():
    return await render_template('friends_leaderboard.html', globalNotice=g.globalNotice)


@hina_friends.route('/friends/<action>', methods=['POST'])
@error_catcher
@login_required
async def friends_action(action):
    valid_actions = {
        'add': 'add_friend',
        'remove': 'remove_friend',
        'block': 'block',
        'unblock': 'unblock',
    }
    if action not in valid_actions:
        return jsonify({'status': 'Invalid action.'}), 400

    form = await request.form
    target_id = form.get('target_id', type=int)
    if not target_id:
        return jsonify({'status': 'Missing target_id.'}), 400

    user_id = session['user_data']['id']

    async with glob.http.post(
        'http://bancho:10000/v1/set_relationship',
        params={
            'id': str(user_id),
            'target': str(target_id),
            'action': valid_actions[action],
        },
        headers={
            'Authorization': f'Bearer {glob.config.api_key}',
            'Host': f'api.{glob.config.domain}',
        },
    ) as resp:
        data = await resp.json()
        return jsonify(data), resp.status
