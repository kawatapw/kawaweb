"""hinaDir: Beatmap mirror browser routes.
Currently only supports osu!direct.
"""

from functools import wraps

from quart import Blueprint, render_template, request, jsonify, g

from objects import glob

hina_beatmaps = Blueprint('hina_beatmaps', __name__)

MIRROR_SEARCH = 'https://osu.direct/api/v2/search'
MIRROR_DOWNLOAD = 'https://osu.direct/api/d'


def error_catcher(func):
    """JSON-safe error catcher (shared one returns HTML via flash())."""
    @wraps(func)
    async def wrapper(*args, **kwargs):
        try:
            return await func(*args, **kwargs)
        except Exception as e:
            import logging
            logging.getLogger('console.error').error(f"Error in {func.__name__}: {e}")
            return jsonify({'status': 'error', 'message': str(e)}), 500
    return wrapper


@hina_beatmaps.route('/beatmaps')
async def beatmaps_page():
    return await render_template('hinaDir/beatmaps.html', globalNotice=g.globalNotice)


@hina_beatmaps.route('/beatmaps/api/search')
@error_catcher
async def beatmaps_search():
    query = request.args.get('query', '', type=str)

    mode = request.args.get('mode', -1, type=int)
    if mode < -1 or mode > 3:
        return jsonify({'status': 'error', 'message': 'Invalid mode.'}), 400

    status = request.args.get('status', 1, type=int)
    if status < -2 or status > 4:
        return jsonify({'status': 'error', 'message': 'Invalid status.'}), 400

    amount = request.args.get('amount', 30, type=int)
    amount = max(1, min(50, amount))

    offset = request.args.get('offset', 0, type=int)
    offset = max(0, offset)

    params = {
        'amount': amount,
        'offset': offset,
        'status': status,
    }
    if query:
        params['query'] = query
    if mode >= 0:
        params['mode'] = mode

    try:
        async with glob.http.get(MIRROR_SEARCH, params=params, timeout=10) as resp:
            if resp.status != 200:
                return jsonify({
                    'status': 'error',
                    'message': f'Mirror returned status {resp.status}.',
                }), 502

            data = await resp.json()
            if data is None:
                data = []

            return jsonify({
                'status': 'success',
                'sets': data,
                'download_base': MIRROR_DOWNLOAD,
            })
    except Exception as e:
        err_name = type(e).__name__
        if 'Timeout' in err_name:
            return jsonify({
                'status': 'error',
                'message': 'Mirror timed out.',
            }), 504
        raise
