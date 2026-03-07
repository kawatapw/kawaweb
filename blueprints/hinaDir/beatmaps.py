"""hinaDir: Beatmap mirror browser routes."""

import time
from collections import defaultdict
from functools import wraps

from quart import Blueprint, render_template, request, jsonify, g

from objects import glob
import config as cfg
from objects.utils import klogging, error_catcher

hina_beatmaps = Blueprint('hina_beatmaps', __name__)

MIRROR_SEARCH = 'https://osu.direct/api/v2/search'
MIRROR_DOWNLOAD = 'https://mirror.hinamizawa.ai/api/v1/hinai/d'

# Simple in-memory rate limiter: IP -> list of timestamps
_pp_rate_limits: dict[str, list[float]] = defaultdict(list)
_PP_RATE_WINDOW = 60  # seconds
_PP_RATE_MAX = 10     # requests per window



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


@hina_beatmaps.route('/beatmaps/api/pp-table')
@error_catcher
async def beatmaps_pp_table():
    """Public proxy for batch PP calculation — no auth required, rate-limited."""
    # Simple IP-based rate limiting
    ip = request.remote_addr or 'unknown'
    now = time.time()
    timestamps = _pp_rate_limits[ip]
    # Prune old entries
    _pp_rate_limits[ip] = [t for t in timestamps if now - t < _PP_RATE_WINDOW]
    if len(_pp_rate_limits[ip]) >= _PP_RATE_MAX:
        return jsonify({'status': 'error', 'message': 'Rate limit exceeded. Try again later.'}), 429
    _pp_rate_limits[ip].append(now)

    ids_raw = request.args.get('ids', '')
    mods = request.args.get('mods', '0')

    if not ids_raw:
        return jsonify({'status': 'error', 'message': 'No IDs provided.'}), 400

    # Collect valid IDs
    valid_ids = []
    for bid in ids_raw.split(',')[:20]:
        bid = bid.strip()
        if bid.isdigit():
            valid_ids.append(bid)

    if not valid_ids:
        return jsonify({'status': 'error', 'message': 'No valid IDs provided.'}), 400

    headers = {
        'Host': f'api.{cfg.domain}',
        'Authorization': f'Bearer {glob.config.api_key}',
    }

    # Warm the map cache: call get_map_info with the first diff ID.
    # Beatmap.from_bid fetches the entire set, so one call caches all diffs.
    try:
        klogging.log(f"Warming PP cache for beatmap ID {valid_ids[0]}...", klogging.Ansi.LYELLOW)
        warm_url = f'https://api.{glob.config.domain}/v1/get_map_info?id={valid_ids[0]}'
        async with glob.http.get(warm_url, headers=headers, timeout=15) as resp:
            pass  # We don't need the response, just trigger the cache
    except Exception:
        pass  # Best-effort; calculate_pp_batch will return per-diff errors if needed

    # Build query params: repeat id= for each diff
    params = [('acc', '100'), ('acc', '99'), ('acc', '98'), ('acc', '95')]
    params.append(('mods', mods))
    for bid in valid_ids:
        params.append(('id', bid))

    url = f'https://api.{glob.config.domain}/v1/calculate_pp_batch'
    try:
        async with glob.http.get(url, headers=headers, params=params) as resp:
            data = await resp.json(content_type=None)
            if resp.status != 200:
                return jsonify({'status': 'error', 'message': data.get('status', 'API error')}), resp.status
            return jsonify(data)
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)}), 500
