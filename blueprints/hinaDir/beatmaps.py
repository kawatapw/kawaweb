"""hinaDir: Beatmap mirror browser routes."""

from quart import Blueprint, render_template, request, jsonify, g, session

from objects import glob
from objects.utils import klogging, flash

hina_beatmaps = Blueprint('hina_beatmaps', __name__)

HINAI_MIRROR = 'https://mirror.hinamizawa.ai'
# /api/v1/hinai/ path bypasses Cloudflare WAF (rule #8)
HINAI_SEARCH = f'{HINAI_MIRROR}/api/v1/hinai/search'
OSUDIRECT_SEARCH = 'https://osu.direct/api/v2/search'
MIRROR_DOWNLOAD = f'{HINAI_MIRROR}/api/v1/hinai/d'

# Status int → osu.direct v2 string
_STATUS_INT_TO_STR = {-2: 'graveyard', -1: 'wip', 0: 'pending', 1: 'ranked',
                      2: 'approved', 3: 'qualified', 4: 'loved'}


def _cheesegull_to_v2(cg: dict) -> dict:
    """Convert CheeseGull beatmapset to osu.direct v2 format.

    CheeseGull: SetID, Artist, Title, Creator, RankedStatus, HasVideo,
                LastUpdate, ChildrenBeatmaps[{BeatmapID, DiffName, ...}]
    osu.direct v2: id, artist, title, creator, status, video, beatmaps[{id, version, ...}]
    """
    status_str = _STATUS_INT_TO_STR.get(cg.get('RankedStatus', 0), 'pending')
    set_id = cg.get('SetID', 0)

    beatmaps = []
    for b in (cg.get('ChildrenBeatmaps') or []):
        beatmaps.append({
            'id': b.get('BeatmapID', 0),
            'beatmapset_id': set_id,
            'mode': str(b.get('Mode', 0)),
            'mode_int': b.get('Mode', 0),
            'difficulty_rating': b.get('DifficultyRating', 0),
            'version': b.get('DiffName', ''),
            'ar': b.get('AR', 0),
            'cs': b.get('CS', 0),
            'accuracy': b.get('OD', 0),  # template reads diff.accuracy for OD
            'drain': b.get('HP', 0),      # template reads diff.drain for HP
            'od': b.get('OD', 0),
            'hp': b.get('HP', 0),
            'bpm': 0,
            'max_combo': b.get('MaxCombo', 0),
            'total_length': b.get('TotalLength', 0),
            'hit_length': b.get('HitLength', 0),
            'count_circles': 0,
            'count_sliders': 0,
            'count_spinners': 0,
            'playcount': 0,
            'passcount': 0,
            'convert': False,
            'checksum': b.get('FileMD5', ''),
        })

    return {
        'id': set_id,
        'artist': cg.get('Artist', ''),
        'artist_unicode': cg.get('Artist', ''),
        'title': cg.get('Title', ''),
        'title_unicode': cg.get('Title', ''),
        'creator': cg.get('Creator', ''),
        'source': '',
        'tags': '',
        'status': status_str,
        'video': bool(cg.get('HasVideo', 0)),
        'storyboard': False,
        'nsfw': False,
        'bpm': 0,
        'ranked_date': cg.get('LastUpdate', ''),
        'submitted_date': '',
        'last_updated': cg.get('LastUpdate', ''),
        'play_count': 0,
        'favourite_count': 0,
        'preview_url': '',
        'is_scoreable': True,
        'discussion_enabled': False,
        'legacy_thread_url': '',
        'availability': {'download_disabled': False, 'more_information': None},
        'covers': {
            'cover': f'https://assets.ppy.sh/beatmaps/{set_id}/covers/cover.jpg',
            'card': f'https://assets.ppy.sh/beatmaps/{set_id}/covers/card.jpg',
        },
        'beatmaps': beatmaps,
    }


@hina_beatmaps.route('/beatmaps')
async def beatmaps_page():
    if not session or 'authenticated' not in session:
        return await flash('error', 'You must be logged in to access that page.', 'hinaDir/login')
    return await render_template('hinaDir/beatmaps.html', globalNotice=g.globalNotice)


@hina_beatmaps.route('/beatmaps/api/search')
async def beatmaps_search():
    query = request.args.get('query', '', type=str)
    source = request.args.get('source', 'hinai', type=str)

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

    if source == 'hinai':
        return await _search_hinai(query, mode, status, amount, offset)
    else:
        return await _search_osudirect(query, mode, status, amount, offset)


async def _search_hinai(query, mode, status, amount, offset):
    """Search via Hinai mirror /api/v1/hinai/search (CheeseGull format)."""
    params: dict = {'amount': amount, 'offset': offset}
    if query:
        params['query'] = query
    if mode >= 0:
        params['mode'] = mode
    if status not in (-99, -1):
        params['status'] = status

    try:
        async with glob.http.get(HINAI_SEARCH, params=params, timeout=10) as resp:
            if resp.status != 200:
                klogging.log(f"Hinai search returned {resp.status}, falling back to osu.direct",
                             klogging.Ansi.LYELLOW)
                return await _search_osudirect(query, mode, status, amount, offset)

            data = await resp.json()
            if data is None:
                data = []

            # Convert CheeseGull format to osu.direct v2 format
            sets = [_cheesegull_to_v2(s) for s in data]

            return jsonify({
                'status': 'success',
                'sets': sets,
                'download_base': MIRROR_DOWNLOAD,
                'source': 'hinai',
            })
    except Exception as e:
        err_name = type(e).__name__
        klogging.log(f"Hinai search error ({err_name}): {e}, falling back to osu.direct",
                     klogging.Ansi.LYELLOW)
        return await _search_osudirect(query, mode, status, amount, offset)


async def _search_osudirect(query, mode, status, amount, offset):
    """Search via osu.direct /api/v2/search (fallback)."""
    params: dict = {'amount': amount, 'offset': offset, 'status': status}
    if query:
        params['query'] = query
    if mode >= 0:
        params['mode'] = mode

    try:
        async with glob.http.get(OSUDIRECT_SEARCH, params=params, timeout=10) as resp:
            if resp.status != 200:
                return jsonify({
                    'status': 'error',
                    'message': f'osu.direct returned status {resp.status}.',
                }), 502

            data = await resp.json()
            if data is None:
                data = []

            return jsonify({
                'status': 'success',
                'sets': data,
                'download_base': MIRROR_DOWNLOAD,
                'source': 'osu_direct',
            })
    except Exception as e:
        err_name = type(e).__name__
        if 'Timeout' in err_name:
            return jsonify({
                'status': 'error',
                'message': 'Search timed out.',
            }), 504
        raise


@hina_beatmaps.errorhandler(Exception)
async def handle_beatmaps_error(error):
    """Handle unexpected exceptions with JSON response."""
    klogging.log(f"Beatmaps API error: {error}", klogging.Ansi.LRED)
    return jsonify({'status': 'error', 'message': 'An unexpected error occurred.'}), 500
