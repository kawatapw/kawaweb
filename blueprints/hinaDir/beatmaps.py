"""hinaDir: Beatmap mirror browser routes + Hinai mirror proxy.

All rich mirror endpoints are proxied through this backend so the frontend
JS never exposes mirror.hinamizawa.ai/v3/ URLs directly.  Only the health
check (/health) stays client-side for the status indicator.
"""

from quart import Blueprint, render_template, request, jsonify, g, session, Response

from objects import glob
from objects.utils import klogging, flash

hina_beatmaps = Blueprint('hina_beatmaps', __name__)

HINAI_MIRROR = 'https://mirror.hinamizawa.ai'
# /api/v1/hinai/ path bypasses Cloudflare WAF (rule #8)
HINAI_SEARCH_V1 = f'{HINAI_MIRROR}/api/v1/hinai/search'
HINAI_SEARCH_V2 = f'{HINAI_MIRROR}/v3/osu/beatmaps/search/v2/'
HINAI_DETAIL = f'{HINAI_MIRROR}/v3/osu/beatmaps/s'
HINAI_PP_CALC = f'{HINAI_MIRROR}/v3/osu/pp-calc'
HINAI_AUDIO = f'{HINAI_MIRROR}/v3/osu/music/audio'
OSUDIRECT_SEARCH = 'https://osu.direct/api/v2/search'
MIRROR_DOWNLOAD = f'{HINAI_MIRROR}/api/v1/hinai/d'

# Mirror is fully public — no auth headers needed.
_MIRROR_HEADERS = {}

# Status int → osu.direct v2 string (for v2 search endpoint)
_STATUS_INT_TO_STR = {-2: 'graveyard', -1: 'wip', 0: 'pending', 1: 'ranked',
                      2: 'approved', 3: 'qualified', 4: 'loved'}

# Mode int → mode string (for v2 search endpoint)
_MODE_INT_TO_STR = {0: 'osu', 1: 'taiko', 2: 'fruits', 3: 'mania'}


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


# ── Page route ──

@hina_beatmaps.route('/beatmaps')
async def beatmaps_page():
    if not session or 'authenticated' not in session:
        return await flash('error', 'You must be logged in to access that page.', 'hinaDir/login')
    return await render_template('hinaDir/beatmaps.html', globalNotice=g.globalNotice)


# ── Hero banner endpoint ──

@hina_beatmaps.route('/beatmaps/api/hero')
async def beatmaps_hero():
    """Return 9 most recently ranked beatmapsets for the hero banner."""
    params = {'status': 'ranked', 'sort': 'ranked_desc', 'limit': 9, 'page': 0}

    try:
        async with glob.http.get(HINAI_SEARCH_V2, params=params, headers=_MIRROR_HEADERS, timeout=10) as resp:
            if resp.status != 200:
                return jsonify({'status': 'error', 'sets': []})

            data = await resp.json()
            raw_sets = data.get('beatmapsets', [])[:9]

            hero_sets = []
            for s in raw_sets:
                covers = s.get('covers', {})
                hero_sets.append({
                    'id': s.get('id', 0),
                    'title': s.get('title', ''),
                    'artist': s.get('artist', ''),
                    'creator': s.get('creator', ''),
                    'cover': covers.get('cover', f"https://assets.ppy.sh/beatmaps/{s.get('id', 0)}/covers/cover.jpg"),
                })

            resp_obj = jsonify({
                'status': 'success',
                'sets': hero_sets,
                'total_count': data.get('total_count', 0),
            })
            resp_obj.headers['Cache-Control'] = 'public, max-age=300, s-maxage=600'
            return resp_obj
    except Exception as e:
        klogging.log(f"Hero banner error ({type(e).__name__}): {e}", klogging.Ansi.LYELLOW)
        return jsonify({'status': 'error', 'sets': []})


# ── Search endpoint (supports pagination via v2) ──

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

    # Pagination params (v2 search)
    page = request.args.get('page', 0, type=int)
    page = max(0, page)
    limit = request.args.get('limit', 50, type=int)
    limit = max(1, min(50, limit))

    # Legacy offset/amount for osu.direct fallback
    amount = request.args.get('amount', 30, type=int)
    amount = max(1, min(50, amount))
    offset = request.args.get('offset', 0, type=int)
    offset = max(0, offset)

    sort = request.args.get('sort', 'ranked_desc', type=str)

    if source == 'hinai':
        return await _search_hinai_v2(query, mode, status, page, limit, sort)
    else:
        return await _search_osudirect(query, mode, status, amount, offset)


async def _search_hinai_v2(query, mode, status, page, limit, sort):
    """Search via Hinai mirror v2 endpoint (with pagination metadata)."""
    params: dict = {'limit': limit, 'page': page, 'sort': sort}
    if query:
        params['query'] = query
    if mode >= 0:
        params['mode'] = _MODE_INT_TO_STR.get(mode, 'osu')
    if status not in (-99, -1):
        params['status'] = _STATUS_INT_TO_STR.get(status, 'ranked')

    try:
        async with glob.http.get(HINAI_SEARCH_V2, params=params, headers=_MIRROR_HEADERS, timeout=15) as resp:
            if resp.status != 200:
                klogging.log(f"Hinai v2 search returned {resp.status}, falling back to v1",
                             klogging.Ansi.LYELLOW)
                return await _search_hinai_v1_fallback(query, mode, status, page, limit)

            data = await resp.json()
            if data is None:
                data = {}

            return jsonify({
                'status': 'success',
                'sets': data.get('beatmapsets', []),
                'total_count': data.get('total_count', 0),
                'total_pages': data.get('total_pages', 1),
                'page': data.get('page', page),
                'limit': data.get('limit', limit),
                'download_base': MIRROR_DOWNLOAD,
                'source': 'hinai',
            })
    except Exception as e:
        err_name = type(e).__name__
        klogging.log(f"Hinai v2 search error ({err_name}): {e}, falling back to v1",
                     klogging.Ansi.LYELLOW)
        return await _search_hinai_v1_fallback(query, mode, status, page, limit)


async def _search_hinai_v1_fallback(query, mode, status, page, limit):
    """Fallback: CheeseGull v1 search (no pagination metadata)."""
    offset = page * limit
    params: dict = {'amount': limit, 'offset': offset}
    if query:
        params['query'] = query
    if mode >= 0:
        params['mode'] = mode
    if status not in (-99, -1):
        params['status'] = status

    try:
        async with glob.http.get(HINAI_SEARCH_V1, params=params, headers=_MIRROR_HEADERS, timeout=10) as resp:
            if resp.status != 200:
                klogging.log(f"Hinai v1 search returned {resp.status}, falling back to osu.direct",
                             klogging.Ansi.LYELLOW)
                return await _search_osudirect(query, mode, status, limit, offset)

            data = await resp.json()
            if data is None:
                data = []

            sets = [_cheesegull_to_v2(s) for s in data]

            return jsonify({
                'status': 'success',
                'sets': sets,
                'total_count': 0,
                'total_pages': 1,
                'page': page,
                'limit': limit,
                'download_base': MIRROR_DOWNLOAD,
                'source': 'hinai',
            })
    except Exception as e:
        err_name = type(e).__name__
        klogging.log(f"Hinai v1 search error ({err_name}): {e}, falling back to osu.direct",
                     klogging.Ansi.LYELLOW)
        return await _search_osudirect(query, mode, status, limit, offset)


async def _search_osudirect(query, mode, status, amount, offset):
    """Search via osu.direct /api/v2/search (fallback, no pagination)."""
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
                'total_count': 0,
                'total_pages': 1,
                'page': 0,
                'limit': amount,
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


# ── Detail proxy (beatmapset + pp enrichment) ──

@hina_beatmaps.route('/beatmaps/api/details/<int:set_id>')
async def beatmaps_detail(set_id):
    """Proxy /v3/osu/beatmaps/s/{id}/details?pp_enrichment=true from mirror."""
    url = f'{HINAI_DETAIL}/{set_id}/details'
    params = {'pp_enrichment': 'true'}

    try:
        async with glob.http.get(url, params=params, headers=_MIRROR_HEADERS, timeout=15) as resp:
            if resp.status != 200:
                return jsonify({
                    'status': 'error',
                    'message': f'Mirror returned {resp.status}.',
                }), resp.status if 400 <= resp.status < 600 else 502

            data = await resp.json()
            return jsonify(data)
    except Exception as e:
        err_name = type(e).__name__
        klogging.log(f"Detail proxy error ({err_name}): {e}", klogging.Ansi.LRED)
        if 'Timeout' in err_name:
            return jsonify({'status': 'error', 'message': 'Detail request timed out.'}), 504
        return jsonify({'status': 'error', 'message': 'Failed to fetch details.'}), 502


# ── PP calc proxy ──

@hina_beatmaps.route('/beatmaps/api/pp-calc/<int:beatmap_id>')
async def beatmaps_pp_calc(beatmap_id):
    """Proxy /v3/osu/pp-calc/{id} from mirror with accuracy/mods params."""
    url = f'{HINAI_PP_CALC}/{beatmap_id}'
    params: dict = {}

    accuracy = request.args.get('accuracy', type=float)
    if accuracy is not None:
        params['accuracy'] = accuracy

    mods = request.args.get('mods', type=str)
    if mods is not None:
        params['mods'] = mods

    try:
        async with glob.http.get(url, params=params, headers=_MIRROR_HEADERS, timeout=10) as resp:
            if resp.status != 200:
                return jsonify({
                    'status': 'error',
                    'message': f'PP calc returned {resp.status}.',
                }), resp.status if 400 <= resp.status < 600 else 502

            data = await resp.json()
            return jsonify(data)
    except Exception as e:
        err_name = type(e).__name__
        klogging.log(f"PP calc proxy error ({err_name}): {e}", klogging.Ansi.LRED)
        if 'Timeout' in err_name:
            return jsonify({'status': 'error', 'message': 'PP calc timed out.'}), 504
        return jsonify({'status': 'error', 'message': 'PP calc failed.'}), 502


# ── Audio stream proxy ──

@hina_beatmaps.route('/beatmaps/api/audio/<int:set_id>')
async def beatmaps_audio(set_id):
    """Proxy /v3/osu/music/audio/{id} from mirror, forwarding Range headers."""
    url = f'{HINAI_AUDIO}/{set_id}'

    # Forward Range header for seeking support + mirror auth
    headers: dict = dict(_MIRROR_HEADERS)
    range_header = request.headers.get('Range')
    if range_header:
        headers['Range'] = range_header

    try:
        async with glob.http.get(url, headers=headers, timeout=30) as resp:
            if resp.status not in (200, 206):
                return Response(
                    'Audio not available',
                    status=resp.status if 400 <= resp.status < 600 else 502,
                )

            body = await resp.read()

            # Build response with same status (200 or 206)
            proxy_headers = {}
            for h in ('Content-Type', 'Content-Length', 'Content-Range',
                      'Accept-Ranges', 'Cache-Control'):
                val = resp.headers.get(h)
                if val:
                    proxy_headers[h] = val

            return Response(body, status=resp.status, headers=proxy_headers)
    except Exception as e:
        err_name = type(e).__name__
        klogging.log(f"Audio proxy error ({err_name}): {e}", klogging.Ansi.LRED)
        return Response('Audio stream failed', status=502)


# ── Error handler ──

@hina_beatmaps.errorhandler(Exception)
async def handle_beatmaps_error(error):
    """Handle unexpected exceptions with JSON response."""
    klogging.log(f"Beatmaps API error: {error}", klogging.Ansi.LRED)
    return jsonify({'status': 'error', 'message': 'An unexpected error occurred.'}), 500
