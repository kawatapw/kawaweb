# API Blueprint for KawaWeb
# Handles API endpoints for leaderboards, player info, etc.

from quart import Blueprint, jsonify, request
from objects import glob
import traceback

api = Blueprint("api", __name__)

# Helper function to get mode integer from string
def get_mode_int(mode_str):
    mode_map = {
        'std': 0, 'vn': 0, 'osu': 0,
        'taiko': 1, 
        'catch': 2, 'ctb': 2,
        'mania': 3,
        'rx': 4, 'relax': 4,
        'rx!taiko': 5,
        'rx!catch': 6,
        'ap': 8, 'autopilot': 8
    }
    return mode_map.get(mode_str, 0)

@api.route("/v1/get_leaderboard")
async def get_leaderboard():
    """API endpoint to get leaderboard data"""
    try:
        # Get query parameters
        mode = int(request.args.get('mode', 0))
        sort = request.args.get('sort', 'pp')  # 'pp' or 'rscore'
        offset = int(request.args.get('offset', 0))
        limit = int(request.args.get('limit', 50))
        
        # Validate parameters
        if sort not in ['pp', 'rscore', 'tscore', 'acc', 'plays']:
            sort = 'pp'
        
        if limit > 100:
            limit = 100
            
        # Build query
        query = f"""
            SELECT 
                u.id as player_id,
                u.name as player_name,
                u.country,
                s.{sort} as sort_value,
                s.pp,
                s.rscore,
                s.tscore,
                s.acc,
                s.plays,
                s.playtime,
                s.max_combo,
                s.xh_count,
                s.x_count,
                s.sh_count,
                s.s_count,
                s.a_count
            FROM stats s
            INNER JOIN users u ON s.id = u.id
            WHERE s.mode = %s
            ORDER BY s.{sort} DESC
            LIMIT %s OFFSET %s
        """
        
        # Execute query
        async with glob.db.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute(query, (mode, limit, offset))
                rows = await cursor.fetchall()
                
                # Get total count for pagination
                await cursor.execute("SELECT COUNT(*) FROM stats WHERE mode = %s", (mode,))
                total_count = (await cursor.fetchone())[0]
        
        # Format response
        leaderboard = []
        for idx, row in enumerate(rows):
            leaderboard.append({
                'rank': offset + idx + 1,
                'player_id': row[0],
                'player_name': row[1],
                'country': row[2],
                'sort_value': float(row[3]) if row[3] else 0,
                'pp': int(row[4]) if row[4] else 0,
                'rscore': int(row[5]) if row[5] else 0,
                'tscore': int(row[6]) if row[6] else 0,
                'acc': float(row[7]) if row[7] else 0,
                'plays': int(row[8]) if row[8] else 0,
                'playtime': int(row[9]) if row[9] else 0,
                'max_combo': int(row[10]) if row[10] else 0,
                'xh_count': int(row[11]) if row[11] else 0,
                'x_count': int(row[12]) if row[12] else 0,
                'sh_count': int(row[13]) if row[13] else 0,
                's_count': int(row[14]) if row[14] else 0,
                'a_count': int(row[15]) if row[15] else 0
            })
        
        return jsonify({
            'status': 'success',
            'leaderboard': leaderboard,
            'total': total_count,
            'offset': offset,
            'limit': limit
        }), 200, {
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Methods': 'GET, OPTIONS',
            'Access-Control-Allow-Headers': 'Content-Type'
        }
        
    except Exception as e:
        print(f"Error in get_leaderboard: {e}")
        traceback.print_exc()
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500, {
            'Access-Control-Allow-Origin': '*'
        }

@api.route("/v1/get_player_count")
async def get_player_count():
    """Get total registered player count"""
    try:
        async with glob.db.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                await cursor.execute("SELECT COUNT(*) FROM users WHERE id > 1")
                count = (await cursor.fetchone())[0]
                
        return jsonify({
            'status': 'success',
            'count': count
        }), 200, {
            'Access-Control-Allow-Origin': '*'
        }
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500, {
            'Access-Control-Allow-Origin': '*'
        }

@api.route("/v1/get_player_info")
async def get_player_info():
    """Get player information"""
    try:
        player_id = request.args.get('id')
        scope = request.args.get('scope', 'stats')
        
        if not player_id:
            return jsonify({'status': 'error', 'message': 'Player ID required'}), 400
            
        async with glob.db.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                # Get user info
                await cursor.execute("""
                    SELECT id, name, country, priv, creation_time, latest_activity
                    FROM users WHERE id = %s
                """, (player_id,))
                user = await cursor.fetchone()
                
                if not user:
                    return jsonify({'status': 'error', 'message': 'Player not found'}), 404
                
                # Get stats for all modes
                await cursor.execute("""
                    SELECT mode, pp, rscore, tscore, acc, plays, playtime, max_combo,
                           xh_count, x_count, sh_count, s_count, a_count
                    FROM stats WHERE id = %s
                """, (player_id,))
                stats = await cursor.fetchall()
                
                stats_dict = {}
                for stat in stats:
                    mode = stat[0]
                    pp_value = int(stat[1]) if stat[1] else 0
                    
                    # Calculate rank for this mode
                    await cursor.execute("""
                        SELECT COUNT(*) + 1 FROM stats 
                        WHERE mode = %s AND pp > %s
                    """, (mode, pp_value))
                    rank = (await cursor.fetchone())[0]
                    
                    stats_dict[mode] = {
                        'pp': pp_value,
                        'rscore': int(stat[2]) if stat[2] else 0,
                        'tscore': int(stat[3]) if stat[3] else 0,
                        'acc': float(stat[4]) if stat[4] else 0,
                        'plays': int(stat[5]) if stat[5] else 0,
                        'playtime': int(stat[6]) if stat[6] else 0,
                        'max_combo': int(stat[7]) if stat[7] else 0,
                        'xh_count': int(stat[8]) if stat[8] else 0,
                        'x_count': int(stat[9]) if stat[9] else 0,
                        'sh_count': int(stat[10]) if stat[10] else 0,
                        's_count': int(stat[11]) if stat[11] else 0,
                        'a_count': int(stat[12]) if stat[12] else 0,
                        'rank': rank
                    }
                
                return jsonify({
                    'status': 'success',
                    'player': {
                        'id': user[0],
                        'name': user[1],
                        'country': user[2],
                        'priv': user[3],
                        'creation_time': user[4],
                        'latest_activity': user[5],
                        'stats': stats_dict
                    }
                }), 200, {
                    'Access-Control-Allow-Origin': '*'
                }
                
    except Exception as e:
        print(f"Error in get_player_info: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500, {
            'Access-Control-Allow-Origin': '*'
        }

@api.route("/v1/get_player_scores")
async def get_player_scores():
    """Get player's recent scores"""
    try:
        player_id = request.args.get('id')
        mode = int(request.args.get('mode', 0))
        scope = request.args.get('scope', 'recent')
        limit = min(int(request.args.get('limit', 50)), 100)
        
        if not player_id:
            return jsonify({'status': 'error', 'message': 'Player ID required'}), 400
        
        async with glob.db.pool.acquire() as conn:
            async with conn.cursor() as cursor:
                # Get scores based on scope
                if scope == 'best':
                    order_by = 'pp DESC'
                else:  # recent
                    order_by = 'play_time DESC'
                
                query = f"""
                    SELECT 
                        s.id, s.map_md5, s.score, s.pp, s.acc,
                        s.max_combo, s.mods, s.n300, s.n100, s.n50,
                        s.nmiss, s.grade, s.play_time,
                        'Unknown Map' as map_name,
                        'Unknown Artist' as artist,
                        'Unknown' as version
                    FROM scores s
                    WHERE s.userid = %s AND s.mode = %s
                    ORDER BY {order_by}
                    LIMIT %s
                """
                
                await cursor.execute(query, (player_id, mode, limit))
                scores = await cursor.fetchall()
                
                scores_list = []
                for score in scores:
                    scores_list.append({
                        'id': score[0],
                        'map_md5': score[1],
                        'score': int(score[2]),
                        'pp': float(score[3]) if score[3] else 0,
                        'acc': float(score[4]) if score[4] else 0,
                        'max_combo': int(score[5]),
                        'mods': int(score[6]),
                        'n300': int(score[7]),
                        'n100': int(score[8]),
                        'n50': int(score[9]),
                        'nmiss': int(score[10]),
                        'grade': score[11],
                        'play_time': score[12].isoformat() if score[12] else None,
                        'map_name': score[13],
                        'artist': score[14],
                        'version': score[15]
                    })
                
                return jsonify({
                    'status': 'success',
                    'scores': scores_list
                }), 200, {
                    'Access-Control-Allow-Origin': '*'
                }
                
    except Exception as e:
        print(f"Error in get_player_scores: {e}")
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500, {
            'Access-Control-Allow-Origin': '*'
        }

@api.route("/v1/get_player_most_played")
async def get_player_most_played():
    """Get player's most played beatmaps"""
    try:
        player_id = request.args.get('id')
        mode = int(request.args.get('mode', 0))
        limit = min(int(request.args.get('limit', 10)), 100)
        
        if not player_id:
            return jsonify({'status': 'error', 'message': 'Player ID required'}), 400
        
        # For now, return mock data since we don't have a plays table
        most_played = [
            {
                'map_id': i,
                'map_name': f'Popular Map {i}',
                'artist': f'Artist {i}',
                'plays': 100 - i * 10
            }
            for i in range(1, min(limit + 1, 6))
        ]
        
        return jsonify({
            'status': 'success',
            'maps': most_played
        }), 200, {
            'Access-Control-Allow-Origin': '*'
        }
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500, {
            'Access-Control-Allow-Origin': '*'
        }

@api.route("/v1/get_player_status")
async def get_player_status():
    """Get player's current status"""
    try:
        player_id = request.args.get('id')
        
        if not player_id:
            return jsonify({'status': 'error', 'message': 'Player ID required'}), 400
        
        # Return online status (mock for now)
        return jsonify({
            'status': 'success',
            'player_status': {
                'online': False,
                'last_seen': 'Recently',
                'action': 'Idle'
            }
        }), 200, {
            'Access-Control-Allow-Origin': '*'
        }
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500, {
            'Access-Control-Allow-Origin': '*'
        }

# Add OPTIONS handler for CORS preflight
@api.route("/v1/<path:path>", methods=['OPTIONS'])
async def handle_options(path):
    return '', 200, {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type'
    }