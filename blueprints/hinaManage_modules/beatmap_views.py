"""
Beatmap Mirror Views
Provides API endpoints for beatmap downloads and information
"""

from django.http import JsonResponse, HttpResponseRedirect, HttpResponse
from django.views.decorators.http import require_http_methods
from django.views.decorators.csrf import csrf_exempt
from django.core.cache import cache
from .beatmap_mirror import BeatmapMirrorAPI
from .osu_api_v2 import OsuAPIv2
from .constants import PLACEHOLDER_IMAGE
import json
import requests
import logging

logger = logging.getLogger(__name__)


def normalize_beatmapset_user_data(beatmapset, source='osu'):
    """
    Normalize user data across different API sources
    Ensures consistent user object structure regardless of source
    """
    if source == 'osu':
        # osu! API v2 beatmapset search doesn't include full user object, only user_id and creator
        # We need to construct the user object from available data
        if 'user' not in beatmapset or not beatmapset['user']:
            # Create user object from user_id and creator fields
            if 'user_id' in beatmapset and 'creator' in beatmapset:
                beatmapset['user'] = {
                    'id': beatmapset['user_id'],
                    'username': beatmapset['creator'],
                    'avatar_url': f"https://a.ppy.sh/{beatmapset['user_id']}"
                }
        elif 'user' in beatmapset and beatmapset['user']:
            # If user object exists, ensure avatar_url is present
            user = beatmapset['user']
            if 'avatar_url' not in user and 'id' in user:
                # Construct avatar URL if missing
                user['avatar_url'] = f"https://a.ppy.sh/{user['id']}"
    else:
        # Catboy mirror - need to construct user object from available data
        if 'creator' in beatmapset and not 'user' in beatmapset:
            # Create a basic user object for Catboy data
            beatmapset['user'] = {
                'username': beatmapset.get('creator', 'Unknown'),
                'id': beatmapset.get('user_id', 0)
            }
            # Add avatar URL if user_id exists
            if beatmapset.get('user_id'):
                beatmapset['user']['avatar_url'] = f"https://a.ppy.sh/{beatmapset['user_id']}"
        elif 'user' in beatmapset and beatmapset['user']:
            # Catboy might have user object, ensure avatar_url
            user = beatmapset['user']
            if 'avatar_url' not in user and 'id' in user:
                user['avatar_url'] = f"https://a.ppy.sh/{user['id']}"
    
    return beatmapset


@require_http_methods(["GET"])
def beatmap_info(request, beatmap_id):
    """
    Get beatmap information by ID
    """
    try:
        beatmap_data = BeatmapMirrorAPI.get_beatmap(beatmap_id)
        
        if beatmap_data:
            return JsonResponse({
                'success': True,
                'data': beatmap_data
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Beatmap not found'
            }, status=404)
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def beatmapset_info(request, beatmapset_id):
    """
    Get beatmapset information by ID
    """
    try:
        beatmapset_data = BeatmapMirrorAPI.get_beatmapset(beatmapset_id)
        
        if beatmapset_data:
            return JsonResponse({
                'success': True,
                'data': beatmapset_data
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Beatmapset not found'
            }, status=404)
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def search_beatmaps_v2(request):
    """
    Enhanced beatmap search with dual API support (Official osu! API + Catboy mirror)
    """
    try:
        # Get parameters
        source = request.GET.get('source', 'osu')  # 'osu' or 'catboy'
        query = request.GET.get('q', '')
        status = request.GET.get('status', '')
        mode = request.GET.get('mode', '')
        genre = request.GET.get('genre', '')
        language = request.GET.get('language', '')
        sort = request.GET.get('sort', '')
        limit = int(request.GET.get('limit', 50))
        cursor = request.GET.get('cursor', '')
        
        if source == 'osu':
            # Use official osu! API
            result = OsuAPIv2.search_beatmapsets(
                query=query,
                status=status,
                mode=mode,
                genre=genre,
                language=language,
                sort=sort,
                cursor_string=cursor
            )
            
            if result:
                # Transform osu! API response to match our format
                beatmapsets = result.get('beatmapsets', [])
                
                # Ensure each beatmapset has beatmapset_id for compatibility and normalize user data
                for beatmapset in beatmapsets:
                    if 'beatmapset_id' not in beatmapset and 'id' in beatmapset:
                        beatmapset['beatmapset_id'] = beatmapset['id']
                    # Normalize user data for consistent frontend display
                    normalize_beatmapset_user_data(beatmapset, source='osu')
                
                # Limit results
                if limit and len(beatmapsets) > limit:
                    beatmapsets = beatmapsets[:limit]
                
                return JsonResponse({
                    'success': True,
                    'source': 'osu',
                    'data': beatmapsets,
                    'count': len(beatmapsets),
                    'cursor': result.get('cursor_string'),
                    'total': result.get('total', len(beatmapsets)),
                    'type': 'search'
                })
            else:
                # Fallback to catboy if osu! API fails
                logger.warning("osu! API failed, falling back to catboy mirror")
                source = 'catboy'
        
        if source == 'catboy':
            # Use catboy mirror (existing logic)
            results = BeatmapMirrorAPI.search_beatmaps(query, limit, {})
            
            # Apply client-side filtering for catboy results
            if results is not None and isinstance(results, list):
                filtered_results = []
                
                status_list = [s.strip().lower() for s in status.split(',')] if status else []
                mode_list = [m.strip().lower() for m in mode.split(',')] if mode else []
                
                for beatmap in results:
                    # Status filter
                    if status_list:
                        beatmap_status = beatmap.get('status', '').lower()
                        if beatmap_status not in status_list:
                            continue
                    
                    # Mode filter
                    if mode_list and 'beatmaps' in beatmap:
                        has_mode = False
                        for bm in beatmap.get('beatmaps', []):
                            bm_mode = bm.get('mode', '').lower()
                            if bm_mode in mode_list:
                                has_mode = True
                                break
                        if not has_mode:
                            continue
                    
                    # Genre filter
                    if genre and genre != '0':
                        beatmap_genre = str(beatmap.get('genre_id', '0'))
                        if beatmap_genre != genre:
                            continue
                    
                    # Language filter
                    if language and language != '0':
                        beatmap_language = str(beatmap.get('language_id', '0'))
                        if beatmap_language != language:
                            continue
                    
                    # Normalize user data for Catboy results
                    normalize_beatmapset_user_data(beatmap, source='catboy')
                    filtered_results.append(beatmap)
                    
                    if len(filtered_results) >= limit:
                        break
                
                results = filtered_results
            else:
                # Normalize all results even if no filtering applied
                if results:
                    for beatmap in results:
                        normalize_beatmapset_user_data(beatmap, source='catboy')
            
            return JsonResponse({
                'success': True,
                'source': 'catboy',
                'data': results or [],
                'count': len(results) if results else 0,
                'type': 'search'
            })
        
        return JsonResponse({
            'success': False,
            'error': 'Invalid source specified'
        }, status=400)
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def search_beatmaps(request):
    """
    Search for beatmaps with advanced filtering options
    """
    try:
        # Search parameters
        query = request.GET.get('q', '')
        limit = int(request.GET.get('limit', 50))
        recent_param = request.GET.get('recent', '')
        recent_bool = recent_param.lower() == 'true'
        
        # Filter parameters
        status = request.GET.get('status', '')  # ranked, loved, pending, wip, graveyard, qualified
        mode = request.GET.get('mode', '')  # osu, taiko, fruits, mania
        min_stars = request.GET.get('min_stars', '')
        max_stars = request.GET.get('max_stars', '')
        min_bpm = request.GET.get('min_bpm', '')
        max_bpm = request.GET.get('max_bpm', '')
        min_length = request.GET.get('min_length', '')
        max_length = request.GET.get('max_length', '')
        creator = request.GET.get('creator', '')
        genre = request.GET.get('genre', '')
        language = request.GET.get('language', '')
        
        # Limit to max 100 results
        limit = min(limit, 100)
        
        # Build filter parameters for API
        filters = {}
        if status:
            filters['status'] = status
        if mode:
            filters['mode'] = mode
        if min_stars:
            filters['min_stars'] = min_stars
        if max_stars:
            filters['max_stars'] = max_stars
        if min_bpm:
            filters['min_bpm'] = min_bpm
        if max_bpm:
            filters['max_bpm'] = max_bpm
        if min_length:
            filters['min_length'] = min_length
        if max_length:
            filters['max_length'] = max_length
        if creator:
            filters['creator'] = creator
        if genre:
            filters['genre'] = genre
        if language:
            filters['language'] = language
        
        # Fetch beatmaps from API (API doesn't support filters, so we get all and filter client-side)
        if not query and recent_bool:
            # Get more results to filter from (API limit is often not ranked/loved)
            results = BeatmapMirrorAPI.search_beatmaps('', 200, {})
        else:
            results = BeatmapMirrorAPI.search_beatmaps(query, min(limit * 3, 150), {})
        
        # Apply client-side filtering since the API doesn't support these filters
        if results is not None and isinstance(results, list):
            filtered_results = []
            
            # Note: The catboy.best API mostly returns recent uploads (pending/WIP)
            # Ranked/loved beatmaps are rare in recent uploads
            # Don't apply default filter if no status specified - show all
            
            status_list = [s.strip().lower() for s in status.split(',')] if status else []
            mode_list = [m.strip().lower() for m in mode.split(',')] if mode else []
            
            for beatmap in results:
                # Status filter
                if status_list:
                    beatmap_status = beatmap.get('status', '').lower()
                    if beatmap_status not in status_list:
                        continue
                
                # Mode filter - check beatmaps array for modes
                if mode_list and 'beatmaps' in beatmap:
                    has_mode = False
                    for bm in beatmap.get('beatmaps', []):
                        bm_mode = bm.get('mode', '').lower()
                        if bm_mode in mode_list:
                            has_mode = True
                            break
                    if not has_mode:
                        continue
                
                # Star rating filter - check max difficulty
                if (min_stars or max_stars) and 'beatmaps' in beatmap:
                    max_diff = 0
                    for bm in beatmap.get('beatmaps', []):
                        diff = bm.get('difficulty_rating', 0)
                        if diff > max_diff:
                            max_diff = diff
                    
                    if min_stars and max_diff < float(min_stars):
                        continue
                    if max_stars and max_diff > float(max_stars):
                        continue
                
                # BPM filter
                if min_bpm or max_bpm:
                    bpm = beatmap.get('bpm', 0)
                    if min_bpm and bpm < float(min_bpm):
                        continue
                    if max_bpm and bpm > float(max_bpm):
                        continue
                
                # Length filter (in seconds)
                if min_length or max_length:
                    length = beatmap.get('total_length', 0)
                    if min_length and length < float(min_length):
                        continue
                    if max_length and length > float(max_length):
                        continue
                
                # Creator filter
                if creator:
                    beatmap_creator = beatmap.get('creator', '').lower()
                    if creator.lower() not in beatmap_creator:
                        continue
                
                # Genre filter
                if genre and genre != '0':
                    beatmap_genre = str(beatmap.get('genre_id', '0'))
                    if beatmap_genre != genre:
                        continue
                
                # Language filter  
                if language and language != '0':
                    beatmap_language = str(beatmap.get('language_id', '0'))
                    if beatmap_language != language:
                        continue
                
                # Normalize user data for Catboy results
                normalize_beatmapset_user_data(beatmap, source='catboy')
                filtered_results.append(beatmap)
                
                # Stop when we have enough results
                if len(filtered_results) >= limit:
                    break
            
            results = filtered_results
        else:
            # Normalize all results even if no filtering applied
            if results:
                for beatmap in results:
                    normalize_beatmapset_user_data(beatmap, source='catboy')
        
        if results is not None:
            return JsonResponse({
                'success': True,
                'data': results,
                'count': len(results) if isinstance(results, list) else 0,
                'type': 'recent' if (not query and recent) else 'search',
                'filters': filters
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Search failed'
            }, status=500)
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def get_download_url(request, beatmapset_id):
    """
    Get download URL for a beatmapset
    """
    try:
        no_video = request.GET.get('no_video', '').lower() == 'true'
        
        download_url = BeatmapMirrorAPI.get_download_url(beatmapset_id, no_video)
        
        # Option to redirect directly or return URL
        if request.GET.get('redirect', '').lower() == 'true':
            return HttpResponseRedirect(download_url)
        
        return JsonResponse({
            'success': True,
            'download_url': download_url,
            'beatmapset_id': beatmapset_id,
            'no_video': no_video
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def get_preview_urls(request, beatmapset_id):
    """
    Get preview URLs (audio and background) for a beatmapset
    """
    try:
        beatmap_id = request.GET.get('beatmap_id')
        full_audio = request.GET.get('full_audio', '').lower() == 'true'
        
        audio_url = BeatmapMirrorAPI.get_preview_audio_url(beatmapset_id, full_audio)
        
        if beatmap_id:
            background_url = BeatmapMirrorAPI.get_background_url(beatmapset_id, int(beatmap_id))
        else:
            background_url = BeatmapMirrorAPI.get_background_url(beatmapset_id)
        
        return JsonResponse({
            'success': True,
            'audio_url': audio_url,
            'background_url': background_url,
            'beatmapset_id': beatmapset_id
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def beatmap_by_md5(request, md5_hash):
    """
    Get beatmap information by MD5 hash
    """
    try:
        beatmap_data = BeatmapMirrorAPI.get_beatmap_by_md5(md5_hash)
        
        if beatmap_data:
            return JsonResponse({
                'success': True,
                'data': beatmap_data
            })
        else:
            return JsonResponse({
                'success': False,
                'error': 'Beatmap not found'
            }, status=404)
            
    except Exception as e:
        return JsonResponse({
            'success': False,
            'error': str(e)
        }, status=500)


@require_http_methods(["GET"])
def proxy_image(request):
    """
    Proxy beatmap cover images to bypass CORS restrictions
    """
    
    image_url = request.GET.get('url')
    
    if not image_url:
        # Return placeholder image instead of JSON error
        return HttpResponse(PLACEHOLDER_IMAGE, content_type='image/png')
    
    # Only allow proxying from ppy.sh domains
    if not ('ppy.sh' in image_url or 'osu.ppy.sh' in image_url):
        # Return placeholder image instead of JSON error
        return HttpResponse(PLACEHOLDER_IMAGE, content_type='image/png')
    
    # Check cache first
    cache_key = f"beatmap_image_{hash(image_url)}"
    cached_image = cache.get(cache_key)
    
    if cached_image:
        return HttpResponse(
            cached_image['content'],
            content_type=cached_image['content_type']
        )
    
    try:
        # Fetch the image with proper headers
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'image/webp,image/apng,image/*,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate, br',
            'Referer': 'https://osu.ppy.sh/',
        }
        
        response = requests.get(image_url, timeout=10, headers=headers)
        
        if response.status_code == 200 and response.content:
            content_type = response.headers.get('Content-Type', 'image/jpeg')
            
            # Verify it's actually an image
            if 'image' in content_type.lower():
                # Cache for 1 hour
                cache.set(cache_key, {
                    'content': response.content,
                    'content_type': content_type
                }, 3600)
                
                return HttpResponse(
                    response.content,
                    content_type=content_type
                )
        
        # If failed, return placeholder
        return HttpResponse(PLACEHOLDER_IMAGE, content_type='image/png')
            
    except requests.RequestException as e:
        # Log the error but return placeholder image
        logger.warning(f"Failed to proxy image {image_url}: {e}")
        return HttpResponse(PLACEHOLDER_IMAGE, content_type='image/png')


@require_http_methods(["GET"])
def mirror_status(request):
    """
    Get beatmap mirror service status
    """
    try:
        # Check if the mirror service is accessible
        response = requests.get(
            "https://catboy.best/api/",
            timeout=5
        )
        
        is_online = response.status_code == 200
        
        return JsonResponse({
            'success': True,
            'service': 'Beatmap Mirror',
            'status': 'online' if is_online else 'offline',
            'mirror_url': 'https://catboy.best',
            'endpoints': {
                'search': '/api/v1/osu/beatmaps/search/',
                'beatmap_info': '/api/v1/osu/beatmaps/b/{beatmap_id}/',
                'beatmapset_info': '/api/v1/osu/beatmaps/s/{beatmapset_id}/',
                'download': '/api/v1/osu/beatmaps/download/{beatmapset_id}/',
                'preview': '/api/v1/osu/beatmaps/preview/{beatmapset_id}/',
                'by_md5': '/api/v1/osu/beatmaps/md5/{md5_hash}/'
            }
        })
        
    except Exception as e:
        return JsonResponse({
            'success': False,
            'service': 'Beatmap Mirror',
            'status': 'error',
            'error': str(e)
        }, status=500)