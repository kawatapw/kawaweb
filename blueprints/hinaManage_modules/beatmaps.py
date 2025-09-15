# -*- coding: utf-8 -*-

"""
Beatmaps Module for HinaManage
Handles beatmap-related functionality with dual API support (osu! v2 + catboy)
"""

__all__ = ('get_hello_world', 'search_beatmaps', 'download_beatmap', 'get_beatmapset', 'normalize_beatmapset_data')

import aiohttp
from typing import Dict, List, Optional, Any
from objects import glob
from objects.utils import klogging
from .osu_api_v2 import osu_api


async def get_hello_world() -> Dict[str, str]:
    """
    Hello world function to test backend connectivity
    
    Returns:
        Dict containing hello world message and status
    """
    return {
        "status": "success",
        "message": "Hello World from HinaManage Beatmaps Module!",
        "module": "beatmaps",
        "version": "1.0.0"
    }


def normalize_beatmapset_data(beatmapset: Dict[str, Any], source: str = 'osu') -> Dict[str, Any]:
    """
    Normalize beatmapset data across different API sources
    Ensures consistent data structure regardless of source

    Args:
        beatmapset: Raw beatmapset data from API
        source: Source API ('osu' or 'catboy')

    Returns:
        Normalized beatmapset data
    """
    try:
        if source == 'osu':
            # osu! API v2 format
            if 'user' not in beatmapset or not beatmapset['user']:
                # Create user object from user_id and creator fields
                if 'user_id' in beatmapset and 'creator' in beatmapset:
                    beatmapset['user'] = {
                        'id': beatmapset['user_id'],
                        'username': beatmapset['creator'],
                        'avatar_url': f"https://a.ppy.sh/{beatmapset['user_id']}"
                    }
            elif 'user' in beatmapset and beatmapset['user']:
                # Ensure avatar_url is present
                user = beatmapset['user']
                if 'avatar_url' not in user and 'id' in user:
                    user['avatar_url'] = f"https://a.ppy.sh/{user['id']}"
        else:
            # Catboy mirror format
            if 'creator' in beatmapset and 'user' not in beatmapset:
                # Create user object for catboy data
                beatmapset['user'] = {
                    'username': beatmapset.get('creator', 'Unknown'),
                    'id': beatmapset.get('user_id', 0)
                }
                if beatmapset.get('user_id'):
                    beatmapset['user']['avatar_url'] = f"https://a.ppy.sh/{beatmapset['user_id']}"
            elif 'user' in beatmapset and beatmapset['user']:
                # Ensure avatar_url for catboy user object
                user = beatmapset['user']
                if 'avatar_url' not in user and 'id' in user:
                    user['avatar_url'] = f"https://a.ppy.sh/{user['id']}"

        # Ensure beatmapset_id field exists
        if 'beatmapset_id' not in beatmapset and 'id' in beatmapset:
            beatmapset['beatmapset_id'] = beatmapset['id']

        return beatmapset

    except Exception as e:
        klogging.log(f"Error normalizing beatmapset data: {e}", klogging.Ansi.LRED)
        return beatmapset


async def search_beatmaps(query: str, limit: int = 50, **kwargs) -> Dict[str, Any]:
    """
    Search for beatmaps using osu! official API v2

    Args:
        query: Search query string
        limit: Maximum number of results to return
        **kwargs: Additional search parameters

    Returns:
        Dict containing search results or error message
    """
    try:
        results = []
        total = 0
        cursor = None

        # Use osu! API v2
        async with osu_api as api:
            osu_result = await api.search_beatmapsets(
                query=query,
                **kwargs
            )

            if osu_result and 'beatmapsets' in osu_result:
                results = osu_result['beatmapsets']
                total = osu_result.get('total', len(results))
                cursor = osu_result.get('cursor_string')

                # Normalize data
                for beatmapset in results:
                    normalize_beatmapset_data(beatmapset, source='osu')

                # Limit results
                if limit and len(results) > limit:
                    results = results[:limit]

                return {
                    "success": True,
                    "status": "success",
                    "source": "osu",
                    "data": results,
                    "count": len(results),
                    "total": total,
                    "cursor": cursor
                }
            else:
                # API failed
                return {
                    "success": False,
                    "status": "error",
                    "message": "osu! API is currently unavailable",
                    "data": [],
                    "count": 0
                }

    except Exception as e:
        klogging.log(f"Error searching beatmaps: {e}", klogging.Ansi.LRED)
        return {
            "success": False,
            "status": "error",
            "message": "Failed to search beatmaps",
            "error": str(e),
            "data": [],
            "count": 0
        }


async def get_beatmapset(beatmapset_id: int) -> Dict[str, Any]:
    """
    Get detailed beatmapset information by ID

    Args:
        beatmapset_id: The beatmapset ID to get info for

    Returns:
        Dict containing beatmapset information
    """
    try:
        async with osu_api as api:
            result = await api.get_beatmapset(beatmapset_id)
            if result:
                normalize_beatmapset_data(result, source='osu')
                return {
                    "success": True,
                    "status": "success",
                    "source": "osu",
                    "data": result
                }

        return {
            "success": False,
            "status": "error",
            "message": f"Beatmapset {beatmapset_id} not found",
            "beatmapset_id": beatmapset_id
        }

    except Exception as e:
        klogging.log(f"Error getting beatmapset {beatmapset_id}: {e}", klogging.Ansi.LRED)
        return {
            "success": False,
            "status": "error",
            "message": "Failed to get beatmapset info",
            "error": str(e)
        }


async def download_beatmap(beatmapset_id: int, no_video: bool = False) -> Dict[str, Any]:
    """
    Get download URL for a beatmapset

    Args:
        beatmapset_id: The beatmapset ID to download
        no_video: Whether to exclude video files

    Returns:
        Dict containing download URL and information
    """
    try:
        # osu! doesn't provide direct download URLs via API
        # Redirect to osu! website for download
        osu_url = f"https://osu.ppy.sh/beatmapsets/{beatmapset_id}/download"
        if no_video:
            osu_url += "?noVideo=1"

        return {
            "success": True,
            "status": "success",
            "source": "osu",
            "download_url": osu_url,
            "beatmapset_id": beatmapset_id,
            "no_video": no_video,
            "requires_login": True,
            "message": "Redirecting to osu! website for download (login required)"
        }

    except Exception as e:
        klogging.log(f"Error getting download for beatmapset {beatmapset_id}: {e}", klogging.Ansi.LRED)
        return {
            "success": False,
            "status": "error",
            "message": "Failed to get download URL",
            "error": str(e)
        }


async def get_beatmap_info(beatmap_id: int) -> Dict:
    """
    Get detailed information about a specific beatmap
    
    Args:
        beatmap_id: The beatmap ID to get info for
        
    Returns:
        Dict containing beatmap information
    """
    try:
        # Placeholder for beatmap info retrieval
        # This will be implemented later with actual API calls
        return {
            "status": "success",
            "message": f"Beatmap info functionality coming soon for ID: {beatmap_id}",
            "beatmap_id": beatmap_id,
            "info": {}
        }
    except Exception as e:
        klogging.log(f"Error getting beatmap info {beatmap_id}: {e}", klogging.Ansi.LRED)
        return {
            "status": "error",
            "message": "Failed to get beatmap info",
            "error": str(e)
        }
