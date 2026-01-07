# -*- coding: utf-8 -*-

"""
Utilities Module for HinaManage
Common utility functions for beatmap management
"""

__all__ = ('validate_beatmap_id', 'format_beatmap_data', 'get_system_status')

import re
from typing import Dict, List, Optional, Any, Union
from objects import glob
from objects.utils import klogging


def validate_beatmap_id(beatmap_id: Union[str, int]) -> Optional[int]:
    """
    Validate and convert beatmap ID to integer
    
    Args:
        beatmap_id: Beatmap ID as string or integer
        
    Returns:
        Valid beatmap ID as integer, or None if invalid
    """
    try:
        if isinstance(beatmap_id, str):
            # Remove any non-digit characters
            clean_id = re.sub(r'[^\d]', '', beatmap_id)
            if not clean_id:
                return None
            beatmap_id = int(clean_id)
        
        # Validate range (osu! beatmap IDs are positive integers)
        if isinstance(beatmap_id, int) and beatmap_id > 0:
            return beatmap_id
        
        return None
    except (ValueError, TypeError):
        return None


def format_beatmap_data(raw_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Format raw beatmap data into standardized structure
    
    Args:
        raw_data: Raw beatmap data from API
        
    Returns:
        Formatted beatmap data
    """
    try:
        # Placeholder for data formatting logic
        # This will be expanded based on actual API response structure
        formatted = {
            "id": raw_data.get("id"),
            "title": raw_data.get("title", "Unknown Title"),
            "artist": raw_data.get("artist", "Unknown Artist"),
            "creator": raw_data.get("creator", "Unknown Creator"),
            "status": raw_data.get("status", "unknown"),
            "difficulty_rating": raw_data.get("difficulty_rating", 0.0),
            "bpm": raw_data.get("bpm", 0),
            "length": raw_data.get("total_length", 0),
            "formatted": True
        }
        
        return formatted
    except Exception as e:
        klogging.log(f"Error formatting beatmap data: {e}", klogging.Ansi.LRED)
        return {
            "error": "Failed to format beatmap data",
            "raw_data": raw_data
        }


def get_system_status() -> Dict[str, Any]:
    """
    Get system status information for HinaManage
    
    Returns:
        Dict containing system status
    """
    try:
        return {
            "status": "operational",
            "module": "hinaManage",
            "version": "1.0.0",
            "features": {
                "beatmap_search": "placeholder",
                "beatmap_download": "placeholder",
                "api_integration": "placeholder"
            },
            "database_connected": hasattr(glob, 'db') and glob.db is not None,
            "debug_mode": getattr(glob.config, 'debug', False)
        }
    except Exception as e:
        klogging.log(f"Error getting system status: {e}", klogging.Ansi.LRED)
        return {
            "status": "error",
            "message": "Failed to get system status",
            "error": str(e)
        }


def sanitize_search_query(query: str) -> str:
    """
    Sanitize search query for safe processing
    
    Args:
        query: Raw search query
        
    Returns:
        Sanitized search query
    """
    try:
        if not isinstance(query, str):
            return ""
        
        # Remove potentially dangerous characters
        sanitized = re.sub(r'[<>"\';\\]', '', query)
        
        # Limit length
        sanitized = sanitized[:200]
        
        # Strip whitespace
        sanitized = sanitized.strip()
        
        return sanitized
    except Exception as e:
        klogging.log(f"Error sanitizing search query: {e}", klogging.Ansi.LRED)
        return ""


def parse_beatmap_url(url: str) -> Optional[int]:
    """
    Parse beatmap ID from osu! URL
    
    Args:
        url: osu! beatmap URL
        
    Returns:
        Beatmap ID if found, None otherwise
    """
    try:
        # Pattern for osu! beatmap URLs
        patterns = [
            r'osu\.ppy\.sh/beatmapsets/\d+#[^/]+/(\d+)',  # New format
            r'osu\.ppy\.sh/b/(\d+)',  # Old format
            r'osu\.ppy\.sh/beatmaps/(\d+)',  # Alternative format
        ]
        
        for pattern in patterns:
            match = re.search(pattern, url)
            if match:
                return int(match.group(1))
        
        return None
    except Exception as e:
        klogging.log(f"Error parsing beatmap URL: {e}", klogging.Ansi.LRED)
        return None
