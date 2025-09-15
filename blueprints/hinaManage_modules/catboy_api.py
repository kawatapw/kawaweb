# -*- coding: utf-8 -*-

"""
Catboy Mirror API Handler for HinaManage
Handles requests to the catboy.best mirror service
"""

__all__ = ('CatboyAPI',)

import aiohttp
import asyncio
from typing import Dict, List, Optional, Any
from objects.utils import klogging


class CatboyAPI:
    """
    Handler for catboy.best mirror API interactions
    """
    
    def __init__(self):
        self.base_url = "https://catboy.best/api/v1/osu"
        self.session: Optional[aiohttp.ClientSession] = None
    
    async def __aenter__(self):
        """Async context manager entry"""
        # Create connector with SSL verification disabled for catboy.best
        connector = aiohttp.TCPConnector(ssl=False)
        self.session = aiohttp.ClientSession(connector=connector)
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _make_request(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Any]:
        """
        Make request to catboy mirror API
        
        Args:
            endpoint: API endpoint (without base URL)
            params: Query parameters
            
        Returns:
            API response data or None if failed
        """
        try:
            if not self.session:
                connector = aiohttp.TCPConnector(ssl=False)
                self.session = aiohttp.ClientSession(connector=connector)
            
            headers = {
                'User-Agent': 'HinaManage/1.0 (KawaWeb Beatmap Manager)',
                'Accept': 'application/json'
            }
            
            url = f"{self.base_url}/{endpoint.lstrip('/')}"
            
            async with self.session.get(url, headers=headers, params=params, timeout=10) as response:
                if response.status == 200:
                    return await response.json()
                else:
                    error_text = await response.text()
                    klogging.log(f"Catboy API request failed: {response.status} - {error_text}", klogging.Ansi.LRED)
                    return None
                    
        except asyncio.TimeoutError:
            klogging.log("Catboy API request timed out", klogging.Ansi.LYELLOW)
            return None
        except Exception as e:
            klogging.log(f"Error making catboy API request: {e}", klogging.Ansi.LRED)
            return None
    
    async def search_beatmaps(self, query: str = '', limit: int = 50, **kwargs) -> Optional[List[Dict[str, Any]]]:
        """
        Search beatmaps using catboy mirror

        Args:
            query: Search query string
            limit: Maximum number of results
            **kwargs: Additional search parameters

        Returns:
            List of beatmap data or None if failed
        """
        try:
            params = {}

            if query:
                params['q'] = query
            if limit:
                params['limit'] = min(limit, 100)  # Cap at 100

            # Try different endpoints as catboy API may have changed
            # First try the basic search endpoint
            result = await self._make_request('search', params)

            # If first attempt fails, try with beatmaps prefix
            if result is None:
                result = await self._make_request('beatmaps', params)

            # If still fails, try the original endpoint format
            if result is None:
                result = await self._make_request('beatmaps/search', params)

            if result and isinstance(result, list):
                klogging.log(f"Catboy API search successful: {len(result)} results", klogging.Ansi.LGREEN)
                return result
            elif result and isinstance(result, dict) and 'data' in result:
                # Handle different response formats
                data = result['data']
                if isinstance(data, list):
                    klogging.log(f"Catboy API search successful: {len(data)} results", klogging.Ansi.LGREEN)
                    return data
            
            return []
            
        except Exception as e:
            klogging.log(f"Error searching catboy beatmaps: {e}", klogging.Ansi.LRED)
            return None
    
    async def get_beatmapset(self, beatmapset_id: int) -> Optional[Dict[str, Any]]:
        """
        Get beatmapset information by ID
        
        Args:
            beatmapset_id: Beatmapset ID
            
        Returns:
            Dict containing beatmapset data or None if failed
        """
        try:
            result = await self._make_request(f'beatmaps/s/{beatmapset_id}/')
            
            if result:
                klogging.log(f"Retrieved beatmapset {beatmapset_id} from catboy API", klogging.Ansi.LGREEN)
            
            return result
            
        except Exception as e:
            klogging.log(f"Error getting beatmapset {beatmapset_id} from catboy: {e}", klogging.Ansi.LRED)
            return None
    
    async def get_beatmap(self, beatmap_id: int) -> Optional[Dict[str, Any]]:
        """
        Get beatmap information by ID
        
        Args:
            beatmap_id: Beatmap ID
            
        Returns:
            Dict containing beatmap data or None if failed
        """
        try:
            result = await self._make_request(f'beatmaps/b/{beatmap_id}/')
            
            if result:
                klogging.log(f"Retrieved beatmap {beatmap_id} from catboy API", klogging.Ansi.LGREEN)
            
            return result
            
        except Exception as e:
            klogging.log(f"Error getting beatmap {beatmap_id} from catboy: {e}", klogging.Ansi.LRED)
            return None
    
    async def get_download_url(self, beatmapset_id: int, no_video: bool = False) -> Optional[str]:
        """
        Get download URL for a beatmapset
        
        Args:
            beatmapset_id: Beatmapset ID
            no_video: Whether to exclude video
            
        Returns:
            Download URL string or None if failed
        """
        try:
            endpoint = f'beatmaps/download/{beatmapset_id}/'
            if no_video:
                endpoint += '?no_video=1'
            
            # For download URLs, we might just return the constructed URL
            # since catboy typically provides direct download links
            download_url = f"{self.base_url}/{endpoint}"
            
            klogging.log(f"Generated catboy download URL for beatmapset {beatmapset_id}", klogging.Ansi.LGREEN)
            return download_url
            
        except Exception as e:
            klogging.log(f"Error getting download URL for beatmapset {beatmapset_id}: {e}", klogging.Ansi.LRED)
            return None
    
    async def get_preview_audio_url(self, beatmapset_id: int, full_audio: bool = False) -> Optional[str]:
        """
        Get preview audio URL for a beatmapset
        
        Args:
            beatmapset_id: Beatmapset ID
            full_audio: Whether to get full audio (if available)
            
        Returns:
            Audio URL string or None if failed
        """
        try:
            if full_audio:
                audio_url = f"{self.base_url}/beatmaps/audio/{beatmapset_id}/"
            else:
                # Use osu! preview URL as fallback
                audio_url = f"https://b.ppy.sh/preview/{beatmapset_id}.mp3"
            
            return audio_url
            
        except Exception as e:
            klogging.log(f"Error getting audio URL for beatmapset {beatmapset_id}: {e}", klogging.Ansi.LRED)
            return None
    
    async def get_background_url(self, beatmapset_id: int, beatmap_id: int = None) -> Optional[str]:
        """
        Get background image URL for a beatmapset
        
        Args:
            beatmapset_id: Beatmapset ID
            beatmap_id: Specific beatmap ID (optional)
            
        Returns:
            Background URL string or None if failed
        """
        try:
            if beatmap_id:
                bg_url = f"{self.base_url}/beatmaps/background/{beatmapset_id}/{beatmap_id}/"
            else:
                bg_url = f"{self.base_url}/beatmaps/background/{beatmapset_id}/"
            
            return bg_url
            
        except Exception as e:
            klogging.log(f"Error getting background URL for beatmapset {beatmapset_id}: {e}", klogging.Ansi.LRED)
            return None
    
    async def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to catboy mirror API
        
        Returns:
            Dict containing connection test results
        """
        try:
            # Try a simple search request
            result = await self.search_beatmaps('test', limit=1)
            
            if result is not None:
                return {
                    "status": "success",
                    "message": "Catboy mirror API connection successful",
                    "api_responsive": True,
                    "service_url": "https://catboy.best"
                }
            else:
                return {
                    "status": "error",
                    "message": "Catboy mirror API not responding",
                    "api_responsive": False,
                    "service_url": "https://catboy.best"
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"Catboy mirror API connection test failed: {str(e)}",
                "api_responsive": False,
                "service_url": "https://catboy.best",
                "error": str(e)
            }


# Global instance for easy access
catboy_api = CatboyAPI()
