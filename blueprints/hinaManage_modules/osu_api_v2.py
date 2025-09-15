# -*- coding: utf-8 -*-

"""
osu! API v2 Handler for HinaManage
Handles authentication and requests to the official osu! API v2
"""

__all__ = ('OsuAPIv2',)

import aiohttp
import asyncio
import os
import json
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta
from objects.utils import klogging


class OsuAPIv2:
    """
    Handler for osu! API v2 interactions
    Manages OAuth2 authentication and API requests
    """
    
    def __init__(self):
        self.base_url = "https://osu.ppy.sh/api/v2"
        self.token_url = "https://osu.ppy.sh/oauth/token"
        self.client_id = None
        self.client_secret = None
        self.access_token = None
        self.token_expires_at = None
        self.session: Optional[aiohttp.ClientSession] = None
        
        # Load credentials from .env file
        self._load_credentials()
    
    def _load_credentials(self):
        """Load osu! API credentials from .env file"""
        try:
            env_path = os.path.join(os.path.dirname(__file__), '.env')
            if os.path.exists(env_path):
                with open(env_path, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            if key == 'Client_ID':
                                self.client_id = value
                            elif key == 'Client_Secret':
                                self.client_secret = value
                
                klogging.log(f"Loaded osu! API credentials (Client ID: {self.client_id})", klogging.Ansi.LGREEN)
            else:
                klogging.log("No .env file found for osu! API credentials", klogging.Ansi.LYELLOW)
                
        except Exception as e:
            klogging.log(f"Error loading osu! API credentials: {e}", klogging.Ansi.LRED)
    
    async def __aenter__(self):
        """Async context manager entry"""
        self.session = aiohttp.ClientSession()
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit"""
        if self.session:
            await self.session.close()
    
    async def _get_access_token(self) -> bool:
        """
        Get OAuth2 access token for osu! API v2
        
        Returns:
            bool: True if token obtained successfully, False otherwise
        """
        if not self.client_id or not self.client_secret:
            klogging.log("Missing osu! API credentials", klogging.Ansi.LRED)
            return False
        
        # Check if current token is still valid
        if (self.access_token and self.token_expires_at and 
            datetime.now() < self.token_expires_at - timedelta(minutes=5)):
            return True
        
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            data = {
                'client_id': self.client_id,
                'client_secret': self.client_secret,
                'grant_type': 'client_credentials',
                'scope': 'public'
            }
            
            async with self.session.post(self.token_url, data=data) as response:
                if response.status == 200:
                    token_data = await response.json()
                    self.access_token = token_data['access_token']
                    expires_in = token_data.get('expires_in', 3600)
                    self.token_expires_at = datetime.now() + timedelta(seconds=expires_in)
                    
                    klogging.log("Successfully obtained osu! API v2 access token", klogging.Ansi.LGREEN)
                    return True
                else:
                    error_text = await response.text()
                    klogging.log(f"Failed to get osu! API token: {response.status} - {error_text}", klogging.Ansi.LRED)
                    return False
                    
        except Exception as e:
            klogging.log(f"Error getting osu! API token: {e}", klogging.Ansi.LRED)
            return False
    
    async def _make_request(self, endpoint: str, params: Dict[str, Any] = None) -> Optional[Dict[str, Any]]:
        """
        Make authenticated request to osu! API v2
        
        Args:
            endpoint: API endpoint (without base URL)
            params: Query parameters
            
        Returns:
            Dict containing API response or None if failed
        """
        if not await self._get_access_token():
            return None
        
        try:
            if not self.session:
                self.session = aiohttp.ClientSession()
            
            headers = {
                'Authorization': f'Bearer {self.access_token}',
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            }
            
            url = f"{self.base_url}/{endpoint.lstrip('/')}"
            
            async with self.session.get(url, headers=headers, params=params) as response:
                if response.status == 200:
                    return await response.json()
                elif response.status == 401:
                    # Token might be expired, try to refresh
                    klogging.log("osu! API token expired, refreshing...", klogging.Ansi.LYELLOW)
                    self.access_token = None
                    if await self._get_access_token():
                        headers['Authorization'] = f'Bearer {self.access_token}'
                        async with self.session.get(url, headers=headers, params=params) as retry_response:
                            if retry_response.status == 200:
                                return await retry_response.json()
                    return None
                else:
                    error_text = await response.text()
                    klogging.log(f"osu! API request failed: {response.status} - {error_text}", klogging.Ansi.LRED)
                    return None
                    
        except Exception as e:
            klogging.log(f"Error making osu! API request: {e}", klogging.Ansi.LRED)
            return None
    
    async def search_beatmapsets(self, query: str = '', **kwargs) -> Optional[Dict[str, Any]]:
        """
        Search beatmapsets using osu! API v2
        
        Args:
            query: Search query string
            **kwargs: Additional search parameters (status, mode, genre, language, sort, cursor_string)
            
        Returns:
            Dict containing search results or None if failed
        """
        try:
            params = {}
            
            if query:
                params['q'] = query
            
            # Map parameters to osu! API format
            if kwargs.get('status'):
                params['s'] = kwargs['status']
            if kwargs.get('mode'):
                params['m'] = kwargs['mode']
            if kwargs.get('genre'):
                params['g'] = kwargs['genre']
            if kwargs.get('language'):
                params['l'] = kwargs['language']
            if kwargs.get('sort'):
                params['sort'] = kwargs['sort']
            if kwargs.get('cursor_string'):
                params['cursor_string'] = kwargs['cursor_string']
            
            result = await self._make_request('beatmapsets/search', params)
            
            if result:
                klogging.log(f"osu! API search successful: {len(result.get('beatmapsets', []))} results", klogging.Ansi.LGREEN)
            
            return result
            
        except Exception as e:
            klogging.log(f"Error searching beatmapsets: {e}", klogging.Ansi.LRED)
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
            result = await self._make_request(f'beatmapsets/{beatmapset_id}')
            
            if result:
                klogging.log(f"Retrieved beatmapset {beatmapset_id} from osu! API", klogging.Ansi.LGREEN)
            
            return result
            
        except Exception as e:
            klogging.log(f"Error getting beatmapset {beatmapset_id}: {e}", klogging.Ansi.LRED)
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
            result = await self._make_request(f'beatmaps/{beatmap_id}')
            
            if result:
                klogging.log(f"Retrieved beatmap {beatmap_id} from osu! API", klogging.Ansi.LGREEN)
            
            return result
            
        except Exception as e:
            klogging.log(f"Error getting beatmap {beatmap_id}: {e}", klogging.Ansi.LRED)
            return None
    
    async def test_connection(self) -> Dict[str, Any]:
        """
        Test connection to osu! API v2
        
        Returns:
            Dict containing connection test results
        """
        try:
            if await self._get_access_token():
                # Try a simple request to verify the token works
                result = await self._make_request('beatmapsets/search', {'q': 'test', 'limit': 1})
                
                return {
                    "status": "success",
                    "message": "osu! API v2 connection successful",
                    "authenticated": True,
                    "has_credentials": bool(self.client_id and self.client_secret),
                    "token_valid": bool(self.access_token),
                    "api_responsive": result is not None
                }
            else:
                return {
                    "status": "error",
                    "message": "Failed to authenticate with osu! API v2",
                    "authenticated": False,
                    "has_credentials": bool(self.client_id and self.client_secret),
                    "token_valid": False,
                    "api_responsive": False
                }
                
        except Exception as e:
            return {
                "status": "error",
                "message": f"osu! API v2 connection test failed: {str(e)}",
                "authenticated": False,
                "has_credentials": bool(self.client_id and self.client_secret),
                "error": str(e)
            }


# Global instance for easy access
osu_api = OsuAPIv2()
