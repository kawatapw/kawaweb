/**
 * User Data Controller
 * Singleton class that manages all user data fetching, caching, normalization, and status batching.
 * Centralized source of truth for user information throughout the application.
 */

class UserDataController {
  constructor() {
    // Singleton instance
    if (UserDataController.instance) {
      return UserDataController.instance;
    }
    UserDataController.instance = this;

    // Configuration
    this.config = {
      apiDomain: domain || 'kawata.pw',
      batchSize: 100,
      statusRefreshInterval: 30000, // 30 seconds
      cacheExpiry: 5 * 60 * 1000, // 5 minutes
      debug: false
    };

    // Cache storage
    this.userCache = new Map(); // userId -> { data, timestamp }
    this.statusCache = new Map(); // userId -> { status, timestamp }
    
    // Subscription system for reactive updates
    this.subscribers = new Map(); // userId -> Set of callback functions
    
    // Batch status update timer
    this.statusTimer = null;
    this.isStatusFetching = false;
    
    // Logger
    this.log = window.console; // Will be enhanced if ColorfulLogger is available
    if (typeof ColorfulLogger !== 'undefined') {
      this.log = ColorfulLogger.child('UserDataController');
    }
    
    this.log.info('LIFECYCLE', 'UserDataController initialized', { config: this.config });
  }

  /**
   * Get normalized user data by user ID
   * Fetches from API if not cached or cache expired
   * @param {string|number} userId - User ID
   * @returns {Promise<object>} Normalized user data
   */
  async getUser(userId) {
    const userIdStr = String(userId);
    
    // Check cache first
    const cached = this.userCache.get(userIdStr);
    if (cached && (Date.now() - cached.timestamp) < this.config.cacheExpiry) {
      this.log.debug('DATA', 'Cache hit for user', { userId: userIdStr, age: Date.now() - cached.timestamp });
      return cached.data;
    }

    this.log.debug('DATA', 'Cache miss, fetching user from API', { userId: userIdStr });
    
    try {
      const url = `${window.location.protocol}//api.${this.config.apiDomain}/v1/get_player_info?id=${userIdStr}&scope=all`;
      this.log.trace('API', 'GET', { url, userId: userIdStr });
      
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error(`API request failed with status ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status !== 'success' || !data.player) {
        throw new Error('No user data found');
      }
      
      // Normalize the user data
      const normalized = this.normalizeUserData(data.player);
      
      // Cache it
      this.userCache.set(userIdStr, {
        data: normalized,
        timestamp: Date.now()
      });
      
      this.log.info('DATA', 'User fetched and cached successfully', { 
        userId: userIdStr, 
        hasStats: !!normalized.stats,
        hasBadges: normalized.info?.badges?.length > 0,
        cacheSize: this.userCache.size 
      });
      
      return normalized;
    } catch (error) {
      this.log.error('DATA', 'Failed to fetch user data', { 
        userId: userIdStr, 
        error: error.message,
        stack: error.stack 
      });
      throw error;
    }
  }

  /**
   * Get multiple users in bulk with deduplication
   * @param {Array<string|number>} userIds - Array of user IDs
   * @returns {Promise<Map<string, object>>} Map of userId -> normalized user data
   */
  async getUsersBulk(userIds) {
    const uniqueIds = [...new Set(userIds.map(String))];
    const result = new Map();
    const toFetch = [];
    
    // Check cache for each user
    for (const userId of uniqueIds) {
      const cached = this.userCache.get(userId);
      if (cached && (Date.now() - cached.timestamp) < this.config.cacheExpiry) {
        result.set(userId, cached.data);
      } else {
        toFetch.push(userId);
      }
    }
    
    this.log.debug('DATA', 'Bulk users request', {
      total: uniqueIds.length,
      fromCache: result.size,
      toFetch: toFetch.length
    });
    
    // Fetch missing users in batches
    if (toFetch.length > 0) {
      // Split into batches
      for (let i = 0; i < toFetch.length; i += this.config.batchSize) {
        const batch = toFetch.slice(i, i + this.config.batchSize);
        this.log.debug('DATA', 'Processing batch', { batchIndex: i / this.config.batchSize + 1, batchSize: batch.length });
        const batchResults = await this.fetchUserBatch(batch);
        
        for (const [userId, userData] of batchResults.entries()) {
          result.set(userId, userData);
        }
      }
    }
    
    this.log.info('DATA', 'Bulk fetch complete', { resultSize: result.size });
    return result;
  }

  /**
   * Fetch a batch of users from the API
   * @param {Array<string>} userIds - Array of user IDs to fetch
   * @returns {Promise<Map<string, object>>} Map of userId -> normalized user data
   */
  async fetchUserBatch(userIds) {
    const result = new Map();
    const userIdsParam = userIds.join(',');
    
    try {
      const url = `${window.location.protocol}//api.${this.config.apiDomain}/v1/get_player_info?id=${userIdsParam}&scope=all`;
      this.log.trace('API', 'POST (batch)', { url, userIdCount: userIds.length });
      
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error(`Batch API request failed with status ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success' && data.players) {
        let successCount = 0;
        let failCount = 0;
        
        for (const [userId, player] of Object.entries(data.players)) {
          if (player.status === 'success' && player.player) {
            const normalized = this.normalizeUserData(player.player);
            result.set(userId, normalized);
            
            // Cache it
            this.userCache.set(userId, {
              data: normalized,
              timestamp: Date.now()
            });
            successCount++;
          } else {
            failCount++;
            this.log.warn('API', 'Batch user fetch failed for user', { userId, status: player?.status });
          }
        }
        
        this.log.debug('API', 'Batch results', { success: successCount, failed: failCount });
      } else {
        this.log.warn('API', 'Batch response missing players data', { status: data.status });
      }
    } catch (error) {
      this.log.error('API', 'Batch fetch error', { error: error.message, userIds: userIds.join(',') });
    }
    
    return result;
  }

  /**
   * Get user status (online/offline/playing etc)
   * @param {string|number} userId - User ID
   * @returns {Promise<object>} Status data
   */
  async getStatus(userId) {
    const userIdStr = String(userId);
    
    // Check cache
    const cached = this.statusCache.get(userIdStr);
    if (cached && (Date.now() - cached.timestamp) < this.config.cacheExpiry) {
      this.log.trace('DATA', 'Status cache hit', { userId: userIdStr });
      return cached.status;
    }
    
    // Fetch fresh status
    try {
      const url = `${window.location.protocol}//api.${this.config.apiDomain}/v1/get_player_status?id=${userIdStr}`;
      this.log.trace('API', 'GET status', { url, userId: userIdStr });
      
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error(`Status API request failed with status ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success') {
        this.statusCache.set(userIdStr, {
          status: data.player_status,
          timestamp: Date.now()
        });
        
        // Notify subscribers
        this.notifySubscribers(userIdStr, data.player_status);
        
        this.log.trace('DATA', 'Status fetched and cached', { userId: userIdStr, status: data.player_status });
        return data.player_status;
      }
      
      this.log.warn('API', 'Status response not success', { userId: userIdStr, status: data.status });
      return null;
    } catch (error) {
      this.log.error('DATA', 'Failed to fetch status', { userId: userIdStr, error: error.message });
      return null;
    }
  }

  /**
   * Get status for multiple users in bulk
   * @param {Array<string|number>} userIds - Array of user IDs
   * @returns {Promise<Map<string, object>>} Map of userId -> status data
   */
  async getStatusBulk(userIds) {
    const uniqueIds = [...new Set(userIds.map(String))];
    const result = new Map();
    
    // Check cache first
    const toFetch = [];
    for (const userId of uniqueIds) {
      const cached = this.statusCache.get(userId);
      if (cached && (Date.now() - cached.timestamp) < this.config.cacheExpiry) {
        result.set(userId, cached.status);
      } else {
        toFetch.push(userId);
      }
    }
    
    this.log.debug('DATA', 'Bulk status request', {
      total: uniqueIds.length,
      fromCache: result.size,
      toFetch: toFetch.length
    });
    
    // Fetch missing statuses in batches
    if (toFetch.length > 0) {
      for (let i = 0; i < toFetch.length; i += this.config.batchSize) {
        const batch = toFetch.slice(i, i + this.config.batchSize);
        const batchResults = await this.fetchStatusBatch(batch);
        
        for (const [userId, status] of batchResults.entries()) {
          result.set(userId, status);
        }
      }
    }
    
    this.log.info('DATA', 'Bulk status fetch complete', { resultSize: result.size });
    return result;
  }

  /**
   * Fetch status batch from API
   * @param {Array<string>} userIds - Array of user IDs
   * @returns {Promise<Map<string, object>>} Map of userId -> status data
   */
  async fetchStatusBatch(userIds) {
    const result = new Map();
    const userIdsParam = userIds.join(',');
    
    try {
      const url = `${window.location.protocol}//api.${this.config.apiDomain}/v1/get_player_status?ids=${userIdsParam}`;
      this.log.trace('API', 'POST (status batch)', { url, userIdCount: userIds.length });
      
      const response = await fetch(url);
      
      if (!response.ok) {
        throw new Error(`Batch status request failed with status ${response.status}`);
      }
      
      const data = await response.json();
      
      if (data.status === 'success' && data.players) {
        let successCount = 0;
        let failCount = 0;
        
        for (const [userId, playerStatus] of Object.entries(data.players)) {
          if (playerStatus.status === 'success') {
            result.set(userId, playerStatus.player_status);
            
            // Cache it
            this.statusCache.set(userId, {
              status: playerStatus.player_status,
              timestamp: Date.now()
            });
            
            // Notify subscribers
            this.notifySubscribers(userId, playerStatus.player_status);
            successCount++;
          } else {
            failCount++;
            this.log.warn('API', 'Batch status fetch failed for user', { userId, status: playerStatus?.status });
          }
        }
        
        this.log.debug('API', 'Status batch results', { success: successCount, failed: failCount });
      } else {
        this.log.warn('API', 'Status batch response missing players data', { status: data.status });
      }
    } catch (error) {
      this.log.error('API', 'Status batch fetch error', { error: error.message, userIds: userIds.join(',') });
    }
    
    return result;
  }

  /**
   * Start periodic status refresh for all cached users
   */
  startStatusRefresh() {
    if (this.statusTimer) {
      this.log.debug('CONFIG', 'Status refresh already running');
      return;
    }
    
    this.log.info('CONFIG', 'Starting periodic status refresh', {
      interval: this.config.statusRefreshInterval,
      cachedUsers: this.userCache.size
    });
    
    this.statusTimer = setInterval(() => {
      this.refreshAllStatuses();
    }, this.config.statusRefreshInterval);
  }

  /**
   * Stop periodic status refresh
   */
  stopStatusRefresh() {
    if (this.statusTimer) {
      clearInterval(this.statusTimer);
      this.statusTimer = null;
      this.log.info('CONFIG', 'Stopped status refresh');
    }
  }

  /**
   * Refresh status for all users in cache
   */
  async refreshAllStatuses() {
    if (this.isStatusFetching) {
      this.log.trace('CONFIG', 'Status fetch already in progress, skipping refresh cycle');
      return;
    }
    
    const userIds = Array.from(this.userCache.keys());
    if (userIds.length === 0) {
      this.log.trace('CONFIG', 'No cached users, skipping status refresh');
      return;
    }
    
    this.isStatusFetching = true;
    this.log.debug('CONFIG', 'Starting automatic status refresh cycle', { userCount: userIds.length });
    
    try {
      const startTime = performance.now();
      await this.getStatusBulk(userIds);
      const duration = performance.now() - startTime;
      this.log.info('PERF', 'Status refresh cycle completed', { 
        userCount: userIds.length,
        duration: `${duration.toFixed(2)}ms`,
        avgPerUser: `${(duration / userIds.length).toFixed(2)}ms`
      });
    } catch (error) {
      this.log.error('CONFIG', 'Status refresh cycle failed', { error: error.message });
    } finally {
      this.isStatusFetching = false;
    }
  }

  /**
   * Subscribe to status updates for a specific user
   * @param {string} userId - User ID to subscribe to
   * @param {function} callback - Callback function(statusData)
   * @returns {function} Unsubscribe function
   */
  subscribeToStatus(userId, callback) {
    const userIdStr = String(userId);
    
    if (!this.subscribers.has(userIdStr)) {
      this.subscribers.set(userIdStr, new Set());
    }
    
    this.subscribers.get(userIdStr).add(callback);
    
    this.log.debug('DATA', 'Subscribed to status updates', { 
      userId: userIdStr, 
      subscriberCount: this.subscribers.get(userIdStr).size,
      totalSubscribers: this.getTotalSubscriberCount() 
    });
    
    // Return unsubscribe function
    return () => {
      this.unsubscribeFromStatus(userIdStr, callback);
    };
  }

  /**
   * Unsubscribe from status updates
   * @param {string} userId - User ID
   * @param {function} callback - Callback to remove
   */
  unsubscribeFromStatus(userId, callback) {
    const userIdStr = String(userId);
    
    if (this.subscribers.has(userIdStr)) {
      this.subscribers.get(userIdStr).delete(callback);
      
      if (this.subscribers.get(userIdStr).size === 0) {
        this.subscribers.delete(userIdStr);
      }
      
      this.log.trace('DATA', 'Unsubscribed from status', { userId: userIdStr });
    }
  }

  /**
   * Notify all subscribers for a user about status update
   * @param {string} userId - User ID
   * @param {object} statusData - New status data
   */
  notifySubscribers(userId, statusData) {
    const userIdStr = String(userId);
    
    if (this.subscribers.has(userIdStr)) {
      const callbacks = this.subscribers.get(userIdStr);
      this.log.trace('DATA', 'Notifying subscribers', { 
        userId: userIdStr, 
        subscriberCount: callbacks.size,
        status: statusData?.status?.action,
        online: statusData?.online 
      });
      
      callbacks.forEach(callback => {
        try {
          callback(statusData);
        } catch (error) {
          this.log.error('DATA', 'Subscriber callback threw error', { 
            userId: userIdStr,
            error: error.message,
            stack: error.stack 
          });
        }
      });
    }
  }

  /**
   * Get total subscriber count across all users
   * @returns {number}
   */
  getTotalSubscriberCount() {
    let total = 0;
    for (const set of this.subscribers.values()) {
      total += set.size;
    }
    return total;
  }

  /**
   * Normalize raw user data from API to standard format
   * @param {object} rawUser - Raw user data from API
   * @returns {object} Normalized user data
   */
  normalizeUserData(rawUser) {
    if (!rawUser) {
      this.log.warn('DATA', 'Attempted to normalize null/undefined raw user data');
      return null;
    }
    
    // Extract user ID from various possible fields
    const userId = rawUser.player_id || rawUser.id || rawUser.user_id || rawUser.info?.id;
    if (!userId) {
      this.log.warn('DATA', 'Could not extract user ID from raw data', { rawUser });
    }
    
    // Normalize info object
    const info = rawUser.info || {};
    const normalizedInfo = {
      id: userId,
      name: rawUser.name || info.name || 'Unknown',
      country: rawUser.country || info.country || null,
      clan_id: rawUser.clan_id || info.clan_id || null,
      clan_tag: rawUser.clan_tag || info.clan_tag || (info.clan?.tag) || null,
      badges: (rawUser.badges || info.badges || []).map(badge => ({
        id: badge.id,
        name: badge.name,
        description: badge.description,
        styles: badge.styles || {}
      })),
      preferred_mode: info.preferred_mode || 0
    };
    
    // Normalize stats object
    let stats = rawUser.stats || info.stats || {};
    
    // Handle different stats structures
    if (stats.current) {
      stats = stats.current;
    } else if (stats[0] || stats[1] || stats[2] || stats[3]) {
      stats = { 0: stats };
    } else {
      stats = { 0: {} };
    }
    
    // Ensure each mode has required fields
    Object.keys(stats).forEach(mode => {
      const modeStats = stats[mode];
      stats[mode] = {
        pp: modeStats.pp || 0,
        acc: modeStats.acc || 0,
        plays: modeStats.plays || 0,
        rank: modeStats.rank || null,
        country_rank: modeStats.country_rank || null,
        tscore: modeStats.tscore || 0,
        rscore: modeStats.rscore || 0,
        playtime: modeStats.playtime || 0,
        max_combo: modeStats.max_combo || 0,
        total_hits: modeStats.total_hits || 0,
        replay_views: modeStats.replay_views || 0,
        xh_count: modeStats.xh_count || 0,
        x_count: modeStats.x_count || 0,
        sh_count: modeStats.sh_count || 0,
        s_count: modeStats.s_count || 0,
        a_count: modeStats.a_count || 0
      };
    });
    
    const normalized = {
      info: normalizedInfo,
      stats: stats,
      // Keep raw data for future use
      raw: rawUser
    };
    
    this.log.trace('DATA', 'Normalized user data', { userId, modes: Object.keys(stats) });
    return normalized;
  }

  /**
   * Get avatar URL for a user
   * @param {string|number|object} user - User ID or normalized user data
   * @returns {string} Avatar URL
   */
  getAvatarUrl(user) {
    const userId = this.extractUserId(user);
    if (!userId) {
      this.log.warn('UTIL', 'getAvatarUrl called with invalid user', { user });
      return '';
    }
    return `https://a.${this.config.apiDomain}/${userId}`;
  }

  /**
   * Get banner URL for a user
   * @param {string|number|object} user - User ID or normalized user data
   * @returns {string} Banner URL
   */
  getBannerUrl(user) {
    const userId = this.extractUserId(user);
    if (!userId) {
      this.log.warn('UTIL', 'getBannerUrl called with invalid user', { user });
      return '';
    }
    return `/banners/${userId}`;
  }

  /**
   * Get flag URL for a country
   * @param {string} country - Country code
   * @returns {string} Flag URL
   */
  getFlagUrl(country) {
    if (!country) {
      this.log.warn('UTIL', 'getFlagUrl called with invalid country', { country });
      return '';
    }
    return `/static/images/flags/${country.toUpperCase()}.png`;
  }

  /**
   * Get clan URL for a clan ID
   * @param {string|number} clanId - Clan ID
   * @returns {string} Clan URL
   */
  getClanUrl(clanId) {
    if (!clanId) {
      this.log.warn('UTIL', 'getClanUrl called with invalid clanId', { clanId });
      return '';
    }
    return `/clans/${clanId}`;
  }

  /**
   * Get profile URL for a user
   * @param {string|number|object} user - User ID or normalized user data
   * @returns {string} Profile URL
   */
  getProfileUrl(user) {
    const userId = this.extractUserId(user);
    if (!userId) {
      this.log.warn('UTIL', 'getProfileUrl called with invalid user', { user });
      return '';
    }
    return `/u/${userId}`;
  }

  /**
   * Get background URL for a user
   * @param {string|number|object} user - User ID or normalized user data
   * @returns {string} Background URL
   */
  getBackgroundUrl(user) {
    const userId = this.extractUserId(user);
    if (!userId) {
      this.log.warn('UTIL', 'getBackgroundUrl called with invalid user', { user });
      return '';
    }
    return `/backgrounds/${userId}`;
  }

  /**
   * Extract user ID from various input types
   * @param {string|number|object} user - User ID or user data object
   * @returns {string|null} User ID
   */
  extractUserId(user) {
    if (!user) return null;
    
    // If it's a string or number, assume it's the ID
    if (typeof user === 'string' || typeof user === 'number') {
      return String(user);
    }
    
    // If it's an object, try to extract ID
    if (typeof user === 'object') {
      // Check various possible ID locations
      return user.info?.id || user.player_id || user.id || user.user_id || null;
    }
    
    return null;
  }

  /**
   * Get current mode stats for a user
   * @param {object} userData - Normalized user data
   * @returns {object|null} Current mode stats
   */
  getCurrentStats(userData) {
    if (!userData || !userData.stats) {
      this.log.trace('DATA', 'getCurrentStats: missing userData or stats', { hasUserData: !!userData, hasStats: !!userData?.stats });
      return null;
    }
    
    const preferredMode = userData.info?.preferred_mode || 0;
    const stats = userData.stats[preferredMode] || null;
    
    if (!stats) {
      this.log.warn('DATA', 'getCurrentStats: no stats for preferred mode', { 
        preferredMode, 
        availableModes: Object.keys(userData.stats) 
      });
    }
    
    return stats;
  }

  /**
   * Clear cache for a specific user or all users
   * @param {string|number} [userId] - Optional user ID to clear
   */
  clearCache(userId) {
    if (userId) {
      const userIdStr = String(userId);
      const hadUser = this.userCache.has(userIdStr);
      const hadStatus = this.statusCache.has(userIdStr);
      this.userCache.delete(userIdStr);
      this.statusCache.delete(userIdStr);
      this.log.info('CONFIG', 'Cleared cache for user', { 
        userId: userIdStr, 
        hadUser,
        hadStatus 
      });
    } else {
      const userCount = this.userCache.size;
      const statusCount = this.statusCache.size;
      this.userCache.clear();
      this.statusCache.clear();
      this.log.info('CONFIG', 'Cleared all caches', { users: userCount, statuses: statusCount });
    }
  }

  /**
   * Get cache statistics
   * @returns {object} Cache stats
   */
  getCacheStats() {
    const stats = {
      userCacheSize: this.userCache.size,
      statusCacheSize: this.statusCache.size,
      subscriberCount: this.getTotalSubscriberCount(),
      config: { ...this.config }
    };
    this.log.trace('CONFIG', 'Cache stats', stats);
    return stats;
  }
}

// Create and export singleton instance
const userDataController = new UserDataController();

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UserDataController, userDataController };
}