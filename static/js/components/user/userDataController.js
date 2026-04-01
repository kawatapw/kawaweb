/**
 * ============================================================================
 * User Data Controller
 * ============================================================================
 *
 * Global singleton controller that manages user data fetching, caching,
 * and component registration for deduplication.
 *
 * Features:
 * - Single source of truth for user data
 * - Request deduplication (one request per userId at a time)
 * - Component registration and notification
 * - Cache with configurable TTL
 * - Integrated status batching
 *
 * Usage:
 *   const controller = window.__userDataController;
 *   controller.registerComponent(userId, component);
 *   controller.unregisterComponent(userId, component);
 *
 * @singleton
 */
(function() {
  'use strict';

  const CACHE_TTL = 5 * 60 * 1000; // 5 minutes for user data
  const STATUS_CACHE_TTL = 30 * 1000; // 30 seconds for status
  const STATUS_BATCH_INTERVAL = 30 * 1000; // 30 seconds batch interval
  const MAX_BATCH_SIZE = 100;

  class UserDataController {
    constructor() {
      // User data cache: userId -> { data, timestamp }
      this.userDataCache = {};

      // Pending requests: userId -> Promise (for deduplication)
      this.pendingRequests = {};

      // Registered components: userId -> [component instances]
      this.registeredComponents = {};

      // Status data cache: userId -> statusData
      this.statusCache = {};

      // Status batch timer
      this.statusBatchTimer = null;

      // Logger
      this.logger = null;

      // Initialize logger if available
      this._initLogger();

      // Start status batch interval
      this._startStatusBatch();
    }

    _initLogger() {
      const waitForLogger = () => {
        if (window.ColorfulLogger) {
          this.logger = window.ColorfulLogger.child('UserDataController');
          this.logger.info('LIFECYCLE', 'Controller initialized', {
            cacheTTL: CACHE_TTL,
            statusCacheTTL: STATUS_CACHE_TTL,
            batchInterval: STATUS_BATCH_INTERVAL,
            maxBatchSize: MAX_BATCH_SIZE
          });
          this.logger.debug('LIFECYCLE', 'Starting status batch interval');
        } else {
          setTimeout(waitForLogger, 100);
        }
      };
      waitForLogger();
    }

    _log(level, category, message, data) {
      if (this.logger) {
        this.logger[level](category, message, data);
      }
    }

    // =========================================================================
    // Component Registration
    // =========================================================================

    /**
     * Register a component for a specific userId
     * @param {string|number} userId
     * @param {Object} component - Vue component instance
     */
    registerComponent(userId, component) {
      this._log('trace', 'REGISTER', 'registerComponent called', { userId, componentType: component?.$options?.name || 'unknown' });

      if (!userId) {
        this._log('warn', 'REGISTER', 'registerComponent called with null/undefined userId');
        return;
      }

      if (!component) {
        this._log('warn', 'REGISTER', 'registerComponent called with null/undefined component', { userId });
        return;
      }

      const userIdStr = String(userId);

      // Initialize array if needed
      if (!this.registeredComponents[userIdStr]) {
        this.registeredComponents[userIdStr] = [];
        this._log('debug', 'REGISTER', `Created new component array for user ${userIdStr}`);
      }

      // Don't add duplicates
      if (this.registeredComponents[userIdStr].includes(component)) {
        this._log('trace', 'REGISTER', `Component already registered for user ${userIdStr}, skipping`);
        return;
      }

      this.registeredComponents[userIdStr].push(component);
      this._log('debug', 'REGISTER', `Component registered for user ${userIdStr}`, {
        totalForUser: this.registeredComponents[userIdStr].length,
        totalUsers: Object.keys(this.registeredComponents).length,
        componentName: component.$options?.name || 'unknown'
      });

      // If we have cached data, update immediately
      if (this.userDataCache[userIdStr] && this._isCacheFresh(this.userDataCache[userIdStr], CACHE_TTL)) {
        this._log('debug', 'CACHE', `Updating new component with cached user data for ${userIdStr}`, {
          cacheAge: Date.now() - this.userDataCache[userIdStr].timestamp,
          cacheTTL: CACHE_TTL
        });
        this._updateComponent(component, 'setUserData', this.userDataCache[userIdStr].data);
      } else {
        this._log('trace', 'CACHE', `No fresh user data cache for ${userIdStr}`, {
          hasCache: !!this.userDataCache[userIdStr],
          isFresh: this.userDataCache[userIdStr] ? this._isCacheFresh(this.userDataCache[userIdStr], CACHE_TTL) : false
        });
      }

      // If we have cached status, update immediately
      if (this.statusCache[userIdStr]) {
        this._log('trace', 'CACHE', `Updating new component with cached status for ${userIdStr}`);
        this._updateComponent(component, 'setStatusData', this.statusCache[userIdStr]);
      } else {
        this._log('trace', 'CACHE', `No status cache for ${userIdStr}`);
      }

      // Fetch data if not cached or stale
      this._ensureUserData(userIdStr);
    }

    /**
     * Unregister a component
     * @param {string|number} userId
     * @param {Object} component
     */
    unregisterComponent(userId, component) {
      this._log('trace', 'UNREGISTER', 'unregisterComponent called', { userId });

      if (!userId) {
        this._log('trace', 'UNREGISTER', 'unregisterComponent called with null/undefined userId');
        return;
      }

      if (!component) {
        this._log('trace', 'UNREGISTER', 'unregisterComponent called with null/undefined component', { userId });
        return;
      }

      const userIdStr = String(userId);

      if (!this.registeredComponents[userIdStr]) {
        this._log('trace', 'UNREGISTER', `No registered components found for user ${userIdStr}`);
        return;
      }

      const index = this.registeredComponents[userIdStr].indexOf(component);
      if (index > -1) {
        this.registeredComponents[userIdStr].splice(index, 1);
        this._log('debug', 'UNREGISTER', `Component unregistered for user ${userIdStr}`, {
          remainingForUser: this.registeredComponents[userIdStr].length,
          totalUsers: Object.keys(this.registeredComponents).length
        });
      } else {
        this._log('trace', 'UNREGISTER', `Component not found in registry for user ${userIdStr}`);
      }

      // Clean up empty arrays
      if (this.registeredComponents[userIdStr].length === 0) {
        delete this.registeredComponents[userIdStr];
        this._log('debug', 'UNREGISTER', `Removed empty component array for user ${userIdStr}`);
      }
    }

    /**
     * Update a component with data using a method name
     * @param {Object} component
     * @param {string} methodName
     * @param {*} data
     */
    _updateComponent(component, methodName, data) {
      if (!component) {
        this._log('warn', 'UPDATE', `_updateComponent called with null component for method ${methodName}`);
        return;
      }

      if (typeof component[methodName] === 'function') {
        try {
          component[methodName](data);
        } catch (error) {
          this._log('error', 'UPDATE', `Error calling ${methodName} on component`, {
            error: error.message,
            stack: error.stack,
            componentName: component.$options?.name || 'unknown'
          });
        }
      } else {
        this._log('warn', 'UPDATE', `Component does not have method ${methodName}`, {
          componentName: component.$options?.name || 'unknown',
          availableMethods: Object.keys(component).filter(k => typeof component[k] === 'function').slice(0, 10)
        });
      }
    }

    /**
     * Notify all registered components for a userId
     * @param {string} userIdStr
     * @param {string} methodName
     * @param {*} data
     */
    _notifyComponents(userIdStr, methodName, data) {
      const components = this.registeredComponents[userIdStr] || [];
      this._log('trace', 'NOTIFY', `Notifying ${components.length} components for user ${userIdStr} with ${methodName}`);
      components.forEach(component => {
        this._updateComponent(component, methodName, data);
      });
    }

    // =========================================================================
    // User Data Management
    // =========================================================================

    /**
     * Ensure user data is loaded (fetch if needed)
     * @param {string} userIdStr
     */
    async _ensureUserData(userIdStr) {
      this._log('trace', 'ENSURE', `_ensureUserData called for ${userIdStr}`);

      // Check cache freshness
      if (this.userDataCache[userIdStr]) {
        const isFresh = this._isCacheFresh(this.userDataCache[userIdStr], CACHE_TTL);
        const cacheAge = Date.now() - this.userDataCache[userIdStr].timestamp;

        if (isFresh) {
          this._log('debug', 'CACHE', `User data cache is fresh for ${userIdStr}`, {
            cacheAge: `${(cacheAge / 1000).toFixed(1)}s`,
            cacheTTL: `${(CACHE_TTL / 1000).toFixed(0)}s`
          });
          return;
        } else {
          this._log('debug', 'CACHE', `User data cache is stale for ${userIdStr}, will refresh`, {
            cacheAge: `${(cacheAge / 1000).toFixed(1)}s`,
            cacheTTL: `${(CACHE_TTL / 1000).toFixed(0)}s`
          });
        }
      } else {
        this._log('debug', 'CACHE', `No user data cache for ${userIdStr}, will fetch`);
      }

      // If already fetching, wait for existing request
      if (this.pendingRequests[userIdStr]) {
        this._log('debug', 'DEDUP', `Waiting for existing request for ${userIdStr}`);
        await this.pendingRequests[userIdStr];
        return;
      }

      // Fetch new data
      await this._fetchUserData(userIdStr);
    }

    /**
     * Fetch user data from API
     * @param {string} userIdStr
     */
    async _fetchUserData(userIdStr) {
      this._log('debug', 'FETCH', `Fetching user data for ${userIdStr}`);

      const promise = this._doFetchUserData(userIdStr);
      this.pendingRequests[userIdStr] = promise;

      try {
        await promise;
      } finally {
        delete this.pendingRequests[userIdStr];
        this._log('trace', 'FETCH', `Cleared pending request for ${userIdStr}`);
      }
    }

    async _doFetchUserData(userIdStr) {
      const protocol = window.location.protocol;
      const apiDomain = window.domain || 'kawata.pw';
      const url = `${protocol}//api.${apiDomain}/v1/get_player_info?id=${userIdStr}&scope=all`;

      this.logger?.perfStart('fetchUserData:' + userIdStr);
      this._log('debug', 'FETCH', `API request starting for ${userIdStr}`, { url });

      try {
        const response = await fetch(url);

        if (!response.ok) {
          this._log('error', 'FETCH', `API request failed for ${userIdStr}`, {
            status: response.status,
            statusText: response.statusText,
            url: url
          });
          throw new Error(`API request failed with status ${response.status}`);
        }

        const data = await response.json();
        this.logger?.perfEnd('fetchUserData:' + userIdStr, { userId: userIdStr, status: data.status });

        if (data.status === 'success' && data.player) {
          const normalizedData = this._normalizeUserData(data.player);

          // Cache the data
          this.userDataCache[userIdStr] = {
            data: normalizedData,
            timestamp: Date.now()
          };

          // Notify all components
          this._notifyComponents(userIdStr, 'setUserData', normalizedData);
          this._log('info', 'FETCH', `User data loaded for ${userIdStr}`, {
            hasInfo: !!normalizedData.info,
            hasStats: !!normalizedData.stats,
            hasBadges: !!normalizedData.info?.badges,
            badgeCount: normalizedData.info?.badges?.length || 0
          });
        } else {
          this._log('warn', 'FETCH', `No user data found for ${userIdStr}`, {
            apiStatus: data.status,
            hasPlayer: !!data.player,
            responseKeys: Object.keys(data)
          });
        }
      } catch (error) {
        this._log('error', 'FETCH', `Error fetching user data for ${userIdStr}`, {
          error: error.message,
          stack: error.stack,
          url: url
        });
      }
    }

    /**
     * Normalize user data to a standard format
     * Handles multiple API response structures
     * @param {Object} user - Raw user data from API
     * @returns {Object} Normalized user data
     */
    _normalizeUserData(user) {
      this._log('trace', 'NORMALIZE', 'Normalizing user data', { hasUser: !!user });

      if (!user) {
        this._log('warn', 'NORMALIZE', 'Received null/undefined user data');
        return null;
      }

      const normalized = { ...user };

      // Ensure info object exists
      if (!normalized.info) {
        this._log('trace', 'NORMALIZE', 'Creating info object from root-level properties');
        normalized.info = {
          id: normalized.player_id || normalized.id,
          name: normalized.name,
          country: normalized.country,
          clan_id: normalized.clan_id,
          clan_tag: normalized.clan_tag,
          clan: normalized.clan || (normalized.clan_tag ? { tag: normalized.clan_tag, id: normalized.clan_id } : null),
          badges: normalized.badges || [],
          preferred_mode: normalized.preferred_mode || 0
        };
      } else {
        // If info exists, ensure badges are properly set
        // Badges might be at root level or in info
        if (!normalized.info.badges && normalized.badges) {
          this._log('trace', 'NORMALIZE', 'Moving badges from root to info object');
          normalized.info.badges = normalized.badges;
        }
        // Ensure badges is always an array
        if (!normalized.info.badges) {
          this._log('trace', 'NORMALIZE', 'Setting empty badges array');
          normalized.info.badges = [];
        }
      }

      // Ensure stats object exists
      if (!normalized.stats) {
        this._log('trace', 'NORMALIZE', 'Creating stats object from root-level properties');
        normalized.stats = {
          current: {
            0: {
              pp: normalized.pp,
              acc: normalized.acc,
              plays: normalized.plays,
              tscore: normalized.tscore,
              rscore: normalized.rscore,
              playtime: normalized.playtime,
              max_combo: normalized.max_combo,
              total_hits: normalized.total_hits,
              replay_views: normalized.replay_views,
              xh_count: normalized.xh_count,
              x_count: normalized.x_count,
              sh_count: normalized.sh_count,
              s_count: normalized.s_count,
              a_count: normalized.a_count,
              rank: normalized.rank,
              country_rank: normalized.country_rank
            }
          }
        };
      }

      // Log badge info for debugging
      this._log('debug', 'NORMALIZE', `Normalized data for user ${normalized.info?.id}`, {
        hasBadges: !!normalized.info?.badges,
        badgeCount: normalized.info?.badges?.length || 0,
        badgesAtRoot: !!normalized.badges,
        badgesInInfo: !!normalized.info?.badges
      });

      return normalized;
    }

    /**
     * Get user data (cached or fetch)
     * @param {string|number} userId
     * @returns {Promise<Object>} User data
     */
    async getUserData(userId) {
      this._log('trace', 'GET', `getUserData called for ${userId}`);
      const userIdStr = String(userId);

      await this._ensureUserData(userIdStr);

      if (this.userDataCache[userIdStr]) {
        this._log('trace', 'GET', `Returning cached data for ${userIdStr}`);
        return this.userDataCache[userIdStr].data;
      }

      this._log('warn', 'GET', `No data available for ${userIdStr} after fetch`);
      return null;
    }

    // =========================================================================
    // Status Management (Batched)
    // =========================================================================

    /**
     * Start status batch interval
     */
    _startStatusBatch() {
      if (this.statusBatchTimer) {
        this._log('debug', 'STATUS', 'Clearing existing status batch timer');
        clearInterval(this.statusBatchTimer);
      }

      this._log('debug', 'STATUS', `Starting status batch interval (${STATUS_BATCH_INTERVAL}ms)`);
      this.statusBatchTimer = setInterval(() => {
        this._fetchBatchStatus();
      }, STATUS_BATCH_INTERVAL);
    }

    /**
     * Fetch batch status for all registered users
     */
    async _fetchBatchStatus() {
      const userIds = Object.keys(this.registeredComponents);

      if (userIds.length === 0) {
        this._log('trace', 'STATUS', 'No registered users, skipping batch status fetch');
        return;
      }

      this._log('debug', 'STATUS', `Fetching batch status for ${userIds.length} users`, { userIds: userIds.slice(0, 5) });

      // Split into batches
      for (let i = 0; i < userIds.length; i += MAX_BATCH_SIZE) {
        const batch = userIds.slice(i, i + MAX_BATCH_SIZE);
        this._log('trace', 'STATUS', `Processing batch ${Math.floor(i / MAX_BATCH_SIZE) + 1} of ${Math.ceil(userIds.length / MAX_BATCH_SIZE)}`, { batchSize: batch.length });
        await this._fetchStatusBatch(batch);
      }
    }

    /**
     * Fetch status for a batch of user IDs
     * @param {string[]} userIds
     */
    async _fetchStatusBatch(userIds) {
      if (userIds.length === 0) {
        this._log('trace', 'STATUS', '_fetchStatusBatch called with empty array');
        return;
      }

      const protocol = window.location.protocol;
      const apiDomain = window.domain || 'kawata.pw';
      const userIdsParam = userIds.join(',');
      const url = `${protocol}//api.${apiDomain}/v1/get_player_status?ids=${userIdsParam}`;

      this.logger?.perfStart('fetchStatusBatch');
      this._log('trace', 'STATUS', `Status API request starting`, { url, userCount: userIds.length });

      try {
        const response = await fetch(url);

        if (!response.ok) {
          this._log('error', 'STATUS', `Status API request failed`, {
            status: response.status,
            statusText: response.statusText,
            url: url
          });
          throw new Error(`Status API request failed with status ${response.status}`);
        }

        const data = await response.json();
        this.logger?.perfEnd('fetchStatusBatch', { userCount: userIds.length, status: data.status });

        if (data.status === 'success' && data.players) {
          const playerCount = Object.keys(data.players).length;
          this._log('debug', 'STATUS', `Batch status loaded`, { playerCount });

          for (const [userId, result] of Object.entries(data.players)) {
            if (result.status === 'success') {
              this.statusCache[userId] = result.player_status;
              this._notifyComponents(userId, 'setStatusData', result.player_status);
            } else {
              this._log('trace', 'STATUS', `Status fetch failed for user ${userId}`, { status: result.status });
            }
          }
        } else {
          this._log('warn', 'STATUS', 'Batch status response invalid', { apiStatus: data.status, hasPlayers: !!data.players });
        }
      } catch (error) {
        this._log('error', 'STATUS', 'Error fetching batch status', {
          error: error.message,
          stack: error.stack,
          url: url,
          userCount: userIds.length
        });
      }
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    /**
     * Check if cache entry is fresh
     * @param {Object} cacheEntry
     * @param {number} ttl
     * @returns {boolean}
     */
    _isCacheFresh(cacheEntry, ttl) {
      if (!cacheEntry || !cacheEntry.timestamp) {
        this._log('trace', 'CACHE', 'Cache entry invalid (no timestamp)', { hasEntry: !!cacheEntry });
        return false;
      }
      const age = Date.now() - cacheEntry.timestamp;
      const isFresh = age < ttl;
      return isFresh;
    }

    /**
     * Clear cache for a specific user
     * @param {string|number} userId
     */
    clearUserCache(userId) {
      const userIdStr = String(userId);
      const hadUserData = !!this.userDataCache[userIdStr];
      const hadStatus = !!this.statusCache[userIdStr];
      delete this.userDataCache[userIdStr];
      delete this.statusCache[userIdStr];
      this._log('debug', 'CACHE', `Cache cleared for user ${userIdStr}`, { hadUserData, hadStatus });
    }

    /**
     * Clear all caches
     */
    clearAllCaches() {
      const userCacheCount = Object.keys(this.userDataCache).length;
      const statusCacheCount = Object.keys(this.statusCache).length;
      this.userDataCache = {};
      this.statusCache = {};
      this._log('debug', 'CACHE', 'All caches cleared', { userCacheCount, statusCacheCount });
    }

    /**
     * Destroy the controller
     */
    destroy() {
      this._log('info', 'LIFECYCLE', 'Destroying controller', {
        registeredUsers: Object.keys(this.registeredComponents).length,
        cachedUsers: Object.keys(this.userDataCache).length,
        cachedStatuses: Object.keys(this.statusCache).length,
        pendingRequests: Object.keys(this.pendingRequests).length
      });

      if (this.statusBatchTimer) {
        clearInterval(this.statusBatchTimer);
        this.statusBatchTimer = null;
        this._log('debug', 'LIFECYCLE', 'Status batch timer cleared');
      }

      this.userDataCache = {};
      this.statusCache = {};
      this.pendingRequests = {};
      this.registeredComponents = {};

      this._log('info', 'LIFECYCLE', 'Controller destroyed');
    }
  }

  // =========================================================================
  // Global Singleton
  // =========================================================================

  // Create global instance
  if (!window.__userDataController) {
    window.__userDataController = new UserDataController();
  }

  // Export for module systems
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = UserDataController;
  }
})();
