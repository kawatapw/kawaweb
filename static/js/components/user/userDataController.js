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
          this.logger.info('LIFECYCLE', 'Controller initialized');
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
      if (!userId || !component) return;

      const userIdStr = String(userId);

      // Initialize array if needed
      if (!this.registeredComponents[userIdStr]) {
        this.registeredComponents[userIdStr] = [];
      }

      // Don't add duplicates
      if (this.registeredComponents[userIdStr].includes(component)) {
        return;
      }

      this.registeredComponents[userIdStr].push(component);
      this._log('debug', 'REGISTER', `Component registered for user ${userIdStr}`, {
        totalForUser: this.registeredComponents[userIdStr].length,
        totalUsers: Object.keys(this.registeredComponents).length
      });

      // If we have cached data, update immediately
      if (this.userDataCache[userIdStr] && this._isCacheFresh(this.userDataCache[userIdStr], CACHE_TTL)) {
        this._log('debug', 'CACHE', `Updating component with cached user data for ${userIdStr}`);
        this._updateComponent(component, 'setUserData', this.userDataCache[userIdStr].data);
      }

      // If we have cached status, update immediately
      if (this.statusCache[userIdStr]) {
        this._log('debug', 'CACHE', `Updating component with cached status for ${userIdStr}`);
        this._updateComponent(component, 'setStatusData', this.statusCache[userIdStr]);
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
      if (!userId || !component) return;

      const userIdStr = String(userId);

      if (!this.registeredComponents[userIdStr]) return;

      const index = this.registeredComponents[userIdStr].indexOf(component);
      if (index > -1) {
        this.registeredComponents[userIdStr].splice(index, 1);
        this._log('debug', 'UNREGISTER', `Component unregistered for user ${userIdStr}`, {
          remainingForUser: this.registeredComponents[userIdStr].length
        });
      }

      // Clean up empty arrays
      if (this.registeredComponents[userIdStr].length === 0) {
        delete this.registeredComponents[userIdStr];
      }
    }

    /**
     * Update a component with data using a method name
     * @param {Object} component
     * @param {string} methodName
     * @param {*} data
     */
    _updateComponent(component, methodName, data) {
      if (component && typeof component[methodName] === 'function') {
        component[methodName](data);
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
      // Check cache freshness
      if (this.userDataCache[userIdStr] && this._isCacheFresh(this.userDataCache[userIdStr], CACHE_TTL)) {
        this._log('debug', 'CACHE', `User data cache is fresh for ${userIdStr}`);
        return;
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
      }
    }

    async _doFetchUserData(userIdStr) {
      const protocol = window.location.protocol;
      const apiDomain = window.domain || 'kawata.pw';

      try {
        const response = await fetch(
          `${protocol}//api.${apiDomain}/v1/get_player_info?id=${userIdStr}&scope=all`
        );

        if (!response.ok) {
          throw new Error(`API request failed with status ${response.status}`);
        }

        const data = await response.json();

        if (data.status === 'success' && data.player) {
          const normalizedData = this._normalizeUserData(data.player);

          // Cache the data
          this.userDataCache[userIdStr] = {
            data: normalizedData,
            timestamp: Date.now()
          };

          // Notify all components
          this._notifyComponents(userIdStr, 'setUserData', normalizedData);
          this._log('info', 'FETCH', `User data loaded for ${userIdStr}`);
        } else {
          this._log('warn', 'FETCH', `No user data found for ${userIdStr}`, data);
        }
      } catch (error) {
        this._log('error', 'FETCH', `Error fetching user data for ${userIdStr}`, error);
      }
    }

    /**
     * Normalize user data to a standard format
     * Handles multiple API response structures
     * @param {Object} user - Raw user data from API
     * @returns {Object} Normalized user data
     */
    _normalizeUserData(user) {
      if (!user) return null;

      const normalized = { ...user };

      // Ensure info object exists
      if (!normalized.info) {
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
          normalized.info.badges = normalized.badges;
        }
        // Ensure badges is always an array
        if (!normalized.info.badges) {
          normalized.info.badges = [];
        }
      }

      // Ensure stats object exists
      if (!normalized.stats) {
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
      const userIdStr = String(userId);

      await this._ensureUserData(userIdStr);

      if (this.userDataCache[userIdStr]) {
        return this.userDataCache[userIdStr].data;
      }

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
        clearInterval(this.statusBatchTimer);
      }

      this.statusBatchTimer = setInterval(() => {
        this._fetchBatchStatus();
      }, STATUS_BATCH_INTERVAL);
    }

    /**
     * Fetch batch status for all registered users
     */
    async _fetchBatchStatus() {
      const userIds = Object.keys(this.registeredComponents);

      if (userIds.length === 0) return;

      this._log('debug', 'STATUS', `Fetching batch status for ${userIds.length} users`);

      // Split into batches
      for (let i = 0; i < userIds.length; i += MAX_BATCH_SIZE) {
        const batch = userIds.slice(i, i + MAX_BATCH_SIZE);
        await this._fetchStatusBatch(batch);
      }
    }

    /**
     * Fetch status for a batch of user IDs
     * @param {string[]} userIds
     */
    async _fetchStatusBatch(userIds) {
      if (userIds.length === 0) return;

      const protocol = window.location.protocol;
      const apiDomain = window.domain || 'kawata.pw';
      const userIdsParam = userIds.join(',');

      try {
        const response = await fetch(
          `${protocol}//api.${apiDomain}/v1/get_player_status?ids=${userIdsParam}`
        );

        if (!response.ok) {
          throw new Error(`Status API request failed with status ${response.status}`);
        }

        const data = await response.json();

        if (data.status === 'success' && data.players) {
          for (const [userId, result] of Object.entries(data.players)) {
            if (result.status === 'success') {
              this.statusCache[userId] = result.player_status;
              this._notifyComponents(userId, 'setStatusData', result.player_status);
            }
          }
        }
      } catch (error) {
        this._log('error', 'STATUS', 'Error fetching batch status', error);
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
      if (!cacheEntry || !cacheEntry.timestamp) return false;
      return (Date.now() - cacheEntry.timestamp) < ttl;
    }

    /**
     * Clear cache for a specific user
     * @param {string|number} userId
     */
    clearUserCache(userId) {
      const userIdStr = String(userId);
      delete this.userDataCache[userIdStr];
      delete this.statusCache[userIdStr];
      this._log('debug', 'CACHE', `Cache cleared for user ${userIdStr}`);
    }

    /**
     * Clear all caches
     */
    clearAllCaches() {
      this.userDataCache = {};
      this.statusCache = {};
      this._log('debug', 'CACHE', 'All caches cleared');
    }

    /**
     * Destroy the controller
     */
    destroy() {
      if (this.statusBatchTimer) {
        clearInterval(this.statusBatchTimer);
        this.statusBatchTimer = null;
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