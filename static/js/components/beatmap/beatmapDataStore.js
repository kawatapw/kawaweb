/**
 * ============================================================================
 * Beatmap Data Store
 * ============================================================================
 *
 * Simple in-memory cache for beatmap data with request deduplication.
 * Provides caching with TTL and prevents duplicate API requests.
 *
 * Usage:
 *   const store = window.__beatmapDataStore;
 *   const beatmap = await store.getBeatmap(beatmapId);
 *   const difficulties = await store.getSetDifficulties(setId);
 *
 * @singleton
 */
(function() {
  'use strict';

  const CACHE_TTL = 2 * 60 * 1000; // 2 minutes for beatmap data
  const SET_CACHE_TTL = 2 * 60 * 1000; // 2 minutes for set difficulties

  class BeatmapDataStore {
    constructor() {
      // Beatmap data cache: beatmapId -> { data, timestamp }
      this.beatmapCache = {};

      // Set difficulties cache: setId -> { data, timestamp }
      this.setCache = {};

      // Pending requests: key -> Promise (for deduplication)
      this.pendingRequests = {};

      // Logger
      this.logger = null;

      // Initialize logger if available
      this._initLogger();
    }

    _initLogger() {
      const waitForLogger = () => {
        if (window.ColorfulLogger) {
          this.logger = window.ColorfulLogger.child('BeatmapDataStore');
          this.logger.info('LIFECYCLE', 'Store initialized', {
            cacheTTL: `${CACHE_TTL / 1000}s`,
            setCacheTTL: `${SET_CACHE_TTL / 1000}s`
          });
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
    // Cache Management
    // =========================================================================

    /**
     * Check if cache entry is fresh
     * @param {Object} cacheEntry
     * @param {number} ttl
     * @returns {boolean}
     */
    _isCacheFresh(cacheEntry, ttl) {
      if (!cacheEntry || !cacheEntry.timestamp) {
        this._log('trace', 'DATA', 'Cache entry invalid (no timestamp)', { hasEntry: !!cacheEntry });
        return false;
      }
      const age = Date.now() - cacheEntry.timestamp;
      const isFresh = age < ttl;
      this._log('trace', 'DATA', `Cache freshness check: ${isFresh ? 'FRESH' : 'STALE'}`, {
        age: `${(age / 1000).toFixed(1)}s`,
        ttl: `${(ttl / 1000).toFixed(0)}s`,
        isFresh
      });
      return isFresh;
    }

    /**
     * Get from cache if fresh
     * @param {string} key
     * @param {Object} cache
     * @param {number} ttl
     * @returns {Object|null}
     */
    _getFromCache(key, cache, ttl) {
      this._log('trace', 'DATA', `Checking cache for key: ${key}`, {
        hasCache: !!cache[key],
        cacheAge: cache[key] ? `${((Date.now() - cache[key].timestamp) / 1000).toFixed(1)}s` : 'N/A'
      });

      if (cache[key] && this._isCacheFresh(cache[key], ttl)) {
        this._log('debug', 'DATA', `Cache HIT for key: ${key}`, {
          age: `${((Date.now() - cache[key].timestamp) / 1000).toFixed(1)}s`
        });
        return cache[key].data;
      }

      if (cache[key]) {
        this._log('debug', 'DATA', `Cache STALE for key: ${key}`, {
          age: `${((Date.now() - cache[key].timestamp) / 1000).toFixed(1)}s`
        });
      } else {
        this._log('debug', 'DATA', `Cache MISS for key: ${key}`);
      }

      return null;
    }

    /**
     * Set cache entry
     * @param {string} key
     * @param {*} data
     * @param {Object} cache
     */
    _setCache(key, data, cache) {
      cache[key] = {
        data: data,
        timestamp: Date.now()
      };
      this._log('debug', 'DATA', `Cached data for key: ${key}`, {
        timestamp: new Date().toISOString()
      });
    }

    // =========================================================================
    // Beatmap Data
    // =========================================================================

    /**
     * Get beatmap data (cached or fetch)
     * @param {number|string} beatmapId
     * @returns {Promise<Object>} Beatmap data
     */
    async getBeatmap(beatmapId) {
      const key = String(beatmapId);
      this._log('info', 'DATA', `getBeatmap called for beatmapId: ${key}`);

      // Check cache
      const cached = this._getFromCache(key, this.beatmapCache, CACHE_TTL);
      if (cached) {
        this._log('info', 'DATA', `Returning cached beatmap for ${key}`, {
          title: cached.title,
          setId: cached.set_id
        });
        return cached;
      }

      // Check pending requests (deduplication)
      const pendingKey = `beatmap_${key}`;
      if (this.pendingRequests[pendingKey]) {
        this._log('debug', 'NETWORK', `Waiting for existing request for beatmap ${key}`);
        return await this.pendingRequests[pendingKey];
      }

      // Fetch new data
      this._log('info', 'NETWORK', `Fetching new beatmap data for ${key}`);
      const promise = this._fetchBeatmap(key);
      this.pendingRequests[pendingKey] = promise;

      try {
        const result = await promise;
        return result;
      } finally {
        delete this.pendingRequests[pendingKey];
        this._log('trace', 'NETWORK', `Cleared pending request for beatmap ${key}`);
      }
    }

    /**
     * Fetch beatmap from API
     * @param {string} beatmapId
     * @returns {Promise<Object>}
     */
    async _fetchBeatmap(beatmapId) {
      this._log('info', 'API', `Fetching beatmap ${beatmapId} from API`);

      const protocol = window.location.protocol;
      const apiDomain = window.domain || 'kawata.pw';
      const url = `${protocol}//api.${apiDomain}/v2/maps/${beatmapId}`;

      this._log('debug', 'API', `API request URL: ${url}`);
      this.logger?.perfStart(`fetchBeatmap:${beatmapId}`);

      try {
        const response = await fetch(url);

        if (!response.ok) {
          this._log('error', 'API', `API request failed for beatmap ${beatmapId}`, {
            status: response.status,
            statusText: response.statusText,
            url
          });
          throw new Error(`API request failed with status ${response.status}`);
        }

        const data = await response.json();
        this.logger?.perfEnd(`fetchBeatmap:${beatmapId}`, { beatmapId, status: data.status });

        if (data.status === 'success' && data.data) {
          const beatmap = data.data;
          this._setCache(beatmapId, beatmap, this.beatmapCache);
          this._log('info', 'API', `Beatmap ${beatmapId} loaded successfully`, {
            title: beatmap.title,
            setId: beatmap.set_id,
            artist: beatmap.artist
          });
          return beatmap;
        } else {
          this._log('warn', 'API', `No beatmap data found for ${beatmapId}`, {
            apiStatus: data.status,
            hasData: !!data.data,
            dataLength: data.data?.length,
            data: data
          });
          return null;
        }
      } catch (error) {
        this._log('error', 'API', `Error fetching beatmap ${beatmapId}`, {
          error: error.message,
          stack: error.stack
        });
        throw error;
      }
    }

    /**
     * Get beatmap by set_id
     * @param {number|string} setId
     * @returns {Promise<Object>} Beatmap data
     */
    async getBeatmapBySet(setId) {
      const key = `set_${setId}`;
      this._log('info', 'DATA', `getBeatmapBySet called for setId: ${setId}`);

      // Check cache
      const cached = this._getFromCache(key, this.beatmapCache, CACHE_TTL);
      if (cached) {
        this._log('info', 'DATA', `Returning cached beatmap for set ${setId}`, {
          title: cached.title
        });
        return cached;
      }

      // Check pending requests
      const pendingKey = `beatmap_set_${setId}`;
      if (this.pendingRequests[pendingKey]) {
        this._log('debug', 'NETWORK', `Waiting for existing request for set ${setId}`);
        return await this.pendingRequests[pendingKey];
      }

      // Fetch new data
      this._log('info', 'NETWORK', `Fetching new beatmap data for set ${setId}`);
      const promise = this._fetchBeatmapBySet(setId);
      this.pendingRequests[pendingKey] = promise;

      try {
        const result = await promise;
        return result;
      } finally {
        delete this.pendingRequests[pendingKey];
        this._log('trace', 'NETWORK', `Cleared pending request for set ${setId}`);
      }
    }

    /**
     * Fetch beatmap by set_id from API
     * @param {string} setId
     * @returns {Promise<Object>}
     */
    async _fetchBeatmapBySet(setId) {
      this._log('info', 'API', `Fetching beatmap by set ${setId} from API`);

      const protocol = window.location.protocol;
      const apiDomain = window.domain || 'kawata.pw';
      const url = `${protocol}//api.${apiDomain}/v1/maps?set_id=${setId}`;

      this._log('debug', 'API', `API request URL: ${url}`);
      this.logger?.perfStart(`fetchBeatmapBySet:${setId}`);

      try {
        const response = await fetch(url);

        if (!response.ok) {
          this._log('error', 'API', `API request failed for set ${setId}`, {
            status: response.status,
            statusText: response.statusText
          });
          throw new Error(`API request failed with status ${response.status}`);
        }

        const data = await response.json();
        this.logger?.perfEnd(`fetchBeatmapBySet:${setId}`, { setId, status: data.status });

        if (data.apiStatus === 'success' && data.data) {
          const beatmap = data.data[0];
          const cacheKey = `set_${setId}`;
          this._setCache(cacheKey, beatmap, this.beatmapCache);
          this._log('info', 'API', `Beatmap set ${setId} loaded successfully`, {
            title: beatmap.title
          });
          return beatmap;
        } else {
          this._log('warn', 'API', `No beatmap data found for set ${setId}`);
          return null;
        }
      } catch (error) {
        this._log('error', 'API', `Error fetching beatmap set ${setId}`, {
          error: error.message,
          stack: error.stack
        });
        throw error;
      }
    }

    // =========================================================================
    // Set Difficulties
    // =========================================================================

    /**
     * Get difficulties for a beatmap set (cached or fetch)
     * @param {number|string} setId
     * @returns {Promise<Array>} Array of difficulties sorted by star rating
     */
    async getSetDifficulties(setId) {
      const key = String(setId);
      this._log('info', 'DATA', `getSetDifficulties called for setId: ${key}`);

      // Check cache
      const cached = this._getFromCache(key, this.setCache, SET_CACHE_TTL);
      if (cached) {
        this._log('info', 'DATA', `Returning cached difficulties for set ${key}`, {
          count: cached.length
        });
        return cached;
      }

      // Check pending requests
      const pendingKey = `difficulties_${key}`;
      if (this.pendingRequests[pendingKey]) {
        this._log('debug', 'NETWORK', `Waiting for existing request for difficulties of set ${key}`);
        return await this.pendingRequests[pendingKey];
      }

      // Fetch new data
      this._log('info', 'NETWORK', `Fetching new difficulties for set ${key}`);
      const promise = this._fetchSetDifficulties(key);
      this.pendingRequests[pendingKey] = promise;

      try {
        const result = await promise;
        return result;
      } finally {
        delete this.pendingRequests[pendingKey];
        this._log('trace', 'NETWORK', `Cleared pending request for difficulties of set ${key}`);
      }
    }

    /**
     * Fetch set difficulties from API
     * @param {string} setId
     * @returns {Promise<Array>}
     */
    async _fetchSetDifficulties(setId) {
      this._log('info', 'API', `Fetching difficulties for set ${setId} from API`);

      const protocol = window.location.protocol;
      const apiDomain = window.domain || 'kawata.pw';
      const url = `${protocol}//api.${apiDomain}/v2/maps?set_id=${setId}&page_size=100`;

      this._log('debug', 'API', `API request URL: ${url}`);
      this.logger?.perfStart(`fetchDifficulties:${setId}`);

      try {
        const response = await fetch(url);

        if (!response.ok) {
          this._log('error', 'API', `API request failed for difficulties of set ${setId}`, {
            status: response.status,
            statusText: response.statusText
          });
          throw new Error(`API request failed with status ${response.status}`);
        }

        const data = await response.json();
        this.logger?.perfEnd(`fetchDifficulties:${setId}`, { setId, status: data.status });

        if (data.status === 'success' && data.data) {
          // Sort by difficulty rating ascending
          const sorted = data.data.sort((a, b) => {
            return (parseFloat(a.difficulty_rating) || 0) - (parseFloat(b.difficulty_rating) || 0);
          });

          this._setCache(setId, sorted, this.setCache);
          this._log('info', 'API', `Difficulties for set ${setId} loaded and sorted`, {
            count: sorted.length,
            minStars: sorted[0]?.difficulty_rating,
            maxStars: sorted[sorted.length - 1]?.difficulty_rating,
            difficulties: sorted.map(d => ({
              id: d.id,
              version: d.version,
              stars: d.difficulty_rating
            }))
          });
          return sorted;
        } else {
          this._log('warn', 'API', `No difficulties found for set ${setId}`, {
            apiStatus: data.status,
            hasData: !!data.data
          });
          return [];
        }
      } catch (error) {
        this._log('error', 'API', `Error fetching difficulties for set ${setId}`, {
          error: error.message,
          stack: error.stack
        });
        throw error;
      }
    }

    // =========================================================================
    // Utility Methods
    // =========================================================================

    /**
     * Clear cache for a specific beatmap
     * @param {number|string} beatmapId
     */
    clearBeatmapCache(beatmapId) {
      const key = String(beatmapId);
      const hadCache = !!this.beatmapCache[key];
      delete this.beatmapCache[key];
      this._log('info', 'DATA', `Cache cleared for beatmap ${key}`, { hadCache });
    }

    /**
     * Clear cache for a specific set
     * @param {number|string} setId
     */
    clearSetCache(setId) {
      const key = String(setId);
      const hadCache = !!this.setCache[key];
      delete this.setCache[key];
      this._log('info', 'DATA', `Cache cleared for set ${key}`, { hadCache });
    }

    /**
     * Clear all caches
     */
    clearAllCaches() {
      const beatmapCount = Object.keys(this.beatmapCache).length;
      const setCount = Object.keys(this.setCache).length;
      this.beatmapCache = {};
      this.setCache = {};
      this._log('info', 'DATA', 'All caches cleared', { beatmapCount, setCount });
    }

    /**
     * Get cache statistics
     */
    getCacheStats() {
      const stats = {
        beatmaps: Object.keys(this.beatmapCache).length,
        sets: Object.keys(this.setCache).length,
        pendingRequests: Object.keys(this.pendingRequests).length
      };
      this._log('debug', 'DATA', 'Cache stats', stats);
      return stats;
    }

    /**
     * Destroy the store
     */
    destroy() {
      this._log('info', 'LIFECYCLE', 'Destroying store', {
        cachedBeatmaps: Object.keys(this.beatmapCache).length,
        cachedSets: Object.keys(this.setCache).length,
        pendingRequests: Object.keys(this.pendingRequests).length
      });

      this.beatmapCache = {};
      this.setCache = {};
      this.pendingRequests = {};

      this._log('info', 'LIFECYCLE', 'Store destroyed');
    }
  }

  // =========================================================================
  // Global Singleton
  // =========================================================================

  // Create global instance
  if (!window.__beatmapDataStore) {
    window.__beatmapDataStore = new BeatmapDataStore();
  }

  // Export for module systems
  if (typeof module !== 'undefined' && module.exports) {
    module.exports = BeatmapDataStore;
  }
})();