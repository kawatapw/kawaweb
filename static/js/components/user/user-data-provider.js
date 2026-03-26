/**
 * User Data Provider
 * Vue component that provides user data and utilities to child components via provide/inject.
 * Wrap your app or component subtree with this to enable the new user profile system.
 */

const UserDataProvider = Vue.component('user-data-provider', {
  props: {
    /**
     * Optional: Pre-fetched user data map (userId -> userData)
     * If provided, these users will be available immediately without fetching
     */
    initialUsers: {
      type: Object,
      default: () => ({})
    },
    
    /**
     * Optional: Enable automatic status refresh for all users
     * @type {Boolean}
     * @default true
     */
    autoRefreshStatus: {
      type: Boolean,
      default: true
    },
    
    /**
     * Optional: Status refresh interval in milliseconds
     * @type {Number}
     * @default 30000
     */
    statusRefreshInterval: {
      type: Number,
      default: 30000
    }
  },
  
  data: function() {
    return {
      // Local reactive state for user data and status
      localUserData: new Map(),
      localStatusData: new Map(),
      isLoading: false,
      error: null,
      // Track loading states per user ID
      loadingStates: new Map(),
      // Track error states per user ID
      errorStates: new Map()
    };
  },
  
  created() {
    this.$log = (typeof ColorfulLogger !== 'undefined') ? ColorfulLogger.child('UserDataProvider') : console;
    
    this.$log.debug('LIFECYCLE', 'Component created', {
      initialUsersCount: Object.keys(this.initialUsers).length,
      autoRefreshStatus: this.autoRefreshStatus,
      statusRefreshInterval: this.statusRefreshInterval
    });
    
    // Initialize with provided user data
    if (this.initialUsers && typeof this.initialUsers === 'object') {
      for (const [userId, userData] of Object.entries(this.initialUsers)) {
        this.localUserData.set(userId, userData);
        this.$log.trace('DATA', 'Pre-loaded user data', { userId, userDataKeys: Object.keys(userData || {}) });
      }
      this.$log.info('DATA', 'Initialized with pre-fetched users', { count: Object.keys(this.initialUsers).length });
    }
    
    // Start status refresh if enabled
    if (this.autoRefreshStatus) {
      this.startStatusRefresh();
    }
  },
  
  beforeDestroy() {
    this.$log.debug('LIFECYCLE', 'Component beforeDestroy');
    this.stopStatusRefresh();
  },
  
  methods: {
    /**
     * Start periodic status refresh
     */
    startStatusRefresh() {
      this.$log.debug('CONFIG', 'Starting status refresh', {
        interval: this.statusRefreshInterval,
        currentControllerInterval: userDataController.config.statusRefreshInterval
      });
      
      // Update controller config if needed
      if (userDataController.config.statusRefreshInterval !== this.statusRefreshInterval) {
        userDataController.config.statusRefreshInterval = this.statusRefreshInterval;
        this.$log.info('CONFIG', 'Updated status refresh interval', { newInterval: this.statusRefreshInterval });
      }
      
      // Start the controller's refresh loop
      userDataController.startStatusRefresh();
    },
    
    /**
     * Stop periodic status refresh
     */
    stopStatusRefresh() {
      this.$log.debug('CONFIG', 'Stopping status refresh');
      userDataController.stopStatusRefresh();
    },
    
    /**
     * Fetch user data for a specific user ID
     * @param {string|number} userId - User ID to fetch
     * @returns {Promise<object>} Normalized user data
     */
    async fetchUser(userId) {
      const userIdStr = String(userId);
      this.$log.debug('DATA', 'Fetching user data', { userId: userIdStr });
      
      // Set loading state for this specific user
      this.loadingStates.set(userIdStr, true);
      this.errorStates.delete(userIdStr);
      
      try {
        const userData = await userDataController.getUser(userIdStr);
        this.localUserData.set(userIdStr, userData);
        this.loadingStates.delete(userIdStr);
        
        this.$log.info('DATA', 'User data fetched successfully', { 
          userId: userIdStr,
          hasStats: !!userData.stats,
          hasBadges: userData.info?.badges?.length > 0 
        });
        return userData;
      } catch (error) {
        this.loadingStates.delete(userIdStr);
        this.errorStates.set(userIdStr, error.message);
        
        this.$log.error('DATA', 'Failed to fetch user data', { 
          userId: userIdStr, 
          error: error.message,
          stack: error.stack 
        });
        throw error;
      }
    },
    
    /**
     * Fetch user status for a specific user ID
     * @param {string|number} userId - User ID to fetch status for
     * @returns {Promise<object>} Status data
     */
    async fetchStatus(userId) {
      const userIdStr = String(userId);
      this.$log.debug('DATA', 'Fetching user status', { userId: userIdStr });
      
      try {
        const statusData = await userDataController.getStatus(userIdStr);
        this.localStatusData.set(userIdStr, statusData);
        this.$log.trace('DATA', 'Status data updated', { userId: userIdStr, statusData });
        return statusData;
      } catch (error) {
        this.$log.error('DATA', 'Failed to fetch user status', { 
          userId: userIdStr, 
          error: error.message 
        });
        throw error;
      }
    },
    
  /**
   * Get user data from local cache or fetch if not available
   * @param {string|number} userId - User ID
   * @returns {object|null} User data (synchronous - returns null if not cached)
   */
  getUserData(userId) {
    const userIdStr = String(userId);
    const cachedData = this.localUserData.get(userIdStr);
    
    // Return cached data immediately if available
    if (cachedData) {
      this.$log.trace('DATA', 'getUserData: returning cached data', { 
        userId: userIdStr, 
        cacheSize: this.localUserData.size 
      });
      return cachedData;
    }
    
    // Check if already loading this user
    if (this.loadingStates.has(userIdStr)) {
      this.$log.trace('DATA', 'getUserData: already loading, returning null', { userId: userIdStr });
      return null;
    }
    
    // If not cached and not loading, trigger async fetch and return null
    // Vue's reactivity will update components when data arrives
    this.fetchUser(userIdStr).catch(error => {
      this.$log.error('DATA', 'getUserData: async fetch failed', { 
        userId: userIdStr, 
        error: error.message 
      });
    });
    
    this.$log.trace('DATA', 'getUserData: not cached, triggering async fetch', { userId: userIdStr });
    return null;
  },
    
    /**
     * Get status data from local cache
     * @param {string|number} userId - User ID
     * @returns {object|null} Status data
     */
    getStatusData(userId) {
      const userIdStr = String(userId);
      const data = this.localStatusData.get(userIdStr) || null;
      this.$log.trace('DATA', 'getStatusData called', { 
        userId: userIdStr, 
        hasData: !!data,
        cacheSize: this.localStatusData.size 
      });
      return data;
    },
    
    /**
     * Subscribe to status updates for a user
     * @param {string} userId - User ID
     * @param {function} callback - Callback(statusData)
     * @returns {function} Unsubscribe function
     */
    subscribeToStatus(userId, callback) {
      this.$log.debug('DATA', 'Subscribing to status updates', { userId: String(userId) });
      return userDataController.subscribeToStatus(userId, (statusData) => {
        // Update local cache
        this.localStatusData.set(String(userId), statusData);
        this.$log.trace('DATA', 'Status update received via subscription', { 
          userId: String(userId),
          status: statusData?.status?.action,
          online: statusData?.online 
        });
        // Call subscriber callback
        callback(statusData);
      });
    },
    
    /**
     * Check if user data is currently loading
     * @param {string|number} userId - User ID
     * @returns {boolean} True if loading
     */
    isUserLoading(userId) {
      const userIdStr = String(userId);
      const isLoading = this.loadingStates.has(userIdStr);
      this.$log.trace('DATA', 'isUserLoading called', { userId: userIdStr, isLoading });
      return isLoading;
    },
    
    /**
     * Get error state for a user
     * @param {string|number} userId - User ID
     * @returns {string|null} Error message or null if no error
     */
    getUserError(userId) {
      const userIdStr = String(userId);
      const error = this.errorStates.get(userIdStr) || null;
      this.$log.trace('DATA', 'getUserError called', { userId: userIdStr, hasError: !!error });
      return error;
    },
    
    /**
     * Clear error state for a user
     * @param {string|number} userId - User ID
     */
    clearUserError(userId) {
      const userIdStr = String(userId);
      this.errorStates.delete(userIdStr);
      this.$log.trace('DATA', 'clearUserError called', { userId: userIdStr });
    }
  },
  
  provide() {
    const self = this;
    
    return {
      // User data access
      getUserData: (userId) => self.getUserData(userId),
      getStatusData: (userId) => self.getStatusData(userId),
      fetchUser: (userId) => self.fetchUser(userId),
      fetchStatus: (userId) => self.fetchStatus(userId),
      
      // Loading and error state helpers
      isUserLoading: (userId) => self.isUserLoading(userId),
      getUserError: (userId) => self.getUserError(userId),
      clearUserError: (userId) => self.clearUserError(userId),
      
      // URL generators
      getAvatarUrl: (user) => userDataController.getAvatarUrl(user),
      getBannerUrl: (user) => userDataController.getBannerUrl(user),
      getFlagUrl: (country) => userDataController.getFlagUrl(country),
      getClanUrl: (clanId) => userDataController.getClanUrl(clanId),
      getProfileUrl: (user) => userDataController.getProfileUrl(user),
      getBackgroundUrl: (user) => userDataController.getBackgroundUrl(user),
      
      // Formatters
      formatNumber: Formatters.formatNumber.bind(Formatters),
      formatAccuracy: Formatters.formatAccuracy.bind(Formatters),
      formatDuration: Formatters.formatDuration.bind(Formatters),
      formatTimeAgo: Formatters.formatTimeAgo.bind(Formatters),
      formatDate: Formatters.formatDate.bind(Formatters),
      formatRank: Formatters.formatRank.bind(Formatters),
      getStatusText: Formatters.getStatusText.bind(Formatters),
      getStatusClass: Formatters.getStatusClass.bind(Formatters),
      getStatusString: Formatters.getStatusString.bind(Formatters),
      
      // Constants
      STATUS: typeof STATUS !== 'undefined' ? STATUS : {},
      GAME_MODES: typeof GAME_MODES !== 'undefined' ? GAME_MODES : {},
      MODS: typeof MODS !== 'undefined' ? MODS : {},
      RANK_GRADES: typeof RANK_GRADES !== 'undefined' ? RANK_GRADES : {},
      
      // Reactive state access
      isUserReady: (userId) => !!self.getUserData(userId),
      getCurrentStats: (userData) => userDataController.getCurrentStats(userData),
      
      // Subscription
      subscribeToStatus: (userId, callback) => self.subscribeToStatus(userId, callback)
    };
  },
  
  render: function(h) {
    // This component doesn't render anything itself
    // It only provides data to children
    return h('div', this.$slots.default);
  }
});

// Auto-register if not using explicit registration
if (typeof Vue !== 'undefined' && !Vue.options.components['user-data-provider']) {
  Vue.component('user-data-provider', UserDataProvider);
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UserDataProvider };
}