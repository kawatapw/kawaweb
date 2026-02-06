/** 
 * ============================================================================
 * Section: Badges component
 * ============================================================================
*/

Vue.component('badge', {
  props: {
    badge: {
      type: Object,
      required: true,
      validator: function (value) {
        return value !== null && typeof value === 'object' && value.hasOwnProperty('styles');
      }
    },
    type: {
      type: Number,
      default: 0,
      validator: function (value) {
        return [0, 1].includes(value);
      }
    },
    test: {
      type: Number,
      default: 0,
      validator: function (value) {
        return [0, 1].includes(value);
      }
    }
  },
  data: function () {
    return {
      badgeId: 'badge-' + Math.random().toString(36).substr(2, 9)
    }
  },
  watch: {
    type: function (newVal) {
      if (typeof newVal !== 'number') {
        this.type = Number(newVal);
      }
    }
  },
  computed: {
    badgeStyle() {
      return {
        '--badge-styles-color': this.badge.styles.color,
        '--badge-hue': this.badge.styles.color,
        '--badge-bg-color': `hsl(${this.badge.styles.color}, 20%, 30%)`,
        '--badge-text-color': `hsl(${this.badge.styles.color}, 100%, 80%)`,
        '--badge-border-color': `hsl(${this.badge.styles.color}, 40%, 35%)`,
        'background-color': `var(--badge-bg-color)`,
        'color': `var(--badge-text-color)`,
        'border': `1px solid var(--badge-border-color)`
      };
    },
    panelStyle() {
      return {
        '--panel-bg-color': `hsl(${this.badge.styles.color}, 20%, 20%)`,
        '--panel-text-color': `hsl(${this.badge.styles.color}, 100%, 80%)`,
        'background-color': `var(--panel-bg-color)`,
        'color': `var(--panel-text-color)`
      };
    },
    badgeDescription() {
      return this.badge.description || `${this.badge.name} badge`;
    }
  },
  created() {
    if (this.test === 1) {
      this.$log.debug('COMPONENTS', 'Type:', this.type);
      this.$log.debug('COMPONENTS', 'Badge:', this.badge);
      this.$log.debug('COMPONENTS', 'Type === 0:', this.type === 0);
      this.$log.debug('COMPONENTS', 'Type === 1:', this.type === 1);
    }
  },
  template: `#badge-template`
});


/**
 * ============================================================================
 * Section: User-Profile Sub-Components
 * ============================================================================
 *
 * Sub-components for the user-profile master component.
 * These components handle specific display styles and functionality.
 */

/**
 * ============================================================================
 * Component: UserProfileHoverPanel
 * ============================================================================
 *
 * Hover panel for username style that shows detailed user information.
 *
 * Props:
 * @param {Object} user - User data object
 * @param {Object} statusData - User status data
 * @param {Boolean} showCountry - Whether to show country
 * @param {Boolean} showClan - Whether to show clan tag
 * @param {Boolean} showBadges - Whether to show badges
 * @param {Boolean} showStatus - Whether to show status
 * @param {Boolean} visible - Whether panel is visible
 * @param {Boolean} interactive - Whether to enable interactions
 * @param {String} avatarUrl - Avatar image URL
 * @param {String} bannerUrl - Banner image URL
 * @param {String} flagUrl - Flag image URL
 * @param {String} clanUrl - Clan page URL
 * @param {String} profileUrl - Profile page URL
 * @param {Object} currentStats - Current mode stats
 * @param {Function} formatNumber - Number formatting function
 * @param {Function} formatAccuracy - Accuracy formatting function
 * @param {Function} statusText - Status text getter
 * @param {Function} statusClasses - Status CSS classes getter
 * @param {Function} mouseEnterPanel - Mouse enter handler
 * @param {Function} mouseLeavePanel - Mouse leave handler
 *
 * @component user-profile-hover-panel
 */
Vue.component('user-profile-hover-panel', {
  props: {
    user: { type: Object, required: true },
    statusData: { type: Object, default: null },
    showCountry: { type: Boolean, default: false },
    showClan: { type: Boolean, default: true },
    showBadges: { type: Boolean, default: true },
    showStatus: { type: Boolean, default: true },
    visible: { type: Boolean, default: false },
    interactive: { type: Boolean, default: true },
    avatarUrl: { type: String, required: true },
    bannerUrl: { type: String, required: true },
    flagUrl: { type: String, required: true },
    clanUrl: { type: String, required: true },
    profileUrl: { type: String, required: true },
    currentStats: { type: Object, default: null },
    formatNumber: { type: Function, required: true },
    formatAccuracy: { type: Function, required: true },
    statusText: { type: String, required: true },
    statusClasses: { type: Object, required: true },
    mouseEnterPanel: { type: Function, required: true },
    mouseLeavePanel: { type: Function, required: true }
  },
  created() {
    this.$log = ColorfulLogger.child('Comp | User Profile | HoverPanel');
    this.$log.debug('LIFECYCLE', 'Component created', {
      hasUser: !!this.user,
      hasAvatarUrl: !!this.avatarUrl,
      hasBannerUrl: !!this.bannerUrl,
      hasFlagUrl: !!this.flagUrl,
      hasClanUrl: !!this.clanUrl,
      hasProfileUrl: !!this.profileUrl,
      hasCurrentStats: !!this.currentStats,
      avatarUrl: this.avatarUrl,
      bannerUrl: this.bannerUrl,
      flagUrl: this.flagUrl,
      clanUrl: this.clanUrl,
      profileUrl: this.profileUrl
    });
  },
  computed: {
    panelClasses() {
      return {
        'user-profile-panel': true,
        'visible': this.visible,
        'interactive': this.interactive
      };
    }
  },
  template: `
    <div :class="panelClasses"
         @mouseenter="mouseEnterPanel"
         @mouseleave="mouseLeavePanel">
      
      <!-- Panel background -->
      <div class="user-profile-panel-background"
           :style="'background-image: url(' + bannerUrl + ')'"></div>
      
      <!-- Panel header -->
      <div class="user-profile-panel-header">
        <div class="user-profile-panel-avatar"
             :style="'background-image: url(' + avatarUrl + ')'"></div>
        
        <div class="user-profile-panel-info">
          <div class="user-profile-panel-name">
            <span v-if="showClan && user.info.clan_tag" class="user-profile-panel-clan">
              [{{ user.info.clan_tag }}]
            </span>
            {{ user.info.name }}
          </div>
          
          <div v-if="currentStats" class="user-profile-panel-rank">
            <span class="user-profile-panel-global-rank">
              #{{ currentStats.rank || '?' }}
            </span>
            <span v-if="showCountry && user.info.country" class="user-profile-panel-country">
              <img :src="flagUrl" :alt="user.info.country" class="user-flag" />
              #{{ currentStats.country_rank || '?' }}
            </span>
          </div>
          
          <div v-if="showBadges && user.info.badges && user.info.badges.length > 0"
               class="user-profile-panel-badges">
            <badge v-for="badge in user.info.badges"
                   :key="badge.id"
                   :badge="badge"
                   :type="1"></badge>
          </div>
        </div>
      </div>
      
      <!-- Panel stats -->
      <div v-if="currentStats" class="user-profile-panel-stats">
        <div class="user-profile-panel-stat-item">
          <div class="user-profile-panel-stat-value">
            {{ formatNumber(currentStats.pp) || '0' }}
          </div>
          <div class="user-profile-panel-stat-label">PP</div>
        </div>
        
        <div class="user-profile-panel-stat-item">
          <div class="user-profile-panel-stat-value">
            {{ formatAccuracy(currentStats.acc) }}%
          </div>
          <div class="user-profile-panel-stat-label">Accuracy</div>
        </div>
        
        <div class="user-profile-panel-stat-item">
          <div class="user-profile-panel-stat-value">
            {{ formatNumber(currentStats.plays) || '0' }}
          </div>
          <div class="user-profile-panel-stat-label">Plays</div>
        </div>
      </div>
      
      <!-- Panel status -->
      <div v-if="showStatus && statusData" class="user-profile-panel-status" :class="statusClasses">
        <i class="fas fa-circle"></i>
        <span>{{ statusText }}</span>
      </div>
    </div>
  `
});

/**
 * ============================================================================
 * Component: UserProfileUsername
 * ============================================================================
 *
 * Username style component with hover panel.
 *
 * Props:
 * @param {Object} user - User data object
 * @param {Object} statusData - User status data
 * @param {Boolean} showCountry - Whether to show country
 * @param {Boolean} showClan - Whether to show clan tag
 * @param {Boolean} showBadges - Whether to show badges
 * @param {Boolean} showStatus - Whether to show status
 * @param {Boolean} interactive - Whether to enable interactions
 * @param {String} avatarUrl - Avatar image URL
 * @param {String} bannerUrl - Banner image URL
 * @param {String} flagUrl - Flag image URL
 * @param {String} clanUrl - Clan page URL
 * @param {String} profileUrl - Profile page URL
 * @param {Object} currentStats - Current mode stats
 * @param {Boolean} profileVisible - Whether profile panel is visible
 * @param {Function} formatNumber - Number formatting function
 * @param {Function} formatAccuracy - Accuracy formatting function
 * @param {Function} statusText - Status text getter
 * @param {Function} statusClasses - Status CSS classes getter
 * @param {Function} showProfile - Show profile handler
 * @param {Function} hideProfile - Hide profile handler
 * @param {Function} handleUsernameClick - Username click handler
 * @param {Function} handleClanClick - Clan click handler
 *
 * @component user-profile-username
 */
Vue.component('user-profile-username', {
  props: {
    user: { type: Object, required: true },
    statusData: { type: Object, default: null },
    showCountry: { type: Boolean, default: false },
    showClan: { type: Boolean, default: true },
    showBadges: { type: Boolean, default: true },
    showStatus: { type: Boolean, default: true },
    interactive: { type: Boolean, default: true },
    avatarUrl: { type: String, required: true },
    bannerUrl: { type: String, required: true },
    flagUrl: { type: String, required: true },
    clanUrl: { type: String, required: true },
    profileUrl: { type: String, required: true },
    currentStats: { type: Object, default: null },
    profileVisible: { type: Boolean, default: false },
    formatNumber: { type: Function, required: true },
    formatAccuracy: { type: Function, required: true },
    statusText: { type: String, required: true },
    statusClasses: { type: Object, required: true },
    statusString: { type: String, required: true },
    showProfile: { type: Function, required: true },
    hideProfile: { type: Function, required: true },
    handleUsernameClick: { type: Function, required: true },
    handleClanClick: { type: Function, required: true },
    mouseEnterPanel: { type: Function, required: true },
    mouseLeavePanel: { type: Function, required: true }
  },
  created() {
    this.$log = ColorfulLogger.child('Comp | User Profile | Username');
    this.$log.debug('LIFECYCLE', 'Component created', {
      hasUser: !!this.user,
      hasAvatarUrl: !!this.avatarUrl,
      hasBannerUrl: !!this.bannerUrl,
      hasFlagUrl: !!this.flagUrl,
      hasClanUrl: !!this.clanUrl,
      hasProfileUrl: !!this.profileUrl,
      hasCurrentStats: !!this.currentStats,
      avatarUrl: this.avatarUrl,
      bannerUrl: this.bannerUrl,
      flagUrl: this.flagUrl,
      clanUrl: this.clanUrl,
      profileUrl: this.profileUrl
    });
  },
  template: `#user-profile-username-template`
});

/**
 * ============================================================================
 * Component: UserProfileCard
 * ============================================================================
 *
 * Card style component with banner, avatar, stats, and status strip.
 *
 * Props:
 * @param {Object} user - User data object
 * @param {Object} statusData - User status data
 * @param {Boolean} showCountry - Whether to show country
 * @param {Boolean} showClan - Whether to show clan tag
 * @param {Boolean} showBadges - Whether to show badges
 * @param {Boolean} showStatus - Whether to show status
 * @param {Boolean} isLoadingStatus - Whether status is loading
 * @param {String} avatarUrl - Avatar image URL
 * @param {String} bannerUrl - Banner image URL
 * @param {String} flagUrl - Flag image URL
 * @param {String} clanUrl - Clan page URL
 * @param {String} profileUrl - Profile page URL
 * @param {Object} currentStats - Current mode stats
 * @param {Function} formatNumber - Number formatting function
 * @param {Function} formatAccuracy - Accuracy formatting function
 * @param {Function} statusText - Status text getter
 * @param {Function} statusClasses - Status CSS classes getter
 *
 * @component user-profile-card
 */
Vue.component('user-profile-card', {
  props: {
    user: { type: Object, required: true },
    statusData: { type: Object, default: null },
    showCountry: { type: Boolean, default: true },
    showClan: { type: Boolean, default: true },
    showBadges: { type: Boolean, default: true },
    showStatus: { type: Boolean, default: true },
    isLoadingStatus: { type: Boolean, default: false },
    avatarUrl: { type: String, required: true },
    bannerUrl: { type: String, required: true },
    flagUrl: { type: String, required: true },
    clanUrl: { type: String, required: true },
    profileUrl: { type: String, required: true },
    currentStats: { type: Object, default: null },
    formatNumber: { type: Function, required: true },
    formatAccuracy: { type: Function, required: true },
    statusText: { type: String, required: true },
    statusClasses: { type: Object, required: true },
    statusString: { type: String, required: true }
  },
  created() {
    this.$log = ColorfulLogger.child('Comp | User Profile | Card');
    this.$log.debug('LIFECYCLE', 'Component created', {
      hasUser: !!this.user,
      hasAvatarUrl: !!this.avatarUrl,
      hasBannerUrl: !!this.bannerUrl,
      hasFlagUrl: !!this.flagUrl,
      hasClanUrl: !!this.clanUrl,
      hasProfileUrl: !!this.profileUrl,
      hasCurrentStats: !!this.currentStats,
      avatarUrl: this.avatarUrl,
      bannerUrl: this.bannerUrl,
      flagUrl: this.flagUrl,
      clanUrl: this.clanUrl,
      profileUrl: this.profileUrl
    });
  },
  template: `#user-profile-card-template`
});

/**
 * ============================================================================
 * Component: UserProfileSearch
 * ============================================================================
 *
 * Search style component for compact display in lists.
 *
 * Props:
 * @param {Object} user - User data object
 * @param {Boolean} showCountry - Whether to show country
 * @param {Boolean} showClan - Whether to show clan tag
 * @param {String} avatarUrl - Avatar image URL
 * @param {String} flagUrl - Flag image URL
 * @param {String} clanUrl - Clan page URL
 * @param {String} profileUrl - Profile page URL
 * @param {Object} currentStats - Current mode stats
 * @param {Function} formatNumber - Number formatting function
 * @param {Function} formatAccuracy - Accuracy formatting function
 *
 * @component user-profile-search
 */
Vue.component('user-profile-search', {
  props: {
    user: { type: Object, required: true },
    showCountry: { type: Boolean, default: false },
    showClan: { type: Boolean, default: true },
    avatarUrl: { type: String, required: true },
    bannerUrl: { type: String, required: false },
    flagUrl: { type: String, required: true },
    clanUrl: { type: String, required: true },
    profileUrl: { type: String, required: true },
    currentStats: { type: Object, default: null },
    formatNumber: { type: Function, required: true },
    formatAccuracy: { type: Function, required: true }
  },
  created() {
    this.$log = ColorfulLogger.child('Comp | User Profile | Search');
    this.$log.debug('COMPONENTS', 'Component created', {
      hasUser: !!this.user,
      hasAvatarUrl: !!this.avatarUrl,
      hasFlagUrl: !!this.flagUrl,
      hasClanUrl: !!this.clanUrl,
      hasProfileUrl: !!this.profileUrl,
      hasCurrentStats: !!this.currentStats,
      avatarUrl: this.avatarUrl,
      flagUrl: this.flagUrl,
      clanUrl: this.clanUrl,
      profileUrl: this.profileUrl
    });
  },
  template: `#user-profile-search-template`
});

/**
 * ============================================================================
 * Component: User-Profile (Master Component)
 * ============================================================================
 *
 * Master component that orchestrates sub-components for different display styles.
 *
 * Features:
 * - Multiple display styles: username, card, search
 * - Automatic data fetching when only userid is provided
 * - Dynamic name formatting: [country] [clan] [username]
 * - Status fetching from API
 * - Badge display with popups
 * - Clan tag linking (future: clan flag/image display)
 * - Username linking to profile page
 * - Optional country display
 *
 * Props:
 * @param {Object} user - User data object (optional if userid provided)
 * @param {String} userid - User ID to fetch data from (required if no user prop)
 * @param {String} displayStyle - Display style: 'username', 'card', or 'search' (default: 'username')
 * @param {Boolean} showCountry - Whether to show country in name display (default: false)
 * @param {Boolean} showClan - Whether to show clan tag (default: true)
 * @param {Boolean} showBadges - Whether to show badges (default: true)
 * @param {Boolean} showStatus - Whether to show user status (default: true)
 * @param {Boolean} interactive - Whether to enable hover/click interactions (default: true)
 * @param {String} domain - API domain (default: 'kawata.pw')
 *
 * Usage Examples:
 *
 * <!-- Username style (default) - shows just the username as a link -->
 * <user-profile userid="12345" display-style="username" />
 *
 * <!-- Card style - shows banner, avatar, stats, and status -->
 * <user-profile :user="userData" display-style="card" showCountry showBadges />
 *
 * <!-- Search style - compact display for search results -->
 * <user-profile :user="userData" display-style="search" />
 *
 * <!-- With only userid (fetches data automatically) -->
 * <user-profile userid="12345" display-style="card" showCountry showClan showBadges showStatus />
 *
 * @component user-profile
 */

/**
 * ============================================================================
 * Component: User-Profile (Master Component)
 * ============================================================================
 *
 * Master component that orchestrates sub-components for different display styles.
 *
 * Features:
 * - Multiple display styles: username, card, search
 * - Automatic data fetching when only userid is provided
 * - Dynamic name formatting: [country] [clan] [username]
 * - Status fetching from API
 * - Badge display with popups
 * - Clan tag linking (future: clan flag/image display)
 * - Username linking to profile page
 * - Optional country display
 *
 * Props:
 * @param {Object} user - User data object (optional if userid provided)
 * @param {String} userid - User ID to fetch data from (required if no user prop)
 * @param {String} displayStyle - Display style: 'username', 'card', or 'search' (default: 'username')
 * @param {Boolean} showCountry - Whether to show country in name display (default: false)
 * @param {Boolean} showClan - Whether to show clan tag (default: true)
 * @param {Boolean} showBadges - Whether to show badges (default: true)
 * @param {Boolean} showStatus - Whether to show user status (default: true)
 * @param {Boolean} interactive - Whether to enable hover/click interactions (default: true)
 * @param {String} domain - API domain (default: 'kawata.pw')
 *
 * Usage Examples:
 *
 * <!-- Username style (default) - shows just the username as a link -->
 * <user-profile userid="12345" display-style="username" />
 *
 * <!-- Card style - shows banner, avatar, stats, and status -->
 * <user-profile :user="userData" display-style="card" showCountry showBadges />
 *
 * <!-- Search style - compact display for search results -->
 * <user-profile :user="userData" display-style="search" />
 *
 * <!-- With only userid (fetches data automatically) -->
 * <user-profile userid="12345" display-style="card" showCountry showClan showBadges showStatus />
 *
 * @component user-profile
 */
Vue.component('user-profile', {
  props: {
    /**
     * User data object (optional if userid provided)
     * @type {Object}
     */
    user: { type: Object, default: null },
    
    /**
     * User ID to fetch data from (required if no user prop)
     * @type {String|Number}
     */
    userid: { type: [String, Number], default: null },
    
    /**
     * Display style: 'username', 'card', or 'search'
     * @type {String}
     * @default 'username'
     */
    displayStyle: {
      type: String,
      default: 'username',
      validator: function(value) {
        return ['username', 'card', 'search'].includes(value);
      }
    },
    
    /**
     * Whether to show country in name display
     * @type {Boolean}
     * @default false
     */
    showCountry: { type: Boolean, default: false },
    
    /**
     * Whether to show clan tag
     * @type {Boolean}
     * @default true
     */
    showClan: { type: Boolean, default: true },
    
    /**
     * Whether to show badges
     * @type {Boolean}
     * @default true
     */
    showBadges: { type: Boolean, default: true },
    
    /**
     * Whether to show user status
     * @type {Boolean}
     * @default true
     */
    showStatus: { type: Boolean, default: true },
    
    /**
     * Whether to enable hover/click interactions
     * @type {Boolean}
     * @default true
     */
    interactive: { type: Boolean, default: true },
    
    /**
     * API domain
     * @type {String}
     * @default 'kawata.pw'
     */
    domain: { type: String, default: domain || 'kawata.pw' }
  },
  
  data: function() {
    return {
      // Internal user data (fetched if only userid provided)
      internalUser: null,
      
      // Loading states
      isLoadingUser: false,
      isLoadingStatus: false,
      
      // Status data
      statusData: null,
      
      // UI state
      profileVisible: false,
      
      // Mouse tracking for hover panel
      mouseOverPanel: false,
      
      // Error state
      error: null,
      
      // Interval for periodic status checking
      statusInterval: null
    };
  },

  created() {
    this.$log = ColorfulLogger.child('Comp | User Profile');
    this.$log.debug('LIFECYCLE', 'Component created', {
      userid: this.userid,
      hasUser: !!this.user,
      showStatus: this.showStatus,
      hasUserData: !!this.userData,
      userData: this.userData
    });
    
    // Fetch user data if only userid is provided
    if (this.userid && !this.user) {
      this.$log.debug('LIFECYCLE', 'Fetching user data (userid provided, no user prop)', { userid: this.userid });
      this.fetchUserData();
    } else if (this.userid && this.user) {
      this.$log.debug('LIFECYCLE', 'Both userid and user provided, using user prop', { userid: this.userid });
    } else if (!this.userid && this.user) {
      this.$log.debug('LIFECYCLE', 'Only user prop provided');
    } else {
      this.$log.debug('LIFECYCLE', 'No userid or user provided');
    }
    
    // Fetch status if needed (when user prop is provided directly)
    if (this.showStatus && this.normalizedUserData) {
      this.$log.debug('LIFECYCLE', 'Starting initial status fetch and interval');
      this.fetchStatus();
      this.startStatusInterval();
    }
  },
  
  computed: {
    /**
     * Get the user data to use (internal or prop)
     */
    userData() {
      return this.internalUser || this.user;
    },
    
    /**
     * Normalized user data in standard format
     */
    normalizedUserData() {
      return this.normalizeUser(this.userData);
    },
    
    /**
     * Check if we have user data
     */
    hasUserData() {
      return this.userData !== null && this.userData !== undefined;
    },
    
    /**
     * Check if we have full user data (not just leaderboard)
     */
    isFullData() {
      return this.normalizedUserData && this.normalizedUserData.info && this.normalizedUserData.stats;
    },
    
    /**
     * Get current mode stats
     * Handles multiple possible data structures from API
     */
    currentStats() {
      if (!this.normalizedUserData) {
        this.$log.debug('DATA', 'No userData for currentStats');
        return null;
      }
      
      // Try stats.current first (new structure)
      if (this.normalizedUserData.stats?.current) {
        const firstMode = Object.keys(this.normalizedUserData.stats.current)[0];
        const stats = this.normalizedUserData.stats.current[firstMode] || null;
        this.$log.debug('DATA', 'Current stats (stats.current)', { firstMode, stats });
        return stats;
      }
      
      // Try stats directly (old structure) - use preferred_mode to get the right stats
      if (this.normalizedUserData.stats) {
        const preferredMode = this.normalizedUserData.info?.preferred_mode || 0;
        const stats = this.normalizedUserData.stats[preferredMode] || null;
        this.$log.debug('DATA', 'Current stats (direct stats)', { preferredMode, stats });
        return stats;
      }
      
      this.$log.debug('DATA', 'No stats found', { userData: this.normalizedUserData });
      return null;
    },
    
    /**
     * Get avatar URL
     * Handles multiple possible ID field names from API
     */
    avatarUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('DATA', 'No userData for avatarUrl');
        return '';
      }
      
      // Try multiple possible ID field names
      const userId = this.normalizedUserData.info.id || this.normalizedUserData.player_id || this.normalizedUserData.id || this.normalizedUserData.user_id;
      this.$log.debug('DATA', 'Avatar URL', {
        userId,
        player_id: this.normalizedUserData.player_id,
        id: this.normalizedUserData.id,
        user_id: this.normalizedUserData.user_id,
        domain: this.domain
      });
      
      if (!userId) {
        this.$log.error('DATA', 'No userId found for avatar', { userData: this.normalizedUserData });
        return '';
      }
      
      return `https://a.${this.domain}/${userId}`;
    },
    
    /**
     * Get banner URL
     * Handles multiple possible ID field names from API
     */
    bannerUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('DATA', 'No userData for bannerUrl');
        return '';
      }
      
      // Try multiple possible ID field names
      const userId = this.normalizedUserData.info.id || this.normalizedUserData.player_id || this.normalizedUserData.id || this.normalizedUserData.user_id;
      this.$log.debug('DATA', 'Banner URL', {
        userId,
        player_id: this.normalizedUserData.player_id,
        id: this.normalizedUserData.id,
        user_id: this.normalizedUserData.user_id
      });
      
      if (!userId) {
        this.$log.error('DATA', 'No userId found for banner', { userData: this.normalizedUserData });
        return '';
      }
      
      return `/banners/${userId}`;
    },

    /**
     * Get banner URL
     * Handles multiple possible ID field names from API
     */
    backgroundUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('DATA', 'No userData for bannerUrl');
        return '';
      }
      
      // Try multiple possible ID field names
      const userId = this.normalizedUserData.info.id || this.normalizedUserData.player_id || this.normalizedUserData.id || this.normalizedUserData.user_id;
      this.$log.debug('DATA', 'Banner URL', {
        userId,
        player_id: this.normalizedUserData.player_id,
        id: this.normalizedUserData.id,
        user_id: this.normalizedUserData.user_id
      });
      
      if (!userId) {
        this.$log.error('DATA', 'No userId found for banner', { userData: this.normalizedUserData });
        return '';
      }
      
      return `/backgrounds/${userId}`;
    },
    
    /**
     * Get flag URL
     * Handles country field in multiple possible locations
     */
    flagUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('DATA', 'No userData for flagUrl');
        return '';
      }
      
      // Try country in info first, then at root level
      const country = this.normalizedUserData.info?.country || this.normalizedUserData.country;
      this.$log.debug('DATA', 'Flag URL', {
        country,
        infoCountry: this.normalizedUserData.info?.country,
        rootCountry: this.normalizedUserData.country
      });
      
      if (!country) {
        this.$log.debug('DATA', 'No country found', { userData: this.normalizedUserData });
        return '';
      }
      
      return `/static/images/flags/${country.toUpperCase()}.png`;
    },
    
    /**
     * Get clan URL
     * Handles clan_id field in multiple possible locations
     */
    clanUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('DATA', 'No userData for clanUrl');
        return '';
      }
      
      // Try clan_id in info first, then at root level
      const clanId = this.normalizedUserData.info?.clan_id || this.normalizedUserData.clan_id;
      this.$log.debug('DATA', 'Clan URL', {
        clanId,
        infoClanId: this.normalizedUserData.info?.clan_id,
        rootClanId: this.normalizedUserData.clan_id
      });
      
      if (!clanId) {
        this.$log.debug('DATA', 'No clan_id found', { userData: this.normalizedUserData });
        return '';
      }
      
      return `/clans/${clanId}`;
    },
    
    /**
     * Get profile URL
     * Handles multiple possible ID field names from API
     */
    profileUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('DATA', 'No userData for profileUrl');
        return '';
      }
      
      // Try multiple possible ID field names
      const userId = this.normalizedUserData.info.id || this.normalizedUserData.player_id || this.normalizedUserData.id || this.normalizedUserData.user_id;
      this.$log.debug('DATA', 'Profile URL', {
        userId,
        player_id: this.normalizedUserData.player_id,
        id: this.normalizedUserData.id,
        user_id: this.normalizedUserData.user_id
      });
      
      if (!userId) {
        this.$log.error('DATA', 'No userId found for profile', { userData: this.normalizedUserData });
        return '';
      }
      
      return `/u/${userId}`;
    },
    
    /**
     * Status text getter
     */
    statusText() {
      if (!this.statusData || this.statusData.online === 'false' || this.statusData.online === false) {
        if (this.statusData && this.statusData.last_seen) {
          return `Offline | Last seen ${this.formatTimeAgo(this.statusData.last_seen)}`;
        }
        return 'Offline';
      }
      
      // Check if status object exists
      if (!this.statusData.status) {
        return 'Online';
      }
      
      // Use actionIntToStr from profile.js logic
      const action = this.statusData.status.action;
      const infoText = this.statusData.status.info_text;
      
      switch (action) {
        case 0:
          return 'Idle: 🔍 Song Select';
        case 1:
          return '🌙 AFK';
        case 2:
          return `Playing: 🎶 ${infoText}`;
        case 3:
          return `Editing: 🔨 ${infoText}`;
        case 4:
          return `Modding: 🔨 ${infoText}`;
        case 5:
          return 'In Multiplayer: Song Select';
        case 6:
          return `Watching: 👓 ${infoText}`;
        // 7 not used
        case 8:
          return `Testing: 🎾 ${infoText}`;
        case 9:
          return `Submitting: 🧼 ${infoText}`;
        // 10 paused, never used
        case 11:
          return 'Idle: 🏢 In multiplayer lobby';
        case 12:
          return `In Multiplayer: Playing 🌍 ${infoText} 🎶`;
        case 13:
          return 'Idle: 🔍 Searching for beatmaps in osu!direct';
        default:
          return 'Unknown: 🚔 not yet implemented!';
      }
    },
    
    /**
     * Status CSS classes getter
     */
    statusClasses() {
      if (!this.statusData || this.statusData.online === 'false' || this.statusData.online === false) return { 'offline': true };
      
      // Check if status object exists
      if (!this.statusData.status) return { 'online': true };
      
      const action = this.statusData.status.action;
      
      if (action === 2 || action === 9) return { 'playing': true };
      if (action === 8) return { 'paused': true };
      if (action === 0) return { 'idle': true };
      if (action === 1) return { 'afk': true };
      
      return { 'online': true };
    },
    
    /**
     * Status string getter for CSS variable
     * Returns the status name as a string (e.g., "playing", "offline")
     */
    statusString() {
      if (!this.statusData || this.statusData.online === 'false' || this.statusData.online === false) return 'offline';
      
      // Check if status object exists
      if (!this.statusData.status) return 'online';
      
      const action = this.statusData.status.action;
      
      if (action === 2 || action === 9) return 'playing';
      if (action === 8) return 'paused';
      if (action === 0) return 'idle';
      if (action === 1) return 'afk';
      
      return 'online';
    },
    
    /**
     * Format accuracy
     */
    formatAccuracy() {
      return (acc) => {
        if (!acc) return '0.00';
        return parseFloat(acc).toFixed(2);
      };
    },
    
    /**
     * Format number
     */
    formatNumber() {
      return (num) => {
        if (!num) return '0';
        return num.toLocaleString();
      };
    }
  },
  
  watch: {
    /**
     * Watch for user prop changes
     */
    user: {
      handler: function(newUser) {
        if (newUser && !this.internalUser) {
          // Reset internal user if new user prop is provided
          this.internalUser = null;
          this.statusData = null;
          this.error = null;
          
          // Fetch status if needed
          if (this.showStatus) {
            this.fetchStatus();
          }
        }
      },
      deep: true
    },
    
    /**
     * Watch for userid changes
     */
    userid: {
      handler: function(newUserid) {
        if (newUserid && !this.user) {
          // Fetch user data if only userid is provided
          this.fetchUserData();
        }
      }
    },
    
    /**
     * Watch for showStatus changes
     */
    showStatus: {
      handler: function(newVal) {
        this.$log.debug('LIFECYCLE', 'showStatus changed', { newVal, hasNormalizedUserData: !!this.normalizedUserData });
        if (newVal && this.normalizedUserData) {
          this.fetchStatus();
          this.startStatusInterval();
        } else {
          this.stopStatusInterval();
        }
      }
    }
  },
  
  beforeDestroy() {
    // Clean up interval when component is destroyed
    this.stopStatusInterval();
  },
  
  methods: {
    /**
     * Normalize user data to standard format
     */
    normalizeUser(user) {
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
          badges: normalized.badges || [],
          preferred_mode: 0, // default
        };
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
              country_rank: normalized.country_rank,
            }
          }
        };
      }
      
      return normalized;
    },
    
    /**
     * Get user ID from user data
     */
    getUserId() {
      if (!this.userData) return null;
      return this.userData.info?.id || this.userData.player_id || this.userData.id;
    },
    
    /**
     * Fetch user data from API
     */
    async fetchUserData() {
      if (!this.userid || this.isLoadingUser) {
        this.$log.debug('NETWORK', 'fetchUserData early return', {
          hasUserid: !!this.userid,
          isLoadingUser: this.isLoadingUser
        });
        return;
      }
      
      this.isLoadingUser = true;
      this.error = null;
      
      this.$log.debug('NETWORK', 'fetchUserData starting');
      
      try {
        const response = await fetch(
          `${window.location.protocol}//api.${this.domain}/v1/get_player_info?id=${this.userid}&scope=all`
        );
        
        if (!response.ok) {
          throw new Error(`API request failed with status ${response.status}`);
        }
        
        const data = await response.json();
        
        this.$log.debug('API', 'Raw API response:', data);
        
        if (data.status === 'success' && data.player) {
          this.internalUser = data.player;
          this.$log.debug('API', 'User data loaded:', data.player);
          this.$log.debug('API', 'User data structure:', {
            hasPlayerId: data.player.hasOwnProperty('player_id'),
            hasId: data.player.hasOwnProperty('id'),
            playerIdValue: data.player.player_id,
            idValue: data.player.id,
            hasInfo: data.player.hasOwnProperty('info'),
            hasStats: data.player.hasOwnProperty('stats'),
            infoStructure: data.player.info,
            statsStructure: data.player.stats
          });
          
          // Fetch status if needed
          if (this.showStatus) {
            this.$log.debug('NETWORK', 'Fetching status after user data loaded');
            await this.fetchStatus();
            // Start periodic status checking after fetching user data
            this.$log.debug('NETWORK', 'Starting status interval after user data loaded');
            this.startStatusInterval();
          }
        } else {
          throw new Error('No user data found');
        }
      } catch (error) {
        this.$log.error('API', 'Error fetching user data:', error);
        this.error = error.message;
      } finally {
        this.isLoadingUser = false;
        this.$log.debug('NETWORK', 'fetchUserData completed');
      }
    },
    
    /**
     * Fetch user status from API
     */
    async fetchStatus() {
      if (!this.normalizedUserData || this.isLoadingStatus) {
        this.$log.debug('NETWORK', 'fetchStatus early return', {
          hasNormalizedUserData: !!this.normalizedUserData,
          isLoadingStatus: this.isLoadingStatus
        });
        return;
      }
      
      const userId = this.normalizedUserData.info.id;
      if (!userId) {
        this.$log.debug('NETWORK', 'fetchStatus early return - no userId');
        return;
      }
      
      this.isLoadingStatus = true;
      
      this.$log.debug('NETWORK', 'fetchStatus starting');
      
      try {
        const response = await fetch(
          `${window.location.protocol}//api.${this.domain}/v1/get_player_status?id=${userId}`
        );
        
        if (!response.ok) {
          throw new Error(`API request failed with status ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.status === 'success') {
          const oldStatus = this.statusData;
          this.statusData = data.player_status;
          this.$log.debug('API', 'Status data loaded:', data);
          this.$log.debug('DATA', 'Status data changed', { 
            oldStatus, 
            newStatus: this.statusData,
            online: this.statusData?.online,
            hasStatus: !!this.statusData?.status
          });
        } else {
          this.statusData = null;
          this.$log.warn('API', 'No status data found in response', data);
        }
      } catch (error) {
        this.$log.error('API', 'Error fetching status:', error);
        this.statusData = null;
      } finally {
        this.isLoadingStatus = false;
        this.$log.debug('NETWORK', 'fetchStatus completed');
      }
    },
    
    /**
     * Start periodic status checking
     */
    startStatusInterval() {
      // Clear any existing interval
      this.stopStatusInterval();
      
      this.$log.debug('LIFECYCLE', 'Starting status interval');
      
      // Check status every 30 seconds
      this.statusInterval = setInterval(() => {
        this.$log.debug('LIFECYCLE', 'Status interval tick', {
          hasNormalizedUserData: !!this.normalizedUserData,
          showStatus: this.showStatus,
          hasInterval: !!this.statusInterval
        });
        if (this.normalizedUserData && this.showStatus) {
          this.$log.debug('NETWORK', 'Fetching status due to interval');
          this.fetchStatus();
        }
      }, 30000);
    },
    
    /**
     * Stop periodic status checking
     */
    stopStatusInterval() {
      if (this.statusInterval) {
        clearInterval(this.statusInterval);
        this.statusInterval = null;
      }
    },
    
    /**
     * Show profile panel (for username style)
     */
    showProfile() {
      if (!this.interactive) return;
      
      // Lazy load full user data if not available
      if (!this.isFullData) {
        const userId = this.getUserId();
        if (userId && !this.userid) {
          this.userid = userId;
        }
        if (this.userid && !this.isLoadingUser) {
          this.fetchUserData();
        }
      }
      
      this.profileVisible = true;
    },
    
    /**
     * Hide profile panel (for username style)
     */
    hideProfile() {
      if (!this.interactive) return;
      // Only hide if not hovering over the panel
      if (!this.mouseOverPanel) {
        this.profileVisible = false;
      }
    },
    
    /**
     * Mouse enter panel handler
     */
    mouseEnterPanel() {
      this.mouseOverPanel = true;
    },
    
    /**
     * Mouse leave panel handler
     */
    mouseLeavePanel() {
      this.mouseOverPanel = false;
      this.profileVisible = false;
    },
    

    /**
     * Formats a date string or Unix timestamp to a "time ago" string.
     * @param {string|number} dateString - The date string from your score object (e.g., '2023-01-10T14:59:00Z') or Unix timestamp in seconds.
     * @returns {string} - A human-readable "time ago" string.
     */
    formatTimeAgo(dateString) {
        // Check if it's a Unix timestamp (number in seconds)
        let date;
        if (typeof dateString === 'number' || /^\d+$/.test(dateString)) {
            // Convert Unix timestamp (seconds) to milliseconds
            date = new Date(dateString * 1000);
        } else {
            // Treat as date string
            date = new Date(dateString);
        }
        
        const now = new Date();
        const seconds = Math.floor((now - date) / 1000);

        let interval = seconds / 31536000;
        if (interval >= 1) {
            const years = Math.floor(interval);
            return years === 1 ? "1 year ago" : years + " years ago";
        }
        
        interval = seconds / 2592000;
        if (interval >= 1) {
            const months = Math.floor(interval);
            return months === 1 ? "1 month ago" : months + " months ago";
        }
        
        interval = seconds / 86400;
        if (interval >= 1) {
            const days = Math.floor(interval);
            return days === 1 ? "1 day ago" : days + " days ago";
        }
        
        interval = seconds / 3600;
        if (interval >= 1) {
            const hours = Math.floor(interval);
            return hours === 1 ? "1 hour ago" : hours + " hours ago";
        }
        
        interval = seconds / 60;
        if (interval >= 1) {
            const minutes = Math.floor(interval);
            return minutes === 1 ? "1 minute ago" : minutes + " minutes ago";
        }
        
        return Math.floor(seconds) + " seconds ago";
    },
    

    
    /**
     * Handle username click
     */
    handleUsernameClick(event) {
      if (!this.interactive) return;
      // Allow default navigation
    },
    
    /**
     * Handle clan click
     */
    handleClanClick(event) {
      if (!this.interactive) return;
      // Allow default navigation
    }
  },
  
  template: `#user-profile-template`
});