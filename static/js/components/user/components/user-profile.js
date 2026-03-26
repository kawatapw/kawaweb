/**
 * User Profile Component
 * Composed component that displays a user's profile with hover panel (username style).
 * This is the most feature-complete component, similar to the original user-profile.
 * Supports multiple display styles and cosmetic slots.
 */

const UserProfile = Vue.component('user-profile', {
  props: {
    /**
     * User ID or user data object
     * If not provided, will try to inject from parent
     */
    user: {
      type: [String, Number, Object],
      default: null
    },
    
    /**
     * Display style: 'username', 'card', 'search'
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
     * Show country flag
     * @type {Boolean}
     * @default false
     */
    showCountry: {
      type: Boolean,
      default: false
    },
    
    /**
     * Show clan tag
     * @type {Boolean}
     * @default true
     */
    showClan: {
      type: Boolean,
      default: true
    },
    
    /**
     * Show badges
     * @type {Boolean}
     * @default true
     */
    showBadges: {
      type: Boolean,
      default: true
    },
    
    /**
     * Show status indicator
     * @type {Boolean}
     * @default true
     */
    showStatus: {
      type: Boolean,
      default: true
    },
    
    /**
     * Enable hover/click interactions
     * @type {Boolean}
     * @default true
     */
    interactive: {
      type: Boolean,
      default: true
    },
    
    /**
     * Which mode's stats to show
     * @type {Number}
     * @default null (uses preferred mode)
     */
    mode: {
      type: Number,
      default: null
    },
    
    /**
     * Which stats to display
     * @type {Array}
     * @default ['pp', 'acc', 'plays']
     */
    statsToShow: {
      type: Array,
      default: () => ['pp', 'acc', 'plays']
    },
    
    /**
     * Additional CSS classes
     */
    customClass: {
      type: String,
      default: ''
    }
  },
  
  inject: {
    // Inject utilities from UserDataProvider
    getUserData: { default: () => null },
    getAvatarUrl: { default: () => '' },
    getBannerUrl: { default: () => '' },
    getFlagUrl: { default: () => '' },
    getClanUrl: { default: () => '' },
    getProfileUrl: { default: () => '' },
    getStatusData: { default: () => null },
    getStatusString: { default: () => 'online' },
    getStatusClass: { default: () => 'online' },
    isUserLoading: { default: () => false },
    getUserError: { default: () => null },
    formatNumber: { default: () => (n) => n },
    formatAccuracy: { default: () => (a) => a.toFixed(2) },
    formatTimeAgo: { default: () => (d) => d }
  },
  
  data: function() {
    return {
      // UI state
      profileVisible: false,
      mouseOverPanel: false,
      
      // Loading states
      isLoadingUser: false,
      isLoadingStatus: false,
      
      // Error state
      error: null
    };
  },
  
  created() {
    this.$log = (typeof ColorfulLogger !== 'undefined') ? ColorfulLogger.child('UserProfile') : console;
    
    this.$log.debug('LIFECYCLE', 'Component created', {
      props: {
        user: this.user,
        displayStyle: this.displayStyle,
        showCountry: this.showCountry,
        showClan: this.showClan,
        showBadges: this.showBadges,
        showStatus: this.showStatus,
        interactive: this.interactive,
        mode: this.mode,
        statsToShow: this.statsToShow
      }
    });
  },
  
  computed: {
    /**
     * Get the user data either from prop or injection, then normalize it
     */
    userData() {
      this.$log.trace('RENDER', 'Computing userData', { 
        hasUserProp: !!this.user,
        userType: this.user ? typeof this.user : 'none'
      });
      
      let rawUser = null;
      if (this.user) {
        if (typeof this.user === 'string' || typeof this.user === 'number') {
          const injectedGetUserData = this.getUserData;
          rawUser = injectedGetUserData ? injectedGetUserData(this.user) : null;
          this.$log.trace('RENDER', 'Resolved user from userId', { 
            userId: this.user,
            hasData: !!rawUser 
          });
        } else {
          rawUser = this.user;
          this.$log.trace('RENDER', 'Using provided user object', { hasData: !!this.user });
        }
      } else {
        const injectedGetUserData = this.getUserData;
        rawUser = injectedGetUserData ? injectedGetUserData() : null;
        this.$log.trace('RENDER', 'Resolved user from provider context', { hasData: !!rawUser });
      }
      
      // Normalize raw user data if needed
      return rawUser ? this.normalizeUser(rawUser) : null;
    },
    
    /**
     * Get user ID
     */
    userId() {
      if (!this.userData) {
        this.$log.trace('RENDER', 'userId: no userData');
        return null;
      }
      const id = this.userData.info?.id || this.userData.player_id || this.userData.id || this.userData.user_id;
      this.$log.trace('RENDER', 'userId computed', { id });
      return id;
    },
    
    /**
     * Banner URL
     */
    bannerUrl() {
      if (!this.userData && !this.user) {
        this.$log.trace('RENDER', 'bannerUrl: no user data');
        return '';
      }
      const url = this.getBannerUrl(this.userData || this.user);
      this.$log.trace('RENDER', 'bannerUrl computed', { url });
      return url || '';
    },
    
    /**
     * Flag URL
     */
    flagUrl() {
      if (!this.userData) {
        this.$log.trace('RENDER', 'flagUrl: no userData');
        return '';
      }
      const country = this.userData.info?.country || this.userData.country;
      if (!country) {
        this.$log.trace('RENDER', 'flagUrl: no country code');
        return '';
      }
      const url = this.getFlagUrl(country);
      this.$log.trace('RENDER', 'flagUrl computed', { country, url });
      return url;
    },
    
    /**
     * Clan URL
     */
    clanUrl() {
      if (!this.userData) {
        this.$log.trace('RENDER', 'clanUrl: no userData');
        return '';
      }
      const clanId = this.userData.info?.clan_id || this.userData.clan_id;
      if (!clanId) {
        this.$log.trace('RENDER', 'clanUrl: no clanId');
        return '';
      }
      const url = this.getClanUrl(clanId);
      this.$log.trace('RENDER', 'clanUrl computed', { clanId, url });
      return url;
    },
    
    /**
     * Profile URL
     */
    profileUrl() {
      if (!this.userData && !this.user) {
        this.$log.trace('RENDER', 'profileUrl: no user data, defaulting to #');
        return '#';
      }
      const url = this.getProfileUrl(this.userData || this.user);
      this.$log.trace('RENDER', 'profileUrl computed', { url });
      return url || '#';
    },
    
    /**
     * Status data
     */
    statusData() {
      if (!this.userId) {
        this.$log.trace('RENDER', 'statusData: no userId');
        return null;
      }
      const injectedGetStatusData = this.getStatusData;
      const data = injectedGetStatusData ? injectedGetStatusData(this.userId) : null;
      this.$log.trace('RENDER', 'statusData computed', { 
        hasData: !!data,
        status: data?.status?.action,
        online: data?.online 
      });
      return data;
    },
    
    /**
     * Status text
     */
    statusText() {
      if (!this.statusData) {
        this.$log.trace('RENDER', 'statusText: no statusData, defaulting to Offline');
        return 'Offline';
      }
      const getStatusText = this.getStatusString;
      const text = getStatusText ? getStatusText(this.statusData) : 'Offline';
      this.$log.trace('RENDER', 'statusText computed', { text });
      return text;
    },
    
    /**
     * Status CSS class
     */
    statusClasses() {
      if (!this.statusData) {
        this.$log.trace('RENDER', 'statusClasses: no statusData, defaulting to offline');
        return { offline: true };
      }
      const getStatusStatus = this.getStatusClass;
      const statusClass = getStatusStatus ? getStatusStatus(this.statusData) : 'offline';
      const classes = { [statusClass]: true };
      this.$log.trace('RENDER', 'statusClasses computed', { classes });
      return classes;
    },
    
    /**
     * Status string for CSS variable
     */
    statusString() {
      if (!this.statusData) {
        this.$log.trace('RENDER', 'statusString: no statusData, defaulting to offline');
        return 'offline';
      }
      const getStatusString = this.getStatusString;
      const str = getStatusString ? getStatusString(this.statusData) : 'offline';
      this.$log.trace('RENDER', 'statusString computed', { str });
      return str;
    },
    
    /**
     * Whether user is online
     */
    isOnline() {
      const online = this.statusData && (this.statusData.online === true || this.statusData.online === 'true');
      this.$log.trace('RENDER', 'isOnline computed', { online });
      return online;
    },
    
    /**
     * Current mode stats
     */
    currentStats() {
      if (!this.userData || !this.userData.stats) {
        this.$log.trace('RENDER', 'currentStats: no userData or stats, returning null');
        return null;
      }
      
      let mode = this.mode;
      if (mode === null) {
        mode = this.userData.info?.preferred_mode || 0;
        this.$log.trace('RENDER', 'currentStats: using preferred mode', { preferredMode: mode });
      }
      
      const stats = this.userData.stats[mode] || null;
      
      if (!stats) {
        this.$log.warn('RENDER', 'currentStats: no stats for mode', { 
          mode, 
          availableModes: Object.keys(this.userData.stats) 
        });
      }
      
      return stats;
    },
    
    /**
     * CSS classes for master container
     */
    containerClasses() {
      const classes = [
        'user-profile-master',
        this.customClass
      ].filter(Boolean);
      this.$log.trace('RENDER', 'containerClasses computed', { classes });
      return classes.join(' ');
    }
  },
  
  watch: {
    /**
     * Watch for user prop changes
     */
    user: {
      handler: function(newUser) {
        this.$log.debug('WATCH', 'user prop changed', { 
          newUser: newUser,
          hasUserData: !!this.userData 
        });
        
        if (newUser && !this.userData) {
          this.error = null;
        }
      },
      deep: true
    }
  },
  
  methods: {
    /**
     * Normalize raw user data from API to standard format
     * Handles both cached format (with info/stats) and raw API format (flat)
     * @param {object} rawUser - Raw user data
     * @returns {object} Normalized user data
     */
    normalizeUser(rawUser) {
      if (!rawUser) {
        this.$log.warn('DATA', 'Attempted to normalize null/undefined raw user data');
        return null;
      }
      
      // If already normalized (has info and stats), return as-is
      if (rawUser.info && rawUser.stats) {
        this.$log.trace('DATA', 'User data already normalized, skipping');
        return rawUser;
      }
      
      this.$log.debug('DATA', 'Normalizing raw user data from API format');
      
      // Extract user ID from various possible fields
      const userId = rawUser.player_id || rawUser.id || rawUser.user_id;
      if (!userId) {
        this.$log.warn('DATA', 'Could not extract user ID from raw data', { rawUser });
      }
      
      // Normalize info object from flat structure
      const normalizedInfo = {
        id: userId,
        name: rawUser.name || 'Unknown',
        country: rawUser.country || null,
        clan_id: rawUser.clan_id || null,
        clan_tag: rawUser.clan_tag || (rawUser.clan?.tag) || null,
        badges: (rawUser.badges || []).map(badge => ({
          id: badge.id,
          name: badge.name,
          description: badge.description,
          styles: badge.styles || {}
        })),
        preferred_mode: rawUser.preferred_mode || 0
      };
      
      // Normalize stats from flat structure to nested mode format
      // Leaderboard data typically has pp, acc, plays, etc. at root level for preferred mode
      const preferredMode = normalizedInfo.preferred_mode || 0;
      const stats = {
        [preferredMode]: {
          pp: rawUser.pp || 0,
          acc: rawUser.acc || 0,
          plays: rawUser.plays || 0,
          rank: rawUser.rank || null,
          country_rank: rawUser.country_rank || null,
          tscore: rawUser.tscore || 0,
          rscore: rawUser.rscore || 0,
          playtime: rawUser.playtime || 0,
          max_combo: rawUser.max_combo || 0,
          total_hits: rawUser.total_hits || 0,
          replay_views: rawUser.replay_views || 0,
          xh_count: rawUser.xh_count || 0,
          x_count: rawUser.x_count || 0,
          sh_count: rawUser.sh_count || 0,
          s_count: rawUser.s_count || 0,
          a_count: rawUser.a_count || 0
        }
      };
      
      const normalized = {
        info: normalizedInfo,
        stats: stats,
        // Keep raw data for future use
        raw: rawUser
      };
      
      this.$log.trace('DATA', 'Normalized user data', { 
        userId, 
        preferredMode,
        statsKeys: Object.keys(stats)
      });
      
      return normalized;
    },
    
    /**
     * Show profile panel (for username style)
     */
    showProfile() {
      if (!this.interactive) {
        this.$log.trace('EVENT', 'showProfile called but interactive=false, ignoring');
        return;
      }
      this.$log.debug('EVENT', 'Showing profile panel', { profileVisible: this.profileVisible });
      this.profileVisible = true;
    },
    
    /**
     * Hide profile panel (for username style)
     */
    hideProfile() {
      if (!this.interactive) {
        this.$log.trace('EVENT', 'hideProfile called but interactive=false, ignoring');
        return;
      }
      
      if (!this.mouseOverPanel) {
        this.$log.debug('EVENT', 'Hiding profile panel', { mouseOverPanel: this.mouseOverPanel });
        this.profileVisible = false;
      } else {
        this.$log.trace('EVENT', 'hideProfile called but mouse is over panel, keeping visible');
      }
    },
    
    /**
     * Mouse enter panel handler
     */
    mouseEnterPanel() {
      this.$log.debug('EVENT', 'Mouse entered panel');
      this.mouseOverPanel = true;
    },
    
    /**
     * Mouse leave panel handler
     */
    mouseLeavePanel() {
      this.$log.debug('EVENT', 'Mouse left panel');
      this.mouseOverPanel = false;
      this.profileVisible = false;
    },
    
    /**
     * Handle username click
     */
    handleUsernameClick(event) {
      this.$log.debug('EVENT', 'Username clicked', {
        interactive: this.interactive,
        profileUrl: this.profileUrl
      });
      
      if (!this.interactive) {
        event.preventDefault();
        this.$log.debug('EVENT', 'Username click prevented (interactive=false)');
        return;
      }
      // Let default navigation happen
    },
    
    /**
     * Handle clan click
     */
    handleClanClick(event) {
      this.$log.debug('EVENT', 'Clan tag clicked', {
        clanTag: this.userData?.info?.clan_tag,
        clanUrl: this.clanUrl,
        interactive: this.interactive
      });
      
      if (!this.interactive) {
        event.preventDefault();
        this.$log.debug('EVENT', 'Clan click prevented (interactive=false)');
      }
      // Let default navigation happen
    },
    
    /**
     * Get badge style object
     * @param {object} badge - Badge data
     * @returns {object} CSS style object
     */
    getBadgeStyle(badge) {
      this.$log.trace('UTIL', 'getBadgeStyle called', { badgeId: badge?.id });
      
      if (!badge || !badge.styles) {
        this.$log.trace('UTIL', 'getBadgeStyle: no styles, returning empty');
        return {};
      }
      
      const styles = badge.styles;
      const styleObj = {
        '--badge-styles-color': styles.color,
        '--badge-hue': styles.color,
        '--badge-bg-color': `hsl(${styles.color}, 20%, 30%)`,
        '--badge-text-color': `hsl(${styles.color}, 100%, 80%)`,
        '--badge-border-color': `hsl(${styles.color}, 40%, 35%)`,
        'backgroundColor': `var(--badge-bg-color)`,
        'color': `var(--badge-text-color)`,
        'border': `1px solid var(--badge-border-color)`
      };
      
      this.$log.trace('UTIL', 'getBadgeStyle: computed', { color: styles.color });
      return styleObj;
    },
    
    /**
     * Get panel style for badge popup
     * @param {object} badge - Badge data
     * @returns {object} CSS style object
     */
    getPanelStyle(badge) {
      this.$log.trace('UTIL', 'getPanelStyle called', { badgeId: badge?.id });
      
      if (!badge || !badge.styles) {
        this.$log.trace('UTIL', 'getPanelStyle: no styles, returning empty');
        return {};
      }
      
      const styles = badge.styles;
      const styleObj = {
        '--panel-bg-color': `hsl(${styles.color}, 20%, 20%)`,
        '--panel-text-color': `hsl(${styles.color}, 100%, 80%)`,
        'backgroundColor': `var(--panel-bg-color)`,
        'color': `var(--panel-text-color)`
      };
      
      this.$log.trace('UTIL', 'getPanelStyle: computed');
      return styleObj;
    }
  },
  
    template: `
    <!-- Loading state -->
    <div v-if="user && isUserLoading(user)" class="user-profile-loading">
      <slot name="loading">
        <i class="fas fa-spinner fa-spin"></i>
        <span>Loading user data...</span>
      </slot>
    </div>
    
    <!-- Error state -->
    <div v-else-if="user && getUserError(user)" class="user-profile-error">
      <slot name="error">
        <i class="fas fa-exclamation-circle"></i>
        <span v-text="getUserError(user)"></span>
      </slot>
    </div>
    
    <div :class="containerClasses" v-else-if="userData">
      
      <!-- Username style with hover panel -->
      <div v-if="displayStyle === 'username'" 
           class="user-profile-username-container"
           @mouseover="showProfile"
           @mouseout="hideProfile">
        
        <!-- Username display -->
        <span class="user-name"
                @mouseover="showProfile"
                @mouseout="hideProfile"
                @click="handleUsernameClick">
          
          <!-- Country flag (if enabled) -->
          <span v-if="showCountry && userData.info.country" class="user-country">
            <img :src="getFlagUrl(userData.info.country)" :alt="userData.info.country" class="user-flag" />
          </span>
          
          <!-- Clan tag (if enabled) -->
          <span v-if="showClan && userData.info.clan_tag" class="user-clan">
            <a :href="getClanUrl(userData.info.clan_id)" @click.stop="handleClanClick" class="user-clan-link">
              <span v-text="'['+ userData.info.clan_tag + ']'"></span>
            </a>
          </span>
          
          <!-- Username (always shown) -->
          <a :href="getProfileUrl(userData)" class="user-username-link">
            <span v-text="userData.info.name"></span>
          </a>
        </span>
        
        <!-- Hover panel (positioned absolutely) -->
        <div class="user-profile-hover-panel-wrapper" 
             :class="{ visible: profileVisible }"
             @mouseenter="mouseEnterPanel"
             @mouseleave="mouseLeavePanel">
          
          <!-- Panel background -->
          <div class="user-profile-panel-background"
               :style="'background-image: url(' + bannerUrl + ')'"></div>
          
          <!-- Panel header -->
          <div class="user-profile-panel-header">
            <div class="user-profile-panel-avatar"
                 :style="'background-image: url(' + getAvatarUrl(userData) + ')'"></div>
            
            <div class="user-profile-panel-info">
              <div class="user-profile-panel-name">
                <span v-if="showClan && userData.info.clan_tag" class="user-profile-panel-clan">
                  [{{ userData.info.clan_tag }}]
                </span>
                <span v-text="userData.info.name"></span>
              </div>
              
              <div v-if="currentStats" class="user-profile-panel-rank">
                <span class="user-profile-panel-global-rank">
                  <span v-text="currentStats.rank || '?'"></span>
                </span>
                <span v-if="showCountry && userData.info.country" class="user-profile-panel-country">
                  <img :src="getFlagUrl(userData.info.country)" :alt="userData.info.country" class="user-flag" />
                  <span v-text="'#' + currentStats.country_rank || '?'"></span>
                </span>
              </div>
              
              <div v-if="showBadges && userData.info.badges && userData.info.badges.length > 0"
                   class="user-profile-panel-badges">
                <div v-for="badge in userData.info.badges"
                     :key="badge.id"
                     class="badge"
                     :class="badge.styles?.customClass || ''"
                     :style="getBadgeStyle(badge)"
                     data-popup-trigger
                     tabindex="0"
                     role="button"
                     :aria-label="badge.name">
                  <bg-effect-psy v-if="badge.styles?.customClass && badge.styles.customClass.includes('psy')"
                                :settings="{
                                  hue: badge.styles.color / 360,
                                  hueVariation: badge.styles.psyHueVar || 0.001,
                                  density: badge.styles.psyDensity || 0,
                                  displacement: badge.styles.psyDisp || 0.1,
                                  speed: badge.styles.psySpeed || 0.2,
                                  gradient: badge.styles.psyGradient || 0.15
                                }"
                                :show-gui="false"
                                :debug-level="0">
                  </bg-effect-psy>
                  <span v-if="badge.styles?.icon" 
                        class="badge-icon" 
                        :class="badge.styles.iconClass || ''"
                        aria-hidden="true">
                    <i :class="badge.styles.icon"></i>
                  </span>
                  <span v-if="badge.styles?.icon === null" class="badge-name" v-text="badge.name"></span>
                  <span v-else class="badge-name" :class="badge.styles.nameClass || ''" v-text="badge.name"></span>
                  
                  <div class="badge-panel position-top"
                       :class="badge.styles?.panelClass || ''"
                       :style="getPanelStyle(badge)"
                       data-popup
                       role="tooltip"
                       aria-live="polite">
                    <h3 v-text="badge.name"></h3>
                    <p v-text="badge.description || badge.name + ' badge'"></p>
                    <div v-if="badge.styles?.panelFooter" 
                         class="badge-panel-footer" 
                         v-text="badge.styles.panelFooter">
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
          
          <!-- Panel stats -->
          <div v-if="currentStats" class="user-profile-panel-stats">
            <div class="user-profile-panel-stat-item">
              <div class="user-profile-panel-stat-value" v-text="formatNumber(currentStats.pp) || '0'"></div>
              <div class="user-profile-panel-stat-label">PP</div>
            </div>
            
            <div class="user-profile-panel-stat-item">
              <div class="user-profile-panel-stat-value" v-text="formatAccuracy(currentStats.acc) + '%'"></div>
              <div class="user-profile-panel-stat-label">Accuracy</div>
            </div>
            
            <div class="user-profile-panel-stat-item">
              <div class="user-profile-panel-stat-value" v-text="formatNumber(currentStats.plays) || '0'"></div>
              <div class="user-profile-panel-stat-label">Plays</div>
            </div>
          </div>
          
          <!-- Panel status -->
          <div v-if="showStatus && statusData" 
               class="user-profile-panel-status"
               :class="statusClasses">
            <i class="fas fa-circle"></i>
            <span v-text="statusText"></span>
          </div>
        </div>
      </div>
      
      <!-- Card style -->
      <user-card v-else-if="displayStyle === 'card'"
                 :user="userData"
                 :show-country="showCountry"
                 :show-clan="showClan"
                 :show-badges="showBadges"
                 :show-status="showStatus"
                 :mode="mode"
                 :stats-to-show="statsToShow"
                 custom-class="user-profile-card-wrapper">
        <!-- Cosmetic slots for card -->
        <template #banner-overlay>
          <slot name="banner-overlay"></slot>
        </template>
        <template #avatar-frame>
          <slot name="avatar-frame"></slot>
        </template>
      </user-card>
      
      <!-- Search style (compact) -->
      <div v-else-if="displayStyle === 'search'" class="user-profile-search-container">
        <a :href="getProfileUrl(userData)" class="user-profile-search" :style="'--user-banner: url(' + bannerUrl + ');'">
          <div class="user-profile-overlay"></div>
          <div class="user-profile-avatar search"
               :style="'background-image: url(' + getAvatarUrl(userData) + ')'"></div>
          
          <div class="user-profile-search-info">
            <div class="user-profile-search-name">
              <span v-if="showCountry && userData.info.country" class="user-profile-search-country">
                <img :src="getFlagUrl(userData.info.country)" :alt="userData.info.country" class="user-flag" />
              </span>
              <span v-if="showClan && userData.info.clan_tag" class="user-profile-search-clan">
                <a :href="getClanUrl(userData.info.clan_id)" class="user-profile-search-clan-link">
                  <span v-text="'[' + userData.info.clan_tag + ']'"></span>
                </a>
              </span>
              <a :href="getProfileUrl(userData)" class="user-profile-search-username">
                <span v-text="userData.info.name"></span>
              </a>
            </div>
            
            <div v-if="currentStats" class="user-profile-search-stats">
              <span class="user-profile-search-stat">
                <i class="fas fa-star"></i>
                <span v-text="formatNumber(currentStats.pp) + 'pp'"></span>
              </span>
              <span class="user-profile-search-stat">
                <i class="fas fa-crosshairs"></i>
                <span v-text="formatAccuracy(currentStats.acc) + '%'"></span>
              </span>
              <span v-if="currentStats.rank" class="user-profile-search-stat">
                <i class="fas fa-trophy"></i>
                <span v-text="'#' + currentStats.rank"></span>
              </span>
            </div>
          </div>
        </a>
      </div>
    </div>
    
    <!-- No data state -->
    <div v-else class="user-profile-no-data">
      <slot name="no-data">
        <span>No user data available</span>
      </slot>
    </div>
  `
});

// Register component
if (typeof Vue !== 'undefined' && !Vue.options.components['user-profile']) {
  Vue.component('user-profile', UserProfile);
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UserProfile };
}