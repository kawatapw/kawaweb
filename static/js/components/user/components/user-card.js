/**
 * User Card Component
 * Composed component that displays a user's profile in a card format.
 * Combines: avatar, name, badges, stats, status
 * Supports cosmetic slots for customization.
 */

const UserCard = Vue.component('user-card', {
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
     * Show country flag
     * @type {Boolean}
     * @default true
     */
    showCountry: {
      type: Boolean,
      default: true
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
    isUserLoading: { default: () => false },
    getUserError: { default: () => null },
    formatNumber: { default: () => (n) => n },
    formatAccuracy: { default: () => (a) => a.toFixed(2) }
  },
  
  created() {
    this.$log = (typeof ColorfulLogger !== 'undefined') ? ColorfulLogger.child('UserCard') : console;
    
    this.$log.debug('LIFECYCLE', 'Component created', {
      props: {
        user: this.user,
        showCountry: this.showCountry,
        showClan: this.showClan,
        showBadges: this.showBadges,
        showStatus: this.showStatus,
        mode: this.mode,
        statsToShow: this.statsToShow
      }
    });
  },
  
  computed: {
    /**
     * Get the user data either from prop or injection
     */
    userData() {
      this.$log.trace('RENDER', 'Computing userData', { 
        hasUserProp: !!this.user,
        userType: this.user ? typeof this.user : 'none'
      });
      
      if (this.user) {
        if (typeof this.user === 'string' || typeof this.user === 'number') {
          const injectedGetUserData = this.getUserData;
          const data = injectedGetUserData ? injectedGetUserData(this.user) : null;
          this.$log.trace('RENDER', 'Resolved user from userId', { 
            userId: this.user,
            hasData: !!data 
          });
          return data;
        }
        this.$log.trace('RENDER', 'Using provided user object', { hasData: !!this.user });
        return this.user;
      }
      
      const injectedGetUserData = this.getUserData;
      const data = injectedGetUserData ? injectedGetUserData() : null;
      this.$log.trace('RENDER', 'Resolved user from provider context', { hasData: !!data });
      return data;
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
      // Try to get from inject, fall back to simple logic
      const getStatusText = this.getStatusString;
      if (getStatusText) {
        const text = getStatusText(this.statusData);
        this.$log.trace('RENDER', 'statusText computed via inject', { text });
        return text;
      }
      
      // Fallback: simple status text
      if (!this.statusData.online && this.statusData.online !== 'true') {
        return 'Offline';
      }
      if (!this.statusData.status) return 'Online';
      const action = this.statusData.status.action;
      return `Status action: ${action}`;
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
     * CSS classes for card container
     */
    cardClasses() {
      const classes = [
        'user-card',
        this.customClass
      ].filter(Boolean);
      this.$log.trace('RENDER', 'cardClasses computed', { classes });
      return classes.join(' ');
    }
  },
  
  methods: {
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
    <div v-if="user && isUserLoading(user)" class="user-card-loading">
      <slot name="loading">
        <i class="fas fa-spinner fa-spin"></i>
        <span>Loading user data...</span>
      </slot>
    </div>
    
    <!-- Error state -->
    <div v-else-if="user && getUserError(user)" class="user-card-error">
      <slot name="error">
        <i class="fas fa-exclamation-circle"></i>
        <span v-text="getUserError(user)"></span>
      </slot>
    </div>
    
    <!-- Main card content -->
    <div :class="cardClasses" v-else-if="userData">
      <div class="user-profile-card-container">
        <div class="user-profile-card">
          <!-- Card background (banner) -->
          <div class="user-profile-card-background"
               :style="'background-image: url(' + bannerUrl + ')'"></div>
          
          <!-- Card overlay -->
          <div class="user-profile-overlay"></div>
          
          <!-- Card content -->
          <div class="user-profile-card-content">
            <!-- Avatar and basic info -->
            <div class="user-profile-card-header">
              <div class="user-profile-card-avatar-container" :style="showStatus && statusData ? { '--user-status': 'var(--status-' + statusString + ')' } : {}">
                <div class="user-profile-avatar with-status"
                     :style="'background-image: url(' + getAvatarUrl(userData) + ')'"></div>
                
                <!-- Status indicator on avatar -->
                <div v-if="showStatus" class="user-profile-card-status-indicator">
                  <div v-if="isOnline" class="user-profile-card-status-circle">
                    <i class="fas fa-circle"></i>
                  </div>
                  <div v-else class="user-profile-card-status-circle offline">
                    <i class="fas fa-circle"></i>
                  </div>
                  
                  <!-- Status text tooltip on hover -->
                  <div v-if="statusData" class="user-profile-card-status-tooltip" v-text="statusText">
                    <span ></span>
                  </div>
                </div>
              </div>
              
              <div class="user-profile-card-info">
                <div class="user-profile-card-name">
                  <span v-if="showCountry && userData.info.country" class="user-profile-card-country">
                    <img :src="getFlagUrl(userData.info.country)" :alt="userData.info.country" class="user-flag" />
                  </span>
                  <span v-if="showClan && userData.info.clan_tag" class="user-profile-card-clan">
                    <a :href="getClanUrl(userData.info.clan_id)" class="user-profile-card-clan-link">
                      <span v-text="'[' + userData.info.clan_tag + ']'"></span>
                    </a>
                  </span>
                  <a :href="getProfileUrl(userData)" class="user-profile-card-username">
                    <span v-text="userData.info.name"></span>
                  </a>
                </div>
                
                <div v-if="currentStats" class="user-profile-card-ranks">
                  <span class="user-profile-card-global-rank">
                    <span v-text="currentStats.rank || '?'"></span>
                  </span>
                  <span v-if="showCountry && userData.info.country" class="user-profile-card-country-rank">
                    <img :src="getFlagUrl(userData.info.country)" :alt="userData.info.country" class="user-flag" />
                    <span v-text="'#' + currentStats.country_rank || '?'"></span>
                  </span>
                </div>
              </div>
            </div>
            
            <!-- Badges -->
            <div v-if="showBadges && userData.info.badges && userData.info.badges.length > 0" class="user-profile-card-badges">
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
            
            <!-- Stats -->
            <div v-if="currentStats" class="user-profile-card-stats">
              <div class="user-profile-card-stat-item">
                <div class="user-profile-card-stat-value" v-text="formatNumber(currentStats.pp) || '0'"></div>
                <div class="user-profile-card-stat-label">PP</div>
              </div>
              
              <div class="user-profile-card-stat-item">
                <div class="user-profile-card-stat-value" v-text="formatAccuracy(currentStats.acc) + '%'"></div>
                <div class="user-profile-card-stat-label">Accuracy</div>
              </div>
              
              <div class="user-profile-card-stat-item">
                <div class="user-profile-card-stat-value" v-text="formatNumber(currentStats.plays) || '0'"></div>
                <div class="user-profile-card-stat-label">Plays</div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
    
    <!-- No data state (only show if user prop is provided but no data available) -->
    <div v-else-if="user && !userData && !isUserLoading(user) && !getUserError(user)" class="user-card-no-data">
      <slot name="no-data">
        <span>No user data available</span>
      </slot>
    </div>
  `
});

// Register component
if (typeof Vue !== 'undefined' && !Vue.options.components['user-card']) {
  Vue.component('user-card', UserCard);
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UserCard };
}