/**
 * User Stats Component
 * Displays a user's stats (PP, Accuracy, Plays, etc.)
 * Uses provide/inject to get user data and formatters.
 */

const UserStats = Vue.component('user-stats', {
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
     * Which mode's stats to show (0=osu!, 1=taiko, 2=catch, 3=mania)
     * If not specified, uses user's preferred mode
     * @type {Number}
     * @default null
     */
    mode: {
      type: Number,
      default: null,
      validator: function(value) {
        return value === null || [0, 1, 2, 3].includes(value);
      }
    },
    
    /**
     * Which stats to display
     * @type {Array}
     * @default ['pp', 'acc', 'plays']
     */
    show: {
      type: Array,
      default: () => ['pp', 'acc', 'plays'],
      validator: function(value) {
        const valid = ['pp', 'acc', 'plays', 'rank', 'country_rank', 'tscore', 'rscore', 'playtime', 'max_combo', 'total_hits'];
        return value.every(item => valid.includes(item));
      }
    },
    
    /**
     * Layout style
     * @type {String}
     * @default 'horizontal'
     */
    layout: {
      type: String,
      default: 'horizontal',
      validator: function(value) {
        return ['horizontal', 'vertical', 'compact'].includes(value);
      }
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
    getCurrentStats: { default: () => null },
    formatNumber: { default: () => (n) => n },
    formatAccuracy: { default: () => (a) => a.toFixed(2) },
    formatRank: { default: () => (r) => r ? `#${r}` : '?' }
  },
  
  created() {
    this.$log = (typeof ColorfulLogger !== 'undefined') ? ColorfulLogger.child('UserStats') : console;
    
    this.$log.debug('LIFECYCLE', 'Component created', {
      props: {
        user: this.user,
        mode: this.mode,
        show: this.show,
        layout: this.layout
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
     * Get stats for the specified mode
     */
    stats() {
      if (!this.userData) {
        this.$log.trace('RENDER', 'stats: no userData, returning null');
        return null;
      }
      
      let mode = this.mode;
      if (mode === null) {
        // Use preferred mode from user data
        mode = this.userData.info?.preferred_mode || 0;
        this.$log.trace('RENDER', 'stats: using preferred mode', { preferredMode: mode });
      }
      
      // Try to get stats from user data directly
      if (this.userData.stats && this.userData.stats[mode]) {
        const stats = this.userData.stats[mode];
        this.$log.trace('RENDER', 'stats: found in userData', { mode, statsKeys: Object.keys(stats) });
        return stats;
      }
      
      // Fall back to getCurrentStats from provider
      const injectedGetCurrentStats = this.getCurrentStats;
      if (injectedGetCurrentStats) {
        const stats = injectedGetCurrentStats(this.userData);
        this.$log.trace('RENDER', 'stats: used getCurrentStats fallback', { 
          mode,
          hasStats: !!stats 
        });
        return stats;
      }
      
      this.$log.warn('RENDER', 'stats: no stats available for mode', { mode });
      return null;
    },
    
    /**
     * CSS classes for stats container
     */
    statsClasses() {
      const classes = [
        'user-stats',
        `user-stats--${this.layout}`,
        this.customClass
      ].filter(Boolean);
      this.$log.trace('RENDER', 'statsClasses computed', { classes });
      return classes.join(' ');
    }
  },
  
  methods: {
    /**
     * Get stat value by key
     * @param {string} key - Stat key (pp, acc, plays, etc.)
     * @returns {string} Formatted stat value
     */
    getStatValue(key) {
      this.$log.trace('UTIL', 'getStatValue called', { key });
      
      if (!this.stats) {
        this.$log.trace('UTIL', 'getStatValue: no stats, returning 0');
        return '0';
      }
      
      const value = this.stats[key];
      if (value === null || value === undefined) {
        this.$log.trace('UTIL', 'getStatValue: stat is null/undefined', { key });
        return '0';
      }
      
      let formatted;
      switch (key) {
        case 'acc':
          formatted = this.formatAccuracy(value) + '%';
          break;
        case 'rank':
        case 'country_rank':
          formatted = this.formatRank(value);
          break;
        default:
          formatted = this.formatNumber(value);
      }
      
      this.$log.trace('UTIL', 'getStatValue: formatted', { key, rawValue: value, formatted });
      return formatted;
    },
    
    /**
     * Get stat label by key
     * @param {string} key - Stat key
     * @returns {string} Label
     */
    getStatLabel(key) {
      const labels = {
        pp: 'PP',
        acc: 'Accuracy',
        plays: 'Plays',
        rank: 'Global Rank',
        country_rank: 'Country Rank',
        tscore: 'Total Score',
        rscore: 'Ranked Score',
        playtime: 'Playtime',
        max_combo: 'Max Combo',
        total_hits: 'Total Hits'
      };
      const label = labels[key] || key;
      this.$log.trace('UTIL', 'getStatLabel', { key, label });
      return label;
    }
  },
  
  template: `
    <div v-if="stats" :class="statsClasses">
      <div v-for="statKey in show" 
           :key="statKey"
           class="user-stats__item"
           :class="'user-stats__item--' + statKey">
        <div class="user-stats__value" v-text="getStatValue(statKey)"></div>
        <div class="user-stats__label" v-text="getStatLabel(statKey)"></div>
      </div>
    </div>
    
    <!-- Empty state -->
    <div v-else class="user-stats-empty">
      <slot name="empty">
        <span class="no-stats">No stats available</span>
      </slot>
    </div>
  `
});

// Register component
if (typeof Vue !== 'undefined' && !Vue.options.components['user-stats']) {
  Vue.component('user-stats', UserStats);
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UserStats };
}