/**
 * User Badges Component
 * Displays a list of user badges with optional popup information.
 * Uses provide/inject to get user data and formatters.
 */

const UserBadges = Vue.component('user-badges', {
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
     * Array of badge objects (if not using user prop)
     * Each badge should have: id, name, description, styles
     */
    badges: {
      type: Array,
      default: null
    },
    
    /**
     * Badge display type: 0 = regular with name, 1 = icon only
     * @type {Number}
     * @default 0
     */
    type: {
      type: Number,
      default: 0,
      validator: function(value) {
        return [0, 1].includes(value);
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
    formatNumber: { default: () => (n) => n },
    formatAccuracy: { default: () => (a) => a.toFixed(2) }
  },
  
  created() {
    this.$log = (typeof ColorfulLogger !== 'undefined') ? ColorfulLogger.child('UserBadges') : console;
    
    this.$log.debug('LIFECYCLE', 'Component created', {
      props: {
        user: this.user,
        badges: this.badges,
        type: this.type
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
     * Get badges array from user data or prop
     */
    badgeList() {
      if (this.badges) {
        this.$log.trace('RENDER', 'Using provided badges array', { count: this.badges.length });
        return this.badges;
      }
      
      if (this.userData && this.userData.info && this.userData.info.badges) {
        const badges = this.userData.info.badges;
        this.$log.trace('RENDER', 'Using badges from user data', { count: badges.length });
        return badges;
      }
      
      this.$log.trace('RENDER', 'No badges available');
      return [];
    },
    
    /**
     * Whether to show badges
     */
    hasBadges() {
      const has = this.badgeList && this.badgeList.length > 0;
      this.$log.trace('RENDER', 'hasBadges computed', { has, count: this.badgeList?.length || 0 });
      return has;
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
    <div v-if="hasBadges" :class="['user-badges', customClass].filter(Boolean).join(' ')">
      <div v-for="badge in badgeList" 
           :key="badge.id"
           class="badge-wrapper"
           :class="'badge-type-' + type">
        
        <!-- Regular badge with name -->
        <div v-if="type === 0" 
             class="badge"
             :class="badge.styles?.customClass || ''"
             :style="getBadgeStyle(badge)"
             data-popup-trigger
             tabindex="0"
             role="button"
             :aria-label="badge.name"
             :aria-describedby="'badge-desc-' + badge.id">
          
          <!-- Psy effect background (if custom class includes 'psy') -->
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
          
          <!-- Badge icon -->
          <span v-if="badge.styles?.icon" 
                class="badge-icon" 
                :class="badge.styles.iconClass || ''"
                aria-hidden="true">
            <i :class="badge.styles.icon"></i>
          </span>
          
          <!-- Badge name -->
          <span class="badge-name" 
                :class="badge.styles.nameClass || ''"
                :id="'badge-desc-' + badge.id"
                v-text="badge.name">
          </span>
          
          <!-- Popup panel -->
          <div class="badge-panel position-top"
               :class="badge.styles?.panelClass || ''"
               :style="getPanelStyle(badge)"
               :id="'badge-panel-' + badge.id"
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
        
        <!-- Icon-only badge -->
        <div v-else-if="type === 1" 
             class="icon-badge"
             :class="badge.styles?.customClass || ''"
             :style="getBadgeStyle(badge)"
             data-popup-trigger
             tabindex="0"
             role="button"
             :aria-label="badge.name"
             :aria-describedby="'badge-desc-icon-' + badge.id">
          
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
          
          <div class="badge-panel position-top"
               :class="badge.styles?.panelClass || ''"
               :style="getPanelStyle(badge)"
               :id="'badge-panel-icon-' + badge.id"
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
    
    <!-- Empty state -->
    <div v-else class="user-badges-empty">
      <slot name="empty">
        <span class="no-badges">No badges</span>
      </slot>
    </div>
  `
});

// Register component
if (typeof Vue !== 'undefined' && !Vue.options.components['user-badges']) {
  Vue.component('user-badges', UserBadges);
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UserBadges };
}