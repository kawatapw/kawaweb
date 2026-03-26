/**
 * User Status Component
 * Displays a user's online status with optional text.
 * Uses provide/inject to get user data and formatters.
 */

const UserStatus = Vue.component('user-status', {
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
     * Show status text (e.g., "Online", "Playing: ...")
     * @type {Boolean}
     * @default true
     */
    showText: {
      type: Boolean,
      default: true
    },
    
    /**
     * Show only the indicator dot (no text)
     * @type {Boolean}
     * @default false
     */
    compact: {
      type: Boolean,
      default: false
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
    getStatusData: { default: () => null },
    getStatusText: { default: () => 'Offline' },
    getStatusClass: { default: () => 'offline' },
    getStatusString: { default: () => 'offline' }
  },
  
  created() {
    this.$log = (typeof ColorfulLogger !== 'undefined') ? ColorfulLogger.child('UserStatus') : console;
    
    this.$log.debug('LIFECYCLE', 'Component created', {
      props: {
        user: this.user,
        showText: this.showText,
        compact: this.compact
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
     * Get user ID from user data
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
      const getStatusText = this.getStatusText;
      const text = getStatusText ? getStatusText(this.statusData) : 'Offline';
      this.$log.trace('RENDER', 'statusText computed', { text });
      return text;
    },
    
    /**
     * Status CSS class
     */
    statusClass() {
      if (!this.statusData) {
        this.$log.trace('RENDER', 'statusClass: no statusData, defaulting to offline');
        return 'offline';
      }
      const getStatusClass = this.getStatusClass;
      const cls = getStatusClass ? getStatusClass(this.statusData) : 'offline';
      this.$log.trace('RENDER', 'statusClass computed', { cls });
      return cls;
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
     * CSS classes
     */
    statusClasses() {
      const classes = [
        'user-status',
        `user-status--${this.statusClass}`,
        this.compact ? 'user-status--compact' : '',
        this.customClass
      ].filter(Boolean);
      this.$log.trace('RENDER', 'statusClasses computed', { classes });
      return classes.join(' ');
    }
  },
  
  template: `
    <div :class="statusClasses" 
         :style="isOnline ? { '--user-status': 'var(--status-' + statusString + ')' } : {}">
      <span class="user-status__indicator"></span>
      <span v-if="!compact && showText" class="user-status__text" v-text="statusText"></span>
    </div>
  `
});

// Register component
if (typeof Vue !== 'undefined' && !Vue.options.components['user-status']) {
  Vue.component('user-status', UserStatus);
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UserStatus };
}