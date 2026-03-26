/**
 * User Avatar Component
 * Displays a user's avatar image with optional size and styling.
 * Uses provide/inject to get user data and URL generators.
 */

const UserAvatar = Vue.component('user-avatar', {
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
     * Size of the avatar
     * @type {String}
     * @default 'medium'
     */
    size: {
      type: String,
      default: 'medium',
      validator: function(value) {
        return ['small', 'medium', 'large', 'xlarge'].includes(value);
      }
    },
    
    /**
     * Additional CSS classes
     */
    customClass: {
      type: String,
      default: ''
    },
    
    /**
     * Show status indicator ring around avatar
     * @type {Boolean}
     * @default false
     */
    showStatus: {
      type: Boolean,
      default: false
    },
    
    /**
     * Link to profile page
     * @type {Boolean}
     * @default true
     */
    linkToProfile: {
      type: Boolean,
      default: true
    },
    
    /**
     * Alt text for image
     */
    alt: {
      type: String,
      default: 'User avatar'
    }
  },
  
  inject: {
    // Inject utilities from UserDataProvider
    getUserData: { default: () => null },
    getAvatarUrl: { default: () => '' },
    getProfileUrl: { default: () => '' },
    getStatusData: { default: () => null },
    getStatusString: { default: () => 'online' }
  },
  
  created() {
    this.$log = (typeof ColorfulLogger !== 'undefined') ? ColorfulLogger.child('UserAvatar') : console;
    
    this.$log.debug('LIFECYCLE', 'Component created', {
      props: {
        user: this.user,
        size: this.size,
        showStatus: this.showStatus,
        linkToProfile: this.linkToProfile
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
        this.$log.trace('RENDER', 'userId computed: no userData');
        return null;
      }
      const id = this.userData.info?.id || this.userData.player_id || this.userData.id || this.userData.user_id;
      this.$log.trace('RENDER', 'userId computed', { id });
      return id;
    },
    
    /**
     * Avatar URL
     */
    avatarUrl() {
      if (!this.userData && !this.user) {
        this.$log.warn('RENDER', 'avatarUrl: no user data or user prop');
        return '';
      }
      const url = this.getAvatarUrl(this.userData || this.user);
      this.$log.trace('RENDER', 'avatarUrl computed', { url });
      return url || '';
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
      this.$log.trace('RENDER', 'statusData computed', { hasData: !!data });
      return data;
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
      const status = getStatusString ? getStatusString(this.statusData) : 'offline';
      this.$log.trace('RENDER', 'statusString computed', { status });
      return status;
    },
    
    /**
     * CSS classes for avatar
     */
    avatarClasses() {
      const classes = [
        'user-avatar',
        `user-avatar--${this.size}`,
        this.showStatus ? 'user-avatar--with-status' : '',
        this.customClass
      ].filter(Boolean);
      this.$log.trace('RENDER', 'avatarClasses computed', { classes });
      return classes.join(' ');
    }
  },
  
  methods: {
    /**
     * Handle avatar click
     */
    handleClick() {
      this.$log.debug('EVENT', 'Avatar click', {
        linkToProfile: this.linkToProfile,
        profileUrl: this.profileUrl
      });
      
      if (this.linkToProfile && this.profileUrl && this.profileUrl !== '#') {
        window.location.href = this.profileUrl;
      }
    }
  },
  
  template: `
    <div :class="avatarClasses" 
         :style="showStatus ? { '--user-status': 'var(--status-' + statusString + ')' } : {}"
         @click="handleClick">
      <img :src="avatarUrl" 
           :alt="alt"
           class="user-avatar__image" />
    </div>
  `
});

// Register component
if (typeof Vue !== 'undefined' && !Vue.options.components['user-avatar']) {
  Vue.component('user-avatar', UserAvatar);
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UserAvatar };
}