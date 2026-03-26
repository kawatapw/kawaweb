/**
 * User Name Component
 * Displays a user's name with optional country flag and clan tag.
 * Uses provide/inject to get user data and URL generators.
 */

const UserName = Vue.component('user-name', {
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
     * Show country flag before name
     * @type {Boolean}
     * @default false
     */
    showCountry: {
      type: Boolean,
      default: false
    },
    
    /**
     * Show clan tag before name
     * @type {Boolean}
     * @default true
     */
    showClan: {
      type: Boolean,
      default: true
    },
    
    /**
     * Make the name a link to profile
     * @type {Boolean}
     * @default true
     */
    linkToProfile: {
      type: Boolean,
      default: true
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
    getFlagUrl: { default: () => '' },
    getClanUrl: { default: () => '' },
    getProfileUrl: { default: () => '' }
  },
  
  created() {
    this.$log = (typeof ColorfulLogger !== 'undefined') ? ColorfulLogger.child('UserName') : console;
    
    this.$log.debug('LIFECYCLE', 'Component created', {
      props: {
        user: this.user,
        showCountry: this.showCountry,
        showClan: this.showClan,
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
     * Clan tag
     */
    clanTag() {
      if (!this.userData) {
        this.$log.trace('RENDER', 'clanTag: no userData');
        return null;
      }
      const tag = this.userData.info?.clan_tag || this.userData.clan_tag || null;
      this.$log.trace('RENDER', 'clanTag computed', { tag });
      return tag;
    },
    
    /**
     * User name
     */
    userName() {
      if (!this.userData) {
        this.$log.trace('RENDER', 'userName: no userData');
        return '';
      }
      const name = this.userData.info?.name || this.userData.name || 'Unknown';
      this.$log.trace('RENDER', 'userName computed', { name });
      return name;
    },
    
    /**
     * Country code
     */
    countryCode() {
      if (!this.userData) {
        this.$log.trace('RENDER', 'countryCode: no userData');
        return null;
      }
      const code = this.userData.info?.country || this.userData.country || null;
      this.$log.trace('RENDER', 'countryCode computed', { code });
      return code;
    },
    
    /**
     * Whether to show clan (has clan tag and showClan is true)
     */
    shouldShowClan() {
      const show = this.showClan && this.clanTag;
      this.$log.trace('RENDER', 'shouldShowClan computed', { showClan: this.showClan, hasClanTag: !!this.clanTag, result: show });
      return show;
    },
    
    /**
     * Whether to show country (has country and showCountry is true)
     */
    shouldShowCountry() {
      const show = this.showCountry && this.countryCode;
      this.$log.trace('RENDER', 'shouldShowCountry computed', { showCountry: this.showCountry, hasCountry: !!this.countryCode, result: show });
      return show;
    }
  },
  
  methods: {
    /**
     * Handle name click
     */
    handleClick(event) {
      this.$log.debug('EVENT', 'Name clicked', {
        linkToProfile: this.linkToProfile,
        profileUrl: this.profileUrl,
        userName: this.userName
      });
      
      if (this.linkToProfile && this.profileUrl && this.profileUrl !== '#') {
        // Let default navigation happen
        this.$log.debug('EVENT', 'Navigating to profile', { url: this.profileUrl });
      }
    },
    
    /**
     * Handle clan click
     */
    handleClanClick(event) {
      this.$log.debug('EVENT', 'Clan tag clicked', {
        clanTag: this.clanTag,
        clanUrl: this.clanUrl
      });
      
      if (!this.linkToProfile) {
        event.preventDefault();
        this.$log.debug('EVENT', 'Clan click prevented (linkToProfile=false)');
      }
      // Let default navigation happen
    }
  },
  
  template: `
    <span :class="['user-name', customClass].filter(Boolean).join(' ')">
      <!-- Country flag -->
      <span v-if="shouldShowCountry" class="user-country">
        <img :src="flagUrl" :alt="countryCode" class="user-flag" />
      </span>
      
      <!-- Clan tag -->
      <span v-if="shouldShowClan" class="user-clan">
        <a :href="clanUrl" @click="handleClanClick" class="user-clan-link">
          <span v-text="'[' + clanTag + ']'"></span>
        </a>
      </span>
      
      <!-- Username -->
      <a v-if="linkToProfile" :href="profileUrl" class="user-username-link" @click="handleClick">
        <span v-text="userName"></span>
      </a>
      <span v-else class="user-username-text" v-text="userName"></span>
    </span>
  `
});

// Register component
if (typeof Vue !== 'undefined' && !Vue.options.components['user-name']) {
  Vue.component('user-name', UserName);
}

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { UserName };
}