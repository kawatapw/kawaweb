/**
 * ============================================================================
 * Component: User Username
 * ============================================================================
 *
 * Displays username with optional clan tag and country flag.
 * Links to user profile page.
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {Boolean} showCountry - Show country flag (default: false)
 * @param {Boolean} showClan - Show clan tag (default: true)
 *
 * CSS Classes:
 * - .user-username-link (from user-profile-good.css)
 * - .user-profile-card-username (from user-profile-good.css)
 * - .user-profile-search-username (from user-profile-good.css)
 *
 * @component user-username
 */
(function() {
  'use strict';

  Vue.component('user-username', {
    name: 'UserUsername',

    inject: {
      userDataController: { default: null }
    },

    props: {
      userId: {
        type: [String, Number],
        required: true
      },
      showCountry: {
        type: Boolean,
        default: false
      },
      showClan: {
        type: Boolean,
        default: true
      }
    },

    data() {
      return {
        userData: null
      };
    },

    computed: {
      /**
       * Get user info
       */
      userInfo() {
        if (!this.userData) return null;
        return this.userData.info || {};
      },

      /**
       * Get username
       */
      username() {
        return this.userInfo?.name || '';
      },

      /**
       * Get clan tag
       */
      clanTag() {
        return this.userInfo?.clan_tag || this.userInfo?.clan?.tag || '';
      },

      /**
       * Get country code
       */
      country() {
        return this.userInfo?.country || '';
      },

      /**
       * Get profile URL
       */
      profileUrl() {
        const id = this._getUserId();
        if (!id) return '#';
        return `/u/${id}`;
      },

      /**
       * Get clan URL
       */
      clanUrl() {
        const clanId = this.userInfo?.clan_id || this.userInfo?.clan?.id;
        if (!clanId) return '#';
        return `/clans/${clanId}`;
      },

      /**
       * Get flag URL
       */
      flagUrl() {
        if (!this.country) return '';
        return `/static/images/flags/${this.country.toUpperCase()}.png`;
      }
    },

    created() {
      this._registerWithController();
    },

    beforeDestroy() {
      this._unregisterFromController();
    },

    watch: {
      userId: function(newId, oldId) {
        if (newId !== oldId) {
          this._unregisterFromController();
          this._registerWithController();
        }
      }
    },

    methods: {
      /**
       * Get user ID from data or props
       */
      _getUserId() {
        if (this.userData) {
          return this.userData.info?.id || this.userData.player_id || this.userData.id;
        }
        return this.userId;
      },

      /**
       * Register with the data controller
       */
      _registerWithController() {
        const controller = this.userDataController || window.__userDataController;
        if (controller) {
          controller.registerComponent(this.userId, this);
        }
      },

      /**
       * Unregister from the data controller
       */
      _unregisterFromController() {
        const controller = this.userDataController || window.__userDataController;
        if (controller) {
          controller.unregisterComponent(this.userId, this);
        }
      },

      /**
       * Set user data (called by controller)
       */
      setUserData(data) {
        this.userData = data;
      },

      /**
       * Handle clan click
       */
      handleClanClick(event) {
        // Allow default navigation
      }
    },

    template: '#user-username-template'
  });
})();