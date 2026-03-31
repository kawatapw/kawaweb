/**
 * ============================================================================
 * Component: User Clan
 * ============================================================================
 *
 * Displays user clan tag with link to clan page.
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 *
 * CSS Classes:
 * - .user-clan (from user-components.css)
 * - .user-profile-card-clan (from user-profile-good.css)
 * - .user-profile-panel-clan (from user-profile-good.css)
 *
 * @component user-clan
 */
(function() {
  'use strict';

  Vue.component('user-clan', {
    name: 'UserClan',

    inject: {
      userDataController: { default: null }
    },

    props: {
      userId: {
        type: [String, Number],
        required: true
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
       * Get clan tag
       */
      clanTag() {
        return this.userInfo?.clan_tag || this.userInfo?.clan?.tag || '';
      },

      /**
       * Get clan ID
       */
      clanId() {
        return this.userInfo?.clan_id || this.userInfo?.clan?.id || null;
      },

      /**
       * Check if user has clan
       */
      hasClan() {
        return !!this.clanTag;
      },

      /**
       * Get clan URL
       */
      clanUrl() {
        if (!this.clanId) return '#';
        return '/clans/' + this.clanId;
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
       * Handle click
       */
      handleClick(event) {
        // Allow default navigation
      }
    },

    template: '#user-clan-template'
  });
})();