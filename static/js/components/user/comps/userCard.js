/**
 * ============================================================================
 * Component: User Card
 * ============================================================================
 *
 * Composed component that displays a user card with banner, avatar, stats, etc.
 * Uses atomic sub-components: banner, avatar, username, clan, flag, rank, badges, stats, status
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {Boolean} showCountry - Show country flag (default: true)
 * @param {Boolean} showClan - Show clan tag (default: true)
 * @param {Boolean} showBadges - Show badges (default: true)
 * @param {Boolean} showStatus - Show status (default: true)
 *
 * CSS Classes:
 * - .user-profile-card (from user-profile-good.css)
 *
 * @component user-card
 */
(function() {
  'use strict';

  Vue.component('user-card', {
    name: 'UserCard',

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
        default: true
      },
      showClan: {
        type: Boolean,
        default: true
      },
      showBadges: {
        type: Boolean,
        default: true
      },
      showStatus: {
        type: Boolean,
        default: true
      }
    },

    data() {
      return {
        userData: null,
        statusData: null
      };
    },

    computed: {
      /**
       * Get profile URL
       */
      profileUrl() {
        var id = this._getUserId();
        if (!id) return '#';
        return '/u/' + id;
      },

      /**
       * Get status string for CSS variable
       */
      statusString() {
        if (!this.statusData || this.statusData.online === 'false' || this.statusData.online === false) return 'offline';
        if (!this.statusData.status) return 'online';

        var action = this.statusData.status.action;
        if (action === 2 || action === 9) return 'playing';
        if (action === 8) return 'paused';
        if (action === 0) return 'idle';
        if (action === 1) return 'afk';

        return 'online';
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
        var controller = this.userDataController || window.__userDataController;
        if (controller) {
          controller.registerComponent(this.userId, this);
        }
      },

      /**
       * Unregister from the data controller
       */
      _unregisterFromController() {
        var controller = this.userDataController || window.__userDataController;
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
       * Set status data (called by controller)
       */
      setStatusData(data) {
        this.statusData = data;
      }
    },

    template: '#user-card-template'
  });
})();