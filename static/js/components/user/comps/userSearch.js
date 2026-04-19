/**
 * ============================================================================
 * Component: User Search
 * ============================================================================
 *
 * Composed component for compact user display in search results/lists.
 * Uses atomic sub-components: avatar, username, clan, flag, stats
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {Boolean} showCountry - Show country flag (default: false)
 * @param {Boolean} showClan - Show clan tag (default: true)
 *
 * CSS Classes:
 * - .user-profile-search (from user-profile-good.css)
 *
 * @component user-search
 */
(function() {
  'use strict';

  Vue.component('user-search', {
    name: 'UserSearch',

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
       * Get profile URL
       */
      profileUrl() {
        var id = this._getUserId();
        if (!id) return '#';
        return '/u/' + id;
      },

      /**
       * Get current stats
       */
      currentStats() {
        if (!this.userData) return null;

        // Try stats.current first
        if (this.userData.stats && this.userData.stats.current) {
          var firstMode = Object.keys(this.userData.stats.current)[0];
          return this.userData.stats.current[firstMode] || null;
        }

        // Try stats directly
        if (this.userData.stats) {
          var preferredMode = this.userData.info?.preferred_mode || 0;
          return this.userData.stats[preferredMode] || null;
        }

        return null;
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
       * Format number with commas
       */
      formatNumber(num) {
        if (num === null || num === undefined) return '0';
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
      },

      /**
       * Format accuracy
       */
      formatAccuracy(acc) {
        if (!acc) return '0.00';
        return parseFloat(acc).toFixed(2);
      }
    },

    template: '#user-search-template'
  });
})();