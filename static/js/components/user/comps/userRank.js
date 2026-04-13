/**
 * ============================================================================
 * Component: User Rank
 * ============================================================================
 *
 * Displays user rank (global and/or country).
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {Boolean} showCountry - Show country rank (default: true)
 * @param {String} separator - Separator between ranks (default: ' / ')
 *
 * CSS Classes:
 * - .user-profile-card-ranks (from user-profile-good.css)
 * - .user-profile-panel-rank (from user-profile-good.css)
 *
 * @component user-rank
 */
(function() {
  'use strict';

  Vue.component('user-rank', {
    name: 'UserRank',

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
      }
    },

    data() {
      return {
        userData: null
      };
    },

    computed: {
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
      },

      /**
       * Get global rank
       */
      globalRank() {
        if (!this.currentStats || !this.currentStats.rank) return null;
        return this.currentStats.rank;
      },

      /**
       * Get country rank
       */
      countryRank() {
        if (!this.currentStats || !this.currentStats.country_rank) return null;
        return this.currentStats.country_rank;
      },

      /**
       * Get country code
       */
      country() {
        if (this.userData && this.userData.info) {
          return this.userData.info.country || '';
        }
        return '';
      },

      /**
       * Get flag URL
       */
      flagUrl() {
        if (!this.country) return '';
        return '/static/images/flags/' + this.country.toUpperCase() + '.png';
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
       * Format rank number
       */
      formatRank(rank) {
        if (!rank) return '?';
        return '#' + rank.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
      }
    },

    template: '#user-rank-template'
  });
})();