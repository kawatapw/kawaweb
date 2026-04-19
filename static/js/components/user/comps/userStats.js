/**
 * ============================================================================
 * Component: User Stats
 * ============================================================================
 *
 * Displays user statistics (PP, accuracy, plays, etc.)
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {Array} fields - Stats fields to display (default: ['pp', 'acc', 'plays'])
 * @param {String} layout - Layout style: 'horizontal', 'vertical', 'compact' (default: 'horizontal')
 *
 * CSS Classes:
 * - .user-stats (from user-components.css)
 * - .user-profile-card-stats (from user-profile-good.css)
 * - .user-profile-panel-stats (from user-profile-good.css)
 *
 * @component user-stats
 */
(function() {
  'use strict';

  Vue.component('user-stats', {
    name: 'UserStats',

    inject: {
      userDataController: { default: null }
    },

    props: {
      userId: {
        type: [String, Number],
        required: true
      },
      fields: {
        type: Array,
        default: function() {
          return ['pp', 'acc', 'plays'];
        }
      },
      layout: {
        type: String,
        default: 'horizontal',
        validator: function(value) {
          return ['horizontal', 'vertical', 'compact'].includes(value);
        }
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

        // Try stats.current first (new structure)
        if (this.userData.stats && this.userData.stats.current) {
          const firstMode = Object.keys(this.userData.stats.current)[0];
          return this.userData.stats.current[firstMode] || null;
        }

        // Try stats directly (old structure)
        if (this.userData.stats) {
          const preferredMode = this.userData.info?.preferred_mode || 0;
          return this.userData.stats[preferredMode] || null;
        }

        return null;
      },

      /**
       * Get stat items to display
       */
      statItems() {
        if (!this.currentStats) return [];

        const items = [];
        const fieldMap = {
          pp: { label: 'PP', value: this._formatNumber(this.currentStats.pp), suffix: '' },
          acc: { label: 'Accuracy', value: this._formatAccuracy(this.currentStats.acc), suffix: '%' },
          plays: { label: 'Plays', value: this._formatNumber(this.currentStats.plays), suffix: '' },
          rank: { label: 'Rank', value: this.currentStats.rank ? '#' + this._formatNumber(this.currentStats.rank) : '-', suffix: '' },
          country_rank: { label: 'Country Rank', value: this.currentStats.country_rank ? '#' + this._formatNumber(this.currentStats.country_rank) : '-', suffix: '' }
        };

        this.fields.forEach(function(field) {
          if (fieldMap[field]) {
            items.push(fieldMap[field]);
          }
        });

        return items;
      },

      /**
       * Get CSS classes
       */
      statsClasses() {
        return {
          'user-stats': true,
          'user-stats--horizontal': this.layout === 'horizontal',
          'user-stats--vertical': this.layout === 'vertical',
          'user-stats--compact': this.layout === 'compact'
        };
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
       * Format number with commas
       */
      _formatNumber(num) {
        if (num === null || num === undefined) return '0';
        return num.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
      },

      /**
       * Format accuracy
       */
      _formatAccuracy(acc) {
        if (!acc) return '0.00';
        return parseFloat(acc).toFixed(2);
      }
    },

    template: '#user-stats-template'
  });
})();