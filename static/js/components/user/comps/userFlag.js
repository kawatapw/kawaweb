/**
 * ============================================================================
 * Component: User Flag
 * ============================================================================
 *
 * Displays user country flag.
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {String} country - Direct country code (optional, overrides userId lookup)
 * @param {String} size - Flag size: 'small', 'normal', 'large' (default: 'normal')
 *
 * CSS Classes:
 * - .user-flag (from user-components.css)
 * - .user-profile-card-country (from user-profile-good.css)
 *
 * @component user-flag
 */
(function() {
  'use strict';

  Vue.component('user-flag', {
    name: 'UserFlag',

    inject: {
      userDataController: { default: null }
    },

    props: {
      userId: {
        type: [String, Number],
        default: null
      },
      country: {
        type: String,
        default: null
      },
      size: {
        type: String,
        default: 'normal',
        validator: function(value) {
          return ['small', 'normal', 'large'].includes(value);
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
       * Get country code
       */
      countryCode() {
        if (this.country) return this.country;
        if (this.userData && this.userData.info) {
          return this.userData.info.country || '';
        }
        return '';
      },

      /**
       * Get flag URL
       */
      flagUrl() {
        if (!this.countryCode) return '';
        return '/static/images/flags/' + this.countryCode.toUpperCase() + '.png';
      },

      /**
       * Get flag alt text
       */
      flagAlt() {
        return this.countryCode ? this.countryCode.toUpperCase() : '';
      },

      /**
       * Get CSS classes
       */
      flagClasses() {
        return {
          'user-flag': true,
          'user-flag--small': this.size === 'small',
          'user-flag--normal': this.size === 'normal',
          'user-flag--large': this.size === 'large'
        };
      }
    },

    created() {
      if (this.userId) {
        this._registerWithController();
      }
    },

    beforeDestroy() {
      if (this.userId) {
        this._unregisterFromController();
      }
    },

    watch: {
      userId: function(newId, oldId) {
        if (newId !== oldId) {
          this._unregisterFromController();
          if (newId) {
            this._registerWithController();
          }
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
      }
    },

    template: '#user-flag-template'
  });
})();