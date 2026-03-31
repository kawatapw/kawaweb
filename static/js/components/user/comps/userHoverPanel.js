/**
 * ============================================================================
 * Component: User Hover Panel
 * ============================================================================
 *
 * Composed component that displays detailed user info on hover.
 * Uses atomic sub-components: banner, avatar, username, clan, flag, rank, badges, stats, status
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {Boolean} visible - Whether panel is visible (default: false)
 * @param {Boolean} showCountry - Show country flag (default: false)
 * @param {Boolean} showClan - Show clan tag (default: true)
 * @param {Boolean} showBadges - Show badges (default: true)
 * @param {Boolean} showStatus - Show status (default: true)
 *
 * CSS Classes:
 * - .user-profile-panel (from user-profile-good.css)
 *
 * @component user-hover-panel
 */
(function() {
  'use strict';

  Vue.component('user-hover-panel', {
    name: 'UserHoverPanel',

    inject: {
      userDataController: { default: null }
    },

    props: {
      userId: {
        type: [String, Number],
        required: true
      },
      visible: {
        type: Boolean,
        default: false
      },
      showCountry: {
        type: Boolean,
        default: false
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
        userData: null
      };
    },

    computed: {
      /**
       * Get panel classes
       */
      panelClasses() {
        return {
          'user-profile-panel': true,
          'visible': this.visible
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
       * Handle mouse enter
       */
      handleMouseEnter() {
        this.$emit('mouseenter');
      },

      /**
       * Handle mouse leave
       */
      handleMouseLeave() {
        this.$emit('mouseleave');
      }
    },

    template: '#user-hover-panel-template'
  });
})();