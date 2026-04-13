/**
 * ============================================================================
 * Component: User Username Hover
 * ============================================================================
 *
 * Composed component that shows username with hover panel.
 * Uses atomic sub-components: username + hover-panel
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {Boolean} showCountry - Show country flag (default: false)
 * @param {Boolean} showClan - Show clan tag (default: true)
 * @param {Boolean} showBadges - Show badges (default: true)
 * @param {Boolean} showStatus - Show status (default: true)
 * @param {Boolean} interactive - Enable hover interactions (default: true)
 *
 * CSS Classes:
 * - .user-profile-username-container (from user-profile-good.css)
 *
 * @component user-username-hover
 */
(function() {
  'use strict';

  Vue.component('user-username-hover', {
    name: 'UserUsernameHover',

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
      },
      showBadges: {
        type: Boolean,
        default: true
      },
      showStatus: {
        type: Boolean,
        default: true
      },
      interactive: {
        type: Boolean,
        default: true
      }
    },

    data() {
      return {
        userData: null,
        profileVisible: false,
        mouseOverPanel: false
      };
    },

    computed: {
      /**
       * Get container classes
       */
      containerClasses() {
        return {
          'user-profile-username-container': true,
          'interactive': this.interactive
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
       * Show profile panel
       */
      showProfile() {
        if (!this.interactive) return;
        this.profileVisible = true;
      },

      /**
       * Hide profile panel
       */
      hideProfile() {
        if (!this.interactive) return;
        if (!this.mouseOverPanel) {
          this.profileVisible = false;
        }
      },

      /**
       * Handle mouse enter on panel
       */
      mouseEnterPanel() {
        this.mouseOverPanel = true;
      },

      /**
       * Handle mouse leave on panel
       */
      mouseLeavePanel() {
        this.mouseOverPanel = false;
        this.profileVisible = false;
      }
    },

    template: '#user-username-hover-template'
  });
})();