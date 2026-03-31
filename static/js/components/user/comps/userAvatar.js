/**
 * ============================================================================
 * Component: User Avatar
 * ============================================================================
 *
 * Displays user avatar with optional status indicator ring.
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {String} size - Avatar size: 'small', 'normal', 'large' (default: 'normal')
 * @param {Boolean} showStatus - Show status indicator ring (default: false)
 *
 * CSS Classes:
 * - .user-profile-avatar (base class from user-profile-good.css)
 * - .with-status (adds status ring glow)
 *
 * @component user-avatar
 */
(function() {
  'use strict';

  Vue.component('user-avatar', {
    name: 'UserAvatar',

    inject: {
      userDataController: { default: null }
    },

    props: {
      userId: {
        type: [String, Number],
        required: true
      },
      size: {
        type: String,
        default: 'normal',
        validator: function(value) {
          return ['small', 'normal', 'large'].includes(value);
        }
      },
      showStatus: {
        type: Boolean,
        default: false
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
       * Get avatar URL
       */
      avatarUrl() {
        if (!this.userData) return '';
        const id = this._getUserId();
        if (!id) return '';
        const apiDomain = window.domain || 'kawata.pw';
        return `https://a.${apiDomain}/${id}`;
      },

      /**
       * Get CSS classes for avatar
       */
      avatarClasses() {
        return {
          'user-profile-avatar': true,
          'with-status': this.showStatus && this.statusData
        };
      },

      /**
       * Get inline styles for avatar
       */
      avatarStyles() {
        const url = this.avatarUrl;
        if (!url) return {};
        return {
          backgroundImage: `url(${url})`
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
       * Set status data (called by controller)
       */
      setStatusData(data) {
        this.statusData = data;
      }
    },

    template: '#user-avatar-template'
  });
})();