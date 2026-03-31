/**
 * ============================================================================
 * Component: User Status
 * ============================================================================
 *
 * Displays user online status with indicator and text.
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {String} style - Display style: 'indicator', 'text', 'full' (default: 'full')
 *
 * CSS Classes:
 * - .user-status (from user-components.css)
 * - .user-profile-panel-status (from user-profile-good.css)
 *
 * Status Classes:
 * - .online, .playing, .idle, .afk, .offline
 *
 * @component user-status
 */
(function() {
  'use strict';

  Vue.component('user-status', {
    name: 'UserStatus',

    inject: {
      userDataController: { default: null }
    },

    props: {
      userId: {
        type: [String, Number],
        required: true
      },
      style: {
        type: String,
        default: 'full',
        validator: function(value) {
          return ['indicator', 'text', 'full'].includes(value);
        }
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
       * Check if user is online
       */
      isOnline() {
        if (!this.statusData) return false;
        return this.statusData.online !== 'false' && this.statusData.online !== false;
      },

      /**
       * Get status string
       */
      statusString() {
        if (!this.isOnline) return 'offline';
        if (!this.statusData.status) return 'online';

        const action = this.statusData.status.action;
        if (action === 2 || action === 9) return 'playing';
        if (action === 8) return 'paused';
        if (action === 0) return 'idle';
        if (action === 1) return 'afk';

        return 'online';
      },

      /**
       * Get status text
       */
      statusText() {
        if (!this.statusData) return 'Offline';

        if (!this.isOnline) {
          if (this.statusData.last_seen) {
            return 'Offline | Last seen ' + this._formatTimeAgo(this.statusData.last_seen);
          }
          return 'Offline';
        }

        if (!this.statusData.status) return 'Online';

        const action = this.statusData.status.action;
        const infoText = this.statusData.status.info_text;

        switch (action) {
          case 0: return 'Idle: 🔍 Song Select';
          case 1: return '🌙 AFK';
          case 2: return 'Playing: 🎶 ' + infoText;
          case 3: return 'Editing: 🔨 ' + infoText;
          case 4: return 'Modding: 🔨 ' + infoText;
          case 5: return 'In Multiplayer: Song Select';
          case 6: return 'Watching: 👓 ' + infoText;
          case 8: return 'Testing: 🎾 ' + infoText;
          case 9: return 'Submitting: 🧼 ' + infoText;
          case 11: return 'Idle: 🏢 In multiplayer lobby';
          case 12: return 'In Multiplayer: Playing 🌍 ' + infoText + ' 🎶';
          case 13: return 'Idle: 🔍 Searching for beatmaps in osu!direct';
          default: return 'Unknown';
        }
      },

      /**
       * Get status classes
       */
      statusClasses() {
        return {
          'user-status': true,
          'online': this.isOnline && this.statusString === 'online',
          'playing': this.statusString === 'playing',
          'idle': this.statusString === 'idle',
          'afk': this.statusString === 'afk',
          'offline': !this.isOnline
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
       * Set status data (called by controller)
       */
      setStatusData(data) {
        this.statusData = data;
      },

      /**
       * Format time ago
       */
      _formatTimeAgo(dateString) {
        var date;
        if (typeof dateString === 'number' || /^\d+$/.test(dateString)) {
          date = new Date(dateString * 1000);
        } else {
          date = new Date(dateString);
        }

        var now = new Date();
        var seconds = Math.floor((now - date) / 1000);

        var interval = seconds / 31536000;
        if (interval >= 1) {
          var years = Math.floor(interval);
          return years === 1 ? '1 year ago' : years + ' years ago';
        }

        interval = seconds / 2592000;
        if (interval >= 1) {
          var months = Math.floor(interval);
          return months === 1 ? '1 month ago' : months + ' months ago';
        }

        interval = seconds / 86400;
        if (interval >= 1) {
          var days = Math.floor(interval);
          return days === 1 ? '1 day ago' : days + ' days ago';
        }

        interval = seconds / 3600;
        if (interval >= 1) {
          var hours = Math.floor(interval);
          return hours === 1 ? '1 hour ago' : hours + ' hours ago';
        }

        interval = seconds / 60;
        if (interval >= 1) {
          var minutes = Math.floor(interval);
          return minutes === 1 ? '1 minute ago' : minutes + ' minutes ago';
        }

        return Math.floor(seconds) + ' seconds ago';
      }
    },

    template: '#user-status-template'
  });
})();