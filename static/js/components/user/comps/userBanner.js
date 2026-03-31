/**
 * ============================================================================
 * Component: User Banner
 * ============================================================================
 *
 * Displays user banner/background image.
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {String} type - Banner type: 'banner' or 'background' (default: 'banner')
 *
 * CSS Classes:
 * - .user-profile-card-background (from user-profile-good.css)
 * - .user-profile-panel-background (from user-profile-good.css)
 *
 * @component user-banner
 */
(function() {
  'use strict';

  Vue.component('user-banner', {
    name: 'UserBanner',

    inject: {
      userDataController: { default: null }
    },

    props: {
      userId: {
        type: [String, Number],
        required: true
      },
      type: {
        type: String,
        default: 'banner',
        validator: function(value) {
          return ['banner', 'background'].includes(value);
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
       * Get banner URL
       */
      bannerUrl() {
        const id = this._getUserId();
        if (!id) return '';
        
        if (this.type === 'background') {
          return `/backgrounds/${id}`;
        }
        return `/banners/${id}`;
      },

      /**
       * Get inline styles
       */
      bannerStyles() {
        const url = this.bannerUrl;
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
      }
    },

    template: '#user-banner-template'
  });
})();