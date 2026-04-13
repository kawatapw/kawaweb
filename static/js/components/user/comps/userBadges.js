/**
 * ============================================================================
 * Component: User Badges
 * ============================================================================
 *
 * Displays user badges with popup panels.
 *
 * Props:
 * @param {String|Number} userId - User ID (required)
 * @param {Array} badges - Direct badges array (optional, overrides userId lookup)
 *
 * CSS Classes:
 * - .user-badges (from user-components.css)
 * - .badge, .iconBadge (from user-components.css)
 *
 * @component user-badges
 */
(function() {
  'use strict';

  Vue.component('user-badges', {
    name: 'UserBadges',

    inject: {
      userDataController: { default: null },
      providedUserId: { default: null }
    },

    props: {
      userId: {
        type: [String, Number],
        default: null
      },
      badges: {
        type: Array,
        default: null
      }
    },

    data() {
      return {
        userData: null,
        internalBadges: null
      };
    },

    computed: {
      /**
       * Get the effective user ID (from prop or injected)
       */
      effectiveUserId() {
        if (this.userId !== null) {
          return this.userId;
        }
        if (this.providedUserId !== null) {
          return this.providedUserId;
        }
        return null;
      },

      /**
       * Get badges array
       */
      badgeList() {
        // Direct prop takes priority
        if (this.badges && this.badges.length > 0) {
          console.log('[UserBadges] Using direct badges prop:', this.badges);
          return this.badges;
        }
        // Fall back to internal badges (from setUserData)
        if (this.internalBadges && this.internalBadges.length > 0) {
          console.log('[UserBadges] Using internal badges:', this.internalBadges);
          return this.internalBadges;
        }
        // Fall back to user data
        if (this.userData && this.userData.info && this.userData.info.badges) {
          console.log('[UserBadges] Using badges from userData.info:', this.userData.info.badges);
          return this.userData.info.badges;
        }
        console.log('[UserBadges] No badges found. userData:', this.userData, 'badges prop:', this.badges, 'internalBadges:', this.internalBadges);
        return [];
      },

      /**
       * Check if we have badges
       */
      hasBadges() {
        return this.badgeList && this.badgeList.length > 0;
      }
    },

    created() {
      console.log('[UserBadges] created() called. userId:', this.userId, 'providedUserId:', this.providedUserId, 'effectiveUserId:', this.effectiveUserId);
      if (this.effectiveUserId) {
        this._registerWithController();
      }
    },

    beforeDestroy() {
      if (this.effectiveUserId) {
        this._unregisterFromController();
      }
    },

    watch: {
      effectiveUserId: {
        handler: function(newId, oldId) {
          console.log('[UserBadges] effectiveUserId changed from', oldId, 'to', newId);
          if (newId !== oldId) {
            this._unregisterFromController();
            if (newId) {
              this._registerWithController();
            }
          }
        },
        immediate: true
      },
      /**
       * Watch for badges prop changes (for profile page usage)
       */
      badges: {
        handler: function(newBadges) {
          console.log('[UserBadges] badges prop changed:', newBadges);
          if (newBadges && newBadges.length > 0) {
            this.internalBadges = newBadges;
          }
        },
        immediate: true,
        deep: true
      }
    },

    methods: {
      /**
       * Register with the data controller
       */
      _registerWithController() {
        const controller = this.userDataController || window.__userDataController;
        if (controller && this.effectiveUserId) {
          controller.registerComponent(this.effectiveUserId, this);
        }
      },

      /**
       * Unregister from the data controller
       */
      _unregisterFromController() {
        const controller = this.userDataController || window.__userDataController;
        if (controller && this.effectiveUserId) {
          controller.unregisterComponent(this.effectiveUserId, this);
        }
      },

      /**
       * Set user data (called by controller)
       */
      setUserData(data) {
        console.log('[UserBadges] setUserData called:', data);
        this.userData = data;
        // Also store badges directly for reactivity
        if (data && data.info && data.info.badges) {
          this.internalBadges = data.info.badges;
          console.log('[UserBadges] Set internalBadges from setUserData:', this.internalBadges);
        }
      }
    },


    template: '#user-badges-template'
  });
})();