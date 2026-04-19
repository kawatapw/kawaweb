/**
 * ============================================================================
 * User Data Provider Component
 * ============================================================================
 *
 * Vue component that wraps the UserDataController and provides data
 * to child components via provide/inject.
 *
 * Features:
 * - Provides user data context to all child components
 * - Manages auto-refresh of status data
 * - Integrates with UserDataController for deduplication
 *
 * Usage:
 *   <user-data-provider :auto-refresh-status="true">
 *     <user-card user-id="123" />
 *     <user-avatar user-id="123" />
 *   </user-data-provider>
 *
 * @component user-data-provider
 */
(function() {
  'use strict';

  Vue.component('user-data-provider', {
    name: 'UserDataProvider',

    props: {
      /**
       * Whether to automatically refresh status data
       * @type {Boolean}
       * @default true
       */
      autoRefreshStatus: {
        type: Boolean,
        default: true
      },
      /**
       * User ID to provide to child components
       * @type {String|Number}
       * @default null
       */
      userId: {
        type: [String, Number],
        default: null
      }
    },

    data() {
      // Initialize controller in data() so it's available when provide() runs
      // (Vue 2 evaluates provide() before created(), so created() is too late)
      const controller = window.__userDataController;

      // Initialize logger
      let logger = null;
      if (window.ColorfulLogger) {
        logger = window.ColorfulLogger.child('UserDataProvider');
      }

      if (!controller) {
        if (logger) {
          logger.error('PROVIDER', 'UserDataController not available in data()');
        } else {
          console.warn('[UserDataProvider] UserDataController not available');
        }
      } else {
        if (logger) {
          logger.debug('LIFECYCLE', 'data() called, controller found', {
            autoRefreshStatus: this.autoRefreshStatus,
            userId: this.userId
          });
        }
      }

      return {
        controller: controller || null,
        logger: logger
      };
    },

    provide() {
      this._log('debug', 'PROVIDER', 'provide() called, providing controller and userId to children', {
        hasController: !!this.controller,
        userId: this.userId
      });

      return {
        userDataController: this.controller,
        providedUserId: this.userId
      };
    },

    created() {
      this._log('debug', 'LIFECYCLE', 'created() called', {
        hasController: !!this.controller,
        userId: this.userId,
        autoRefreshStatus: this.autoRefreshStatus
      });

      if (!this.controller) {
        this._log('error', 'LIFECYCLE', 'Controller not available in created()');
      }
    },

    mounted() {
      this._log('debug', 'LIFECYCLE', 'mounted() called', {
        userId: this.userId,
        childCount: this.$children ? this.$children.length : 0
      });
    },

    beforeDestroy() {
      this._log('debug', 'LIFECYCLE', 'beforeDestroy() called', {
        userId: this.userId
      });
    },

    watch: {
      userId(newVal, oldVal) {
        this._log('debug', 'PROVIDER', 'userId prop changed', {
          oldValue: oldVal,
          newValue: newVal
        });
      },
      autoRefreshStatus(newVal, oldVal) {
        this._log('debug', 'PROVIDER', 'autoRefreshStatus prop changed', {
          oldValue: oldVal,
          newValue: newVal
        });
      }
    },

    methods: {
      _log(level, category, message, data) {
        if (this.logger) {
          this.logger[level](category, message, data);
        }
      }
    },

    render(h) {
      this._log('trace', 'RENDER', 'render() called');

      // Render children without wrapping DOM element
      if (this.$slots.default) {
        const slotCount = this.$slots.default.length;
        this._log('trace', 'RENDER', `Rendering ${slotCount} child slot(s)`);
        return slotCount === 1
          ? this.$slots.default[0]
          : h('div', { style: { display: 'contents' } }, this.$slots.default);
      }

      this._log('trace', 'RENDER', 'No default slot content');
      return null;
    }
  });
})();