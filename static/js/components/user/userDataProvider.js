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
      if (!controller) {
        console.warn('[UserDataProvider] UserDataController not available');
      }
      return {
        controller: controller || null
      };
    },

    provide() {
      return {
        userDataController: this.controller,
        providedUserId: this.userId
      };
    },

    render(h) {
      // Render children without wrapping DOM element
      if (this.$slots.default) {
        return this.$slots.default.length === 1 
          ? this.$slots.default[0] 
          : h('div', { style: { display: 'contents' } }, this.$slots.default);
      }
      return null;
    }
  });
})();