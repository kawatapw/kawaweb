/**
 * User Profile Components - Index
 * Registers all user profile components and provides a simple way to include them.
 */

// Import dependencies (in a build system these would be proper imports)
// In plain JS, we assume these files are loaded in order

// Export all components for manual registration if needed
const UserComponents = {
  UserDataController: typeof UserDataController !== 'undefined' ? UserDataController : null,
  UserDataProvider: typeof UserDataProvider !== 'undefined' ? UserDataProvider : null,
  UserAvatar: typeof UserAvatar !== 'undefined' ? UserAvatar : null,
  UserName: typeof UserName !== 'undefined' ? UserName : null,
  UserBadges: typeof UserBadges !== 'undefined' ? UserBadges : null,
  UserStatus: typeof UserStatus !== 'undefined' ? UserStatus : null,
  UserStats: typeof UserStats !== 'undefined' ? UserStats : null,
  UserCard: typeof UserCard !== 'undefined' ? UserCard : null,
  UserProfile: typeof UserProfile !== 'undefined' ? UserProfile : null
};

// Auto-register all components with Vue (if not already registered)
function registerAll() {
  if (typeof Vue === 'undefined') {
    console.error('UserComponents: Vue is not defined. Make sure Vue is loaded before this script.');
    return;
  }
  
  // Components are already self-registering via Vue.component()
  // This function exists for explicit registration if needed
  console.log('UserComponents: All components registered');
}

// Initialize when DOM is ready
if (typeof document !== 'undefined') {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', registerAll);
  } else {
    registerAll();
  }
}

// Export for module systems
if (typeof module !== 'undefined' && module.exports) {
  module.exports = UserComponents;
}

// Also expose globally for debugging
if (typeof window !== 'undefined') {
  window.UserComponents = UserComponents;
}