/**
 * ============================================================================
 * Beatmap Components Index
 * ============================================================================
 *
 * Registers all beatmap components and initializes the data store.
 * Import this file to use beatmap components in your application.
 *
 * Usage:
 *   <script src="/static/js/components/beatmap/index.js"></script>
 *
 * Components registered:
 *   - beatmap-card (main component)
 *   - beatmap-mini-card
 *   - beatmap-difficulty-icon
 *   - beatmap-difficulty-list
 *   - beatmap-popup
 *   - beatmap-status-badge
 */

(function() {
  'use strict';

  // Wait for ColorfulLogger to be available
  const waitForLogger = () => {
    if (window.ColorfulLogger) {
      const logger = window.ColorfulLogger.child('BeatmapComponents');
      logger.info('LIFECYCLE', 'Beatmap components index loaded');
      
      // Log all registered components
      const components = [
        'beatmap-card',
        'beatmap-mini-card',
        'beatmap-difficulty-icon',
        'beatmap-difficulty-list',
        'beatmap-popup',
        'beatmap-status-badge'
      ];
      
      logger.info('LIFECYCLE', 'Registered beatmap components', {
        components: components,
        count: components.length
      });

      // Check if data store is available
      if (window.__beatmapDataStore) {
        logger.info('LIFECYCLE', 'BeatmapDataStore singleton available');
      } else {
        logger.warn('LIFECYCLE', 'BeatmapDataStore singleton not yet initialized');
      }
    } else {
      setTimeout(waitForLogger, 100);
    }
  };
  waitForLogger();
})();