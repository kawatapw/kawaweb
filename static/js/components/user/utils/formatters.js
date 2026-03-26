/**
 * User Profile System - Formatters
 * Shared formatting utilities for numbers, accuracy, dates, etc.
 */

const Formatters = {
  /**
   * Format a number with locale-specific thousands separators
   * @param {number} num - Number to format
   * @returns {string} Formatted number
   */
  formatNumber(num) {
    if (num === null || num === undefined || isNaN(num)) return '0';
    return num.toLocaleString();
  },

  /**
   * Format accuracy to 2 decimal places with percentage
   * @param {number} acc - Accuracy value (0-100)
   * @returns {string} Formatted accuracy string (e.g., "99.50%")
   */
  formatAccuracy(acc) {
    if (acc === null || acc === undefined || isNaN(acc)) return '0.00';
    return parseFloat(acc).toFixed(2);
  },

  /**
   * Format seconds to human-readable duration (MM:SS or HH:MM:SS)
   * @param {number} seconds - Duration in seconds
   * @returns {string} Formatted duration
   */
  formatDuration(seconds) {
    if (!seconds || isNaN(seconds)) return '0:00';
    
    const hrs = Math.floor(seconds / 3600);
    const mins = Math.floor((seconds % 3600) / 60);
    const secs = Math.floor(seconds % 60);
    
    if (hrs > 0) {
      return `${hrs}:${mins.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
    }
    return `${mins}:${secs.toString().padStart(2, '0')}`;
  },

  /**
   * Format a date string or Unix timestamp to "time ago" string
   * @param {string|number} dateString - Date string or Unix timestamp (seconds)
   * @returns {string} Human-readable time ago string
   */
  formatTimeAgo(dateString) {
    let date;
    if (typeof dateString === 'number' || /^\d+$/.test(dateString)) {
      // Unix timestamp in seconds - convert to milliseconds
      date = new Date(dateString * 1000);
    } else {
      // Date string
      date = new Date(dateString);
    }
    
    if (isNaN(date.getTime())) return 'Never';
    
    const now = new Date();
    const seconds = Math.floor((now - date) / 1000);
    
    const intervals = [
      { label: 'year', seconds: 31536000 },
      { label: 'month', seconds: 2592000 },
      { label: 'day', seconds: 86400 },
      { label: 'hour', seconds: 3600 },
      { label: 'minute', seconds: 60 },
      { label: 'second', seconds: 1 }
    ];
    
    for (const interval of intervals) {
      const count = Math.floor(seconds / interval.seconds);
      if (count >= 1) {
        return `${count} ${interval.label}${count !== 1 ? 's' : ''} ago`;
      }
    }
    
    return 'Just now';
  },

  /**
   * Format a date to localized date string
   * @param {string|number} dateString - Date string or timestamp
   * @returns {string} Formatted date
   */
  formatDate(dateString) {
    let date;
    if (typeof dateString === 'number' || /^\d+$/.test(dateString)) {
      date = new Date(dateString * 1000);
    } else {
      date = new Date(dateString);
    }
    
    if (isNaN(date.getTime())) return 'Invalid date';
    return date.toLocaleDateString();
  },

  /**
   * Format rank with # prefix
   * @param {number} rank - Rank number
   * @returns {string} Formatted rank (e.g., "#1")
   */
  formatRank(rank) {
    if (rank === null || rank === undefined || isNaN(rank)) return '?';
    return `#${rank}`;
  },

  /**
   * Get status text from status data
   * @param {object} statusData - Status data from API
   * @returns {string} Human-readable status text
   */
  getStatusText(statusData) {
    if (!statusData || statusData.online === false || statusData.online === 'false') {
      if (statusData && statusData.last_seen) {
        return `Offline | Last seen ${this.formatTimeAgo(statusData.last_seen)}`;
      }
      return 'Offline';
    }
    
    if (!statusData.status) return 'Online';
    
    const action = statusData.status.action;
    const infoText = statusData.status.info_text || '';
    
    const statusMap = {
      0: `Idle: 🔍 Song Select`,
      1: '🌙 AFK',
      2: `Playing: 🎶 ${infoText}`,
      3: `Editing: 🔨 ${infoText}`,
      4: `Modding: 🔨 ${infoText}`,
      5: 'In Multiplayer: Song Select',
      6: `Watching: 👓 ${infoText}`,
      8: `Testing: 🎾 ${infoText}`,
      9: `Submitting: 🧼 ${infoText}`,
      11: 'Idle: 🏢 In multiplayer lobby',
      12: `In Multiplayer: Playing 🌍 ${infoText} 🎶`,
      13: 'Idle: 🔍 Searching for beatmaps in osu!direct'
    };
    
    return statusMap[action] || 'Unknown: 🚔 not yet implemented!';
  },

  /**
   * Get status CSS class from status data
   * @param {object} statusData - Status data from API
   * @returns {string} CSS class name
   */
  getStatusClass(statusData) {
    if (!statusData || statusData.online === false || statusData.online === 'false') {
      return 'offline';
    }
    
    if (!statusData.status) return 'online';
    
    const action = statusData.status.action;
    
    if (action === 2 || action === 9) return 'playing';
    if (action === 8) return 'paused';
    if (action === 0 || action === 11 || action === 13) return 'idle';
    if (action === 1) return 'afk';
    
    return 'online';
  },

  /**
   * Get status string for CSS variable
   * @param {object} statusData - Status data from API
   * @returns {string} Status name for CSS variable
   */
  getStatusString(statusData) {
    if (!statusData || statusData.online === false || statusData.online === 'false') {
      return 'offline';
    }
    
    if (!statusData.status) return 'online';
    
    const action = statusData.status.action;
    
    if (action === 2 || action === 9) return 'playing';
    if (action === 8) return 'paused';
    if (action === 0 || action === 11 || action === 13) return 'idle';
    if (action === 1) return 'afk';
    
    return 'online';
  }
};

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Formatters;
}