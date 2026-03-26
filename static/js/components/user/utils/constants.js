/**
 * User Profile System - Constants
 * Centralized constants for status codes, mode names, and other shared values
 */

const STATUS = {
  ONLINE: 'online',
  OFFLINE: 'offline',
  IDLE: 'idle',
  AFK: 'afk',
  PLAYING: 'playing',
  PAUSED: 'paused'
};

const STATUS_ACTIONS = {
  0: { name: 'idle', label: 'Idle: 🔍 Song Select', class: 'idle' },
  1: { name: 'afk', label: '🌙 AFK', class: 'afk' },
  2: { name: 'playing', label: 'Playing: 🎶 {info}', class: 'playing' },
  3: { name: 'editing', label: 'Editing: 🔨 {info}', class: 'editing' },
  4: { name: 'modding', label: 'Modding: 🔨 {info}', class: 'modding' },
  5: { name: 'multiplayer_song_select', label: 'In Multiplayer: Song Select', class: 'online' },
  6: { name: 'watching', label: 'Watching: 👓 {info}', class: 'watching' },
  8: { name: 'testing', label: 'Testing: 🎾 {info}', class: 'testing' },
  9: { name: 'submitting', label: 'Submitting: 🧼 {info}', class: 'submitting' },
  11: { name: 'multiplayer_lobby', label: 'Idle: 🏢 In multiplayer lobby', class: 'idle' },
  12: { name: 'multiplayer_playing', label: 'In Multiplayer: Playing 🌍 {info} 🎶', class: 'playing' },
  13: { name: 'searching', label: 'Idle: 🔍 Searching for beatmaps in osu!direct', class: 'idle' }
};

const GAME_MODES = {
  0: { name: 'osu!standard', icon: 'osu!', short: 'osu!' },
  1: { name: 'osu!taiko', icon: '🥁', short: 'taiko' },
  2: { name: 'osu!catch', icon: '🍎', short: 'catch' },
  3: { name: 'osu!mania', icon: '🎹', short: 'mania' }
};

const MODS = {
  0: { name: 'No Mod', abbr: 'NM' },
  1: { name: 'No Fail', abbr: 'NF' },
  2: { name: 'Easy', abbr: 'EZ' },
  4: { name: 'Touch Device', abbr: 'TD' },
  8: { name: 'Hard Rock', abbr: 'HR' },
  16: { name: 'Perfect', abbr: 'PF' },
  32: { name: 'Sudden Death', abbr: 'SD' },
  64: { name: 'Double Time', abbr: 'DT' },
  256: { name: 'Nightcore', abbr: 'NC' },
  1024: { name: 'Half Time', abbr: 'HT' },
  4096: { name: 'Flashlight', abbr: 'FL' },
  8192: { name: 'Relax', abbr: 'RX' },
  16384: { name: 'Autopilot', abbr: 'AP' },
  32768: { name: 'Spun Out', abbr: 'SO' }
};

const RANK_GRADES = {
  'XH': { color: '#FFD700', label: 'SS+' },
  'X': { color: '#FFD700', label: 'SS' },
  'S': { color: '#C0C0C0', label: 'S' },
  'A': { color: '#4CAF50', label: 'A' },
  'B': { color: '#2196F3', label: 'B' },
  'C': { color: '#9C27B0', label: 'C' },
  'D': { color: '#F44336', label: 'D' }
};

const COUNTRY_FLAGS_PATH = '/static/images/flags';

// Export for use in modules
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { STATUS, STATUS_ACTIONS, GAME_MODES, MODS, RANK_GRADES, COUNTRY_FLAGS_PATH };
}