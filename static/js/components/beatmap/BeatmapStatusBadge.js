/**
 * ============================================================================
 * Beatmap Status Badge Component
 * ============================================================================
 *
 * A small badge displaying beatmap status (Ranked, Loved, Pending, etc.)
 *
 * Props:
 *   - status: Number/String - Beatmap status code
 *   - size: String - 'small', 'medium' (default: 'medium')
 *
 * Usage:
 *   <beatmap-status-badge :status="beatmap.status"></beatmap-status-badge>
 */
Vue.component('beatmap-status-badge', {
  props: {
    status: {
      type: [Number, String],
      required: true
    },
    size: {
      type: String,
      default: 'medium',
      validator: function(value) {
        return ['small', 'medium'].includes(value);
      }
    }
  },

  data: function() {
    return {
      statusNames: {
        '-2': 'Graveyard',
        '-1': 'WIP',
        '0': 'Pending',
        '1': 'Ranked',
        '2': 'Ranked',
        '3': 'Approved',
        '4': 'Qualified',
        '5': 'Loved'
      },
      statusColors: {
        '-2': 'var(--beatmap-status-graveyard)',
        '-1': 'var(--beatmap-status-wip)',
        '0': 'var(--beatmap-status-pending)',
        '1': 'var(--beatmap-status-ranked)',
        '2': 'var(--beatmap-status-ranked)',
        '3': 'var(--beatmap-status-approved)',
        '4': 'var(--beatmap-status-qualified)',
        '5': 'var(--beatmap-status-loved)'
      }
    };
  },

  created() {
    this.$log = window.ColorfulLogger ? window.ColorfulLogger.child('BeatmapStatusBadge') : null;
    this._log('debug', 'LIFECYCLE', 'Component created', {
      status: this.status,
      size: this.size
    });
  },

  computed: {
    /**
     * Get display name for status
     */
    statusName() {
      const name = this.statusNames[String(this.status)] || 'Unknown';
      this._log('trace', 'RENDER', `Status name: ${name} (status: ${this.status})`);
      return name;
    },

    /**
     * Get color for status
     */
    statusColor() {
      const color = this.statusColors[String(this.status)] || 'var(--beatmap-status-graveyard)';
      this._log('trace', 'RENDER', `Status color: ${color} (status: ${this.status})`);
      return color;
    },

    /**
     * Size class
     */
    sizeClass() {
      return 'beatmap-status-badge--' + this.size;
    }
  },

  methods: {
    _log(level, section, message, data) {
      if (this.$log) {
        this.$log[level](section, message, data);
      }
    }
  },

  template: `
    <span 
      :class="['beatmap-status-badge', sizeClass]"
      :style="{ backgroundColor: statusColor }">
      {{ statusName }}
    </span>
  `
});