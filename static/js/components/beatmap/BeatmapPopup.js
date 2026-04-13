/**
 * ============================================================================
 * Beatmap Popup Component
 * ============================================================================
 *
 * A hover popup panel displaying detailed beatmap information.
 * Consolidates the duplicated popup code from the old component.
 *
 * Props:
 *   - beatmap: Object - Beatmap data
 *   - difficulty: Object - Selected difficulty data
 *   - difficulties: Array - All difficulties in the set (optional)
 *   - rankChange: Object - Rank change data (optional)
 *   - showStatus: Boolean - Whether to show status badge
 *
 * Events:
 *   - difficulty-click: Emitted when a difficulty is clicked (params: difficultyId, setId)
 *   - details-click: Emitted when details button is clicked
 *
 * Usage:
 *   <beatmap-popup
 *     :beatmap="mapData"
 *     :difficulty="selectedDiff"
 *     :difficulties="allDiffs"
 *     :rank-change="rankData"
 *     :show-status="true"
 *     @difficulty-click="handleDiffClick">
 *   </beatmap-popup>
 */
Vue.component('beatmap-popup', {
  mixins: [mixin_formatting],

  props: {
    beatmap: {
      type: Object,
      required: true
    },
    difficulty: {
      type: Object,
      required: true
    },
    difficulties: {
      type: Array,
      default: function() { return []; }
    },
    rankChange: {
      type: Object,
      default: null
    },
    showStatus: {
      type: Boolean,
      default: true
    }
  },

  created() {
    this.$log = window.ColorfulLogger ? window.ColorfulLogger.child('BeatmapPopup') : null;
    this._log('debug', 'LIFECYCLE', 'Component created', {
      beatmapId: this.beatmap?.id,
      setId: this.beatmap?.set_id,
      difficultyId: this.difficulty?.id,
      hasDifficulties: this.difficulties?.length > 0,
      hasRankChange: !!this.rankChange
    });
  },

  computed: {
    /**
     * Get other difficulties (excluding current one)
     */
    otherDifficulties() {
      if (!this.difficulties || this.difficulties.length <= 1) {
        this._log('trace', 'RENDER', 'No other difficulties available');
        return [];
      }
      const filtered = this.difficulties.filter(d => d.id !== this.difficulty.id);
      this._log('debug', 'RENDER', `Other difficulties count: ${filtered.length}`);
      return filtered;
    },

    /**
     * Check if there are multiple difficulties
     */
    hasMultipleDifficulties() {
      return this.difficulties && this.difficulties.length > 1;
    },

    /**
     * Get difficulty star rating
     */
    starRating() {
      if (!this.difficulty || !this.difficulty.difficulty_rating) {
        return null;
      }
      const rating = parseFloat(this.difficulty.difficulty_rating).toFixed(2);
      this._log('trace', 'RENDER', `Star rating: ${rating}`);
      return rating;
    },

    /**
     * Get star rating color
     */
    starColor() {
      if (!this.difficulty || !this.difficulty.difficulty_rating) {
        return '#FFCC22';
      }
      const stars = parseFloat(this.difficulty.difficulty_rating);
      let color;
      if (stars < 2) color = '#4FC0FF';
      else if (stars < 2.7) color = '#4FC0FF';
      else if (stars < 4) color = '#66FF33';
      else if (stars < 5.3) color = '#FFCC22';
      else if (stars < 6.5) color = '#FF66AA';
      else color = '#AA88FF';

      this._log('trace', 'RENDER', `Star color: ${color} (stars: ${stars})`);
      return color;
    },

    /**
     * Get rank change info
     */
    rankChangeInfo() {
      if (!this.rankChange) return null;

      const diff = this.rankChange.newRank - this.rankChange.oldRank;

      let result;
      if (diff === 0) result = { icon: 'fa-equals', color: 'var(--beatmap-rank-unchanged)', text: 'Unchanged' };
      else if (diff < 0) result = { icon: 'fa-arrow-up', color: 'var(--beatmap-rank-improved)', text: 'Improved' };
      else result = { icon: 'fa-arrow-down', color: 'var(--beatmap-rank-declined)', text: 'Declined' };

      this._log('debug', 'RENDER', 'Rank change info', {
        oldRank: this.rankChange.oldRank,
        newRank: this.rankChange.newRank,
        diff,
        text: result.text
      });

      return result;
    },

    /**
     * Get formatted rank change text
     */
    rankChangeText() {
      if (!this.rankChange) return '';
      return `#${this.rankChange.newRank} (was #${this.rankChange.oldRank})`;
    }
  },

  methods: {
    _log(level, section, message, data) {
      if (this.$log) {
        this.$log[level](section, message, data);
      }
    },

    /**
     * Get status name from status code
     */
    getStatusName(status) {
      const names = {
        '-2': 'Graveyard',
        '-1': 'WIP',
        '0': 'Pending',
        '1': 'Ranked',
        '2': 'Ranked',
        '3': 'Approved',
        '4': 'Qualified',
        '5': 'Loved'
      };
      const name = names[String(status)] || 'Unknown';
      this._log('trace', 'RENDER', `Status name: ${name} (status: ${status})`);
      return name;
    },

    /**
     * Get status color from status code
     */
    getStatusColor(status) {
      const colors = {
        '-2': 'var(--beatmap-status-graveyard)',
        '-1': 'var(--beatmap-status-wip)',
        '0': 'var(--beatmap-status-pending)',
        '1': 'var(--beatmap-status-ranked)',
        '2': 'var(--beatmap-status-ranked)',
        '3': 'var(--beatmap-status-approved)',
        '4': 'var(--beatmap-status-qualified)',
        '5': 'var(--beatmap-status-loved)'
      };
      const color = colors[String(status)] || 'var(--beatmap-status-graveyard)';
      this._log('trace', 'RENDER', `Status color: ${color} (status: ${status})`);
      return color;
    },

    /**
     * Handle difficulty click
     */
    handleDifficultyClick(diff, event) {
      event.stopPropagation();
      this._log('info', 'EVENT', 'Difficulty clicked in popup', {
        difficultyId: diff.id,
        version: diff.version,
        setId: this.beatmap.set_id
      });
      this.$emit('difficulty-click', diff.id, this.beatmap.set_id, diff);
    },

    /**
     * Handle details click
     */
    handleDetailsClick(event) {
      event.stopPropagation();
      this._log('info', 'EVENT', 'Details button clicked', {
        difficultyId: this.difficulty.id,
        setId: this.beatmap.set_id
      });
      this.$emit('details-click', this.difficulty.id, this.beatmap.set_id);
    }
  },

  template: `
    <div class="beatmap-popup">
      <!-- Header -->
      <div class="beatmap-popup__header">
        <div class="beatmap-popup__title" :title="beatmap.title">
          {{ beatmap.title || 'Loading...' }}
        </div>
        <div class="beatmap-popup__artist" :title="beatmap.artist">
          {{ beatmap.artist || '' }}
        </div>
        <div class="beatmap-popup__version" :title="difficulty.version">
          {{ difficulty.version || '' }}
        </div>
      </div>

      <!-- Details -->
      <div class="beatmap-popup__details">
        <!-- Creator -->
        <div class="beatmap-popup__creator" :title="'Mapped by ' + beatmap.creator">
          Mapped by <span>{{ beatmap.creator || '' }}</span>
        </div>

        <!-- Stats -->
        <div class="beatmap-popup__stats">
          <div v-if="difficulty.bpm" class="beatmap-popup__stat">
            <i class="fas fa-heartbeat"></i>
            <span>{{ Math.round(difficulty.bpm) }}bpm</span>
          </div>
          <div v-if="difficulty.hit_length" class="beatmap-popup__stat">
            <i class="fas fa-clock"></i>
            <span>{{ formatLength(difficulty.hit_length) }}</span>
          </div>
          <div v-if="starRating" class="beatmap-popup__stat">
            <i class="fas fa-star" :style="{ color: starColor }"></i>
            <span>{{ starRating }}</span>
          </div>
          <div v-if="showStatus" class="beatmap-popup__stat">
            <span class="beatmap-popup__status" 
              :style="{ backgroundColor: getStatusColor(beatmap.status) }">
              {{ getStatusName(beatmap.status) }}
            </span>
          </div>
        </div>

        <!-- Rank change info -->
        <div v-if="rankChangeInfo" class="beatmap-popup__rank-change">
          <div class="beatmap-popup__rank-label">Rank:</div>
          <div class="beatmap-popup__rank-value" :style="{ color: rankChangeInfo.color }">
            <span>{{ rankChangeText }}</span>
            <i :class="['fas', rankChangeInfo.icon]"></i>
          </div>
        </div>

        <!-- Other difficulties -->
        <div v-if="hasMultipleDifficulties" class="beatmap-popup__diffs">
          <div class="beatmap-popup__diffs-header">Other difficulties:</div>
          <div class="beatmap-popup__diffs-list">
            <div v-for="diff in otherDifficulties" 
              :key="diff.id" 
              class="beatmap-popup__diff-item"
              @click="handleDifficultyClick(diff, $event)">
              <span class="beatmap-popup__diff-name" :title="diff.version">
                {{ diff.version }}
              </span>
              <span v-if="diff.difficulty_rating" class="beatmap-popup__diff-stars">
                {{ parseFloat(diff.difficulty_rating).toFixed(2) }}
              </span>
            </div>
          </div>
        </div>

        <!-- Actions -->
        <div class="beatmap-popup__actions">
          <a :href="'https://osu.ppy.sh/b/' + difficulty.id" 
            target="_blank" 
            class="beatmap-popup__action"
            @click.stop>
            <i class="fas fa-external-link-alt"></i> osu!
          </a>
          <a class="beatmap-popup__action" 
            @click.stop="handleDetailsClick">
            <i class="fas fa-info-circle"></i> Details
          </a>
          <a :href="'/d/' + beatmap.set_id" 
            class="beatmap-popup__action"
            @click.stop>
            <i class="fas fa-download"></i> Download
          </a>
        </div>
      </div>
    </div>
  `
});