/**
 * ============================================================================
 * Beatmap Difficulty List Component
 * ============================================================================
 *
 * A scrollable list of difficulty icons sorted by star rating.
 * Improved design from the old component with better UX.
 *
 * Props:
 *   - difficulties: Array - List of difficulty objects
 *   - selectedId: Number - Currently selected difficulty ID
 *   - setId: Number - Beatmap set ID
 *   - rankChanges: Object - Rank change data per difficulty (optional)
 *   - showNames: Boolean - Whether to show difficulty names
 *   - maxVisible: Number - Maximum visible items before scrolling (default: 6)
 *
 * Events:
 *   - select: Emitted when a difficulty is selected (params: difficultyId, setId, difficulty)
 *
 * Usage:
 *   <beatmap-difficulty-list
 *     :difficulties="sortedDiffs"
 *     :selected-id="selectedDiffId"
 *     :set-id="setId"
 *     :rank-changes="rankData"
 *     @select="handleSelect">
 *   </beatmap-difficulty-list>
 */
Vue.component('beatmap-difficulty-list', {
  mixins: [mixin_formatting],

  props: {
    difficulties: {
      type: Array,
      required: true,
      default: function() { return []; }
    },
    selectedId: {
      type: [Number, String],
      default: null
    },
    setId: {
      type: [Number, String],
      required: true
    },
    rankChanges: {
      type: Object,
      default: function() { return {}; }
    },
    showNames: {
      type: Boolean,
      default: false
    },
    maxVisible: {
      type: Number,
      default: 6
    }
  },

  data: function() {
    return {
      scrollPosition: 0,
      isLoading: false
    };
  },

  created() {
    this.$log = window.ColorfulLogger ? window.ColorfulLogger.child('BeatmapDifficultyList') : null;
    this._log('debug', 'LIFECYCLE', 'Component created', {
      setId: this.setId,
      selectedId: this.selectedId,
      difficultiesCount: this.difficulties?.length,
      maxVisible: this.maxVisible
    });
  },

  computed: {
    /**
     * Sort difficulties by star rating ascending
     */
    sortedDifficulties() {
      if (!this.difficulties || this.difficulties.length === 0) {
        this._log('trace', 'RENDER', 'No difficulties to sort');
        return [];
      }
      const sorted = [...this.difficulties].sort((a, b) => {
        return (parseFloat(a.difficulty_rating) || 0) - (parseFloat(b.difficulty_rating) || 0);
      });
      this._log('debug', 'RENDER', `Sorted ${sorted.length} difficulties by star rating`);
      return sorted;
    },

    /**
     * Get visible difficulties based on scroll position
     */
    visibleDifficulties() {
      const start = this.scrollPosition;
      const end = start + this.maxVisible;
      const visible = this.sortedDifficulties.slice(start, end);
      this._log('trace', 'RENDER', `Visible difficulties: ${visible.length} (range: ${start}-${end})`);
      return visible;
    },

    /**
     * Check if we can scroll backward
     */
    canScrollBack() {
      return this.scrollPosition > 0;
    },

    /**
     * Check if we can scroll forward
     */
    canScrollForward() {
      return this.scrollPosition + this.maxVisible < this.sortedDifficulties.length;
    },

    /**
     * Get total count
     */
    totalCount() {
      return this.sortedDifficulties.length;
    },

    /**
     * Get current position indicator
     */
    positionIndicator() {
      const start = this.scrollPosition + 1;
      const end = Math.min(this.scrollPosition + this.maxVisible, this.totalCount);
      return `${start}-${end} of ${this.totalCount}`;
    }
  },

  methods: {
    _log(level, section, message, data) {
      if (this.$log) {
        this.$log[level](section, message, data);
      }
    },

    /**
     * Get rank change info for a difficulty
     */
    getRankChangeInfo(diffId) {
      if (!this.rankChanges || !this.rankChanges[diffId]) {
        return null;
      }
      const change = this.rankChanges[diffId];
      const diff = change.newRank - change.oldRank;

      let result;
      if (diff === 0) result = { icon: 'fa-equals', color: 'var(--beatmap-rank-unchanged)' };
      else if (diff < 0) result = { icon: 'fa-arrow-up', color: 'var(--beatmap-rank-improved)' };
      else result = { icon: 'fa-arrow-down', color: 'var(--beatmap-rank-declined)' };

      this._log('trace', 'RENDER', `Rank change for diff ${diffId}`, {
        oldRank: change.oldRank,
        newRank: change.newRank,
        diff,
        icon: result.icon
      });

      return result;
    },

    /**
     * Handle difficulty selection
     */
    handleSelect(diff, event) {
      event.stopPropagation();
      this._log('info', 'EVENT', 'Difficulty selected from list', {
        difficultyId: diff.id,
        version: diff.version,
        stars: diff.difficulty_rating,
        setId: this.setId
      });
      this.$emit('select', diff.id, this.setId, diff);
    },

    /**
     * Scroll difficulties left
     */
    scrollLeft() {
      if (this.canScrollBack) {
        this.scrollPosition = Math.max(0, this.scrollPosition - 1);
        this._log('debug', 'EVENT', 'Scrolled left', {
          newPosition: this.scrollPosition,
          visibleRange: this.positionIndicator
        });
      }
    },

    /**
     * Scroll difficulties right
     */
    scrollRight() {
      if (this.canScrollForward) {
        this.scrollPosition += 1;
        this._log('debug', 'EVENT', 'Scrolled right', {
          newPosition: this.scrollPosition,
          visibleRange: this.positionIndicator
        });
      }
    },

    /**
     * Handle icon click (emit for popup)
     */
    handleIconClick(diffId, setId) {
      this._log('info', 'EVENT', 'Difficulty icon clicked', {
        difficultyId: diffId,
        setId: setId
      });
      this.$emit('icon-click', diffId, setId);
    }
  },

  watch: {
    /**
     * Reset scroll when difficulties change
     */
    difficulties: function() {
      this.scrollPosition = 0;
      this._log('debug', 'DATA', 'Difficulties changed, reset scroll position');
    }
  },

  template: `
    <div class="beatmap-diff-list">
      <!-- Loading state -->
      <div v-if="isLoading" class="beatmap-diff-list__loading">
        <div class="beatmap-diff-list__spinner"></div>
        <span>Loading...</span>
      </div>

      <!-- Empty state -->
      <div v-else-if="sortedDifficulties.length === 0" class="beatmap-diff-list__empty">
        No difficulties found
      </div>

      <!-- Difficulty list with scroll controls -->
      <div v-else class="beatmap-diff-list__container">
        <!-- Left scroll button -->
        <button v-if="canScrollBack" 
          class="beatmap-diff-list__scroll-btn beatmap-diff-list__scroll-btn--left" 
          @click.stop="scrollLeft">
          <i class="fas fa-chevron-left"></i>
        </button>

        <!-- Position indicator -->
        <div class="beatmap-diff-list__indicator">
          {{ positionIndicator }}
        </div>

        <!-- Difficulties -->
        <div class="beatmap-diff-list__items">
          <beatmap-difficulty-icon
            v-for="diff in visibleDifficulties"
            :key="diff.id"
            :difficulty="diff"
            :set-id="setId"
            :rank-change="getRankChangeInfo(diff.id)"
            :selected="diff.id == selectedId"
            :show-name="showNames"
            size="medium"
            @click="handleIconClick">
          </beatmap-difficulty-icon>
        </div>

        <!-- Right scroll button -->
        <button v-if="canScrollForward" 
          class="beatmap-diff-list__scroll-btn beatmap-diff-list__scroll-btn--right" 
          @click.stop="scrollRight">
          <i class="fas fa-chevron-right"></i>
        </button>
      </div>
    </div>
  `
});