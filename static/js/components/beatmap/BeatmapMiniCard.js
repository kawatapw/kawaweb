/**
 * ============================================================================
 * Beatmap Mini Card Component
 * ============================================================================
 *
 * The main mini mode card component that composes all sub-components.
 * Features background image, optional difficulty list, and popup on hover.
 *
 * Props:
 *   - beatmap: Object - Beatmap data (required)
 *   - difficulties: Array - All difficulties in the set (optional)
 *   - selectedDifficultyId: Number - Selected difficulty ID
 *   - showAllDifficulties: Boolean - Show difficulty list below card
 *   - rankChanges: Object - Rank change data per difficulty (optional)
 *   - showStatus: Boolean - Show status badge
 *   - showPlays: Boolean - Show play count
 *   - interactive: Boolean - Enable click interactions
 *
 * Events:
 *   - click: Emitted when card is clicked
 *   - difficulty-click: Emitted when a difficulty is clicked
 *
 * Usage:
 *   <beatmap-mini-card
 *     :beatmap="mapData"
 *     :difficulties="allDiffs"
 *     :selected-difficulty-id="selectedId"
 *     :show-all-difficulties="true"
 *     :show-status="true"
 *     :show-plays="true"
 *     @click="handleClick">
 *   </beatmap-mini-card>
 */
Vue.component('beatmap-mini-card', {
  mixins: [mixin_formatting],

  props: {
    beatmap: {
      type: Object,
      required: true,
      validator: function(value) {
        return value !== null && typeof value === 'object' && 
               (value.hasOwnProperty('id') || value.hasOwnProperty('set_id'));
      }
    },
    difficulties: {
      type: Array,
      default: function() { return []; }
    },
    selectedDifficultyId: {
      type: [Number, String],
      default: null
    },
    showAllDifficulties: {
      type: Boolean,
      default: false
    },
    rankChanges: {
      type: Object,
      default: function() { return {}; }
    },
    showStatus: {
      type: Boolean,
      default: true
    },
    showPlays: {
      type: Boolean,
      default: false
    },
    interactive: {
      type: Boolean,
      default: true
    }
  },

  data: function() {
    return {
      loading: false,
      error: null,
      setDifficulties: [],
      popupVisible: false
    };
  },

  created() {
    this.$log = window.ColorfulLogger ? window.ColorfulLogger.child('BeatmapMiniCard') : null;
    this._log('debug', 'LIFECYCLE', 'Component created', {
      beatmapId: this.beatmap?.id,
      setId: this.beatmap?.set_id,
      selectedDifficultyId: this.selectedDifficultyId,
      showAllDifficulties: this.showAllDifficulties,
      interactive: this.interactive
    });
    // Load difficulties if showing all
    if (this.showAllDifficulties && this.beatmap.set_id) {
      this.loadDifficulties();
    }
  },

  computed: {
    /**
     * Get cover image URL
     */
    coverUrl() {
      const setId = this.beatmap.set_id;
      const url = setId ? `https://assets.ppy.sh/beatmaps/${setId}/covers/card.jpg` : '';
      this._log('trace', 'RENDER', `Cover URL: ${url}`);
      return url;
    },

    /**
     * Get selected difficulty object
     */
    selectedDifficulty() {
      if (this.selectedDifficultyId && this.setDifficulties.length > 0) {
        const diff = this.setDifficulties.find(d => d.id == this.selectedDifficultyId) || this.beatmap;
        this._log('trace', 'RENDER', 'Selected difficulty from set', {
          difficultyId: diff?.id,
          version: diff?.version
        });
        return diff;
      }
      return this.beatmap;
    },

    /**
     * Check if there are multiple difficulties
     */
    hasMultipleDifficulties() {
      return this.setDifficulties.length > 1;
    },

    /**
     * Get status name
     */
    statusName() {
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
      const name = names[String(this.beatmap.status)] || 'Unknown';
      this._log('trace', 'RENDER', `Status name: ${name} (status: ${this.beatmap.status})`);
      return name;
    },

    /**
     * Get status color
     */
    statusColor() {
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
      const color = colors[String(this.beatmap.status)] || 'var(--beatmap-status-graveyard)';
      this._log('trace', 'RENDER', `Status color: ${color} (status: ${this.beatmap.status})`);
      return color;
    },

    /**
     * Get play count
     */
    playCount() {
      return this.beatmap.plays || 0;
    }
  },

  methods: {
    _log(level, section, message, data) {
      if (this.$log) {
        this.$log[level](section, message, data);
      }
    },

    /**
     * Load set difficulties if needed
     */
    async loadDifficulties() {
      if (this.loading || !this.beatmap.set_id || this.setDifficulties.length > 0) {
        this._log('trace', 'DATA', 'Skipping difficulty load', {
          loading: this.loading,
          setId: this.beatmap.set_id,
          alreadyLoaded: this.setDifficulties.length > 0
        });
        return;
      }

      this.loading = true;
      this.error = null;
      this._log('info', 'DATA', `Loading difficulties for set ${this.beatmap.set_id}`);

      try {
        const store = window.__beatmapDataStore;
        if (store) {
          this.setDifficulties = await store.getSetDifficulties(this.beatmap.set_id);
          this._log('info', 'DATA', `Loaded ${this.setDifficulties.length} difficulties for set ${this.beatmap.set_id}`);
        } else {
          this._log('warn', 'DATA', 'BeatmapDataStore not available');
        }
      } catch (error) {
        this._log('error', 'DATA', 'Error loading difficulties', { error: error.message });
        this.error = error.message;
      } finally {
        this.loading = false;
      }
    },

    /**
     * Handle card click
     */
    handleClick(event) {
      if (!this.interactive) {
        this._log('trace', 'EVENT', 'Card click ignored (not interactive)');
        return;
      }
      this._log('info', 'EVENT', 'Card clicked', {
        beatmapId: this.beatmap.id,
        setId: this.beatmap.set_id
      });
      beatmapBus.$emit('show-beatmap-panel', this.beatmap.id, this.beatmap.set_id);
    },

    /**
     * Handle difficulty click
     */
    handleDifficultyClick(difficultyId, setId, difficulty) {
      this._log('info', 'EVENT', 'Difficulty clicked in card', {
        difficultyId: difficultyId,
        setId: setId,
        version: difficulty?.version
      });
    },

    /**
     * Handle icon click (show popup)
     */
    handleIconClick(difficultyId, setId) {
      this._log('info', 'EVENT', 'Icon clicked for popup', {
        difficultyId: difficultyId,
        setId: setId
      });
      // Emit to parent for popup handling
    }
  },

  /* created() merged above */

  watch: {
    /**
     * Reload difficulties when prop changes
     */
    showAllDifficulties: function(newVal) {
      if (newVal && this.beatmap.set_id) {
        this._log('debug', 'DATA', 'showAllDifficulties changed, loading difficulties');
        this.loadDifficulties();
      }
    }
  },

  template: `
    <div :class="['beatmap-mini-card', { 'beatmap-mini-card--interactive': interactive }]" 
      @click="handleClick">
      
      <!-- Background image -->
      <div class="beatmap-mini-card__background">
        <img v-if="coverUrl" :src="coverUrl" alt="Beatmap Cover" class="beatmap-mini-card__image">
        <div class="beatmap-mini-card__overlay"></div>
      </div>

      <!-- Content -->
      <div class="beatmap-mini-card__content">
        <!-- Single difficulty icon (left side) -->
        <div v-if="!showAllDifficulties" class="beatmap-mini-card__single-diff">
          <beatmap-difficulty-icon
            :difficulty="selectedDifficulty"
            :set-id="beatmap.set_id"
            :rank-change="rankChanges[selectedDifficulty.id]"
            size="medium"
            @click="handleIconClick"
            showName="true">
          </beatmap-difficulty-icon>
        </div>

        <!-- Map info (center) -->
        <div class="beatmap-mini-card__info" :class="{ 'beatmap-mini-card__info--with-diff': !showAllDifficulties }">
          <div class="beatmap-mini-card__title" :title="beatmap.title">
            {{ beatmap.title || 'Loading...' }}
          </div>
          <div class="beatmap-mini-card__artist" :title="beatmap.artist">
            {{ beatmap.artist || '' }}
          </div>
          <div class="beatmap-mini-card__creator" :title="'Mapped by ' + beatmap.creator">
            {{ beatmap.creator || '' }}
          </div>
        </div>

        <!-- Right side content -->
        <div class="beatmap-mini-card__right">
          <div v-if="showStatus" class="beatmap-mini-card__status" :style="{ backgroundColor: statusColor }">
            {{ statusName }}
          </div>
          <div v-if="showPlays && playCount" class="beatmap-mini-card__plays">
            <i class="fas fa-play"></i>
            <span>{{ formatNumber(playCount) }}</span>
          </div>
        </div>
      </div>

      <!-- Difficulty list (below card) -->
      <div v-if="showAllDifficulties && hasMultipleDifficulties" class="beatmap-mini-card__diffs">
        <beatmap-difficulty-list
          :difficulties="setDifficulties"
          :selected-id="selectedDifficultyId"
          :set-id="beatmap.set_id"
          :rank-changes="rankChanges"
          :show-names="false"
          :max-visible="6"
          @icon-click="handleIconClick">
        </beatmap-difficulty-list>
      </div>
    </div>
  `
});