/**
 * ============================================================================
 * Beatmap Card Component (Main)
 * ============================================================================
 *
 * The main beatmap card component that switches between display modes.
 * Replaces the old monolithic bmap-card component.
 *
 * Props:
 *   - beatmap: Object - Beatmap data (required)
 *   - mode: String - Display mode: 'mini', 'compact' (default: 'mini')
 *   - showAllDifficulties: Boolean - Show difficulty list
 *   - selectedDifficultyId: Number - Selected difficulty ID
 *   - rankChanges: Object - Rank change data (optional)
 *   - isSet: Boolean - Whether this is a set (deprecated, use showAllDifficulties)
 *   - showPlays: Boolean - Show play count
 *   - showStatus: Boolean - Show status badge
 *   - interactive: Boolean - Enable click interactions
 *   - autoLoad: Boolean - Auto-load full data if partial
 *
 * Events:
 *   - beatmap-click: Emitted when card is clicked
 *   - difficulty-click: Emitted when a difficulty is clicked
 *   - data-loaded: Emitted when full data is loaded
 *   - data-error: Emitted when data loading fails
 *
 * Usage:
 *   <beatmap-card
 *     :beatmap="mapData"
 *     mode="mini"
 *     :show-all-difficulties="true"
 *     :show-plays="true"
 *     @beatmap-click="handleClick">
 *   </beatmap-card>
 */
Vue.component('beatmap-card', {
  mixins: [mixin_formatting, mixin_conversion],

  props: {
    beatmap: {
      type: Object,
      required: true,
      validator: function(value) {
        return value !== null && typeof value === 'object' && 
               (value.hasOwnProperty('id') || value.hasOwnProperty('set_id'));
      }
    },
    mode: {
      type: String,
      default: 'mini',
      validator: function(value) {
        return ['mini', 'compact'].includes(value);
      }
    },
    showAllDifficulties: {
      type: Boolean,
      default: false
    },
    selectedDifficultyId: {
      type: [Number, String],
      default: null
    },
    rankChanges: {
      type: Object,
      default: function() { return {}; }
    },
    isSet: {
      type: Boolean,
      default: false
    },
    showPlays: {
      type: Boolean,
      default: false
    },
    showStatus: {
      type: Boolean,
      default: true
    },
    interactive: {
      type: Boolean,
      default: true
    },
    autoLoad: {
      type: Boolean,
      default: true
    }
  },

  data: function() {
    return {
      fullData: null,
      setDifficulties: [],
      loading: false,
      dataLoading: false,
      error: null
    };
  },

  created() {
    this.$log = window.ColorfulLogger ? window.ColorfulLogger.child('BeatmapCard') : null;
    this._log('debug', 'LIFECYCLE', 'Component created', {
      beatmapId: this.beatmap?.id,
      setId: this.beatmap?.set_id,
      mode: this.mode,
      showAllDifficulties: this.showAllDifficulties,
      autoLoad: this.autoLoad
    });
  },

  computed: {
    /**
     * Use full data if available, otherwise use prop data
     */
    mapData() {
      return this.fullData || this.beatmap;
    },

    /**
     * Check if we have complete data
     */
    hasCompleteData() {
      return this.fullData !== null || 
             (this.beatmap.title && this.beatmap.artist && this.beatmap.creator);
    }
  },

  methods: {
    _log(level, section, message, data) {
      if (this.$log) {
        this.$log[level](section, message, data);
      }
    },

    /**
     * Load full map data if needed
     */
    async loadMapData() {
      if (this.dataLoading || this.hasCompleteData) {
        this._log('trace', 'DATA', 'Skipping map data load', {
          loading: this.dataLoading,
          hasCompleteData: this.hasCompleteData
        });
        return;
      }

      this.dataLoading = true;
      this.error = null;
      this._log('info', 'DATA', 'Loading full map data');

      try {
        const store = window.__beatmapDataStore;
        if (!store) {
          throw new Error('BeatmapDataStore not available');
        }

        let data;
        if (this.beatmap.id) {
          this._log('debug', 'DATA', `Fetching beatmap by ID: ${this.beatmap.id}`);
          data = await store.getBeatmap(this.beatmap.id);
        } else if (this.beatmap.set_id) {
          this._log('debug', 'DATA', `Fetching beatmap by set ID: ${this.beatmap.set_id}`);
          data = await store.getBeatmapBySet(this.beatmap.set_id);
        } else if (this.beatmap.md5) {
          this._log('debug', 'DATA', `Fetching beatmap by MD5: ${this.beatmap.md5}`);
          // MD5 lookup not implemented in store, use direct API
          data = await this.fetchByMd5(this.beatmap.md5);
        } else {
          throw new Error('Insufficient data to load map details');
        }

        if (data) {
          this.fullData = data;
          this._log('info', 'DATA', 'Map data loaded successfully', {
            title: data.title,
            setId: data.set_id
          });
          this.$emit('data-loaded', data);
        }
      } catch (error) {
        this._log('error', 'DATA', 'Error loading map data', { error: error.message });
        this.error = error.message;
        this.$emit('data-error', error);
      } finally {
        this.dataLoading = false;
      }
    },

    /**
     * Fetch beatmap by MD5 (fallback)
     */
    async fetchByMd5(md5) {
      this._log('info', 'API', `Fetching beatmap by MD5: ${md5}`);
      const protocol = window.location.protocol;
      const apiDomain = window.domain || 'kawata.pw';
      const url = `${protocol}//api.${apiDomain}/v1/maps?md5=${encodeURIComponent(md5)}`;

      this._log('debug', 'API', `API request URL: ${url}`);

      try {
        const response = await fetch(url);
        if (!response.ok) {
          throw new Error(`API request failed with status ${response.status}`);
        }

        const data = await response.json();
        if (data.status === 'success' && data.data && data.data.length > 0) {
          this._log('info', 'API', 'Beatmap loaded by MD5', { title: data.data[0].title });
          return data.data[0];
        }
        return null;
      } catch (error) {
        this._log('error', 'API', 'Error fetching beatmap by MD5', { error: error.message });
        throw error;
      }
    },

    /**
     * Load set difficulties
     */
    async loadSetDifficulties() {
      if (this.loading || !this.mapData.set_id || this.setDifficulties.length > 0) {
        this._log('trace', 'DATA', 'Skipping difficulties load', {
          loading: this.loading,
          setId: this.mapData.set_id,
          alreadyLoaded: this.setDifficulties.length > 0
        });
        return;
      }

      this.loading = true;
      this.error = null;
      this._log('info', 'DATA', `Loading difficulties for set ${this.mapData.set_id}`);

      try {
        const store = window.__beatmapDataStore;
        if (store) {
          this.setDifficulties = await store.getSetDifficulties(this.mapData.set_id);
          this._log('info', 'DATA', `Loaded ${this.setDifficulties.length} difficulties`);
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
    handleClick(beatmapId, setId) {
      this._log('info', 'EVENT', 'Card clicked', { beatmapId, setId });
      beatmapBus.$emit('show-beatmap-panel', this.beatmap?.id, this.beatmap?.set_id)
    },

    /**
     * Handle difficulty click
     */
    handleDifficultyClick(difficultyId, setId, difficulty) {
      this._log('info', 'EVENT', 'Difficulty clicked', {
        difficultyId: difficultyId,
        setId: setId,
        version: difficulty?.version
      });
    },

    /**
     * Handle icon click (for popup)
     */
    handleIconClick(difficultyId, setId) {
      this._log('info', 'EVENT', 'Icon clicked for popup', { difficultyId, setId });
      // Emit to parent for popup handling
    }
  },

  created: function() {
    // Auto-load data if needed
    if (this.autoLoad && !this.hasCompleteData) {
      this.loadMapData();
    }
  },

  mounted: function() {
    // Load difficulties if showing all
    if (this.showAllDifficulties && this.mapData.set_id && this.setDifficulties.length === 0) {
      this.loadSetDifficulties();
    }
  },

  watch: {
    /**
     * Reload when beatmap prop changes
     */
    beatmap: function() {
      this.fullData = null;
      if (this.autoLoad && !this.hasCompleteData) {
        this._log('debug', 'DATA', 'Beatmap prop changed, reloading data');
        this.loadMapData();
      }
    },

    /**
     * Reload difficulties when showAllDifficulties changes
     */
    showAllDifficulties: function(newVal) {
      if (newVal && this.mapData.set_id && this.setDifficulties.length === 0) {
        this._log('debug', 'DATA', 'showAllDifficulties changed, loading difficulties');
        this.loadSetDifficulties();
      }
    }
  },

  template: `
    <div :class="['beatmap-card', 'beatmap-card--mode-' + mode]">
      <!-- Loading state -->
      <div v-if="dataLoading" class="beatmap-card__loading">
        <div class="beatmap-card__spinner"></div>
        <span>Loading beatmap...</span>
      </div>

      <!-- Error state -->
      <div v-else-if="error" class="beatmap-card__error">
        <i class="fas fa-exclamation-circle"></i>
        <span>{{ error }}</span>
        <button @click.stop="loadMapData" class="beatmap-card__retry">Retry</button>
      </div>

      <!-- Mini mode -->
      <beatmap-mini-card
        v-else-if="mode === 'mini'"
        :beatmap="mapData"
        :difficulties="setDifficulties"
        :selected-difficulty-id="selectedDifficultyId"
        :show-all-difficulties="showAllDifficulties"
        :rank-changes="rankChanges"
        :show-status="showStatus"
        :show-plays="showPlays"
        :interactive="interactive"
        @click="handleClick"
        @difficulty-click="handleDifficultyClick"
        @icon-click="handleIconClick">
      </beatmap-mini-card>

      <!-- Compact mode (placeholder for future implementation) -->
      <div v-else-if="mode === 'compact'" class="beatmap-card__compact">
        <!-- TODO: Implement compact mode -->
        <p>Compact mode not yet implemented</p>
      </div>
    </div>
  `
});