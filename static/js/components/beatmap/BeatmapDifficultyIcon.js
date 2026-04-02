/**
 * ============================================================================
 * Beatmap Difficulty Icon Component
 * ============================================================================
 *
 * A circular icon displaying the game mode with difficulty-based coloring.
 * Supports optional rank change indicator badge.
 *
 * Props:
 *   - difficulty: Object with { mode, difficulty_rating, version, id }
 *   - setId: Number - Beatmap set ID (for popup/details)
 *   - rankChange: Object with { oldRank, newRank } (optional)
 *   - selected: Boolean - Whether this is the selected difficulty
 *   - showName: Boolean - Whether to show difficulty name below icon
 *   - size: String - 'small', 'medium', 'large' (default: 'medium')
 *
 * Events:
 *   - click: Emitted when icon is clicked (params: difficultyId, setId)
 *
 * Usage:
 *   <beatmap-difficulty-icon
 *     :difficulty="diff"
 *     :set-id="setId"
 *     :selected="isSelected"
 *     @click="handleClick">
 *   </beatmap-difficulty-icon>
 */
Vue.component('beatmap-difficulty-icon', {
  mixins: [mixin_formatting],
  
  props: {
    difficulty: {
      type: Object,
      required: true
    },
    setId: {
      type: [Number, String],
      default: null
    },
    rankChange: {
      type: Object,
      default: null
    },
    selected: {
      type: Boolean,
      default: false
    },
    showName: {
      type: Boolean,
      default: false
    },
    size: {
      type: String,
      default: 'medium',
      validator: function(value) {
        return ['small', 'medium', 'large'].includes(value);
      }
    }
  },

  data: function() {
    return {
      fetchedMode: null
    };
  },

  created() {
    this.$log = window.ColorfulLogger ? window.ColorfulLogger.child('BeatmapDifficultyIcon') : null;
    this._log('debug', 'LIFECYCLE', 'Component created', {
      difficultyId: this.difficulty?.id,
      setId: this.setId,
      selected: this.selected,
      size: this.size
    });
    
    // Fetch mode if not available in difficulty data
    if (this.difficulty?.mode === undefined && this.difficulty?.id) {
      this.fetchMapMode();
    }
  },

  computed: {
    /**
     * Get CSS class for difficulty rating tier
     */
    difficultyTier() {
      if (!this.difficulty || !this.difficulty.difficulty_rating) {
        this._log('trace', 'RENDER', 'No difficulty rating available');
        return '';
      }
      const stars = parseFloat(this.difficulty.difficulty_rating);
      const tier = 'difficulty-' + Math.floor(stars);
      this._log('trace', 'RENDER', `Difficulty tier: ${tier} (stars: ${stars})`);
      return tier;
    },

    /**
     * Get difficulty color as RGB string
     */
    difficultyColor() {
      if (!this.difficulty) {
        this._log('trace', 'RENDER', 'No difficulty data, using default color');
        return '200, 200, 200';
      }

      try {
        const stars = parseFloat(this.difficulty.difficulty_rating || 0);
        
        // Determine color based on star rating
        let color;
        if (stars < 1.5) color = '79, 192, 255';      // Easy - Blue
        else if (stars < 2.25) color = '102, 255, 51';     // Normal - Green
        else if (stars < 4) color = '255, 204, 34';        // Hard - Yellow
        else if (stars < 5.25) color = '255, 102, 170';    // Insane - Pink
        else if (stars < 6.5) color = '170, 136, 255';     // Expert - Purple
        else color = '255, 102, 102';                       // Expert+ - Red

        this._log('trace', 'RENDER', `Difficulty color: ${color} (stars: ${stars})`);
        return color;
      } catch (error) {
        this._log('error', 'RENDER', 'Error calculating difficulty color', { error: error.message });
        return '200, 200, 200';
      }
    },

    /**
     * Get mode icon class
     */
    modeIcon() {
      // Try to get mode from difficulty data first, then fetched mode
      const modeValue = this.difficulty?.mode !== undefined && this.difficulty?.mode !== null
        ? parseInt(this.difficulty.mode)
        : (this.fetchedMode !== null && this.fetchedMode !== undefined
          ? parseInt(this.fetchedMode)
          : null);
      
      if (modeValue === null) {
        this._log('warn', 'RENDER', 'No mode data available (not in difficulty and not fetched), using music icon', {
          difficultyId: this.difficulty?.id,
          difficultyMode: this.difficulty?.mode,
          fetchedMode: this.fetchedMode,
          hasDifficulty: !!this.difficulty,
          difficultyData: this.difficulty
        });
        return 'fas fa-music';
      }

      const modeIcons = {
        0: 'osu-mode icon-osu',      // osu!standard
        1: 'osu-mode icon-taiko',    // osu!taiko
        2: 'osu-mode icon-catch',    // osu!catch
        3: 'osu-mode icon-mania'     // osu!mania
      };

      const icon = modeIcons[modeValue];
      
      if (!icon) {
        this._log('warn', 'RENDER', `Unknown mode value: ${this.difficulty?.mode || this.fetchedMode} (parsed: ${modeValue}), using music icon`, {
          difficultyId: this.difficulty?.id,
          originalMode: this.difficulty?.mode,
          fetchedMode: this.fetchedMode,
          parsedMode: modeValue
        });
        return 'fas fa-music';
      }
      
      this._log('trace', 'RENDER', `Mode icon: ${icon} (mode: ${this.difficulty?.mode || this.fetchedMode}, parsed: ${modeValue})`);
      return icon;
    },

    /**
     * Get rank change info (icon and color)
     */
    rankChangeInfo() {
      if (!this.rankChange) return null;

      const diff = this.rankChange.newRank - this.rankChange.oldRank;

      let result;
      if (diff === 0) result = { icon: 'fa-equals', color: 'var(--beatmap-rank-unchanged)' };
      else if (diff < 0) result = { icon: 'fa-arrow-up', color: 'var(--beatmap-rank-improved)' };
      else result = { icon: 'fa-arrow-down', color: 'var(--beatmap-rank-declined)' };

      this._log('debug', 'RENDER', 'Rank change info', {
        oldRank: this.rankChange.oldRank,
        newRank: this.rankChange.newRank,
        diff,
        icon: result.icon
      });

      return result;
    },

    /**
     * Get formatted rank change text
     */
    rankChangeText() {
      if (!this.rankChange) return '';
      return `#${this.rankChange.newRank} (was #${this.rankChange.oldRank})`;
    },

    /**
     * Size class for CSS
     */
    sizeClass() {
      return 'beatmap-diff-icon--' + this.size;
    }
  },

  methods: {
    _log(level, section, message, data) {
      if (this.$log) {
        this.$log[level](section, message, data);
      }
    },

    /**
     * Fetch map mode from API when not available in difficulty data
     */
    async fetchMapMode() {
      if (!this.difficulty?.id) {
        this._log('warn', 'API', 'Cannot fetch mode: no difficulty ID');
        return;
      }

      this._log('info', 'API', `Fetching mode for map ${this.difficulty.id}`);

      try {
        const protocol = window.location.protocol;
        const apiDomain = window.domain || 'kawata.pw';
        const url = `${protocol}//api.${apiDomain}/v2/maps/${this.difficulty.id}`;

        this._log('debug', 'API', `API request URL: ${url}`);

        const response = await fetch(url);
        if (!response.ok) {
          throw new Error(`API request failed with status ${response.status}`);
        }

        const data = await response.json();
        
        this._log('debug', 'API', `API response for map ${this.difficulty.id}`, {
          status: data.status,
          hasData: !!data.data,
          modeInData: data.data?.mode,
          fullData: data
        });
        
        if (data.status === 'success' && data.data && data.data.mode !== undefined) {
          this.$set(this, 'fetchedMode', data.data.mode);
          this._log('info', 'API', `Fetched mode for map ${this.difficulty.id}: ${this.fetchedMode}`, {
            title: data.data.title,
            version: data.data.version,
            mode: this.fetchedMode
          });
        } else {
          this._log('warn', 'API', `No map data found for ID ${this.difficulty.id}`, { data });
        }
      } catch (error) {
        this._log('error', 'API', `Error fetching mode for map ${this.difficulty.id}`, { 
          error: error.message 
        });
      }
    },

    /**
     * Handle click event
     */
    handleClick(event) {
      event.stopPropagation();
      this._log('info', 'EVENT', 'Difficulty icon clicked', {
        difficultyId: this.difficulty.id,
        setId: this.setId,
        selected: this.selected
      });
      this.$emit('click', this.difficulty.id, this.setId);
    }
  },

  template: `
    <div 
      :class="['beatmap-diff-icon', sizeClass, difficultyTier, { 'beatmap-diff-icon--selected': selected }]"
      :style="{ '--diff-color': difficultyColor }"
      @click="handleClick">
      
      <!-- Mode icon -->
      <div class="beatmap-diff-icon__inner">
        <i :class="modeIcon" class="beatmap-diff-icon__mode"></i>
        
        <!-- Rank change badge -->
        <div v-if="rankChangeInfo" 
          class="beatmap-diff-icon__rank-badge"
          :style="{ backgroundColor: rankChangeInfo.color }">
          <i :class="['fas', rankChangeInfo.icon]"></i>
        </div>
      </div>
      
      <!-- Difficulty name (optional) -->
      <div v-if="showName && difficulty.version" 
        class="beatmap-diff-icon__name"
        :title="difficulty.version">
        {{ difficulty.version }}
      </div>
    </div>
  `
});