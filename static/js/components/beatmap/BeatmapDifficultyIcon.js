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
    // Rank changes object (keyed by difficulty ID) - from old component
    rankChanges: {
      type: Object,
      default: function() { return {}; }
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
    },
    // Status change props for split-circle design
    oldStatus: {
      type: [Number, String],
      default: null
    },
    newStatus: {
      type: [Number, String],
      default: null
    }
  },

  data: function() {
    return {
      fullMapData: null
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
    
    // Fetch full map data if mode or difficulty_rating is missing
    if (this.difficulty?.id && (this.difficulty?.mode === undefined || this.difficulty?.difficulty_rating === undefined)) {
      this.fetchFullMapData();
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
     * Get difficulty color as RGB string using d3 interpolation
     * Based on the old difficulty-icon component's color calculation
     */
    difficultyColor() {
      // Use fullMapData.diff if available, otherwise use difficulty.difficulty_rating
      const difficultyRating = this.fullMapData?.diff ?? this.difficulty?.difficulty_rating;
      
      if (!difficultyRating) {
        this._log('trace', 'RENDER', 'No difficulty rating available, using default color');
        return '200, 200, 200';
      }

      try {
        // Check if d3 is available
        if (typeof d3 === 'undefined') {
          this._log('warn', 'RENDER', 'd3 not available, using fallback color calculation');
          return this._fallbackDifficultyColor();
        }

        const scale = d3.scaleLinear()
          .domain([0.1, 1.25, 2, 2.5, 3.3, 4.2, 4.9, 5.8, 6.7, 7.7, 9])
          .clamp(true)
          .range([
            '#4290FB', '#4FC0FF', '#4FFFD5', '#7CFF4F', '#F6F05C',
            '#FF8068', '#FF4E6F', '#C645B8', '#6563DE', '#18158E', '#000000'
          ])
          .interpolate(d3.interpolateRgb.gamma(2.2));
        
        const stars = parseFloat(difficultyRating || 0);
        const color = d3.color(scale(stars));
        const rgb = color ? `${color.r}, ${color.g}, ${color.b}` : '200, 200, 200';
        
        this._log('trace', 'RENDER', `Difficulty color: ${rgb} (stars: ${stars})`);
        return rgb;
      } catch (error) {
        this._log('error', 'RENDER', 'Error calculating difficulty color', { error: error.message });
        return this._fallbackDifficultyColor();
      }
    },

    /**
     * Fallback color calculation when d3 is not available
     */
    _fallbackDifficultyColor() {
      const difficultyRating = this.fullMapData?.diff ?? this.difficulty?.difficulty_rating;
      const stars = parseFloat(difficultyRating || 0);
      let color;
      if (stars < 1.5) color = '79, 192, 255';
      else if (stars < 2.25) color = '102, 255, 51';
      else if (stars < 4) color = '255, 204, 34';
      else if (stars < 5.25) color = '255, 102, 170';
      else if (stars < 6.5) color = '170, 136, 255';
      else color = '255, 102, 102';
      return color;
    },

    /**
     * Get mode icon class
     */
    modeIcon() {
      // Use fullMapData.mode if available, otherwise use difficulty.mode
      const modeValue = this.fullMapData?.mode !== undefined && this.fullMapData?.mode !== null
        ? parseInt(this.fullMapData.mode)
        : (this.difficulty?.mode !== undefined && this.difficulty?.mode !== null
          ? parseInt(this.difficulty.mode)
          : null);
      
      if (modeValue === null) {
        this._log('warn', 'RENDER', 'No mode data available, using music icon', {
          difficultyId: this.difficulty?.id,
          difficultyMode: this.difficulty?.mode,
          fullMapDataMode: this.fullMapData?.mode,
          hasDifficulty: !!this.difficulty,
          hasFullMapData: !!this.fullMapData
        });
        return 'fas fa-music';
      }

      const modeIcons = {
        0: 'mode-osu',      // osu!standard
        1: 'mode-taiko',    // osu!taiko
        2: 'mode-catch',    // osu!catch
        3: 'mode-mania'     // osu!mania
      };

      const icon = modeIcons[modeValue];
      
      if (!icon) {
        this._log('warn', 'RENDER', `Unknown mode value: ${modeValue}, using music icon`, {
          difficultyId: this.difficulty?.id,
          difficultyMode: this.difficulty?.mode,
          fullMapDataMode: this.fullMapData?.mode,
          parsedMode: modeValue
        });
        return 'fas fa-music';
      }
      
      this._log('trace', 'RENDER', `Mode icon: ${icon} (mode: ${modeValue})`);
      return icon;
    },

    /**
     * Get rank change info - checks both direct prop and rankChanges object
     */
    rankChangeInfo() {
      // First check direct rankChange prop
      let change = this.rankChange;
      
      // If not provided directly, look up from rankChanges by difficulty ID (like old component)
      if (!change && this.rankChanges && this.difficulty?.id) {
        change = this.rankChanges[this.difficulty.id] || null;
      }

      if (!change) return null;

      const diff = change.newRank - change.oldRank;

      let result;
      if (diff === 0) result = { icon: 'fa-equals', color: 'var(--beatmap-rank-unchanged)' };
      else if (diff < 0) result = { icon: 'fa-arrow-up', color: 'var(--beatmap-rank-improved)' };
      else result = { icon: 'fa-arrow-down', color: 'var(--beatmap-rank-declined)' };

      this._log('debug', 'RENDER', 'Rank change info', {
        difficultyId: this.difficulty?.id,
        oldRank: change.oldRank,
        newRank: change.newRank,
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
    },

    /**
     * Check if status has changed
     */
    hasStatusChange() {
      return this.oldStatus !== null && 
             this.newStatus !== null && 
             this.oldStatus !== this.newStatus;
    },

    /**
     * Get status color based on status code
     */
    statusColors() {
      const colors = {
        '-2': 'hsl(0, 0%, 40%)',      // Graveyard
        '-1': 'hsl(0, 0%, 40%)',      // WIP
        '0': 'hsl(0, 0%, 45%)',       // Pending
        '1': 'hsl(120, 100%, 40%)',   // Ranked
        '2': 'hsl(199, 100%, 50%)',   // Ranked (same as 1)
        '3': 'hsl(155, 100%, 50%)',   // Approved
        '4': 'hsl(144, 100%, 50%)',   // Qualified
        '5': 'hsl(320, 100%, 50%)'    // Loved
      };
      return colors;
    },

    /**
     * Get old status color
     */
    oldStatusColor() {
      if (this.oldStatus === null) return '#666';
      return this.statusColors[String(this.oldStatus)] || '#666';
    },

    /**
     * Get new status color
     */
    newStatusColor() {
      if (this.newStatus === null) return '#4CAF50';
      return this.statusColors[String(this.newStatus)] || '#4CAF50';
    },

    /**
     * Get status change text for tooltip
     */
    statusChangeText() {
      const statusNames = {
        '-2': 'Graveyard',
        '-1': 'WIP',
        '0': 'Pending',
        '1': 'Ranked',
        '2': 'Ranked',
        '3': 'Approved',
        '4': 'Qualified',
        '5': 'Loved'
      };
      const oldName = statusNames[String(this.oldStatus)] || 'Unknown';
      const newName = statusNames[String(this.newStatus)] || 'Unknown';
      return `${oldName} → ${newName}`;
    }
  },

  methods: {
    _log(level, section, message, data) {
      if (this.$log) {
        this.$log[level](section, message, data);
      }
    },

    /**
     * Fetch full map data from beatmapDataStore
     */
    async fetchFullMapData() {
      if (!this.difficulty?.id) {
        this._log('warn', 'DATA', 'Cannot fetch full map data: no difficulty ID');
        return;
      }

      this._log('info', 'DATA', `Fetching full map data for ${this.difficulty.id}`);

      try {
        const store = window.__beatmapDataStore;
        if (!store) {
          this._log('error', 'DATA', 'BeatmapDataStore not available');
          return;
        }

        const mapData = await store.getBeatmap(this.difficulty.id);
        
        if (mapData) {
          this.$set(this, 'fullMapData', mapData);
          this._log('info', 'DATA', `Full map data loaded for ${this.difficulty.id}`, {
            title: mapData.title,
            mode: mapData.mode,
            diff: mapData.diff,
            difficulty_rating: mapData.difficulty_rating
          });
        } else {
          this._log('warn', 'DATA', `No map data found for ID ${this.difficulty.id}`);
        }
      } catch (error) {
        this._log('error', 'DATA', `Error fetching full map data for ${this.difficulty.id}`, { 
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
      :class="['beatmap-diff-icon', sizeClass, difficultyTier, { 
        'beatmap-diff-icon--selected': selected,
        'beatmap-diff-icon--status-changed': hasStatusChange
      }]"
      :style="{ 
        '--diff-color': difficultyColor,
        '--old-status-color': oldStatusColor,
        '--new-status-color': newStatusColor
      }"
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
      
      <!-- Status change indicator (shown on hover when status changed) -->
      <div v-if="hasStatusChange" 
        class="beatmap-diff-icon__status-change"
        :title="statusChangeText">
        {{ statusChangeText }}
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