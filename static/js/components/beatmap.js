// Note: Needs to be refactored into a master component with multiple sub-components for displaying beatmaps in various display styles around the website.
Vue.component('bmap-card', {
  mixins: [mixin_formatting, mixin_conversion],
  props: {
    // The beatmap data object - can be partial data
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
      default: 'standard',
      validator: function(value) {
        return ['mini', 'compact'].includes(value);
      }
    },
    // Whether to show all difficulties or just the selected one
    showAllDifficulties: {
      type: Boolean,
      default: false
    },
    // Selected difficulty ID to highlight (if showing all diffs) or display (if showing single diff)
    selectedDifficultyId: {
      type: Number,
      default: null
    },
    // Rank change data for difficulties (optional)
    rankChanges: {
      type: Object,
      default: () => ({})
      // Format: { diffId: { oldRank: number, newRank: number } }
    },
    // Whether this is a single difficulty or a set of difficulties
    isSet: {
      type: Boolean,
      default: false
    },
    // Whether to show play count (for most played maps)
    showPlays: {
      type: Boolean,
      default: false
    },
    // Whether to show the beatmap status
    showStatus: {
      type: Boolean,
      default: true
    },
    // Whether to enable click interactions
    interactive: {
      type: Boolean,
      default: true
    },
    // Whether to auto-load complete data if partial data is provided
    autoLoad: {
      type: Boolean,
      default: true
    },
  },
  data: function() {
    return {
      expanded: false,
      loading: false,
      dataLoading: false,
      fullData: null,
      setDifficulties: [],
      error: null,
      statusNames: {
        "-2": "Graveyard",
        "-1": "WIP",
        "0": "Pending",
        "2": "Ranked",
        "3": "Approved",
        "4": "Qualified",
        "5": "Loved"
      },
      statusColors: {
        "-2": "hsl(0, 0%, 40%)",
        "-1": "hsl(0, 0%, 40%)",
        "0": "hsl(0, 0.00%, 45%)",
        "1": "hsl(120, 100%, 40%)",
        "2": "hsl(199, 100.00%, 50.00%)",
        "3": "hsl(155, 100.00%, 50.00%)",
        "4": "hsl(144, 100.00%, 50.00%)",
        "5": "hsl(320, 100%, 50%)"
      },
      difficultyExpanded: false,
      popupPosition: 'top', // 'top', 'left', 'right' - will be calculated dynamically
      visibleDifficultyRange: { start: 0, end: 6 }, // For scrolling difficulties
    };
  },
  async created() {
    this.$log = ColorfulLogger.child('Comp | Beatmap Card');
    // Auto-load complete data if needed
    if (this.autoLoad && !this.hasCompleteData) {
      this.loadMapData();
    }
  },
  computed: {
    // Use full data if available, otherwise use the prop data
    mapData() {
      return this.fullData || this.beatmap;
    },
    // Check if we have complete data
    hasCompleteData() {
      return this.fullData !== null || 
             (this.beatmap.title && this.beatmap.artist && this.beatmap.creator);
    },
    coverUrl() {
      const setId = this.mapData.set_id;
      return setId ? `https://assets.ppy.sh/beatmaps/${setId}/covers/cover.jpg` : '';
    },
    cardUrl() {
      const setId = this.mapData.set_id;
      return setId ? `https://assets.ppy.sh/beatmaps/${setId}/covers/card.jpg` : '';
    },
    listUrl() {
      const setId = this.mapData.set_id;
      return setId ? `https://assets.ppy.sh/beatmaps/${setId}/covers/list.jpg` : '';
    },
    thumbnailUrl() {
      const setId = this.mapData.set_id;
      return setId ? `https://b.ppy.sh/thumb/${setId}l.jpg` : '';
    },
    statusName() {
      return this.statusNames[this.mapData.status] || "Unknown";
    },
    statusColor() {
      return this.statusColors[this.mapData.status] || "hsl(0, 0%, 40%)";
    },
    hasMultipleDifficulties() {
      return this.isSet || (this.setDifficulties && this.setDifficulties.length > 0);
    },
    // Format difficulty stars with proper color
    difficultyStars() {
      if (!this.mapData.difficulty_rating) return null;
      
      const stars = parseFloat(this.mapData.difficulty_rating);
      let color;
      
      if (stars < 2) color = '#4FC0FF';
      else if (stars < 2.7) color = '#4FC0FF';
      else if (stars < 4) color = '#66FF33';
      else if (stars < 5.3) color = '#FFCC22';
      else if (stars < 6.5) color = '#FF66AA';
      else color = '#AA88FF';
      
      return {
        value: stars.toFixed(2),
        color: color
      };
    },
    // Get the selected difficulty object
    selectedDifficulty() {
      if (!this.selectedDifficultyId) return this.mapData;
      
      if (this.setDifficulties && this.setDifficulties.length > 0) {
        return this.setDifficulties.find(d => d.id === this.selectedDifficultyId) || this.mapData;
      }
      
      return this.mapData;
    },
    
    // Get visible difficulties for scrolling
    visibleDifficulties() {
      if (!this.setDifficulties || this.setDifficulties.length === 0) return [];
      
      return this.setDifficulties.slice(
        this.visibleDifficultyRange.start, 
        this.visibleDifficultyRange.end
      );
    },
    
    // Check if we need to show scroll controls
    hasMoreDifficulties() {
      return this.setDifficulties && this.setDifficulties.length > this.visibleDifficultyRange.end;
    },
    
    // Check if we can scroll back
    canScrollBack() {
      return this.visibleDifficultyRange.start > 0;
    },
  },
  methods: {
    async loadMapData() {
      if (this.dataLoading || this.hasCompleteData) return;
      
      this.dataLoading = true;
      this.error = null;
      
      try {
        // Determine which API endpoint to use based on available data
        let endpoint;
        let params = {};
        
        if (this.beatmap.id) {
          endpoint = `${window.location.protocol}//api.${domain}/v1/maps`;
          params.id = this.beatmap.id;
        } else if (this.beatmap.set_id) {
          endpoint = `${window.location.protocol}//api.${domain}/v1/maps`;
          params.set_id = this.beatmap.set_id;
        } else if (this.beatmap.md5) {
          endpoint = `${window.location.protocol}//api.${domain}/v1/maps`;
          params.md5 = this.beatmap.md5;
        } else {
          throw new Error("Insufficient data to load map details");
        }
        
        // Build query string
        const queryString = Object.entries(params)
          .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
          .join('&');
        
        const response = await fetch(`${endpoint}?${queryString}`);
        
        if (!response.ok) {
          throw new Error(`API request failed with status ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.status === 'success' && data.data && data.data.length > 0) {
          this.fullData = data.data[0];
          
          // If this is a set, load other difficulties
          if (this.isSet && this.fullData.set_id) {
            this.loadSetDifficulties();
          }
          
          this.$emit('data-loaded', this.fullData);
        } else {
          throw new Error("No map data found");
        }
      } catch (error) {
        console.error("Error loading map data:", error);
        this.error = error.message;
        this.$emit('data-error', error);
      } finally {
        this.dataLoading = false;
      }
    },
    async loadSetDifficulties() {
      if (this.loading || !this.mapData.set_id) return;
      
      this.loading = true;
      this.error = null;
      
      try {
        const endpoint = `${window.location.protocol}//api.${domain}/v2/maps`;
        const params = {
          set_id: this.mapData.set_id,
          page_size: 100 // Get all difficulties
        };
        
        // Build query string
        const queryString = Object.entries(params)
          .map(([key, value]) => `${key}=${encodeURIComponent(value)}`)
          .join('&');
        
        const response = await fetch(`${endpoint}?${queryString}`);
        
        if (!response.ok) {
          throw new Error(`API request failed with status ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.status === 'success' && data.data) {
          this.setDifficulties = data.data.sort((a, b) => {
            // Sort by difficulty rating
            return (a.difficulty_rating || 0) - (b.difficulty_rating || 0);
          });
          
          this.$emit('difficulties-loaded', this.setDifficulties);
        } else {
          throw new Error("No difficulties found");
        }
      } catch (error) {
        console.error("Error loading beatmap difficulties:", error);
        this.error = error.message;
        this.$emit('difficulties-error', error);
      } finally {
        this.loading = false;
      }
    },
    handleClick() {
      if (!this.interactive) return;
      
      // Emit event for parent components to handle
      this.$emit('beatmap-click', this.mapData.id, this.mapData.set_id);
    },
    handleDifficultyClick(difficulty, event) {
      event.stopPropagation();
      if (!this.interactive) return;
      
      // Emit event for parent components to handle
      this.$emit('difficulty-click', difficulty.id, this.mapData.set_id, difficulty);
    },
    // Scroll difficulties left
    scrollDifficultiesLeft() {
      if (this.canScrollBack) {
        this.visibleDifficultyRange.start = Math.max(0, this.visibleDifficultyRange.start - 1);
        this.visibleDifficultyRange.end = Math.max(6, this.visibleDifficultyRange.end - 1);
      }
    },
    
    // Scroll difficulties right
    scrollDifficultiesRight() {
      if (this.hasMoreDifficulties) {
        this.visibleDifficultyRange.start += 1;
        this.visibleDifficultyRange.end += 1;
      }
    },
    
    // Get rank change icon and color
    getRankChangeInfo(diffId) {
      if (!this.rankChanges || !this.rankChanges[diffId]) return null;
      
      const change = this.rankChanges[diffId];
      const diff = change.newRank - change.oldRank;
      
      if (diff === 0) return { icon: 'fa-equals', color: '#AAAAAA' };
      if (diff < 0) return { icon: 'fa-arrow-up', color: '#66FF33' }; // Rank improved (lower is better)
      return { icon: 'fa-arrow-down', color: '#FF6666' }; // Rank decreased
    },
    
    // Format the rank change text
    formatRankChange(diffId) {
      if (!this.rankChanges || !this.rankChanges[diffId]) return '';
      
      const change = this.rankChanges[diffId];
      return `#${change.newRank} (was #${change.oldRank})`;
    },
    
    difficultyColor(diff) {
      if (!diff || !diff.diff) {
        this.$log.debug('diff', 'Using default grey due to lack of diff info:', diff);
        return '200, 200, 200'; // Default gray RGB values
      }
  
      try {
        // Create color scale
        const difficultyColourSpectrum = d3.scaleLinear()
          .domain([0.1, 1.25, 2, 2.5, 3.3, 4.2, 4.9, 5.8, 6.7, 7.7, 9])
          .clamp(true)
          .range(['#4290FB', '#4FC0FF', '#4FFFD5', '#7CFF4F', '#F6F05C', '#FF8068', '#FF4E6F', '#C645B8', '#6563DE', '#18158E', '#000000'])
          .interpolate(d3.interpolateRgb.gamma(2.2));
  
        // Get difficulty rating
        const stars = parseFloat(diff.diff || 0);
        
        // Convert hex to RGB
        const color = d3.color(difficultyColourSpectrum(stars));
        return color ? `${color.r}, ${color.g}, ${color.b}` : '200, 200, 200';
      } catch (error) {
        this.$log.error('Diff', 'Error calculating difficulty color:', error);
        return '200, 200, 200'; // Fallback color
      }
    }
  },
  mounted() {
    // Load difficulties if showing all
    if (this.showAllDifficulties && this.mapData.set_id && !this.setDifficulties.length) {
      this.loadSetDifficulties();
    }
  },
  template: `#bmap-card-template`
});
