const mixin_formatting = {
  methods: {
    /**
     * Format the length of a song in MM:SS format
     * @param {number} seconds - The length of the song in seconds
     * @returns {string} The formatted time string in MM:SS format
     */
    formatLength(seconds) {
      if (!seconds) return '0:00';
      const minutes = Math.floor(seconds / 60);
      const secs = seconds % 60;
      return `${minutes}:${secs.toString().padStart(2, '0')}`;
    },

    formatNumber(num) {
      if (!num) return '0';
      return num.toLocaleString();
    },
  },
};
const mixin_conversion = {
  methods: {
    // Get mode icon class
    getModeIcon(mode) {
      const modes = {
        0: 'mode-osu', // osu!
        1: 'mode-taiko', // taiko
        2: 'mode-catch', // catch
        3: 'mode-mania' // mania
      };
      return modes[mode] || modes[0];
    },
    // Get mode name
    getModeName(mode) {
      const modes = {
        0: 'osu!',
        1: 'osu!taiko',
        2: 'osu!catch',
        3: 'osu!mania'
      };
      return modes[mode] || modes[0];
    },
  },
};
const mixin_beatmap_utils = {
  methods: {
    
  },
};

/* Smaller Components */
  // Section: Rank Change Badge Component
    Vue.component('rank-change-badge', {
      name: 'RankChangeBadge', // Added name for child logger
      props: {
        change: {
          type: Object,
          required: true
        }
      },
      computed: {
        diff() {
          // Assert that change object has expected properties
          this.$log.assert(
            this.change && typeof this.change.newRank === 'number' && typeof this.change.oldRank === 'number',
            'RankChangeBadge',
            'Invalid "change" prop structure.',
            { change: this.change },
            false
          );
          const difference = this.change.newRank - this.change.oldRank;
          this.$log.debug('RankChangeBadge', `Calculated rank difference: ${difference}`, { change: this.change });
          return difference;
        },
        icon() {
          if (this.diff === 0) return 'fa-equals';
          if (this.diff < 0) return 'fa-arrow-up'; // Assuming lower rank number is better (arrow up)
          return 'fa-arrow-down'; // Assuming higher rank number is worse (arrow down)
        },
        color() {
          if (this.diff === 0) return '#AAAAAA';
          if (this.diff < 0) return '#66FF33'; // Green for improvement
          return '#FF6666'; // Red for decline
        },
        text() {
          const textValue = `#${this.change.newRank} (was #${this.change.oldRank})`;
          this.$log.debug('RankChangeBadge', `Formatted rank change text: ${textValue}`);
          return textValue;
        }
      },
      created() {
        this.$log.debug('RankChangeBadge', 'Component created.', { change: this.change });
      },
      template: `
        <div class="rank-change-badge" :style="{ backgroundColor: color }">
          <i class="fas" :class="icon"></i>
          <!-- You might want to display the text here too, or in a tooltip -->
          <!-- <span class="rank-change-text">{{ text }}</span> -->
        </div>
      `
    });

  // Section: Difficulty Icon Component
    Vue.component('difficulty-icon', {
      mixins: [mixin_formatting, mixin_conversion],
      props: {
        diff: { type: Object, required: true },
        setId: { type: Number, required: true },
        rankChanges: { type: Object, default: () => ({}) },
        interactive: { type: Boolean, default: true }
      },
      computed: {
        diffColor() {
          if (!this.diff || !this.diff.diff) return '200, 200, 200';
        
          try {
            const scale = d3.scaleLinear()
              .domain([0.1, 1.25, 2, 2.5, 3.3, 4.2, 4.9, 5.8, 6.7, 7.7, 9])
              .clamp(true)
              .range([
                '#4290FB', '#4FC0FF', '#4FFFD5', '#7CFF4F', '#F6F05C',
                '#FF8068', '#FF4E6F', '#C645B8', '#6563DE', '#18158E', '#000000'
              ])
              .interpolate(d3.interpolateRgb.gamma(2.2));
            
            const stars = parseFloat(this.diff.diff || 0);
            const color = d3.color(scale(stars));
            return color ? `${color.r}, ${color.g}, ${color.b}` : '200, 200, 200';
          } catch (e) {
            this.$log.error('difficulty-icon color error:', e);
            return '200, 200, 200';
          }
        },
        rankChange() {
          return this.rankChanges[this.diff.id] || null;
        }
      },
      methods: {
        handleClick(e) {
          e.stopPropagation();
          if (!this.interactive) return;
          beatmapBus.$emit('show-beatmap-panel', this.diff.id, this.setId);
        }
      },
      template: `
        <div class="beatmap-mini-difficulty-icon-container"
             :style="{ '--diff-color': diffColor }">
    
          <div class="beatmap-mini-difficulty-icon"
               @click="handleClick"
               data-popup-trigger>
    
            <i :class="getModeIcon(diff.mode)"
               class="beatmap-mini-mode-icon"></i>
    
            <rank-change-indicator
              v-if="rankChange"
              :change="rankChange" />
          </div>
    
          <slot></slot>
        </div>
      `
    });
  // Section: Difficulty Popup Component
    Vue.component('difficulty-popup', {
      mixins: [mixin_formatting, mixin_conversion],
      props: {
        mapData: {
          type: Object,
          required: true
        },
        diff: {
          type: Object,
          required: true
        },
        setDifficulties: {
          type: Array,
          default: () => []
        },
        rankChanges: {
          type: Object,
          default: () => ({})
        },
        showStatus: {
          type: Boolean,
          default: true
        },
        loading: {
          type: Boolean,
          default: false
        }
      },
      computed: {
        statusName() {
          return this.mapData.status != null
            ? ({
                "-2": "Graveyard",
                "-1": "WIP",
                "0": "Pending",
                "2": "Ranked",
                "3": "Approved",
                "4": "Qualified",
                "5": "Loved"
              }[this.mapData.status] || "Unknown")
            : "Unknown";
        },
        statusColor() {
          return ({
            "-2": "hsl(0, 0%, 40%)",
            "-1": "hsl(0, 0%, 40%)",
            "0": "hsl(0, 0.00%, 45%)",
            "1": "hsl(120, 100%, 40%)",
            "2": "hsl(199, 100.00%, 50.00%)",
            "3": "hsl(155, 100.00%, 50.00%)",
            "4": "hsl(144, 100.00%, 50.00%)",
            "5": "hsl(320, 100%, 50%)"
          }[this.mapData.status] || "hsl(0, 0%, 40%)");
        },
        rankChange() {
          return this.rankChanges[this.diff.id] || null;
        },
        rankDiff() {
          if (!this.rankChange) return 0;
          return this.rankChange.newRank - this.rankChange.oldRank;
        },
        rankIcon() {
          if (!this.rankChange) return null;
          if (this.rankDiff === 0) return 'fa-equals';
          if (this.rankDiff < 0) return 'fa-arrow-up';
          return 'fa-arrow-down';
        },
        rankColor() {
          if (!this.rankChange) return null;
          if (this.rankDiff === 0) return '#AAAAAA';
          if (this.rankDiff < 0) return '#66FF33';
          return '#FF6666';
        }
      },
      methods: {
        handleDiffClick(diff, e) {
          e.stopPropagation();
          beatmapBus.$emit('show-beatmap-panel', diff.id, this.mapData.set_id);
        }
      },
      template: `
        <div class="beatmap-mini-popup position-top" data-popup>
          <div class="beatmap-mini-popup-header">
            <div class="beatmap-mini-popup-title" :title="mapData.title">
              {{ mapData.title || 'Loading...' }}
            </div>
            <div class="beatmap-mini-popup-artist" :title="mapData.artist">
              {{ mapData.artist || '' }}
            </div>
            <div class="beatmap-mini-popup-version" :title="diff.version">
              {{ diff.version || '' }}
            </div>
          </div>
    
          <div class="beatmap-mini-popup-details">
            <div class="beatmap-mini-popup-creator"
                 :title="'Mapped by ' + mapData.creator">
              Mapped by {{ mapData.creator || '' }}
            </div>
    
            <div class="beatmap-mini-popup-stats">
              <div v-if="diff.bpm" class="beatmap-mini-popup-stat">
                <i class="fas fa-heartbeat"></i>
                {{ Math.round(diff.bpm) }}bpm
              </div>
    
              <div v-if="diff.hit_length" class="beatmap-mini-popup-stat">
                <i class="fas fa-clock"></i>
                {{ formatLength(diff.hit_length) }}
              </div>
    
              <div v-if="diff.difficulty_rating" class="beatmap-mini-popup-stat">
                <difficulty-stars :stars="diff.difficulty_rating" />
              </div>
    
              <div v-if="showStatus" class="beatmap-mini-popup-stat">
                <span class="beatmap-mini-status"
                      :style="{ backgroundColor: statusColor }">
                  {{ statusName }}
                </span>
              </div>
            </div>
    
            <!-- Rank change -->
            <div v-if="rankChange" class="beatmap-mini-popup-rank-change">
              <div class="beatmap-mini-popup-rank-label">Rank:</div>
              <div class="beatmap-mini-popup-rank-value"
                   :style="{ color: rankColor }">
                #{{ rankChange.newRank }} (was #{{ rankChange.oldRank }})
                <i class="fas" :class="rankIcon"></i>
              </div>
            </div>
    
            <!-- Other difficulties -->
            <div v-if="setDifficulties.length > 1"
                 class="beatmap-mini-popup-other-diffs">
              <div class="beatmap-mini-popup-diffs-header">
                Other difficulties:
              </div>
    
              <div v-if="loading" class="beatmap-mini-popup-loading">
                Loading...
              </div>
    
              <div v-else class="beatmap-mini-popup-diffs-list">
                <div v-for="d in setDifficulties.filter(x => x.id !== diff.id)"
                     :key="d.id"
                     class="beatmap-mini-popup-diff"
                     @click="handleDiffClick(d, $event)">
                  <span class="beatmap-mini-popup-diff-name"
                        :title="d.version">
                    {{ d.version }}
                  </span>
                  <span v-if="d.difficulty_rating"
                        class="beatmap-mini-popup-diff-stars">
                    {{ parseFloat(d.difficulty_rating).toFixed(2) }}
                  </span>
                  <span v-if="rankChanges[d.id]"
                        class="beatmap-mini-popup-diff-rank"
                        :style="{ color: rankColor }">
                    <i class="fas" :class="rankIcon"></i>
                  </span>
                </div>
              </div>
            </div>
    
            <!-- Actions -->
            <div class="beatmap-mini-popup-actions">
              <a :href="'https://osu.ppy.sh/b/' + diff.id"
                 target="_blank"
                 class="beatmap-mini-popup-action"
                 @click.stop>
                <i class="fas fa-external-link-alt"></i> osu!
              </a>
    
              <a class="beatmap-mini-popup-action"
                 @click.stop="handleDiffClick(diff, $event)">
                <i class="fas fa-info-circle"></i> Details
              </a>
    
              <a :href="'/d/' + mapData.set_id"
                 class="beatmap-mini-popup-action"
                 @click.stop>
                <i class="fas fa-download"></i> Download
              </a>
            </div>
          </div>
        </div>
      `
    });
  // Section: 


Vue.component('badge', {
  props: {
    badge: {
      type: Object,
      required: true,
      validator: function (value) {
        return value !== null && typeof value === 'object' && value.hasOwnProperty('styles');
      }
    },
    type: {
      type: Number,
      default: 0,
      validator: function (value) {
        return [0, 1].includes(value);
      }
    },
    test: {
      type: Number,
      default: 0,
      validator: function (value) {
        return [0, 1].includes(value);
      }
    }
  },
  data: function () {
    return {
      badgeId: 'badge-' + Math.random().toString(36).substr(2, 9)
    }
  },
  watch: {
    type: function (newVal) {
      if (typeof newVal !== 'number') {
        this.type = Number(newVal);
      }
    }
  },
  computed: {
    badgeStyle() {
      return {
        '--badge-styles-color': this.badge.styles.color,
        '--badge-hue': this.badge.styles.color,
        '--badge-bg-color': `hsl(${this.badge.styles.color}, 20%, 30%)`,
        '--badge-text-color': `hsl(${this.badge.styles.color}, 100%, 80%)`,
        '--badge-border-color': `hsl(${this.badge.styles.color}, 40%, 35%)`,
        'background-color': `var(--badge-bg-color)`,
        'color': `var(--badge-text-color)`,
        'border': `1px solid var(--badge-border-color)`
      };
    },
    panelStyle() {
      return {
        '--panel-bg-color': `hsl(${this.badge.styles.color}, 20%, 20%)`,
        '--panel-text-color': `hsl(${this.badge.styles.color}, 100%, 80%)`,
        'background-color': `var(--panel-bg-color)`,
        'color': `var(--panel-text-color)`
      };
    },
    badgeDescription() {
      return this.badge.description || `${this.badge.name} badge`;
    }
  },
  created() {
    if (this.test === 1) {
      this.$log.debug('Type:', this.type);
      this.$log.debug('Badge:', this.badge);
      this.$log.debug('Type === 0:', this.type === 0);
      this.$log.debug('Type === 1:', this.type === 1);
    }
  },
  template: `#badge-template`
});

Vue.component('user-profile-old', {
  props: ['user'],
  data: function() {
      return {
          id: null,
          loaded: false,
          dataFetched: {
              stats: false,
              recent: false,
              best: false,
              mostPlayed: false
          },
          profileVisible: false,
          isExpanded: false,
          activeTab: 'performance',
          mouseOverPanel: false,
          isLoading: {
              stats: false,
              recent: false,
              best: false,
              mostPlayed: false
          },
          currentMode: 0, // Default to standard mode
          currentMods: 'vn' // Default to vanilla
      };
  },
  async created() {
    if (this.user && !this.loaded) {
      if (!this.user.player_id === undefined) {
        this.id = this.user.player_id;
      };
      // Initialize user.info if it doesn't exist
      if (!this.user.info) {
        this.user.info = {
          badges: [],
          mostPlayedMaps: []
        };
        // Move relevant properties from root to info
        const rootProps = ['badges', 'clan_id', 'clan_name', 'clan_tag', 'country', 'name', 'player_id'];
        rootProps.forEach(prop => {
          if (this.user[prop] !== undefined) {
            this.user.info[prop] = this.user[prop];
            if (prop !== 'player_id') {
              delete this.user[prop];
            }
          }
        });
      }
      if (!this.user.stats) {
        this.user.stats = {
          current: {}
        };
        // Move relevant properties from root to stats.current
        const statsProps = ['a_count', 'acc', 'max_combo', 'plays', 'playtime', 'pp', 'rscore', 's_count', 'sh_count', 'tscore', 'x_count', 'xh_count'];
        statsProps.forEach(prop => {
          if (this.user[prop] !== undefined) {
            this.user.stats.current[prop] = this.user[prop];
            delete this.user[prop];
          }
        });
      }
      if (!this.user.scores) {
        this.user.scores = {
          recent: [],
          best: []
        };
      }
      this.$log.debug('Data', "User info initialized:", this.user);
      this.loaded = true;
    }
  },
  // Add this to the component definition
  watch: {
    user: {
      handler: function(newUser) {
        if (newUser && newUser.player_id !== this.id) {
          // Reset component state for the new user
          this.loaded = false;
          this.id = newUser.player_id;
          this.dataFetched = {
            stats: false,
            recent: false,
            best: false,
            mostPlayed: false
          };
          this.profileVisible = false;

          // Re-initialize the user data structure
          this.created();
        }
      },
      deep: true
    }
  },
  methods: {
    resetState: function() {
      this.loaded = false;
      this.dataFetched = {
        stats: false,
        recent: false,
        best: false,
        mostPlayed: false
      };
      this.profileVisible = false;
      this.isExpanded = false;
      // Re-initialize if needed
      this.created();
    },
    showProfile: async function() {
      this.profileVisible = true;
      if (!this.dataFetched.stats && !this.isLoading.stats) {
        await this.fetchPlayerData();
      }
    },
    hideProfile: function() {
        // Only hide if not hovering over the panel
        if (!this.mouseOverPanel) {
            this.profileVisible = false;
            this.isExpanded = false;
        }
    },
    mouseEnterPanel: function() {
        this.mouseOverPanel = true;
    },
    mouseLeavePanel: function() {
        this.mouseOverPanel = false;
        this.profileVisible = false;
        this.isExpanded = false;
    },

    toggleExpand: async function() {
        this.isExpanded = !this.isExpanded;
        
        if (this.isExpanded) {
          await this.loadActiveTabData();
        }
    },
    setActiveTab: async function(tab) {
        this.activeTab = tab;
        
        // Only load data if expanded and data for this tab hasn't been loaded yet
        if (this.isExpanded) {
            await this.loadActiveTabData();
        }
    },
    loadActiveTabData: async function() {
        switch(this.activeTab) {
            case 'performance':
                // Stats are loaded with player data
                break;
            case 'recent':
                if (!this.user.scores.recent || this.user.scores.recent.length === 0) {
                    await this.loadScores('recent');
                }
                break;
            case 'best':
                if (!this.user.scores.best || this.user.scores.best.length === 0) {
                    await this.loadScores('best');
                }
                break;
            case 'most':
                if (!this.user.info.mostPlayedMaps || this.user.info.mostPlayedMaps.length === 0) {
                    await this.loadMostPlayedMaps();
                }
                break;
        }
    },
    fetchPlayerData: function() {
        this.isLoading.stats = true;
        
        return fetch(`${window.location.protocol}//api.${domain}/v1/get_player_info?id=${this.user.player_id}&scope=all`)
            .then(response => response.json())
            .then(data => {
                if (!this.user.info) {
                    this.user.info = {};
                }
                // Merge the player data into user.info
                this.user.info = {
                    ...this.user.info,
                    ...data.player.info
                };
                this.user.stats = {
                    ...this.user.stats,
                    ...data.player.stats
                };
                this.$log.debug('Data', "Player data loaded:", this.user);
            })
            .catch(error => {
              this.$log.error('Data', "Error fetching player data:", error);
            })
            .finally(() => {
              this.isLoading.stats = false;
              this.dataFetched.stats = true;
              // Force Vue to re-render after data updates
              this.$nextTick(() => {
                this.$forceUpdate();
                this.$log.info('Lifecycle', "DOM updated with new player data");
              });
            });
    },
    loadScores: function(type) {
        this.isLoading[type] = true;
        const limit = 5; // Limit to 5 scores
        
        return fetch(`${window.location.protocol}//api.${domain}/v1/get_player_scores?id=${this.user.player_id}&mode=${this.modeToGulagInt()}&scope=${type}&limit=${limit}`)
            .then(response => response.json())
            .then(data => {
                if (type === 'recent') {
                  this.user.scores.recent = data.scores;
              } else {
                    this.user.scores.best = data.scores;
              }
              this.$log.debug('DATA', `${type} scores loaded:`, data.scores);
            })
            .catch(error => {
              this.$log.error('API', `Error fetching ${type} scores:`, error);
            })
            .finally(() => {
                this.isLoading[type] = false;
                this.dataFetched[type] = true;
                // Force Vue to re-render after data updates
                this.$nextTick(() => {
                  this.$forceUpdate();
                  this.$log.info('LIFECYCLE', "DOM updated with new player data");
                });
            });
    },
    loadMostPlayedMaps: function() {
        this.isLoading.mostPlayed = true;
        const limit = 3; // Limit to 3 maps
        
        return fetch(`${window.location.protocol}//api.${domain}/v1/get_player_most_played?id=${this.user.player_id}&mode=${this.modeToGulagInt()}&limit=${limit}`)
            .then(response => response.json())
            .then(data => {
                this.user.info.mostPlayedMaps = data.maps;
                this.$log.info('DATA', "Most played maps loaded:", this.user.info.mostPlayedMaps);
            })
            .catch(error => {
              this.$log.error('API', "Error fetching most played maps:", error);
            })
            .finally(() => {
                this.isLoading.mostPlayed = false;
                this.dataFetched.mostPlayed = true;
                // Force Vue to re-render after data updates
                this.$nextTick(() => {
                  this.$forceUpdate();
                  this.$log.info('LIFECYCLE', "DOM updated with new player data");
                });
            });
    },
    changeMode: function(mode, mods) {
        this.currentMode = mode;
        this.currentMods = mods || 'vn';
        
        // Reload data for the active tab in the new mode
        if (this.isExpanded) {
            this.loadActiveTabData();
        }
    },
    modeToGulagInt: function() {
        switch (this.currentMode + "|" + this.currentMods) {
            case 'std|vn':
            case '0|vn':
                return 0;
            case 'taiko|vn':
            case '1|vn':
                return 1;
            case 'catch|vn':
            case '2|vn':
                return 2;
            case 'mania|vn':
            case '3|vn':
                return 3;
            case 'std|rx':
            case '0|rx':
                return 4;
            case 'taiko|rx':
            case '1|rx':
                return 5;
            case 'catch|rx':
            case '2|rx':
                return 6;
            case 'std|ap':
            case '0|ap':
                return 8;
            default:
                return 0;
        }
    },
    formatNumber: function(num) {
        if (!num) return '0';
        return num.toLocaleString();
    },
    formatTime: function(seconds) {
        if (!seconds) return '0h';
        
        const hours = Math.floor(seconds / 3600);
        const minutes = Math.floor((seconds % 3600) / 60);
        
        if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else {
            return `${minutes}m`;
        }
    },
    secondsToDhm: function(seconds) {
        seconds = Number(seconds);
        var dDisplay = `${Math.floor(seconds / (3600 * 24))}d `;
        var hDisplay = `${Math.floor(seconds % (3600 * 24) / 3600)}h `;
        var mDisplay = `${Math.floor(seconds % 3600 / 60)}m `;
        return dDisplay + hDisplay + mDisplay;
    }
  },
  computed: {
      profileClasses: function() {
        return {
          'visible': this.profileVisible,
          'expanded': this.isExpanded
        };
      },
      currentModeStats: function() {
        if (!this.user?.stats?.current) return null;
        
        // Find stats for the current mode
        const gulagMode = this.modeToGulagInt();
        for (const mode in this.user.stats.current) {
          if (parseInt(mode) === gulagMode) {
            return this.user.stats.current[mode];
          }
        }
        
        // Default to first available mode if current not found
        const firstMode = Object.keys(this.user.stats.current)[0];
        return this.user.stats.current[firstMode] || null;
      },
      modeNames: function() {
          return {
              'std|vn': 'osu!',
              'taiko|vn': 'Taiko',
              'catch|vn': 'Catch',
              'mania|vn': 'Mania',
              'std|rx': 'Relax',
              'taiko|rx': 'Taiko RX',
              'catch|rx': 'Catch RX',
              'std|ap': 'Autopilot'
          };
      },
      availableModes: function() {
          if (!this.user.stats) return [];
          
          const modes = [];
          for (const mode in this.user.stats) {
              const modeInt = parseInt(mode);
              let gameMode, modType;
              
              // Convert mode int back to mode and mod type
              if (modeInt === 0) { gameMode = 'std'; modType = 'vn'; }
              else if (modeInt === 1) { gameMode = 'taiko'; modType = 'vn'; }
              else if (modeInt === 2) { gameMode = 'catch'; modType = 'vn'; }
              else if (modeInt === 3) { gameMode = 'mania'; modType = 'vn'; }
              else if (modeInt === 4) { gameMode = 'std'; modType = 'rx'; }
              else if (modeInt === 5) { gameMode = 'taiko'; modType = 'rx'; }
              else if (modeInt === 6) { gameMode = 'catch'; modType = 'rx'; }
              else if (modeInt === 8) { gameMode = 'std'; modType = 'ap'; }
              else continue;
              
              // Only add modes with some activity
              const stats = this.user.stats[mode];
              if (stats && (stats.playcount > 0 || stats.pp > 0)) {
                  modes.push({ 
                      mode: gameMode, 
                      mods: modType, 
                      display: this.modeNames[`${gameMode}|${modType}`] 
                  });
              }
          }
          
          return modes;
      }
  },
  template: `
    <span :id="user.player_id" class="user-name" @mouseover="showProfile" @mouseout="hideProfile">
      <a :href="'/u/'+user.player_id+'?mode='+mode+'&mods='+mods">
          {{ user.info.name }}
      </a>
      <div :id="user.player_id" class="profile-panel" :class="profileClasses" 
           @mouseenter="mouseEnterPanel" @mouseleave="mouseLeavePanel">
        <div class="profile-panel-background" :style="'background-image: url(/backgrounds/' + user.player_id + ')'"></div>
        
        <div class="profile-panel-header">
          <div class="profile-panel-avatar" :style="'background-image: url(https://a.' + domain + '/' + user.player_id + ')'"></div>
          <div class="profile-panel-info">
            <div class="name">
              <span v-if="user.info.clan_tag">
                <a>[{{ user.info.clan_tag }}]</a>
              </span>
              {{ user.info.name }}
            </div>
            <div class="rank" v-if="user.stats">
              <span class="global">#{{ user.stats.current.rank || '?' }}</span>
              <span class="country">
                <img :src="'/static/images/flags/' + (user.info.country || '').toUpperCase() + '.png'" alt="Country Flag" class="flag" />
                #{{ user.stats.current.country_rank || '?' }}
              </span>
            </div>
            <div class="badge-block compact">
              <badge v-for="badge in user.info?.badges" :badge="badge" :type="1"></badge>
            </div>
          </div>
        </div>
        
        <div class="profile-panel-stats" v-if="user.stats">
          <div class="stat-item">
            <div class="stat-value">{{ formatNumber(user.stats.current.pp) || '0' }}</div>
            <div class="stat-label">PP</div>
          </div>
          <div class="stat-item">
            <div class="stat-value">{{ user.stats.current.acc ? user.stats.current.acc.toFixed(2) : '0.00' }}%</div>
            <div class="stat-label">Accuracy</div>
          </div>
          <div class="stat-item">
            <div class="stat-value">{{ formatNumber(user.stats.current.plays) || '0' }}</div>
            <div class="stat-label">Plays</div>
          </div>
        </div>
        
        <div class="profile-panel-expand" @click.stop="toggleExpand">
            <div class="expand-icon"></div>
        </div>
        
        <div class="profile-panel-details" v-show="isExpanded">
          <!-- Mode selector -->
          <div v-if="availableModes.length > 0" class="mode-selector">
            <div v-for="modeOption in availableModes" 
                 :key="modeOption.mode + '|' + modeOption.mods" 
                 @click="changeMode(modeOption.mode, modeOption.mods)"
                 :class="['mode-option', { active: currentMode === modeOption.mode && currentMods === modeOption.mods }]">
              {{ modeOption.display }}
            </div>
          </div>
          
          <div class="profile-panel-tabs">
            <div class="profile-tab" 
                 :class="{ active: activeTab === 'performance' }" 
                 @click="setActiveTab('performance')">Performance</div>
            <div class="profile-tab" 
                 :class="{ active: activeTab === 'recent' }" 
                 @click="setActiveTab('recent')">Recent</div>
            <div class="profile-tab" 
                 :class="{ active: activeTab === 'best' }" 
                 @click="setActiveTab('best')">Best</div>
            <div class="profile-tab" 
                 :class="{ active: activeTab === 'most' }" 
                 @click="setActiveTab('most')">Most Played</div>
          </div>
          
          <div class="profile-panel-content">
            <!-- Loading indicator -->
            <div v-if="isLoading.stats && activeTab === 'performance'" class="loading-indicator">
                Loading player data...
            </div>
            
            <!-- Performance tab -->
            <div class="tab-content performance-stats" v-show="activeTab === 'performance'" v-if="activeTab === 'performance' && user.stats.current && !isLoading.stats">
              <div class="performance-item">
                <div class="performance-label">Performance</div>
                <div class="performance-value">{{ formatNumber(user.stats.current.pp) }}pp</div>
              </div>
              <div class="performance-item">
                <div class="performance-label">Accuracy</div>
                <div class="performance-value">{{ user.stats.current.acc ? user.stats.current.acc.toFixed(2) : '0.00' }}%</div>
              </div>
              <div class="performance-item">
                <div class="performance-label">Ranked Score</div>
                <div class="performance-value">{{ formatNumber(user.stats.current.rscore) }}</div>
              </div>
              <div class="performance-item">
                <div class="performance-label">Total Score</div>
                <div class="performance-value">{{ formatNumber(user.stats.current.tscore) }}</div>
              </div>
              <div class="performance-item">
                <div class="performance-label">Play Count</div>
                <div class="performance-value">{{ formatNumber(user.stats.current.plays) }}</div>
              </div>
              <div class="performance-item">
                <div class="performance-label">Play Time</div>
                <div class="performance-value">{{ secondsToDhm(user.stats.current.playtime || 0) }}</div>
              </div>
              <div class="performance-item">
                <div class="performance-label">Max Combo</div>
                <div class="performance-value">{{ formatNumber(user.stats.current.max_combo) }}x</div>
              </div>
              <div class="performance-item">
                <div class="performance-label">Replays Watched</div>
                <div class="performance-value">{{ formatNumber(user.stats.current.replay_views) }}</div>
              </div>
            </div>
            
            <!-- Recent scores tab -->
            <div class="tab-content recent-scores" v-show="activeTab === 'recent'" v-if="activeTab === 'recent'">
              <div v-if="isLoading.recent" class="loading-indicator">
                Loading recent scores...
              </div>
              <div v-else-if="user.scores.recent && user.scores.recent.length > 0">
                <score-card v-for="(score, index) in user.scores.recent":score="score"></score-card>
              </div>
              <div v-else class="empty-state">No recent scores found</div>
            </div>
            
            <!-- Best scores tab -->
            <div class="tab-content best-scores" v-show="activeTab === 'best'" v-if="activeTab === 'best'">
              <div v-if="isLoading.best" class="loading-indicator">
                  Loading best scores...
              </div>
              <div v-else-if="user.scores.best && user.scores.best.length > 0">
                <score-card v-for="(score, index) in user.scores.best":score="score"></score-card>
              </div>
              <div v-else class="empty-state">No best scores found</div>
            </div>
            
            <!-- Most played maps tab -->
            <div class="tab-content most-played" v-show="activeTab === 'most'" v-if="activeTab === 'most'">
              <div v-if="isLoading.mostPlayed" class="loading-indicator">
                Loading most played maps...
              </div>
              <div v-else-if="user.info.mostPlayedMaps && user.info.mostPlayedMaps.length > 0">
                <bmap-card v-for="(map, index) in user.info.mostPlayedMaps" :beatmap="map" mode="mini" :is-set="false" :show-plays="true"></bmap-card>
              </div>
              <div v-else class="empty-state">No most played maps found</div>
            </div>
          </div>
        </div>
      </div>
    </span>
  `,
});

/**
 * ============================================================================
 * Section: User-Profile Sub-Components
 * ============================================================================
 *
 * Sub-components for the user-profile master component.
 * These components handle specific display styles and functionality.
 */

/**
 * ============================================================================
 * Component: UserProfileHoverPanel
 * ============================================================================
 *
 * Hover panel for username style that shows detailed user information.
 *
 * Props:
 * @param {Object} user - User data object
 * @param {Object} statusData - User status data
 * @param {Boolean} showCountry - Whether to show country
 * @param {Boolean} showClan - Whether to show clan tag
 * @param {Boolean} showBadges - Whether to show badges
 * @param {Boolean} showStatus - Whether to show status
 * @param {Boolean} visible - Whether panel is visible
 * @param {Boolean} interactive - Whether to enable interactions
 * @param {String} avatarUrl - Avatar image URL
 * @param {String} bannerUrl - Banner image URL
 * @param {String} flagUrl - Flag image URL
 * @param {String} clanUrl - Clan page URL
 * @param {String} profileUrl - Profile page URL
 * @param {Object} currentStats - Current mode stats
 * @param {Function} formatNumber - Number formatting function
 * @param {Function} formatAccuracy - Accuracy formatting function
 * @param {Function} statusText - Status text getter
 * @param {Function} statusClasses - Status CSS classes getter
 * @param {Function} mouseEnterPanel - Mouse enter handler
 * @param {Function} mouseLeavePanel - Mouse leave handler
 *
 * @component user-profile-hover-panel
 */
Vue.component('user-profile-hover-panel', {
  props: {
    user: { type: Object, required: true },
    statusData: { type: Object, default: null },
    showCountry: { type: Boolean, default: false },
    showClan: { type: Boolean, default: true },
    showBadges: { type: Boolean, default: true },
    showStatus: { type: Boolean, default: true },
    visible: { type: Boolean, default: false },
    interactive: { type: Boolean, default: true },
    avatarUrl: { type: String, required: true },
    bannerUrl: { type: String, required: true },
    flagUrl: { type: String, required: true },
    clanUrl: { type: String, required: true },
    profileUrl: { type: String, required: true },
    currentStats: { type: Object, default: null },
    formatNumber: { type: Function, required: true },
    formatAccuracy: { type: Function, required: true },
    statusText: { type: String, required: true },
    statusClasses: { type: Object, required: true },
    mouseEnterPanel: { type: Function, required: true },
    mouseLeavePanel: { type: Function, required: true }
  },
  created() {
    this.$log.debug('UserProfileHoverPanel', 'Component created', {
      hasUser: !!this.user,
      hasAvatarUrl: !!this.avatarUrl,
      hasBannerUrl: !!this.bannerUrl,
      hasFlagUrl: !!this.flagUrl,
      hasClanUrl: !!this.clanUrl,
      hasProfileUrl: !!this.profileUrl,
      hasCurrentStats: !!this.currentStats,
      avatarUrl: this.avatarUrl,
      bannerUrl: this.bannerUrl,
      flagUrl: this.flagUrl,
      clanUrl: this.clanUrl,
      profileUrl: this.profileUrl
    });
  },
  computed: {
    panelClasses() {
      return {
        'user-profile-panel': true,
        'visible': this.visible,
        'interactive': this.interactive
      };
    }
  },
  template: `
    <div :class="panelClasses"
         @mouseenter="mouseEnterPanel"
         @mouseleave="mouseLeavePanel">
      
      <!-- Panel background -->
      <div class="user-profile-panel-background"
           :style="'background-image: url(' + bannerUrl + ')'"></div>
      
      <!-- Panel header -->
      <div class="user-profile-panel-header">
        <div class="user-profile-panel-avatar"
             :style="'background-image: url(' + avatarUrl + ')'"></div>
        
        <div class="user-profile-panel-info">
          <div class="user-profile-panel-name">
            <span v-if="showClan && user.info.clan_tag" class="user-profile-panel-clan">
              [{{ user.info.clan_tag }}]
            </span>
            {{ user.info.name }}
          </div>
          
          <div v-if="currentStats" class="user-profile-panel-rank">
            <span class="user-profile-panel-global-rank">
              #{{ currentStats.rank || '?' }}
            </span>
            <span v-if="showCountry && user.info.country" class="user-profile-panel-country">
              <img :src="flagUrl" :alt="user.info.country" class="user-flag" />
              #{{ currentStats.country_rank || '?' }}
            </span>
          </div>
          
          <div v-if="showBadges && user.info.badges && user.info.badges.length > 0"
               class="user-profile-panel-badges">
            <badge v-for="badge in user.info.badges"
                   :key="badge.id"
                   :badge="badge"
                   :type="1"></badge>
          </div>
        </div>
      </div>
      
      <!-- Panel stats -->
      <div v-if="currentStats" class="user-profile-panel-stats">
        <div class="user-profile-panel-stat-item">
          <div class="user-profile-panel-stat-value">
            {{ formatNumber(currentStats.pp) || '0' }}
          </div>
          <div class="user-profile-panel-stat-label">PP</div>
        </div>
        
        <div class="user-profile-panel-stat-item">
          <div class="user-profile-panel-stat-value">
            {{ formatAccuracy(currentStats.acc) }}%
          </div>
          <div class="user-profile-panel-stat-label">Accuracy</div>
        </div>
        
        <div class="user-profile-panel-stat-item">
          <div class="user-profile-panel-stat-value">
            {{ formatNumber(currentStats.plays) || '0' }}
          </div>
          <div class="user-profile-panel-stat-label">Plays</div>
        </div>
      </div>
      
      <!-- Panel status -->
      <div v-if="showStatus && statusData" class="user-profile-panel-status" :class="statusClasses">
        <i class="fas fa-circle"></i>
        <span>{{ statusText }}</span>
      </div>
    </div>
  `
});

/**
 * ============================================================================
 * Component: UserProfileUsername
 * ============================================================================
 *
 * Username style component with hover panel.
 *
 * Props:
 * @param {Object} user - User data object
 * @param {Object} statusData - User status data
 * @param {Boolean} showCountry - Whether to show country
 * @param {Boolean} showClan - Whether to show clan tag
 * @param {Boolean} showBadges - Whether to show badges
 * @param {Boolean} showStatus - Whether to show status
 * @param {Boolean} interactive - Whether to enable interactions
 * @param {String} avatarUrl - Avatar image URL
 * @param {String} bannerUrl - Banner image URL
 * @param {String} flagUrl - Flag image URL
 * @param {String} clanUrl - Clan page URL
 * @param {String} profileUrl - Profile page URL
 * @param {Object} currentStats - Current mode stats
 * @param {Boolean} profileVisible - Whether profile panel is visible
 * @param {Function} formatNumber - Number formatting function
 * @param {Function} formatAccuracy - Accuracy formatting function
 * @param {Function} statusText - Status text getter
 * @param {Function} statusClasses - Status CSS classes getter
 * @param {Function} showProfile - Show profile handler
 * @param {Function} hideProfile - Hide profile handler
 * @param {Function} handleUsernameClick - Username click handler
 * @param {Function} handleClanClick - Clan click handler
 *
 * @component user-profile-username
 */
Vue.component('user-profile-username', {
  props: {
    user: { type: Object, required: true },
    statusData: { type: Object, default: null },
    showCountry: { type: Boolean, default: false },
    showClan: { type: Boolean, default: true },
    showBadges: { type: Boolean, default: true },
    showStatus: { type: Boolean, default: true },
    interactive: { type: Boolean, default: true },
    avatarUrl: { type: String, required: true },
    bannerUrl: { type: String, required: true },
    flagUrl: { type: String, required: true },
    clanUrl: { type: String, required: true },
    profileUrl: { type: String, required: true },
    currentStats: { type: Object, default: null },
    profileVisible: { type: Boolean, default: false },
    formatNumber: { type: Function, required: true },
    formatAccuracy: { type: Function, required: true },
    statusText: { type: String, required: true },
    statusClasses: { type: Object, required: true },
    statusString: { type: String, required: true },
    showProfile: { type: Function, required: true },
    hideProfile: { type: Function, required: true },
    handleUsernameClick: { type: Function, required: true },
    handleClanClick: { type: Function, required: true },
    mouseEnterPanel: { type: Function, required: true },
    mouseLeavePanel: { type: Function, required: true }
  },
  created() {
    this.$log.debug('UserProfileUsername', 'Component created', {
      hasUser: !!this.user,
      hasAvatarUrl: !!this.avatarUrl,
      hasBannerUrl: !!this.bannerUrl,
      hasFlagUrl: !!this.flagUrl,
      hasClanUrl: !!this.clanUrl,
      hasProfileUrl: !!this.profileUrl,
      hasCurrentStats: !!this.currentStats,
      avatarUrl: this.avatarUrl,
      bannerUrl: this.bannerUrl,
      flagUrl: this.flagUrl,
      clanUrl: this.clanUrl,
      profileUrl: this.profileUrl
    });
  },
  template: `#user-profile-username-template`
});

/**
 * ============================================================================
 * Component: UserProfileCard
 * ============================================================================
 *
 * Card style component with banner, avatar, stats, and status strip.
 *
 * Props:
 * @param {Object} user - User data object
 * @param {Object} statusData - User status data
 * @param {Boolean} showCountry - Whether to show country
 * @param {Boolean} showClan - Whether to show clan tag
 * @param {Boolean} showBadges - Whether to show badges
 * @param {Boolean} showStatus - Whether to show status
 * @param {Boolean} isLoadingStatus - Whether status is loading
 * @param {String} avatarUrl - Avatar image URL
 * @param {String} bannerUrl - Banner image URL
 * @param {String} flagUrl - Flag image URL
 * @param {String} clanUrl - Clan page URL
 * @param {String} profileUrl - Profile page URL
 * @param {Object} currentStats - Current mode stats
 * @param {Function} formatNumber - Number formatting function
 * @param {Function} formatAccuracy - Accuracy formatting function
 * @param {Function} statusText - Status text getter
 * @param {Function} statusClasses - Status CSS classes getter
 *
 * @component user-profile-card
 */
Vue.component('user-profile-card', {
  props: {
    user: { type: Object, required: true },
    statusData: { type: Object, default: null },
    showCountry: { type: Boolean, default: true },
    showClan: { type: Boolean, default: true },
    showBadges: { type: Boolean, default: true },
    showStatus: { type: Boolean, default: true },
    isLoadingStatus: { type: Boolean, default: false },
    avatarUrl: { type: String, required: true },
    bannerUrl: { type: String, required: true },
    flagUrl: { type: String, required: true },
    clanUrl: { type: String, required: true },
    profileUrl: { type: String, required: true },
    currentStats: { type: Object, default: null },
    formatNumber: { type: Function, required: true },
    formatAccuracy: { type: Function, required: true },
    statusText: { type: String, required: true },
    statusClasses: { type: Object, required: true },
    statusString: { type: String, required: true }
  },
  created() {
    this.$log.debug('UserProfileCard', 'Component created', {
      hasUser: !!this.user,
      hasAvatarUrl: !!this.avatarUrl,
      hasBannerUrl: !!this.bannerUrl,
      hasFlagUrl: !!this.flagUrl,
      hasClanUrl: !!this.clanUrl,
      hasProfileUrl: !!this.profileUrl,
      hasCurrentStats: !!this.currentStats,
      avatarUrl: this.avatarUrl,
      bannerUrl: this.bannerUrl,
      flagUrl: this.flagUrl,
      clanUrl: this.clanUrl,
      profileUrl: this.profileUrl
    });
  },
  template: `#user-profile-card-template`
});

/**
 * ============================================================================
 * Component: UserProfileSearch
 * ============================================================================
 *
 * Search style component for compact display in lists.
 *
 * Props:
 * @param {Object} user - User data object
 * @param {Boolean} showCountry - Whether to show country
 * @param {Boolean} showClan - Whether to show clan tag
 * @param {String} avatarUrl - Avatar image URL
 * @param {String} flagUrl - Flag image URL
 * @param {String} clanUrl - Clan page URL
 * @param {String} profileUrl - Profile page URL
 * @param {Object} currentStats - Current mode stats
 * @param {Function} formatNumber - Number formatting function
 * @param {Function} formatAccuracy - Accuracy formatting function
 *
 * @component user-profile-search
 */
Vue.component('user-profile-search', {
  props: {
    user: { type: Object, required: true },
    showCountry: { type: Boolean, default: false },
    showClan: { type: Boolean, default: true },
    avatarUrl: { type: String, required: true },
    bannerUrl: { type: String, required: false },
    flagUrl: { type: String, required: true },
    clanUrl: { type: String, required: true },
    profileUrl: { type: String, required: true },
    currentStats: { type: Object, default: null },
    formatNumber: { type: Function, required: true },
    formatAccuracy: { type: Function, required: true }
  },
  created() {
    this.$log.debug('UserProfileSearch', 'Component created', {
      hasUser: !!this.user,
      hasAvatarUrl: !!this.avatarUrl,
      hasFlagUrl: !!this.flagUrl,
      hasClanUrl: !!this.clanUrl,
      hasProfileUrl: !!this.profileUrl,
      hasCurrentStats: !!this.currentStats,
      avatarUrl: this.avatarUrl,
      flagUrl: this.flagUrl,
      clanUrl: this.clanUrl,
      profileUrl: this.profileUrl
    });
  },
  template: `#user-profile-search-template`
});

/**
 * ============================================================================
 * Component: User-Profile (Master Component)
 * ============================================================================
 *
 * Master component that orchestrates sub-components for different display styles.
 *
 * Features:
 * - Multiple display styles: username, card, search
 * - Automatic data fetching when only userid is provided
 * - Dynamic name formatting: [country] [clan] [username]
 * - Status fetching from API
 * - Badge display with popups
 * - Clan tag linking (future: clan flag/image display)
 * - Username linking to profile page
 * - Optional country display
 *
 * Props:
 * @param {Object} user - User data object (optional if userid provided)
 * @param {String} userid - User ID to fetch data from (required if no user prop)
 * @param {String} displayStyle - Display style: 'username', 'card', or 'search' (default: 'username')
 * @param {Boolean} showCountry - Whether to show country in name display (default: false)
 * @param {Boolean} showClan - Whether to show clan tag (default: true)
 * @param {Boolean} showBadges - Whether to show badges (default: true)
 * @param {Boolean} showStatus - Whether to show user status (default: true)
 * @param {Boolean} interactive - Whether to enable hover/click interactions (default: true)
 * @param {String} domain - API domain (default: 'kawata.pw')
 *
 * Usage Examples:
 *
 * <!-- Username style (default) - shows just the username as a link -->
 * <user-profile userid="12345" display-style="username" />
 *
 * <!-- Card style - shows banner, avatar, stats, and status -->
 * <user-profile :user="userData" display-style="card" showCountry showBadges />
 *
 * <!-- Search style - compact display for search results -->
 * <user-profile :user="userData" display-style="search" />
 *
 * <!-- With only userid (fetches data automatically) -->
 * <user-profile userid="12345" display-style="card" showCountry showClan showBadges showStatus />
 *
 * @component user-profile
 */

/**
 * ============================================================================
 * Component: User-Profile (Master Component)
 * ============================================================================
 *
 * Master component that orchestrates sub-components for different display styles.
 *
 * Features:
 * - Multiple display styles: username, card, search
 * - Automatic data fetching when only userid is provided
 * - Dynamic name formatting: [country] [clan] [username]
 * - Status fetching from API
 * - Badge display with popups
 * - Clan tag linking (future: clan flag/image display)
 * - Username linking to profile page
 * - Optional country display
 *
 * Props:
 * @param {Object} user - User data object (optional if userid provided)
 * @param {String} userid - User ID to fetch data from (required if no user prop)
 * @param {String} displayStyle - Display style: 'username', 'card', or 'search' (default: 'username')
 * @param {Boolean} showCountry - Whether to show country in name display (default: false)
 * @param {Boolean} showClan - Whether to show clan tag (default: true)
 * @param {Boolean} showBadges - Whether to show badges (default: true)
 * @param {Boolean} showStatus - Whether to show user status (default: true)
 * @param {Boolean} interactive - Whether to enable hover/click interactions (default: true)
 * @param {String} domain - API domain (default: 'kawata.pw')
 *
 * Usage Examples:
 *
 * <!-- Username style (default) - shows just the username as a link -->
 * <user-profile userid="12345" display-style="username" />
 *
 * <!-- Card style - shows banner, avatar, stats, and status -->
 * <user-profile :user="userData" display-style="card" showCountry showBadges />
 *
 * <!-- Search style - compact display for search results -->
 * <user-profile :user="userData" display-style="search" />
 *
 * <!-- With only userid (fetches data automatically) -->
 * <user-profile userid="12345" display-style="card" showCountry showClan showBadges showStatus />
 *
 * @component user-profile
 */
Vue.component('user-profile', {
  props: {
    /**
     * User data object (optional if userid provided)
     * @type {Object}
     */
    user: { type: Object, default: null },
    
    /**
     * User ID to fetch data from (required if no user prop)
     * @type {String|Number}
     */
    userid: { type: [String, Number], default: null },
    
    /**
     * Display style: 'username', 'card', or 'search'
     * @type {String}
     * @default 'username'
     */
    displayStyle: {
      type: String,
      default: 'username',
      validator: function(value) {
        return ['username', 'card', 'search'].includes(value);
      }
    },
    
    /**
     * Whether to show country in name display
     * @type {Boolean}
     * @default false
     */
    showCountry: { type: Boolean, default: false },
    
    /**
     * Whether to show clan tag
     * @type {Boolean}
     * @default true
     */
    showClan: { type: Boolean, default: true },
    
    /**
     * Whether to show badges
     * @type {Boolean}
     * @default true
     */
    showBadges: { type: Boolean, default: true },
    
    /**
     * Whether to show user status
     * @type {Boolean}
     * @default true
     */
    showStatus: { type: Boolean, default: true },
    
    /**
     * Whether to enable hover/click interactions
     * @type {Boolean}
     * @default true
     */
    interactive: { type: Boolean, default: true },
    
    /**
     * API domain
     * @type {String}
     * @default 'kawata.pw'
     */
    domain: { type: String, default: domain || 'kawata.pw' }
  },
  
  data: function() {
    return {
      // Internal user data (fetched if only userid provided)
      internalUser: null,
      
      // Loading states
      isLoadingUser: false,
      isLoadingStatus: false,
      
      // Status data
      statusData: null,
      
      // UI state
      profileVisible: false,
      
      // Mouse tracking for hover panel
      mouseOverPanel: false,
      
      // Error state
      error: null,
      
      // Interval for periodic status checking
      statusInterval: null
    };
  },
  
  computed: {
    /**
     * Get the user data to use (internal or prop)
     */
    userData() {
      return this.internalUser || this.user;
    },
    
    /**
     * Normalized user data in standard format
     */
    normalizedUserData() {
      return this.normalizeUser(this.userData);
    },
    
    /**
     * Check if we have user data
     */
    hasUserData() {
      return this.userData !== null && this.userData !== undefined;
    },
    
    /**
     * Check if we have full user data (not just leaderboard)
     */
    isFullData() {
      return this.normalizedUserData && this.normalizedUserData.info && this.normalizedUserData.stats;
    },
    
    /**
     * Get current mode stats
     * Handles multiple possible data structures from API
     */
    currentStats() {
      if (!this.normalizedUserData) {
        this.$log.debug('UserProfile', 'No userData for currentStats');
        return null;
      }
      
      // Try stats.current first (new structure)
      if (this.normalizedUserData.stats?.current) {
        const firstMode = Object.keys(this.normalizedUserData.stats.current)[0];
        const stats = this.normalizedUserData.stats.current[firstMode] || null;
        this.$log.debug('UserProfile', 'Current stats (stats.current)', { firstMode, stats });
        return stats;
      }
      
      // Try stats directly (old structure) - use preferred_mode to get the right stats
      if (this.normalizedUserData.stats) {
        const preferredMode = this.normalizedUserData.info?.preferred_mode || 0;
        const stats = this.normalizedUserData.stats[preferredMode] || null;
        this.$log.debug('UserProfile', 'Current stats (direct stats)', { preferredMode, stats });
        return stats;
      }
      
      this.$log.debug('UserProfile', 'No stats found', { userData: this.normalizedUserData });
      return null;
    },
    
    /**
     * Get avatar URL
     * Handles multiple possible ID field names from API
     */
    avatarUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('UserProfile', 'No userData for avatarUrl');
        return '';
      }
      
      // Try multiple possible ID field names
      const userId = this.normalizedUserData.info.id || this.normalizedUserData.player_id || this.normalizedUserData.id || this.normalizedUserData.user_id;
      this.$log.debug('UserProfile', 'Avatar URL', {
        userId,
        player_id: this.normalizedUserData.player_id,
        id: this.normalizedUserData.id,
        user_id: this.normalizedUserData.user_id,
        domain: this.domain
      });
      
      if (!userId) {
        this.$log.error('UserProfile', 'No userId found for avatar', { userData: this.normalizedUserData });
        return '';
      }
      
      return `https://a.${this.domain}/${userId}`;
    },
    
    /**
     * Get banner URL
     * Handles multiple possible ID field names from API
     */
    bannerUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('UserProfile', 'No userData for bannerUrl');
        return '';
      }
      
      // Try multiple possible ID field names
      const userId = this.normalizedUserData.info.id || this.normalizedUserData.player_id || this.normalizedUserData.id || this.normalizedUserData.user_id;
      this.$log.debug('UserProfile', 'Banner URL', {
        userId,
        player_id: this.normalizedUserData.player_id,
        id: this.normalizedUserData.id,
        user_id: this.normalizedUserData.user_id
      });
      
      if (!userId) {
        this.$log.error('UserProfile', 'No userId found for banner', { userData: this.normalizedUserData });
        return '';
      }
      
      return `/banners/${userId}`;
    },

    /**
     * Get banner URL
     * Handles multiple possible ID field names from API
     */
    backgroundUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('UserProfile', 'No userData for bannerUrl');
        return '';
      }
      
      // Try multiple possible ID field names
      const userId = this.normalizedUserData.info.id || this.normalizedUserData.player_id || this.normalizedUserData.id || this.normalizedUserData.user_id;
      this.$log.debug('UserProfile', 'Banner URL', {
        userId,
        player_id: this.normalizedUserData.player_id,
        id: this.normalizedUserData.id,
        user_id: this.normalizedUserData.user_id
      });
      
      if (!userId) {
        this.$log.error('UserProfile', 'No userId found for banner', { userData: this.normalizedUserData });
        return '';
      }
      
      return `/backgrounds/${userId}`;
    },
    
    /**
     * Get flag URL
     * Handles country field in multiple possible locations
     */
    flagUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('UserProfile', 'No userData for flagUrl');
        return '';
      }
      
      // Try country in info first, then at root level
      const country = this.normalizedUserData.info?.country || this.normalizedUserData.country;
      this.$log.debug('UserProfile', 'Flag URL', {
        country,
        infoCountry: this.normalizedUserData.info?.country,
        rootCountry: this.normalizedUserData.country
      });
      
      if (!country) {
        this.$log.debug('UserProfile', 'No country found', { userData: this.normalizedUserData });
        return '';
      }
      
      return `/static/images/flags/${country.toUpperCase()}.png`;
    },
    
    /**
     * Get clan URL
     * Handles clan_id field in multiple possible locations
     */
    clanUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('UserProfile', 'No userData for clanUrl');
        return '';
      }
      
      // Try clan_id in info first, then at root level
      const clanId = this.normalizedUserData.info?.clan_id || this.normalizedUserData.clan_id;
      this.$log.debug('UserProfile', 'Clan URL', {
        clanId,
        infoClanId: this.normalizedUserData.info?.clan_id,
        rootClanId: this.normalizedUserData.clan_id
      });
      
      if (!clanId) {
        this.$log.debug('UserProfile', 'No clan_id found', { userData: this.normalizedUserData });
        return '';
      }
      
      return `/clans/${clanId}`;
    },
    
    /**
     * Get profile URL
     * Handles multiple possible ID field names from API
     */
    profileUrl() {
      if (!this.normalizedUserData) {
        this.$log.debug('UserProfile', 'No userData for profileUrl');
        return '';
      }
      
      // Try multiple possible ID field names
      const userId = this.normalizedUserData.info.id || this.normalizedUserData.player_id || this.normalizedUserData.id || this.normalizedUserData.user_id;
      this.$log.debug('UserProfile', 'Profile URL', {
        userId,
        player_id: this.normalizedUserData.player_id,
        id: this.normalizedUserData.id,
        user_id: this.normalizedUserData.user_id
      });
      
      if (!userId) {
        this.$log.error('UserProfile', 'No userId found for profile', { userData: this.normalizedUserData });
        return '';
      }
      
      return `/u/${userId}`;
    },
    
    /**
     * Status text getter
     */
    statusText() {
      if (!this.statusData || this.statusData.online === 'false' || this.statusData.online === false) {
        if (this.statusData && this.statusData.last_seen) {
          return `Offline | Last seen ${this.formatTimeAgo(this.statusData.last_seen)}`;
        }
        return 'Offline';
      }
      
      // Check if status object exists
      if (!this.statusData.status) {
        return 'Online';
      }
      
      // Use actionIntToStr from profile.js logic
      const action = this.statusData.status.action;
      const infoText = this.statusData.status.info_text;
      
      switch (action) {
        case 0:
          return 'Idle: 🔍 Song Select';
        case 1:
          return '🌙 AFK';
        case 2:
          return `Playing: 🎶 ${infoText}`;
        case 3:
          return `Editing: 🔨 ${infoText}`;
        case 4:
          return `Modding: 🔨 ${infoText}`;
        case 5:
          return 'In Multiplayer: Song Select';
        case 6:
          return `Watching: 👓 ${infoText}`;
        // 7 not used
        case 8:
          return `Testing: 🎾 ${infoText}`;
        case 9:
          return `Submitting: 🧼 ${infoText}`;
        // 10 paused, never used
        case 11:
          return 'Idle: 🏢 In multiplayer lobby';
        case 12:
          return `In Multiplayer: Playing 🌍 ${infoText} 🎶`;
        case 13:
          return 'Idle: 🔍 Searching for beatmaps in osu!direct';
        default:
          return 'Unknown: 🚔 not yet implemented!';
      }
    },
    
    /**
     * Status CSS classes getter
     */
    statusClasses() {
      if (!this.statusData || this.statusData.online === 'false' || this.statusData.online === false) return { 'offline': true };
      
      // Check if status object exists
      if (!this.statusData.status) return { 'online': true };
      
      const action = this.statusData.status.action;
      
      if (action === 2 || action === 9) return { 'playing': true };
      if (action === 8) return { 'paused': true };
      if (action === 0) return { 'idle': true };
      if (action === 1) return { 'afk': true };
      
      return { 'online': true };
    },
    
    /**
     * Status string getter for CSS variable
     * Returns the status name as a string (e.g., "playing", "offline")
     */
    statusString() {
      if (!this.statusData || this.statusData.online === 'false' || this.statusData.online === false) return 'offline';
      
      // Check if status object exists
      if (!this.statusData.status) return 'online';
      
      const action = this.statusData.status.action;
      
      if (action === 2 || action === 9) return 'playing';
      if (action === 8) return 'paused';
      if (action === 0) return 'idle';
      if (action === 1) return 'afk';
      
      return 'online';
    },
    
    /**
     * Format accuracy
     */
    formatAccuracy() {
      return (acc) => {
        if (!acc) return '0.00';
        return parseFloat(acc).toFixed(2);
      };
    },
    
    /**
     * Format number
     */
    formatNumber() {
      return (num) => {
        if (!num) return '0';
        return num.toLocaleString();
      };
    }
  },
  
  watch: {
    /**
     * Watch for user prop changes
     */
    user: {
      handler: function(newUser) {
        if (newUser && !this.internalUser) {
          // Reset internal user if new user prop is provided
          this.internalUser = null;
          this.statusData = null;
          this.error = null;
          
          // Fetch status if needed
          if (this.showStatus) {
            this.fetchStatus();
          }
        }
      },
      deep: true
    },
    
    /**
     * Watch for userid changes
     */
    userid: {
      handler: function(newUserid) {
        if (newUserid && !this.user) {
          // Fetch user data if only userid is provided
          this.fetchUserData();
        }
      }
    },
    
    /**
     * Watch for showStatus changes
     */
    showStatus: {
      handler: function(newVal) {
        this.$log.debug('UserProfile', 'showStatus changed', { newVal, hasNormalizedUserData: !!this.normalizedUserData });
        if (newVal && this.normalizedUserData) {
          this.fetchStatus();
          this.startStatusInterval();
        } else {
          this.stopStatusInterval();
        }
      }
    }
  },
  
  created() {
    this.$log = ColorfulLogger.child('Comp | User Profile');
    this.$log.debug('UserProfile', 'Component created', {
      userid: this.userid,
      hasUser: !!this.user,
      showStatus: this.showStatus,
      hasUserData: !!this.userData,
      userData: this.userData
    });
    
    // Fetch user data if only userid is provided
    if (this.userid && !this.user) {
      this.$log.debug('UserProfile', 'Fetching user data (userid provided, no user prop)', { userid: this.userid });
      this.fetchUserData();
    } else if (this.userid && this.user) {
      this.$log.debug('UserProfile', 'Both userid and user provided, using user prop', { userid: this.userid });
    } else if (!this.userid && this.user) {
      this.$log.debug('UserProfile', 'Only user prop provided');
    } else {
      this.$log.debug('UserProfile', 'No userid or user provided');
    }
    
    // Fetch status if needed (when user prop is provided directly)
    if (this.showStatus && this.normalizedUserData) {
      this.$log.debug('UserProfile', 'Starting initial status fetch and interval');
      this.fetchStatus();
      this.startStatusInterval();
    }
  },
  
  beforeDestroy() {
    // Clean up interval when component is destroyed
    this.stopStatusInterval();
  },
  
  methods: {
    /**
     * Normalize user data to standard format
     */
    normalizeUser(user) {
      if (!user) return null;
      
      const normalized = { ...user };
      
      // Ensure info object exists
      if (!normalized.info) {
        normalized.info = {
          id: normalized.player_id || normalized.id,
          name: normalized.name,
          country: normalized.country,
          clan_id: normalized.clan_id,
          clan_tag: normalized.clan_tag,
          badges: normalized.badges || [],
          preferred_mode: 0, // default
        };
      }
      
      // Ensure stats object exists
      if (!normalized.stats) {
        normalized.stats = {
          current: {
            0: {
              pp: normalized.pp,
              acc: normalized.acc,
              plays: normalized.plays,
              tscore: normalized.tscore,
              rscore: normalized.rscore,
              playtime: normalized.playtime,
              max_combo: normalized.max_combo,
              total_hits: normalized.total_hits,
              replay_views: normalized.replay_views,
              xh_count: normalized.xh_count,
              x_count: normalized.x_count,
              sh_count: normalized.sh_count,
              s_count: normalized.s_count,
              a_count: normalized.a_count,
              rank: normalized.rank,
              country_rank: normalized.country_rank,
            }
          }
        };
      }
      
      return normalized;
    },
    
    /**
     * Get user ID from user data
     */
    getUserId() {
      if (!this.userData) return null;
      return this.userData.info?.id || this.userData.player_id || this.userData.id;
    },
    
    /**
     * Fetch user data from API
     */
    async fetchUserData() {
      if (!this.userid || this.isLoadingUser) {
        this.$log.debug('UserProfile', 'fetchUserData early return', {
          hasUserid: !!this.userid,
          isLoadingUser: this.isLoadingUser
        });
        return;
      }
      
      this.isLoadingUser = true;
      this.error = null;
      
      this.$log.debug('UserProfile', 'fetchUserData starting');
      
      try {
        const response = await fetch(
          `${window.location.protocol}//api.${this.domain}/v1/get_player_info?id=${this.userid}&scope=all`
        );
        
        if (!response.ok) {
          throw new Error(`API request failed with status ${response.status}`);
        }
        
        const data = await response.json();
        
        this.$log.debug('API', 'Raw API response:', data);
        
        if (data.status === 'success' && data.player) {
          this.internalUser = data.player;
          this.$log.debug('API', 'User data loaded:', data.player);
          this.$log.debug('API', 'User data structure:', {
            hasPlayerId: data.player.hasOwnProperty('player_id'),
            hasId: data.player.hasOwnProperty('id'),
            playerIdValue: data.player.player_id,
            idValue: data.player.id,
            hasInfo: data.player.hasOwnProperty('info'),
            hasStats: data.player.hasOwnProperty('stats'),
            infoStructure: data.player.info,
            statsStructure: data.player.stats
          });
          
          // Fetch status if needed
          if (this.showStatus) {
            this.$log.debug('UserProfile', 'Fetching status after user data loaded');
            await this.fetchStatus();
            // Start periodic status checking after fetching user data
            this.$log.debug('UserProfile', 'Starting status interval after user data loaded');
            this.startStatusInterval();
          }
        } else {
          throw new Error('No user data found');
        }
      } catch (error) {
        this.$log.error('API', 'Error fetching user data:', error);
        this.error = error.message;
      } finally {
        this.isLoadingUser = false;
        this.$log.debug('UserProfile', 'fetchUserData completed');
      }
    },
    
    /**
     * Fetch user status from API
     */
    async fetchStatus() {
      if (!this.normalizedUserData || this.isLoadingStatus) {
        this.$log.debug('UserProfile', 'fetchStatus early return', {
          hasNormalizedUserData: !!this.normalizedUserData,
          isLoadingStatus: this.isLoadingStatus
        });
        return;
      }
      
      const userId = this.normalizedUserData.info.id;
      if (!userId) {
        this.$log.debug('UserProfile', 'fetchStatus early return - no userId');
        return;
      }
      
      this.isLoadingStatus = true;
      
      this.$log.debug('UserProfile', 'fetchStatus starting');
      
      try {
        const response = await fetch(
          `${window.location.protocol}//api.${this.domain}/v1/get_player_status?id=${userId}`
        );
        
        if (!response.ok) {
          throw new Error(`API request failed with status ${response.status}`);
        }
        
        const data = await response.json();
        
        if (data.status === 'success') {
          const oldStatus = this.statusData;
          this.statusData = data.player_status;
          this.$log.debug('API', 'Status data loaded:', data);
          this.$log.debug('UserProfile', 'Status data changed', { 
            oldStatus, 
            newStatus: this.statusData,
            online: this.statusData?.online,
            hasStatus: !!this.statusData?.status
          });
        } else {
          this.statusData = null;
          this.$log.warn('API', 'No status data found in response', data);
        }
      } catch (error) {
        this.$log.error('API', 'Error fetching status:', error);
        this.statusData = null;
      } finally {
        this.isLoadingStatus = false;
        this.$log.debug('UserProfile', 'fetchStatus completed');
      }
    },
    
    /**
     * Start periodic status checking
     */
    startStatusInterval() {
      // Clear any existing interval
      this.stopStatusInterval();
      
      this.$log.debug('UserProfile', 'Starting status interval');
      
      // Check status every 30 seconds
      this.statusInterval = setInterval(() => {
        this.$log.debug('UserProfile', 'Status interval tick', {
          hasNormalizedUserData: !!this.normalizedUserData,
          showStatus: this.showStatus,
          hasInterval: !!this.statusInterval
        });
        if (this.normalizedUserData && this.showStatus) {
          this.$log.debug('UserProfile', 'Fetching status due to interval');
          this.fetchStatus();
        }
      }, 30000);
    },
    
    /**
     * Stop periodic status checking
     */
    stopStatusInterval() {
      if (this.statusInterval) {
        clearInterval(this.statusInterval);
        this.statusInterval = null;
      }
    },
    
    /**
     * Show profile panel (for username style)
     */
    showProfile() {
      if (!this.interactive) return;
      
      // Lazy load full user data if not available
      if (!this.isFullData) {
        const userId = this.getUserId();
        if (userId && !this.userid) {
          this.userid = userId;
        }
        if (this.userid && !this.isLoadingUser) {
          this.fetchUserData();
        }
      }
      
      this.profileVisible = true;
    },
    
    /**
     * Hide profile panel (for username style)
     */
    hideProfile() {
      if (!this.interactive) return;
      // Only hide if not hovering over the panel
      if (!this.mouseOverPanel) {
        this.profileVisible = false;
      }
    },
    
    /**
     * Mouse enter panel handler
     */
    mouseEnterPanel() {
      this.mouseOverPanel = true;
    },
    
    /**
     * Mouse leave panel handler
     */
    mouseLeavePanel() {
      this.mouseOverPanel = false;
      this.profileVisible = false;
    },
    

    /**
     * Formats a date string or Unix timestamp to a "time ago" string.
     * @param {string|number} dateString - The date string from your score object (e.g., '2023-01-10T14:59:00Z') or Unix timestamp in seconds.
     * @returns {string} - A human-readable "time ago" string.
     */
    formatTimeAgo(dateString) {
        // Check if it's a Unix timestamp (number in seconds)
        let date;
        if (typeof dateString === 'number' || /^\d+$/.test(dateString)) {
            // Convert Unix timestamp (seconds) to milliseconds
            date = new Date(dateString * 1000);
        } else {
            // Treat as date string
            date = new Date(dateString);
        }
        
        const now = new Date();
        const seconds = Math.floor((now - date) / 1000);

        let interval = seconds / 31536000;
        if (interval >= 1) {
            const years = Math.floor(interval);
            return years === 1 ? "1 year ago" : years + " years ago";
        }
        
        interval = seconds / 2592000;
        if (interval >= 1) {
            const months = Math.floor(interval);
            return months === 1 ? "1 month ago" : months + " months ago";
        }
        
        interval = seconds / 86400;
        if (interval >= 1) {
            const days = Math.floor(interval);
            return days === 1 ? "1 day ago" : days + " days ago";
        }
        
        interval = seconds / 3600;
        if (interval >= 1) {
            const hours = Math.floor(interval);
            return hours === 1 ? "1 hour ago" : hours + " hours ago";
        }
        
        interval = seconds / 60;
        if (interval >= 1) {
            const minutes = Math.floor(interval);
            return minutes === 1 ? "1 minute ago" : minutes + " minutes ago";
        }
        
        return Math.floor(seconds) + " seconds ago";
    },
    

    
    /**
     * Handle username click
     */
    handleUsernameClick(event) {
      if (!this.interactive) return;
      // Allow default navigation
    },
    
    /**
     * Handle clan click
     */
    handleClanClick(event) {
      if (!this.interactive) return;
      // Allow default navigation
    }
  },
  
  template: `#user-profile-template`
});

Vue.component('score-card', {
  delimiters: ["<%", "%>"],
  props: {
    score: {
      type: Object,
      required: true
    }
  },
  created () {
    this.$log = ColorfulLogger.child('Comp | Score Card');
  },
  methods: {
    formatNumber(num) {
      if (!num) return '0';
      num += '';
      var x = num.split('.');
      var x1 = x[0];
      var x2 = x.length > 1 ? '.' + x[1] : '';
      var rgx = /(\d+)(\d{3})/;
      while (rgx.test(x1)) {
        x1 = x1.replace(rgx, '$1' + ',' + '$2');
      }
      return x1 + x2;
    },
    DisplayCheats(obj) {
      if (!obj) return '';
      
      let htmlString = '';
      if (obj.RelaxHack === true) htmlString += `<div>Relax</div>`;
      if (obj.ARChanger === true & obj.ARChangerAR) htmlString += `<div>AR: ${obj.ARChangerAR.toFixed(2)}</div>`;
      if (obj.Timewarp === true) {
        if (obj.TimewarpRate || obj.TimewarpType == 'Rate') htmlString += `<div>TW: ${obj.TimewarpRate}%</div>`
        else if (obj.TimewarpMultiplier || obj.TimewarpType == 'Multiplier') htmlString += `<div>TW: ${obj.TimewarpMultiplier}x</div>`
      }
      if (obj.AimType) {
        if (obj.AimType == 'Correction' || obj.AimCorrectionValue)
          if (obj.AimCorrectionRelative === true) htmlString += `<div>AC: CS + ${obj.AimCorrectionValue}</div>`
          else htmlString += `<div>AC: ${obj.AimCorrectionValue}</div>`
          if (obj.TapOnCorrect === true) htmlString += `<div>AC: TOC</div>`
        if (obj.AimType == 'OBAA') {
          htmlString += `<div>AA: OsuBuddy</div>`
        }
        if (obj.AimType == 'MapleAA') {
          htmlString += `<div class="maple-settings" onmouseover="showMaplePopup(event, this)" onmouseout="hideMaplePopup()">
            Maple AA: ${this.MAAIntToStr(obj.Algorithm)}
            <div class="maple-popup">
              ${this.generateMapleSettingsHTML(obj)}
            </div>
          </div>`;
        }
      }
      if (obj.HiddenRemover === true) htmlString += `<div>No HD</div>`;
      if (obj.FlashlightRemover === true) htmlString += `<div>No FL</div>`;
      this.$log.debug("Score", `Displaying score card for score: ${this.score.id}`, this.score);
      return htmlString;
    },
    MAAIntToStr(int) {
      switch (int) {
        case 0:
          return 'V1';
        case 1:
          return 'V2';
        case 2:
          return 'V3';
        case 3:
          return 'V-L1';
      }
    },
    generateMapleSettingsHTML(obj) {
      const iconMap = {
        // Aiming & FOV
        FOV_Base: '🎯',
        FOV_Min: '📍',
        FOV_Max: '🎪',
        MaxOffset: '📏',

        // Strength Settings
        BaseStrength: '💪',
        Power: '⚡',
        AimStrength: '🎯',
        ResyncStrength: '🔄',
        SliderPower: '⚡',

        // Movement & Prediction
        PredictiveAiming: '🔮',
        PredictionMs: '⏱️',
        MovementSmoothing: '🌊',
        MovementThreshold: '📊',

        // Proximity & Timing
        MinProximityStrength: '📉',
        MaxProximityStrength: '📈',
        MinTimingStrength: '⏰',
        MaxTimingStrength: '⚡',

        // Slider Handling
        EnhancedSliderHandling: '🎚️',
        SliderProgressionScale: '📐',
        MinSliderStrength: '🔽',
        MaxSliderStrength: '🔼',
        AssistOnSliders: '🛷',

        // Angle Settings
        AngleInfluence: '📐',
        MaxAngleInfluence: '📏',
        MinAngleStrength: '↘️',
        MaxAngleStrength: '↗️',

        // Acceleration
        UseAcceleration: '🚀',
        AccelerationExponent: '📈',
        AccelFactor: '🏃'
      };
    
      let settingsHTML = '<div class="settings-grid">';
      
      // Generate settings based on algorithm version
      switch(obj.Algorithm) {
        case 0: // V1
          settingsHTML += this.generateSettingItem('FOV_Base', obj.FOV_Base, iconMap);
          settingsHTML += this.generateSettingItem('FOV_Min', obj.FOV_Min, iconMap);
          settingsHTML += this.generateSettingItem('FOV_Max', obj.FOV_Max, iconMap);
          settingsHTML += this.generateSettingItem('AimStrength', obj.AimStrength, iconMap);
          settingsHTML += this.generateSettingItem('AccelFactor', obj.AccelFactor, iconMap);
          break;
        
        case 1: // V2
          settingsHTML += this.generateSettingItem('Power', obj.Power, iconMap);
          settingsHTML += this.generateSettingItem('AssistOnSliders', obj.AssistOnSliders, iconMap);
          break;
        
        case 2: // V3
          settingsHTML += this.generateSettingItem('Power', obj.Power, iconMap);
          settingsHTML += this.generateSettingItem('SliderPower', obj.SliderPower, iconMap);
          break;
        case 3: // VL1
          const vl1Settings = [
            'FOV_Base', 'FOV_Min', 'FOV_Max', 'MaxOffset', 'FovDynamicScale', 'FovScaleMin', 'FovScaleMax', 'PreemptScale', 'MovementSmoothing', 'MovementThreshold',
            'BaseStrength', 'ResyncStrength', 'MinProximityStrength', 'MaxProximityStrength', 'MinTimingStrength', 'MaxTimingStrength'
          ];

          // Add base settings
          vl1Settings.forEach(setting => {
            if (obj[setting] !== undefined) {
              settingsHTML += this.generateSettingItem(setting, obj[setting], iconMap);
            }
          });
        
          // Handle Grouped Settings
          if (obj.PredictiveAiming !== undefined) {
            settingsHTML += this.generateSettingItem('PredictiveAiming', obj.PredictiveAiming, iconMap);
            if (obj.PredictiveAiming === true && obj.PredictionMs !== undefined) {
              settingsHTML += this.generateSettingItem('PredictionMs', obj.PredictionMs, iconMap);
            }
          }
          if (obj.EnhancedSliderHandling !== undefined) {
            settingsHTML += this.generateSettingItem('EnhancedSliderHandling', obj.EnhancedSliderHandling, iconMap);
            if (obj.EnhancedSliderHandling === true) {
              if (obj.SliderProgressionScale !== undefined) settingsHTML += this.generateSettingItem('SliderProgressionScale', obj.SliderProgressionScale, iconMap);
              if (obj.MinSliderStrength !== undefined) settingsHTML += this.generateSettingItem('MinSliderStrength', obj.MinSliderStrength, iconMap);
              if (obj.MaxSliderStrength !== undefined) settingsHTML += this.generateSettingItem('MaxSliderStrength', obj.MaxSliderStrength, iconMap);
            }
          }
          if (obj.AngleInfluence !== undefined) {
            settingsHTML += this.generateSettingItem('AngleInfluence', obj.AngleInfluence, iconMap);
            if (obj.AngleInfluence === true) {
              if (obj.MaxAngleInfluence !== undefined) settingsHTML += this.generateSettingItem('MaxAngleInfluence', obj.MaxAngleInfluence, iconMap);
              if (obj.MinAngleStrength !== undefined) settingsHTML += this.generateSettingItem('MinAngleStrength', obj.MinAngleStrength, iconMap);
              if (obj.MaxAngleStrength !== undefined) settingsHTML += this.generateSettingItem('MaxAngleStrength', obj.MaxAngleStrength, iconMap);
            }
          }
          if (obj.UseAcceleration !== undefined) {
            settingsHTML += this.generateSettingItem('UseAcceleration', obj.UseAcceleration, iconMap);
            if (obj.UseAcceleration === true) {
              if (obj.AccelerationExponent !== undefined) settingsHTML += this.generateSettingItem('AccelerationExponent', obj.AccelerationExponent, iconMap);
            }
          }
          break;
      }
      
      settingsHTML += '</div>';
      return settingsHTML;
    },
    
    generateSettingItem(name, value, iconMap) {
      const icon = iconMap[name] || '⚙️';
      return `
        <div class="setting-item">
          <span class="setting-name">${this.formatSettingName(name)}</span>
          <span class="setting-icon">${icon}</span>
          <span class="setting-value">${this.formatSettingValue(value)}</span>
        </div>
      `;
    },
    
    formatSettingName(name) {
      return name.split('_').join(' ').replace(/([A-Z])/g, ' $1').trim();
    },
    
    formatSettingValue(value) {
      if (typeof value === 'boolean') return value ? 'On' : 'Off';
      if (typeof value === 'number') return value.toFixed(2);
      return value;
    }
  },
  template: `#score-card-template`
});

Vue.component('score-list', {
  props: {
    scores: {
      type: Array,
      required: true
    },
    loading: {
      type: Boolean,
      default: false
    },
    showMore: {
      type: Boolean,
      default: false
    },
    title: {
      type: String,
      default: 'Scores'
    },
    emptyMessage: {
      type: String,
      default: 'No scores available'
    },
    emptySubMessage: {
      type: String,
      default: 'Try playing a map and submitting your score!'
    }
  },
  methods: {
    loadMore() {
      this.$emit('load-more');
    }
  },
  template: `#score-list-template`
});

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
