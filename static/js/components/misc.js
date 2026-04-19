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
  beforeDestroy() {
    // Clean up status interval
    this.stopStatusInterval();
    
    // Clean up any pending fetch requests
    if (this.isLoadingUser || this.isLoadingStatus) {
      if (this.$log) {
        this.$log.warn('LIFECYCLE', 'Component destroyed while data was loading');
      }
    }
    
    if (this.$log) {
      this.$log.debug('LIFECYCLE', 'User profile old component destroyed');
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
