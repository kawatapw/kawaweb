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
/*
// Vue Portal Component
  // 🧠 Simple Stack Handler
  let popupStack = []

  const mixin_popupmanager = {
    data: function() {
      return {
        __popups: {},
        activePopups: {},
      }
    },
    methods: {
      registerPopup(id, metadata = {}) {
        if (!id) {
          this.$log.error('[PopupManager] Missing ID.')
          return
        }
      
        // Initialize __popups if it doesn't exist
        if (!this.__popups) {
          this.__popups = {}
          this.$log.warn('[PopupManager] __popups was undefined, initializing.')
        }
      
        if (popupStack.includes(id)) {
          this.$log.info(`[PopupManager] Popup already in stack: ${id}`)
        } else {
          popupStack.push(id)
          this.$log.debug(`[PopupManager] Stack updated: ${popupStack.join(', ')}`)
        }
      
        this.__popups[id] = { ...metadata, zIndex: 1000 + popupStack.length }
      
        this.$log.info(`[PopupManager] Registered popup: ${id}`, this.__popups[id])
      },
      
      unregisterPopup(id) {
        const index = popupStack.indexOf(id)
        if (index !== -1) popupStack.splice(index, 1)

        delete this.__popups[id]
        this.$log.debug(`[PopupManager] Unregistered popup: ${id}`)
      },

      getPopupZIndex(id) {
        return this.__popups[id]?.zIndex || 1000
      },

      listPopups() {
        return popupStack.slice()
      }
    },
    beforeDestroy() {
      popupStack = []
      this.__popups = {}
      this.$log.debug('[PopupManager] Stack cleared.')
    }
  }

  // 🌀 Portal Component for Vue 2
  Vue.component('Portal', {
    props: {
      to: { type: String, required: true },
      id: { type: String, default: () => `portal-${Math.random().toString(36).substr(2, 8)}` },
      classes: { type: [String, Array, Object], default: '' },
      render: { type: Boolean, default: true },
      zIndex: { type: Number, default: null }
    },

    data() {
      return {
        targetEl: null,
        contentEl: null,
        mountedComponent: null
      }
    },

    mounted() {
      this.targetEl = document.querySelector(this.to);
      if (!this.targetEl) {
        this.$log.error(`[Portal:${this.id}] Target "${this.to}" not found.`);
        return;
      }
  
      this.contentEl = document.createElement('div');
      this.contentEl.id = this.id;
      this.contentEl.className = this.classes;
      this.targetEl.appendChild(this.contentEl);
      
      this.updateContent();
      this.$log.debug(`[Portal:${this.id}] Mounted to ${this.to}`);
    },

    updated() {
      this.updateContent()
    },

    methods: {
      updateContent() {
        if (!this.contentEl || !this.render) return;
        
        // Clear previous content
        if (this.mountedComponent) {
          this.mountedComponent.$destroy();
          this.mountedComponent = null;
        }
        
        this.contentEl.innerHTML = '';
        
        if (this.$slots.default && this.$slots.default.length) {
          // Create a new Vue instance to render the slot content
          const ComponentClass = Vue.extend({
            name: 'PortalContent',
            parent: this,
            render: (h) => h('div', this.$slots.default)
          });
          
          this.mountedComponent = new ComponentClass().$mount();
          this.contentEl.appendChild(this.mountedComponent.$el);
          
          // Apply z-index if provided
          if (this.zIndex !== null) {
            this.contentEl.style.zIndex = this.zIndex;
          }
          
          this.$log.debug(`[Portal:${this.id}] Content updated`, this.contentEl);
        }
      }
    },

    beforeDestroy() {
      if (this.mountedComponent) {
        this.mountedComponent.$destroy();
      }
      
      if (this.contentEl && this.targetEl) {
        this.targetEl.removeChild(this.contentEl);
      }
      
      this.$log.debug(`[Portal:${this.id}] Removed from ${this.to}`);
    },

    render(h) {
      return null // this component renders nothing in-place
    }
  })
*/

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
      showPanel: false,
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
  methods: {
    showPanelInfo() {
      this.showPanel = true;
    },
    hidePanelInfo() {
      this.showPanel = false;
    },
    togglePanelInfo() {
      this.showPanel = !this.showPanel;
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
  template: `
  <span data-popup="badge">
    <!-- Regular badge -->
    <div v-if="type === 0"  class="badge"  :class="badge.styles.customClass"  :style="badgeStyle"  @mouseover="showPanelInfo"  @mouseleave="hidePanelInfo" @focus="showPanelInfo" @blur="hidePanelInfo"
     @keydown.enter="togglePanelInfo" @keydown.space="togglePanelInfo" tabindex="0" role="button" :aria-label="badge.name" :aria-describedby="badgeId + '-desc'" :aria-expanded="showPanel">
      <bg-effect-psy :settings="{ hue: badge.styles.color / 360, hueVariation: badge.styles.psyHueVar ? badge.styles.psyHueVar : 0.001, density: badge.styles.psyDensity ? badge.styles.psyDensity : 0, displacement: badge.styles.psyDisp ? badge.styles.psyDisp : 0.1, speed: badge.styles.psySpeed ? badge.styles.psySpeed : 0.2, gradient: badge.styles.psyGradient ? badge.styles.psyGradient : 0.15 }" :show-gui="false" :debug-level="0" v-if="badge.styles.customClass && badge.styles.customClass.includes('psy')"></bg-effect-psy>
      <span class="icon"  v-if="badge.styles.icon"  :class="badge.styles.iconClass" aria-hidden="true">
        <i v-bind:class="'' + badge.styles.icon"></i>
      </span>
      
      <span class="badge-name"  :class="badge.styles.nameClass" :id="badgeId">
        {{ badge.name }}
      </span>
      
      <div class="badge-panel"  :class="badge.styles.panelClass"  :style="panelStyle" :id="badgeId + '-desc'" role="tooltip" aria-live="polite">
        <h3>{{ badge.name }}</h3>
        <p>{{ badge.description }}</p>
        <div v-if="badge.styles.panelFooter" class="badge-panel-footer">
          {{ badge.styles.panelFooter }}
        </div>
      </div>
    </div>
    
    <!-- Icon badge -->
    <div v-if="type === 1"  class="iconBadge"  :class="badge.styles.customClass"  :style="badgeStyle"  @mouseover="showPanelInfo"  @mouseleave="hidePanelInfo" @focus="showPanelInfo" @blur="hidePanelInfo" 
     @keydown.enter="togglePanelInfo" @keydown.space="togglePanelInfo" tabindex="0" role="button" :aria-label="badge.name" :aria-describedby="badgeId + '-desc'" :aria-expanded="showPanel">
      <span class="icon"  v-if="badge.styles.icon"  :class="badge.styles.iconClass" aria-hidden="true">
        <i v-bind:class="'' + badge.styles.icon"></i>
      </span>
      
      <div class="badge-panel"  :class="badge.styles.panelClass"  :style="panelStyle" :id="badgeId + '-desc'" role="tooltip" aria-live="polite">
        <h3>{{ badge.name }}</h3>
        <p>{{ badge.description }}</p>
        <div v-if="badge.styles.panelFooter" class="badge-panel-footer">
          {{ badge.styles.panelFooter }}
        </div>
      </div>
    </div>
  </span>
  `
});


Vue.component('user-profile', {
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
          badgePopupVisible: false,
          badgePopupTop: 0,
          badgePopupLeft: 0,
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
      this.$log.debug("User info initialized:", this.user);
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
      this.badgePopupVisible = false;
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
    showBadgePopup: function(event, badge) {
        if (this.badgePopupVisible != badge.id) {
            this.badgePopupVisible = badge.id;
            // Calculate the position of the badge popup relative to the badge icon
            const badgeIcon = event.target;
            const badgeIconRect = badgeIcon.getBoundingClientRect();
            this.badgePopupTop = badgeIconRect.top + badgeIconRect.height + 6 + 'px';
            this.badgePopupLeft = badgeIconRect.left + 'px';
        }
    },
    hideBadgePopup: function() {
        this.badgePopupVisible = false;
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
                this.$log.debug("Player data loaded:", this.user);
            })
            .catch(error => {
              this.$log.error("Error fetching player data:", error);
            })
            .finally(() => {
              this.isLoading.stats = false;
              this.dataFetched.stats = true;
              // Force Vue to re-render after data updates
              this.$nextTick(() => {
                this.$forceUpdate();
                this.$log.info("DOM updated with new player data");
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
              this.$log.debug(`${type} scores loaded:`, data.scores);
            })
            .catch(error => {
              this.$log.error(`Error fetching ${type} scores:`, error);
            })
            .finally(() => {
                this.isLoading[type] = false;
                this.dataFetched[type] = true;
                // Force Vue to re-render after data updates
                this.$nextTick(() => {
                  this.$forceUpdate();
                  this.$log.info("DOM updated with new player data");
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
                this.$log.info("Most played maps loaded:", this.user.info.mostPlayedMaps);
            })
            .catch(error => {
              this.$log.error("Error fetching most played maps:", error);
            })
            .finally(() => {
                this.isLoading.mostPlayed = false;
                this.dataFetched.mostPlayed = true;
                // Force Vue to re-render after data updates
                this.$nextTick(() => {
                  this.$forceUpdate();
                  this.$log.info("DOM updated with new player data");
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
              <badge v-for="badge in user.info?.badges" :badge="badge" :type="1" 
                     @mouseover="showBadgePopup($event, badge)" 
                     @mouseout="hideBadgePopup"></badge>
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
      
      <div class="badge-popup" :class="{ visible: badgePopupVisible }" :style="{ top: badgePopupTop, left: badgePopupLeft }" v-if="badgePopupVisible">
        <div class="badge-popup-title">{{ user.info?.badges?.find(b => b.id === badgePopupVisible)?.name }}</div>
        <div class="badge-popup-description">{{ user.info?.badges?.find(b => b.id === badgePopupVisible)?.description }}</div>
      </div>
    </span>
  `,
});

Vue.component('score-card', {
  delimiters: ["<%", "%>"],
  props: {
    score: {
      type: Object,
      required: true
    }
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
      this.$log.debug("Score", this.score);
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
  template: `
    <div class="map-single"
      :style="\`background: linear-gradient(hsl(var(--main), 25%, 25%, 90%), hsl(var(--main), 25%, 25%, 90%)), url(https://assets.ppy.sh/beatmaps/\${score.beatmap.set_id}/covers/cover.jpg)\`"
      @click="scoreBus.$emit('show-score-window', score.id)">
      <div class="map-data">
        <div class="map-image">
          <img :src="'https://assets.ppy.sh/beatmaps/' + score.beatmap.set_id + '/covers/card.jpg'"
            class="map-image-picture">
        </div>
        <div class="map-content1">
          <div class="map-title-block">
            <div class="map-title">
              <a class="beatmap-link" @click.stop="beatmapBus.$emit('show-beatmap-panel', score.beatmap.id, score.beatmap.set_id)">
                <% score.beatmap.title %> [<% score.beatmap.version %>] <span v-if="score.mods != 0">+<% score.mods_readable %></span>
              </a>
            </div>
            <div class="map-creators">
              By <a class=""><% score.beatmap.artist %></a>
              |
              Mapped by <a><% score.beatmap.creator %></a>
            </div>
          </div>
          <div class="play-stats-block">
            <div class="play-stats">
              <% formatNumber(score.score) %> / <% score.max_combo %><b>x</b> <span class="cheat_values" v-html="DisplayCheats(score.cheat_values)"></span>
            </div>
            <div class="map-date">
              <time><% timeago ? timeago.format(score.play_time) : new Date(score.play_time).toLocaleString() %></time>
            </div>
          </div>
        </div>
        <div class="map-content2">
          <div class="score-details d-flex">
            <div class="score-details_right-block">
              <div class="score-details_pp-block">
                <div class="map-pp">
                  <% score.pp.toFixed() %><span class="map-pp-unit">pp</span>
                </div>
                <div class="map-acc">accuracy:&nbsp;<b>
                    <% score.acc.toFixed(2) %>%
                  </b></div>
              </div>
              <div class="score-details_grade-block">
                <div class="rank-single">
                  <div :class="'map-rank rank-'+score.grade">
                    <% score.grade.replace("X", "SS" ).replace("H", "" ) %>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  `
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
  template: `
    <div class="log-block" :class="{ 'load': loading }">
      <div class="header">
        <div class="title">
          <i class="fas fa-trophy"></i> {{ title }}
        </div>
      </div>
      <div v-if="scores.length > 0" class="scores">
        <score-card 
          v-for="(score, index) in scores" 
          :key="score.id" 
          :score="score"
          @score-click="$emit('score-click', score.id)"
          @beatmap-click="$emit('beatmap-click', $event[0], $event[1])">
        </score-card>
      </div>
      <div v-else-if="scores.length === 0" class="stats-block">
        <div class="columns is-marginless">
          <div class="column is-1">
            <h1 class="title">: (</h1>
          </div>
          <div class="column">
            <h1 class="title is-6">{{ emptyMessage }}</h1>
            <p class="subtitle is-7">{{ emptySubMessage }}</p>
          </div>
        </div>
      </div>
      <div v-if="showMore" class="extra-block" id="hina-stats-block">
        <a class="show-button" @click="loadMore">Show more</a>
      </div>
    </div>
  `
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
        this.$log.debug('using default grey due to lack of diff info:', diff);
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
        this.$log.error('Error calculating difficulty color:', error);
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
  template: `
  <div :class="['beatmap-card', 'mode-' + mode, { 'expanded': expanded, 'interactive': interactive }]" 
       @click="handleClick">
    <!-- Loading state -->
    <div v-if="dataLoading" class="beatmap-loading-overlay">
      <div class="beatmap-loading-spinner"></div>
      <div class="beatmap-loading-text">Loading beatmap...</div>
    </div>
    
    <!-- Error state -->
    <div v-else-if="error" class="beatmap-error">
      <i class="fas fa-exclamation-circle"></i>
      <span>{{ error }}</span>
      <button @click.stop="loadMapData" class="beatmap-retry-btn">Retry</button>
    </div>
    
    <!-- Mini Mode -->
    <div v-else-if="mode === 'mini'" class="beatmap-mini">
      <div class="beatmap-mini-background">
        <img :src="cardUrl" alt="Beatmap Cover">
        <div class="beatmap-mini-overlay"></div>
      </div>
      
      <div class="beatmap-mini-content">
        <!-- Single difficulty mode - show icon on the left -->
        <div v-if="!showAllDifficulties" class="beatmap-mini-single-diff">
          <div class="beatmap-mini-diff-icon-container" :style="{ '--diff-color': difficultyColor(selectedDifficulty) }" v-data-popup
              :class="[selectedDifficulty.difficulty_rating ? 'difficulty-' + Math.floor(parseFloat(selectedDifficulty.difficulty_rating)) : '']">
            
            <!-- Difficulty icon with rank change indicator if available -->
            <div class="beatmap-mini-diff-icon" @click.stop="beatmapBus.$emit('show-beatmap-panel', selectedDifficulty.id, mapData.set_id)" data-popup-trigger>
              <i :class="getModeIcon(selectedDifficulty.mode)" class="beatmap-mini-mode-icon"></i>
              
              <div v-if="rankChanges && rankChanges[selectedDifficulty.id]" class="beatmap-mini-rank-change"
                   :style="{ backgroundColor: getRankChangeInfo(selectedDifficulty.id).color }">
                <i :class="['fas', getRankChangeInfo(selectedDifficulty.id).icon]"></i>
              </div>
            </div>
            
            <!-- Popup panel with position based on screen location -->
              <div :class="['beatmap-mini-popup', 'position-' + 'top']" data-popup> <!-- Remake Dynamic Position Logic -->
                <div class="beatmap-mini-popup-header">
                  <div class="beatmap-mini-popup-title" :title="mapData.title">{{ mapData.title || 'Loading...' }}</div>
                  <div class="beatmap-mini-popup-artist" :title="mapData.artist">{{ mapData.artist || '' }}</div>
                  <div class="beatmap-mini-popup-version" :title="selectedDifficulty.version">{{ selectedDifficulty.version || '' }}</div>
                </div>

                <div class="beatmap-mini-popup-details">
                  <div class="beatmap-mini-popup-creator" :title="'Mapped by ' + mapData.creator">
                    Mapped by {{ mapData.creator || '' }}
                  </div>

                  <div class="beatmap-mini-popup-stats">
                    <div v-if="selectedDifficulty.bpm" class="beatmap-mini-popup-stat">
                      <i class="fas fa-heartbeat"></i> {{ Math.round(selectedDifficulty.bpm) }}bpm
                    </div>
                    <div v-if="selectedDifficulty.hit_length" class="beatmap-mini-popup-stat">
                      <i class="fas fa-clock"></i> {{ formatLength(selectedDifficulty.hit_length) }}
                    </div>
                    <div v-if="selectedDifficulty.difficulty_rating" class="beatmap-mini-popup-stat">
                      <i class="fas fa-star" :style="{ color: difficultyStars ? difficultyStars.color : '#FFCC22' }"></i> 
                      {{ parseFloat(selectedDifficulty.difficulty_rating).toFixed(2) }}
                    </div>
                    <div v-if="showStatus" class="beatmap-mini-popup-stat">
                      <span class="beatmap-mini-status" :style="{ backgroundColor: statusColor }">{{ statusName }}</span>
                    </div>
                  </div>

                  <!-- Rank change info if available -->
                  <div v-if="rankChanges && rankChanges[selectedDifficulty.id]" class="beatmap-mini-popup-rank-change">
                    <div class="beatmap-mini-popup-rank-label">Rank:</div>
                    <div class="beatmap-mini-popup-rank-value" 
                         :style="{ color: getRankChangeInfo(selectedDifficulty.id).color }">
                      {{ formatRankChange(selectedDifficulty.id) }}
                      <i :class="['fas', getRankChangeInfo(selectedDifficulty.id).icon]"></i>
                    </div>
                  </div>

                  <!-- Other difficulties in the set -->
                  <div v-if="hasMultipleDifficulties" class="beatmap-mini-popup-other-diffs">
                    <div class="beatmap-mini-popup-diffs-header">Other difficulties:</div>
                    <div v-if="loading" class="beatmap-mini-popup-loading">Loading...</div>
                    <div v-else-if="setDifficulties.length <= 1" class="beatmap-mini-popup-no-diffs">None</div>
                    <div v-else class="beatmap-mini-popup-diffs-list">
                      <div v-for="diff in setDifficulties.filter(d => d.id !== selectedDifficulty.id)" 
                           :key="diff.id" 
                           class="beatmap-mini-popup-diff"
                           @click.stop="handleDifficultyClick(diff, $event)">
                        <span class="beatmap-mini-popup-diff-name" :title="diff.version">{{ diff.version }}</span>
                        <span v-if="diff.difficulty_rating" class="beatmap-mini-popup-diff-stars">
                          {{ parseFloat(diff.difficulty_rating).toFixed(2) }}
                        </span>

                        <!-- Rank change for other difficulties if available -->
                        <span v-if="rankChanges && rankChanges[diff.id]" 
                              class="beatmap-mini-popup-diff-rank"
                              :style="{ color: getRankChangeInfo(diff.id).color }">
                          <i :class="['fas', getRankChangeInfo(diff.id).icon]"></i>
                        </span>
                      </div>
                    </div>
                  </div>

                  <!-- Actions -->
                  <div class="beatmap-mini-popup-actions">
                    <a :href="'https://osu.ppy.sh/b/' + selectedDifficulty.id" target="_blank" class="beatmap-mini-popup-action" @click.stop>
                      <i class="fas fa-external-link-alt"></i> osu!
                    </a>
                    <a class="beatmap-mini-popup-action" @click.stop="console.log('Beatmap ID:', selectedDifficulty.id)">
                      <i class="fas fa-info-circle"></i> Details
                    </a>
                    <a :href="'/d/' + mapData.set_id" class="beatmap-mini-popup-action" @click.stop>
                      <i class="fas fa-download"></i> Download
                    </a>
                  </div>
                </div>
              </div>
          </div>
        </div>
        
        <!-- Map info (center section) -->
        <div class="beatmap-mini-info" :class="{ 'with-single-diff': !showAllDifficulties }">
          <div class="beatmap-mini-title" :title="mapData.title">{{ mapData.title || 'Loading...' }}</div>
          <div class="beatmap-mini-artist" :title="mapData.artist">{{ mapData.artist || '' }}</div>
          <div class="beatmap-mini-creator" :title="'Mapped by ' + mapData.creator">{{ mapData.creator || '' }}</div>
        </div>
        
        <!-- Status indicator (right side) -->
        <div class="content-right">
          <div v-if="showStatus" class="beatmap-mini-status-indicator" :style="{ backgroundColor: statusColor }">
            {{ statusName }}
          </div>
          <div v-if="showPlays && mapData.plays" class="beatmap-mini-plays">
            <i class="fas fa-play"></i> {{ formatNumber(mapData.plays) }}
          </div>
        </div>
      </div>
    </div>
    <!-- Difficulty icons section (when showing all difficulties) -->
    <div v-if="showAllDifficulties && hasMultipleDifficulties && mode === 'mini'" 
         :class="['beatmap-mini-difficulties']">
      <div class="beatmap-mini-difficulties-container">
        <!-- Loading state -->
        <div v-if="loading" class="beatmap-mini-difficulties-loading">
          <div class="beatmap-mini-loading-spinner"></div>
          <span>Loading...</span>
        </div>
        
        <!-- No difficulties found -->
        <div v-else-if="setDifficulties.length === 0" class="beatmap-mini-no-difficulties">
          No difficulties found
        </div>
        
        <!-- Difficulties list with scroll controls -->
        <div v-else class="beatmap-mini-difficulties-scroll-container">
          <!-- Left scroll button -->
          <button v-if="canScrollBack" 
                  class="beatmap-mini-difficulties-scroll-btn left" 
                  @click.stop="scrollDifficultiesLeft">
            <i class="fas fa-chevron-left"></i>
          </button>
          
          <!-- Difficulties -->
          <div class="beatmap-mini-difficulties-list">
            <div v-for="diff in visibleDifficulties" v-portal-popup
                 :key="diff.id" 
                 :class="['beatmap-mini-difficulty-icon-container']" :style="{ '--diff-color': difficultyColor(diff) }">
              
              <!-- Difficulty icon -->
              <div class="beatmap-mini-difficulty-icon" @click.stop="beatmapBus.$emit('show-beatmap-panel', diff.id, mapData.set_id)" data-popup-trigger>
                <i :class="getModeIcon(diff.mode)" class="beatmap-mini-mode-icon"></i>
                
                <!-- Rank change indicator if available -->
                <div v-if="rankChanges && rankChanges[diff.id]" class="beatmap-mini-rank-change"
                     :style="{ backgroundColor: getRankChangeInfo(diff.id).color }">
                  <i :class="['fas', getRankChangeInfo(diff.id).icon]"></i>
                </div>
              </div>
              
              <!-- Difficulty name (shown when expanded) -->
              <div v-if="difficultyExpanded" class="beatmap-mini-difficulty-name" :title="diff.version">
                {{ diff.version }}
              </div>
              
              <!-- Popup panel (same as single difficulty mode) -->
                <div :class="['beatmap-mini-popup', 'position-' + 'top' ]" data-popup> <!-- Remake Dynamic Position Logic -->
                  <div class="beatmap-mini-popup-header">
                    <div class="beatmap-mini-popup-title" :title="mapData.title">{{ mapData.title || 'Loading...' }}</div>
                    <div class="beatmap-mini-popup-artist" :title="mapData.artist">{{ mapData.artist || '' }}</div>
                    <div class="beatmap-mini-popup-version" :title="diff.version">{{ diff.version || '' }}</div>
                  </div>

                  <div class="beatmap-mini-popup-details">
                    <div class="beatmap-mini-popup-creator" :title="'Mapped by ' + mapData.creator">
                      Mapped by {{ mapData.creator || '' }}
                    </div>

                    <div class="beatmap-mini-popup-stats">
                      <div v-if="diff.bpm" class="beatmap-mini-popup-stat">
                        <i class="fas fa-heartbeat"></i> {{ Math.round(diff.bpm) }}bpm
                      </div>
                      <div v-if="diff.hit_length" class="beatmap-mini-popup-stat">
                        <i class="fas fa-clock"></i> {{ formatLength(diff.hit_length) }}
                      </div>
                      <div v-if="diff.difficulty_rating" class="beatmap-mini-popup-stat">
                        <i class="fas fa-star" :style="{ color: difficultyStars ? difficultyStars.color : '#FFCC22' }"></i> 
                        {{ parseFloat(diff.difficulty_rating).toFixed(2) }}
                      </div>
                      <div v-if="showStatus" class="beatmap-mini-popup-stat">
                        <span class="beatmap-mini-status" :style="{ backgroundColor: statusColor }">{{ statusName }}</span>
                      </div>
                    </div>

                    <!-- Rank change info if available -->
                    <div v-if="rankChanges && rankChanges[diff.id]" class="beatmap-mini-popup-rank-change">
                      <div class="beatmap-mini-popup-rank-label">Rank:</div>
                      <div class="beatmap-mini-popup-rank-value" 
                           :style="{ color: getRankChangeInfo(diff.id).color }">
                        {{ formatRankChange(diff.id) }}
                        <i :class="['fas', getRankChangeInfo(diff.id).icon]"></i>
                      </div>
                    </div>

                    <!-- Actions -->
                    <div class="beatmap-mini-popup-actions">
                      <a :href="'https://osu.ppy.sh/b/' + diff.id" target="_blank" class="beatmap-mini-popup-action" @click.stop>
                        <i class="fas fa-external-link-alt"></i> osu!
                      </a>
                      <a class="beatmap-mini-popup-action" @click.stop="beatmapBus.$emit('show-beatmap-panel', diff.id, mapData.set_id)">
                        <i class="fas fa-info-circle"></i> Details
                      </a>
                      <a :href="'/d/' + mapData.set_id" class="beatmap-mini-popup-action" @click.stop>
                        <i class="fas fa-download"></i> Download
                      </a>
                    </div>
                  </div>
                </div>
            </div>
          </div>
          
          <!-- Right scroll button -->
          <button v-if="hasMoreDifficulties" class="beatmap-mini-difficulties-scroll-btn right" 
                  @click.stop="scrollDifficultiesRight">
            <i class="fas fa-chevron-right"></i>
          </button>
        </div>
      </div>
    </div>

    <!-- Compact Mode -->
    <div v-else-if="mode === 'compact'" class="beatmap-compact">
      <div class="beatmap-thumbnail" :style="{ backgroundImage: 'url(' + thumbnailUrl + ')' }">
        <div v-if="!isSet && difficultyStars" class="beatmap-stars-small" :style="{ color: difficultyStars.color }">
          <i class="fas fa-star"></i> {{ difficultyStars.value }}
        </div>
      </div>
      <div class="beatmap-info">
        <div class="beatmap-title">{{ mapData.title || 'Loading...' }}</div>
        <div class="beatmap-artist">{{ mapData.artist || '' }}</div>
        <div v-if="!isSet" class="beatmap-version">{{ mapData.version || '' }}</div>
        <div v-if="showPlays && mapData.plays" class="beatmap-plays">
          <i class="fas fa-play"></i> {{ formatNumber(mapData.plays) }}
        </div>
      </div>
    </div>
  </div>
  `
});
