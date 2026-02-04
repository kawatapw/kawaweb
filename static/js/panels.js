// ================= GLOBAL EVENT BUSES =================
// Use lightweight event buses instead of full Vue instances
// This prevents memory leaks from Vue's reactivity system
class EventBus {
  constructor() {
    this.listeners = {};
  }
  
  $on(event, callback) {
    if (!this.listeners[event]) {
      this.listeners[event] = [];
    }
    this.listeners[event].push(callback);
  }
  
  $off(event, callback) {
    if (!this.listeners[event]) return;
    
    if (callback) {
      const index = this.listeners[event].indexOf(callback);
      if (index > -1) {
        this.listeners[event].splice(index, 1);
      }
    } else {
      this.listeners[event] = [];
    }
  }
  
  $emit(event, ...args) {
    if (!this.listeners[event]) return;
    
    // Create a copy to avoid issues if listeners are removed during iteration
    const callbacks = [...this.listeners[event]];
    callbacks.forEach(callback => {
      try {
        callback(...args);
      } catch (err) {
        logger.error(`EventBus`,`Error in listener for ${event}:`, err);
      }
    });
  }
  
  $destroy() {
    this.listeners = {};
  }
}

const searchBus = new EventBus();
const docsBus = new EventBus();
const beatmapBus = new EventBus();
const scoreBus = new EventBus();

// Export cleanup function for use on page unload
window.cleanupEventBuses = function() {
  searchBus.$destroy();
  docsBus.$destroy();
  beatmapBus.$destroy();
  scoreBus.$destroy();
  logger.log('EventBus', 'All event buses cleaned up');
};

// ================= SEARCH ICON =================
bootstrapVue('search-icon', {
    el: '#search-icon',
    data: { isAnimating: false },
    methods: {
        showSearchWindow() { searchBus.$emit('show-search-window'); },
        startAnimation() { this.isAnimating = true; },
        stopAnimation() { this.isAnimating = false; }
    }
});

// ================= SEARCH WINDOW =================
bootstrapVue('search-panel', {
    el: '#search-panel',
    templateId: 'search-panel-template',
    data: {
        show: false,
        query: '',
        players: [],
        playersLoading: false,
        playersError: null,
        maps: [],
        mapsLoading: false,
        mapsError: null,
        typingTimeout: null,
        currentAudio: null,
        searchId: 0,
        hasSearched: false
    },
    created() {
        this.$log = ColorfulLogger.child('Search Panel');
        this.$log.info('LIFECYCLE', 'Search Panel created');
        this.handleShowSearchWindow = () => {
            this.show = true;
            this.$nextTick(() => {
                if (this.$refs.searchInput) {
                    this.$refs.searchInput.focus();
                }
            });
        };
        searchBus.$on('show-search-window', this.handleShowSearchWindow);
    },
    computed: {
        hasResults() {
            return this.players.length > 0 || this.maps.length > 0;
        },
        isLoading() {
            return this.playersLoading || this.mapsLoading;
        }
    },
    methods: {
        close() {
            this.show = false;
            this.resetQuery();
        },
        resetQuery() {
            this.query = '';
            this.players = [];
            this.maps = [];
            this.playersLoading = false;
            this.mapsLoading = false;
            this.playersError = null;
            this.mapsError = null;
            this.hasSearched = false;
        },
        async search() {
            if (this.query.trim() === '') {
                this.players = [];
                this.maps = [];
                this.hasSearched = false;
                return;
            }

            const currentSearchId = ++this.searchId;
            this.hasSearched = true;
            this.playersLoading = true;
            this.mapsLoading = true;
            this.playersError = null;
            this.mapsError = null;

            try {
                // Fetch players
                try {
                    const playersResponse = await fetch(
                        `https://api.${domain}/v1/search_players?limit=10&q=${encodeURIComponent(this.query)}`,
                        { signal: AbortSignal.timeout(5000) }
                    );
                    
                    if (!playersResponse.ok) {
                        throw new Error(`HTTP ${playersResponse.status}`);
                    }
                    
                    const playersData = await playersResponse.json();
                    if (currentSearchId === this.searchId) {
                        this.players = playersData.result || [];
                    }
                } catch (err) {
                    if (currentSearchId === this.searchId) {
                        this.playersError = 'Failed to load players';
                        this.$log.error('API', 'Search error (players)', err);
                    }
                }

                // Fetch beatmaps
                try {
                    const mapsResponse = await fetch(
                        `https://osu.direct/api/search?amount=10&query=${encodeURIComponent(this.query)}`,
                        { signal: AbortSignal.timeout(5000) }
                    );
                    
                    if (!mapsResponse.ok) {
                        throw new Error(`HTTP ${mapsResponse.status}`);
                    }
                    
                    const mapsData = await mapsResponse.json();
                    if (currentSearchId === this.searchId) {
                        // Initialize thumbnailError property for each map
                        this.maps = (mapsData || []).map(map => ({
                            ...map,
                            thumbnailError: false
                        }));
                    }
                } catch (err) {
                    if (currentSearchId === this.searchId) {
                        this.mapsError = 'Failed to load beatmaps';
                        this.$log.error('API', 'Search error (maps)', err);
                    }
                }
            } finally {
                if (currentSearchId === this.searchId) {
                    this.playersLoading = false;
                    this.mapsLoading = false;
                }
            }
        },
        handleInput() {
            clearTimeout(this.typingTimeout);
            const delay = Math.max(1200 - (this.query.length * 80), 400);
            this.typingTimeout = setTimeout(() => this.search(), delay);
        },
        interract(setId) {
            const audio = document.getElementById(`audio-${setId}`);
            if (!audio) return;

            if (this.currentAudio && this.currentAudio !== audio) {
                this.currentAudio.pause();
            }
            
            if (audio.paused) {
                audio.play();
                this.currentAudio = audio;
            } else {
                audio.pause();
                if (this.currentAudio === audio) {
                    this.currentAudio = null;
                }
            }
        },
        clearAudio() {
            if (this.currentAudio) {
                this.currentAudio.pause();
                this.currentAudio = null;
            }
        },
        openBeatmapPanel(map) {
            if (!map || !map.SetID) return;
            
            // Close the search panel
            this.close();
            
            // Emit event to open beatmap panel
            // The beatmap panel expects (id, set_id)
            // We'll pass null for id since we're opening the set
            beatmapBus.$emit('show-beatmap-panel', null, map.SetID);
        },
        /**
         * Normalize beatmap API response data to match the difficulty-icon component format
         * @param {Object} map - The beatmap set object from the search API
         * @returns {Array} - Normalized difficulty objects
         */
        getNormalizedDifficulties(map) {
            if (!map || !map.ChildrenBeatmaps) return [];
            
            return map.ChildrenBeatmaps.map(diff => ({
                id: diff.BeatmapID,
                diff: diff.DifficultyRating,
                mode: diff.Mode,
                version: diff.DiffName,
                // Add any other properties the component might need
                bpm: diff.BPM,
                hit_length: diff.HitLength,
                difficulty_rating: diff.DifficultyRating
            }));
        }
    },
    beforeDestroy() {
        // Clean up event bus listeners
        if (this.handleShowSearchWindow) {
            searchBus.$off('show-search-window', this.handleShowSearchWindow);
        }
        
        // Clean up audio references
        this.clearAudio();
        
        // Clean up typing timeout
        if (this.typingTimeout) {
            clearTimeout(this.typingTimeout);
            this.typingTimeout = null;
        }
    }
});

// ================= DOCS PANEL =================
bootstrapVue('docs', {
    el: '#docs',
    data: {
        module: 'Rules',
        page: 'Main'
    },
    async created() {
        this.$log = ColorfulLogger.child('Docs URL Handler');
        this.$log.info('LIFECYCLE', 'Docs URL Handler created');
        const urlParams = new URLSearchParams(window.location.search);
        const pathParts = window.location.pathname.split('/');
        if (pathParts[1] === 'docs') {
            let doc = pathParts[2];
            let page = urlParams.get('page');
            if (page === "Cheats") page = "Clients";

            setTimeout(() => this.showDocsPanel(doc, page), 100);
        }
    },
    methods: {
        showDocsPanel(doc, page) {
            this.module = doc || 'Rules';
            this.page = page || 'Main';
            docsBus.$emit('show-docs-panel', this.module, this.page);
        }
    }
});

bootstrapVue('docs-panel', {
    el: '#docs-panel',
    templateId: 'docs-panel-template',
    data: {
        show: false,
        module: 'Rules',
        page: 'Main'
    },
    created() {
        this.$log = ColorfulLogger.child('Docs Panel');
        this.$log.info('LIFECYCLE', 'Docs Panel created');
        this.handleShowDocsPanel = (module, page) => {
            this.module = module || 'Rules';
            this.page = page || 'Main';
            this.show = true;
        };
        docsBus.$on('show-docs-panel', this.handleShowDocsPanel);
    },
    beforeDestroy() {
        if (this.handleShowDocsPanel) {
            docsBus.$off('show-docs-panel', this.handleShowDocsPanel);
        }
    },
    methods: {
        close() { this.show = false; },
        LoadDoc(module, page) {
            this.module = module;
            this.page = page || 'Main';
            this.$log.info('LIFECYCLE', `Loading ${module} doc...`);
        }
    }
});

// ================= BEATMAP URL HANDLER =================
bootstrapVue('beatmap', {
    el: '#beatmap-panel',
    data: { id: null, set_id: null },
    async created() {
        this.$log = ColorfulLogger.child('BeatmapURL');
        this.$log.info('LIFECYCLE', 'Beatmap URL Handler created');
        const pathParts = window.location.pathname.split('/');
        if (pathParts[1] === 'b') {
            this.id = parseInt(pathParts[2]);
            this.set_id = await this.fetchSetIdFromMap(this.id);
            this.deferShow();
        }
        if (pathParts[1] === 's') {
            this.set_id = parseInt(pathParts[2]);
            this.deferShow();
        }
    },
    methods: {
        deferShow() {
            setTimeout(() => beatmapBus.$emit('show-beatmap-panel', this.id, this.set_id), 10);
        },
        async fetchSetIdFromMap(id) {
            try {
                const res = await fetch(`https://api.${domain}/v2/maps/${id}`);
                const json = await res.json();
                return json.data.set_id;
            } catch (err) {
                this.$log.error('API', 'Error fetching set ID from map', err);
                return null;
            }
        }
    }
});

// ================= BEATMAP PANEL =================
bootstrapVue('beatmap-panel', {
    el: '#beatmap-panel',
    templateId: 'beatmap-panel-template',
    data: {
        show: false,
        id: null,
        set_id: null,
        beatmaps: [],
        selected: null,
        leaderboards: [],
        currentAudio: null,
        // Filter state
        selectedMode: 0, // 0: osu, 1: taiko, 2: catch, 3: mania
        selectedRuleset: 0, // 0: vanilla, 1: relax, 2: autopilot
        selectedMods: 0 // Bitmask of selected mods
    },
    created() {
        this.$log = ColorfulLogger.child('Beatmap Panel');
        this.$log.info('LIFECYCLE', 'Beatmap Panel created');
        beatmapBus.$on('show-beatmap-panel', this.openPanel);
        beatmapBus.$on('select-beatmap', this.selectMap);
    },
    beforeDestroy() {
        this.$log.info('LIFECYCLE', 'Beatmap Panel destroyed, cleaning up');
        beatmapBus.$off('show-beatmap-panel', this.openPanel);
        beatmapBus.$off('select-beatmap', this.selectMap);
        
        // Clean up audio references
        if (this.currentAudio) {
            this.currentAudio.pause();
            this.currentAudio = null;
        }
    },
    computed: {
        hasLeaderboards() { 
            const has = this.leaderboards.length > 0;
            this.$log.debug('DATA', `hasLeaderboards: ${has}`, { leaderboards: this.leaderboards });
            return has;
        },
        topScore() { 
            const score = this.leaderboards[0] || null;
            if (score) {
                this.$log.debug('DATA', 'Top score retrieved', { scoreId: score.id, player: score.player_name });
            }
            return score;
        },
        selectedStats() { 
            const stats = this.selected || {};
            this.$log.debug('DATA', 'selectedStats accessed', { 
                hasSelected: !!this.selected, 
                title: stats.title,
                artist: stats.artist 
            });
            return stats;
        },
        // Get the full game mode (mode + ruleset)
        fullGameMode() {
            const mode = this.selectedMode;
            const ruleset = this.selectedRuleset;
            
            // Ruleset offsets: vanilla=0, relax=4, autopilot=8
            // This matches the backend GameMode enum:
            // 0-3: Vanilla (osu, taiko, catch, mania)
            // 4-7: Relax (osu, taiko, catch, mania)
            // 8-11: Autopilot (osu, taiko, catch, mania)
            const rulesetOffset = ruleset === 1 ? 4 : (ruleset === 2 ? 8 : 0);
            
            return mode + rulesetOffset;
        },
        // Get valid mods for current mode and ruleset
        validMods() {
            const mode = this.selectedMode;
            const ruleset = this.selectedRuleset;
            
            // Base mods that are valid for all modes/rulesets
            let valid = 0;
            
            // Mods that work in all modes (excluding non-submittable mods)
            valid |= (1 << 0);  // NOFAIL
            valid |= (1 << 1);  // EASY
            valid |= (1 << 3);  // HIDDEN
            valid |= (1 << 4);  // HARDROCK
            valid |= (1 << 5);  // SUDDENDEATH
            valid |= (1 << 6);  // DOUBLETIME
            valid |= (1 << 8);  // HALFTIME
            valid |= (1 << 9);  // NIGHTCORE
            valid |= (1 << 10); // FLASHLIGHT
            valid |= (1 << 14); // PERFECT
            valid |= (1 << 29); // SCOREV2
            
            // Mode-specific mods (excluding non-submittable mods)
            if (mode === 0) { // osu!
                valid |= (1 << 2);  // TOUCHSCREEN
                valid |= (1 << 12); // SPUNOUT
                valid |= (1 << 20); // FADEIN
                // Note: AUTOPLAY, CINEMA, TARGET are not submittable
                // Note: RELAX and AUTOPILOT are rulesets, not mods
            } else if (mode === 1) { // taiko
                valid |= (1 << 20); // FADEIN
                // Note: AUTOPLAY, CINEMA, TARGET are not submittable
                // Note: RELAX is a ruleset, not a mod
            } else if (mode === 2) { // catch
                valid |= (1 << 20); // FADEIN
                // Note: AUTOPLAY, CINEMA, TARGET are not submittable
                // Note: RELAX is a ruleset, not a mod
            } else if (mode === 3) { // mania
                valid |= (1 << 20); // FADEIN
                valid |= (1 << 30); // MIRROR
                valid |= (1 << 15); // KEY4
                valid |= (1 << 16); // KEY5
                valid |= (1 << 17); // KEY6
                valid |= (1 << 18); // KEY7
                valid |= (1 << 19); // KEY8
                valid |= (1 << 24); // KEY9
                valid |= (1 << 25); // KEYCOOP
                valid |= (1 << 26); // KEY1
                valid |= (1 << 27); // KEY3
                valid |= (1 << 28); // KEY2
                // Note: AUTOPLAY, CINEMA, TARGET are not submittable
                // Note: RELAX is a ruleset, not a mod
            }
            
            // Remove mods that conflict with ruleset
            if (ruleset === 1) { // Relax ruleset
                // In relax ruleset, SPUNOUT is not valid
                valid &= ~(1 << 12); // Remove SPUNOUT
            } else if (ruleset === 2) { // Autopilot ruleset
                // In autopilot ruleset, SPUNOUT is not valid
                valid &= ~(1 << 12); // Remove SPUNOUT
            }
            
            return valid;
        },
        // Get list of mods that are currently selected and valid
        selectedModsList() {
            const mods = [];
            const valid = this.validMods;
            
            for (let i = 0; i < 31; i++) {
                const modBit = 1 << i;
                if ((this.selectedMods & modBit) && (valid & modBit)) {
                    mods.push(modBit);
                }
            }
            
            return mods;
        },
        // Get mods as a string for API
        modsString() {
            return this.selectedModsList.map(mod => {
                const modNames = {
                    0: 'NF', 1: 'EZ', 2: 'TD', 3: 'HD', 4: 'HR', 5: 'SD', 6: 'DT',
                    7: 'RX', 8: 'HT', 9: 'NC', 10: 'FL', 11: 'AU', 12: 'SO', 13: 'AP',
                    14: 'PF', 15: '4K', 16: '5K', 17: '6K', 18: '7K', 19: '8K', 20: 'FI',
                    21: 'RN', 22: 'CN', 23: 'TP', 24: '9K', 25: 'CO', 26: '1K', 27: '3K',
                    28: '2K', 29: 'V2', 30: 'MR'
                };
                const bitIndex = Math.log2(mod);
                return modNames[bitIndex] || '';
            }).join('');
        },
        // Get list of valid mod bits for display
        validModsList() {
            const mods = [];
            const valid = this.validMods;
            
            for (let i = 0; i < 31; i++) {
                const modBit = 1 << i;
                if (valid & modBit) {
                    mods.push(modBit);
                }
            }
            
            return mods;
        },
        // Get list of mods that are incompatible with currently selected mods
        incompatibleMods() {
            const incompatible = [];
            
            // Check each valid mod to see if it conflicts with selected mods
            for (let i = 0; i < 31; i++) {
                const modBit = 1 << i;
                
                // Only check mods that are valid for current mode/ruleset
                if (this.validMods & modBit) {
                    // Check if this mod conflicts with any selected mod
                    const conflicts = this.getModConflicts(modBit);
                    if (conflicts.length > 0) {
                        incompatible.push(modBit);
                    }
                }
            }
            
            return incompatible;
        }
    },
    methods: {
        async openPanel(id, set_id) {
            this.$log.info('LIFECYCLE', 'Opening beatmap panel', { id, set_id });
            this.id = id ?? null;
            this.set_id = set_id ?? null;
            
            // Assert that set_id is provided
            this.$log.assert(
                this.set_id !== null && this.set_id !== undefined,
                'LIFECYCLE',
                'set_id is required to open beatmap panel',
                { id, set_id },
                false
            );
            
            await this.fetchBeatmaps();
            this.show = true;
            this.$log.info('LIFECYCLE', 'Beatmap panel opened', { 
                show: this.show, 
                beatmapsCount: this.beatmaps.length,
                hasSelected: !!this.selected 
            });
        },
        close() { 
            this.$log.info('LIFECYCLE', 'Closing beatmap panel');
            this.show = false; 
        },
        async fetchBeatmaps() {
            this.$log.info('API', 'Fetching beatmaps', { set_id: this.set_id });
            
            try {
                const url = `https://api.${domain}/v2/maps?set_id=${this.set_id}`;
                this.$log.debug('API', 'Fetching from URL', { url });
                
                const res = await fetch(url);
                
                // Assert HTTP response is OK
                this.$log.assert(
                    res.ok,
                    'API',
                    'HTTP response not OK',
                    { status: res.status, statusText: res.statusText, url },
                    false
                );
                
                const json = await res.json();
                this.$log.debug('API', 'API response received', { 
                    hasData: !!json.data,
                    dataLength: json.data?.length || 0 
                });
                
                // Assert that data exists
                this.$log.assert(
                    json.data && Array.isArray(json.data) && json.data.length > 0,
                    'API',
                    'No beatmap data returned from API',
                    { set_id: this.set_id, rawData: json },
                    false
                );
                
                this.beatmaps = json.data.sort((a, b) => a.diff - b.diff);
                this.$log.debug('DATA', 'Beatmaps sorted by difficulty', { 
                    count: this.beatmaps.length,
                    minDiff: this.beatmaps[0]?.diff,
                    maxDiff: this.beatmaps[this.beatmaps.length - 1]?.diff 
                });
                
                // Determine selected beatmap
                if (this.id !== null) {
                    this.selected = this.beatmaps.find(m => m.id === this.id);
                    if (!this.selected) {
                        this.$log.warn('DATA', 'Specific beatmap ID not found, using first beatmap', { 
                            requestedId: this.id,
                            availableIds: this.beatmaps.map(m => m.id) 
                        });
                        this.selected = this.beatmaps[0];
                    }
                } else {
                    this.selected = this.beatmaps[0];
                }
                
                // Assert that selected is now valid
                this.$log.assert(
                    this.selected !== null && this.selected !== undefined,
                    'DATA',
                    'Failed to select a beatmap',
                    { 
                        beatmapsCount: this.beatmaps.length,
                        requestedId: this.id,
                        set_id: this.set_id 
                    },
                    true
                );
                
                this.$log.debug('DATA', 'Selected beatmap', { 
                    id: this.selected.id,
                    version: this.selected.version,
                    diff: this.selected.diff 
                });
                
                await this.fetchLeaderboards();
            } catch (err) {
                this.$log.error('API', 'Error fetching beatmaps', { 
                    error: err.message,
                    stack: err.stack,
                    set_id: this.set_id 
                });
                
                // Ensure selected is null on error to prevent template errors
                this.selected = null;
                this.beatmaps = [];
            }
        },
        async fetchLeaderboards() {
            this.$log.info('API', 'Fetching leaderboards', { 
                hasSelected: !!this.selected,
                selectedId: this.selected?.id,
                mode: this.selectedMode,
                ruleset: this.selectedRuleset,
                mods: this.selectedMods,
                modsString: this.modsString 
            });
            
            if (!this.selected) {
                this.$log.warn('API', 'Cannot fetch leaderboards - no selected beatmap');
                return;
            }
            
            try {
                // Build URL with filters
                let url = `https://api.${domain}/v1/get_map_scores?id=${this.selected.id}&scope=best`;
                
                // Add mode parameter (full game mode including ruleset)
                const fullMode = this.fullGameMode;
                url += `&mode=${fullMode}`;
                
                // Add mods parameter if any mods are selected
                if (this.selectedModsList.length > 0) {
                    url += `&mods=${this.modsString}`;
                }
                
                this.$log.debug('API', 'Fetching from URL', { url });
                
                const res = await fetch(url);
                
                // Assert HTTP response is OK
                this.$log.assert(
                    res.ok,
                    'API',
                    'HTTP response not OK',
                    { status: res.status, statusText: res.statusText, url, selectedId: this.selected.id },
                    false
                );
                
                const json = await res.json();
                this.$log.debug('API', 'API response received', { 
                    hasScores: !!json.scores,
                    scoresLength: json.scores?.length || 0 
                });
                
                this.leaderboards = json.scores || [];
                this.$log.info('API', 'Leaderboards fetched', { 
                    count: this.leaderboards.length,
                    selectedId: this.selected.id,
                    mode: fullMode,
                    mods: this.modsString 
                });
            } catch (err) {
                this.$log.error('API', 'Error fetching leaderboards', { 
                    error: err.message,
                    stack: err.stack,
                    selectedId: this.selected?.id 
                });
                this.leaderboards = [];
            }
        },
        selectMap(id) {
            this.$log.info('LIFECYCLE', 'Selecting beatmap', { id });
            
            if (!id) {
                this.$log.warn('LIFECYCLE', 'Invalid beatmap ID provided', { id });
                return;
            }
            
            this.id = id;
            this.selected = this.beatmaps.find(m => m.id === id) || this.beatmaps[0];
            
            // Assert that selected is now valid
            this.$log.assert(
                this.selected !== null && this.selected !== undefined,
                'LIFECYCLE',
                'Failed to select beatmap',
                { 
                    requestedId: id,
                    beatmapsCount: this.beatmaps.length,
                    availableIds: this.beatmaps.map(m => m.id) 
                },
                true
            );
            
            this.$log.debug('DATA', 'Beatmap selected', { 
                id: this.selected.id,
                version: this.selected.version 
            });
            
            this.leaderboards = [];
            this.fetchLeaderboards();
        },
        playMapAudio(setId) {
            this.$log.info('LIFECYCLE', 'Playing map audio', { setId });
            
            const audio = document.getElementById(`audio-${setId}`);
            const playButton = document.getElementById(`play-${setId}`);
            const mapPlayDiv = playButton ? playButton.parentElement : null;
            
            // Assert that audio element exists
            this.$log.assert(
                audio !== null,
                'LIFECYCLE',
                'Audio element not found',
                { setId, elementId: `audio-${setId}` },
                false
            );
            
            if (!audio) return;
            
            // If clicking the same audio that's already playing, pause it
            if (this.currentAudio && this.currentAudio === audio && !audio.paused) {
                this.$log.debug('LIFECYCLE', 'Pausing current audio');
                audio.pause();
                if (mapPlayDiv) {
                    mapPlayDiv.classList.remove('playing');
                    // Don't reset progress - keep it at current position
                }
                // Cancel any pending animation frame
                if (audio.animationFrameId) {
                    cancelAnimationFrame(audio.animationFrameId);
                    audio.animationFrameId = null;
                }
                this.currentAudio = null;
                return;
            }
            
            // Pause any other audio that's playing
            if (this.currentAudio && this.currentAudio !== audio) {
                this.$log.debug('LIFECYCLE', 'Pausing previous audio');
                this.currentAudio.pause();
                // Remove playing class from previous button and cancel animation frame
                const prevAudio = this.currentAudio;
                const prevPlayButton = document.getElementById(`play-${prevAudio.id.replace('audio-', '')}`);
                if (prevPlayButton) {
                    const prevMapPlayDiv = prevPlayButton.parentElement;
                    if (prevMapPlayDiv) {
                        prevMapPlayDiv.classList.remove('playing');
                        prevMapPlayDiv.style.setProperty('--audio-progress', '0%');
                    }
                }
                if (prevAudio.animationFrameId) {
                    cancelAnimationFrame(prevAudio.animationFrameId);
                    prevAudio.animationFrameId = null;
                }
            }
            
            // Play the new audio
            this.$log.debug('LIFECYCLE', 'Playing audio');
            audio.play();
            
            // Add playing class and set up progress tracking
            if (mapPlayDiv) {
                mapPlayDiv.classList.add('playing');
                mapPlayDiv.style.setProperty('--audio-progress', '0%');
            }
            
            // Store reference to mapPlayDiv for cleanup
            audio.mapPlayDiv = mapPlayDiv;
            
            // Start smooth progress animation
            this.startSmoothProgress(audio);
            
            // Reset progress when audio ends
            audio.addEventListener('ended', () => {
                if (mapPlayDiv) {
                    mapPlayDiv.classList.remove('playing');
                    mapPlayDiv.style.setProperty('--audio-progress', '0%');
                }
                // Cancel animation frame
                if (audio.animationFrameId) {
                    cancelAnimationFrame(audio.animationFrameId);
                    audio.animationFrameId = null;
                }
                // Force Vue to update the icon
                if (this.$forceUpdate) {
                    this.$forceUpdate();
                }
            });
            
            // Reset progress only when paused at the beginning
            audio.addEventListener('pause', () => {
                if (mapPlayDiv && audio.currentTime === 0) {
                    mapPlayDiv.classList.remove('playing');
                    mapPlayDiv.style.setProperty('--audio-progress', '0%');
                }
                // Cancel animation frame
                if (audio.animationFrameId) {
                    cancelAnimationFrame(audio.animationFrameId);
                    audio.animationFrameId = null;
                }
            });
            
            this.currentAudio = audio;
        },
        
        /**
         * Starts smooth progress animation using requestAnimationFrame
         * @param {HTMLAudioElement} audio - The audio element
         */
        startSmoothProgress(audio) {
            const updateProgress = () => {
                if (!audio || !audio.mapPlayDiv || audio.paused) return;
                
                const progress = (audio.currentTime / audio.duration) * 100;
                audio.mapPlayDiv.style.setProperty('--audio-progress', `${progress}%`);
                
                // Continue animation frame
                audio.animationFrameId = requestAnimationFrame(updateProgress);
            };
            
            // Start the animation loop
            audio.animationFrameId = requestAnimationFrame(updateProgress);
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
         * Formats a date string to a more readable local date and time.
         * @param {string} dateString - The date string from your score object.
         * @returns {string} - A formatted date string.
         */
        formatDate(dateString) {
            const options = {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false // Use 24-hour format
            };
            return new Date(dateString).toLocaleString(undefined, options);
        },
        /**
         * Formats a duration in seconds into a MM:SS string.
         * @param {number} totalSeconds - The total duration in seconds.
         * @returns {string} - Formatted string like "2:05".
         */
        formatDuration(totalSeconds) {
            const minutes = Math.floor(totalSeconds / 60);
            const seconds = totalSeconds % 60;
            const formattedMinutes = String(minutes);
            const formattedSeconds = String(seconds).padStart(2, '0');
            return `${formattedMinutes}:${formattedSeconds}`;
        },
        
        // ================= FILTER METHODS =================
        
        /**
         * Select a game mode (osu, taiko, catch, mania)
         * @param {number} mode - The mode to select (0-3)
         */
        selectMode(mode) {
            this.$log.info('LIFECYCLE', 'Selecting mode', { mode });
            
            if (mode < 0 || mode > 3) {
                this.$log.warn('LIFECYCLE', 'Invalid mode provided', { mode });
                return;
            }
            
            this.selectedMode = mode;
            
            // Clear mods that are not valid for this mode
            this.filterModsForMode();
            
            // Refetch leaderboards with new mode
            this.refetchLeaderboards();
        },
        
        /**
         * Select a ruleset (vanilla, relax, autopilot)
         * @param {number} ruleset - The ruleset to select (0-2)
         */
        selectRuleset(ruleset) {
            this.$log.info('LIFECYCLE', 'Selecting ruleset', { ruleset });
            
            if (ruleset < 0 || ruleset > 2) {
                this.$log.warn('LIFECYCLE', 'Invalid ruleset provided', { ruleset });
                return;
            }
            
            this.selectedRuleset = ruleset;
            
            // Clear mods that are not valid for this ruleset
            this.filterModsForRuleset();
            
            // Refetch leaderboards with new ruleset
            this.refetchLeaderboards();
        },
        
        /**
         * Toggle a mod on/off
         * @param {number} modBit - The mod bit to toggle (1 << modIndex)
         */
        toggleMod(modBit) {
            this.$log.info('LIFECYCLE', 'Toggling mod', { modBit });
            
            // Check if mod is valid for current mode/ruleset
            if (!(this.validMods & modBit)) {
                this.$log.warn('LIFECYCLE', 'Mod not valid for current mode/ruleset', { 
                    modBit,
                    validMods: this.validMods,
                    mode: this.selectedMode,
                    ruleset: this.selectedRuleset 
                });
                return;
            }
            
            // Check for mod conflicts before enabling
            if (!(this.selectedMods & modBit)) {
                const conflicts = this.getModConflicts(modBit);
                if (conflicts.length > 0) {
                    this.$log.warn('LIFECYCLE', 'Mod conflicts with already selected mods', { 
                        modBit,
                        conflicts,
                        selectedMods: this.selectedMods 
                    });
                    // Just return early - mod will be greyed out in UI
                    return;
                }
            }
            
            // Toggle the mod
            if (this.selectedMods & modBit) {
                this.selectedMods &= ~modBit;
                this.$log.debug('LIFECYCLE', 'Mod disabled', { modBit });
            } else {
                this.selectedMods |= modBit;
                this.$log.debug('LIFECYCLE', 'Mod enabled', { modBit });
            }
            
            // Refetch leaderboards with new mods
            this.refetchLeaderboards();
        },
        
        /**
         * Get mods that conflict with the given mod
         * @param {number} modBit - The mod bit to check
         * @returns {Array} - Array of conflicting mod bits
         */
        getModConflicts(modBit) {
            const conflicts = [];
            const selected = this.selectedMods;
            
            // Check each selected mod for conflicts
            for (let i = 0; i < 31; i++) {
                const otherModBit = 1 << i;
                if (selected & otherModBit) {
                    if (this.modsConflict(modBit, otherModBit)) {
                        conflicts.push(otherModBit);
                    }
                }
            }
            
            return conflicts;
        },
        
        /**
         * Check if two mods conflict
         * @param {number} mod1 - First mod bit
         * @param {number} mod2 - Second mod bit
         * @returns {boolean} - True if mods conflict
         */
        modsConflict(mod1, mod2) {
            // EZ and HR conflict
            if ((mod1 === (1 << 1) && mod2 === (1 << 4)) || 
                (mod1 === (1 << 4) && mod2 === (1 << 1))) {
                return true;
            }
            
            // DT and HT conflict
            if ((mod1 === (1 << 6) && mod2 === (1 << 8)) || 
                (mod1 === (1 << 8) && mod2 === (1 << 6))) {
                return true;
            }
            
            // DT and NC conflict (similar mods)
            if ((mod1 === (1 << 6) && mod2 === (1 << 9)) || 
                (mod1 === (1 << 9) && mod2 === (1 << 6))) {
                return true;
            }
            
            // SD and PF conflict (similar mods)
            if ((mod1 === (1 << 5) && mod2 === (1 << 14)) || 
                (mod1 === (1 << 14) && mod2 === (1 << 5))) {
                return true;
            }
            
            // NF and SD conflict
            if ((mod1 === (1 << 0) && mod2 === (1 << 5)) || 
                (mod1 === (1 << 5) && mod2 === (1 << 0))) {
                return true;
            }
            
            // NF and PF conflict
            if ((mod1 === (1 << 0) && mod2 === (1 << 14)) || 
                (mod1 === (1 << 14) && mod2 === (1 << 0))) {
                return true;
            }
            
            // HD and FI conflict in mania
            if (this.selectedMode === 3 && 
                ((mod1 === (1 << 3) && mod2 === (1 << 20)) || 
                 (mod1 === (1 << 20) && mod2 === (1 << 3)))) {
                return true;
            }
            
            return false;
        },
        
        /**
         * Clear all selected mods
         */
        clearMods() {
            this.$log.info('LIFECYCLE', 'Clearing all mods');
            this.selectedMods = 0;
            this.refetchLeaderboards();
        },
        
        /**
         * Filter selected mods to only include those valid for current mode
         */
        filterModsForMode() {
            const valid = this.validMods;
            const filtered = this.selectedMods & valid;
            
            if (filtered !== this.selectedMods) {
                this.$log.debug('LIFECYCLE', 'Filtered mods for mode', { 
                    oldMods: this.selectedMods,
                    newMods: filtered,
                    mode: this.selectedMode,
                    ruleset: this.selectedRuleset 
                });
                this.selectedMods = filtered;
            }
        },
        
        /**
         * Filter selected mods to only include those valid for current ruleset
         */
        filterModsForRuleset() {
            const valid = this.validMods;
            const filtered = this.selectedMods & valid;
            
            if (filtered !== this.selectedMods) {
                this.$log.debug('LIFECYCLE', 'Filtered mods for ruleset', { 
                    oldMods: this.selectedMods,
                    newMods: filtered,
                    mode: this.selectedMode,
                    ruleset: this.selectedRuleset 
                });
                this.selectedMods = filtered;
            }
        },
        
        /**
         * Refetch leaderboards with current filters
         */
        async refetchLeaderboards() {
            this.$log.info('LIFECYCLE', 'Refetching leaderboards with filters', { 
                mode: this.selectedMode,
                ruleset: this.selectedRuleset,
                mods: this.selectedMods 
            });
            
            if (!this.selected) {
                this.$log.warn('LIFECYCLE', 'Cannot refetch - no selected beatmap');
                return;
            }
            
            await this.fetchLeaderboards();
        },
        
        /**
         * Get the display name for a mode
         * @param {number} mode - The mode (0-3)
         * @returns {string} - The display name
         */
        getModeName(mode) {
            const names = ['osu!', 'taiko', 'catch', 'mania'];
            return names[mode] || 'Unknown';
        },
        
        /**
         * Get the display name for a ruleset
         * @param {number} ruleset - The ruleset (0-2)
         * @returns {string} - The display name
         */
        getRulesetName(ruleset) {
            const names = ['Vanilla', 'Relax', 'Autopilot'];
            return names[ruleset] || 'Unknown';
        },
        
        /**
         * Get the icon for a mode
         * @param {number} mode - The mode (0=osu!, 1=taiko, 2=catch, 3=mania)
         * @returns {string} - The HTML for the icon
         */
        getModeIcon(mode) {
            const icons = {
                0: '<i class="fas fa-circle"></i>',      // osu!
                1: '<i class="fas fa-drum"></i>',        // taiko
                2: '<i class="fas fa-apple-alt"></i>',   // catch
                3: '<i class="fas fa-keyboard"></i>'     // mania
            };
            return icons[mode] || '<i class="fas fa-question"></i>';
        },
        
        /**
         * Get the icon for a ruleset
         * @param {number} ruleset - The ruleset (0=vanilla, 1=relax, 2=autopilot)
         * @returns {string} - The HTML for the icon
         */
        getRulesetIcon(ruleset) {
            const icons = {
                0: '<i class="fas fa-gamepad"></i>',     // Vanilla
                1: '<i class="fas fa-couch"></i>',       // Relax
                2: '<i class="fas fa-crosshairs"></i>'   // Autopilot
            };
            return icons[ruleset] || '<i class="fas fa-question"></i>';
        },
        
        /**
         * Get the display name for a mod bit
         * @param {number} modBit - The mod bit (1 << modIndex)
         * @returns {string} - The display name
         */
        getModName(modBit) {
            const modNames = {
                0: 'NF', 1: 'EZ', 2: 'TD', 3: 'HD', 4: 'HR', 5: 'SD', 6: 'DT',
                7: 'RX', 8: 'HT', 9: 'NC', 10: 'FL', 11: 'AU', 12: 'SO', 13: 'AP',
                14: 'PF', 15: '4K', 16: '5K', 17: '6K', 18: '7K', 19: '8K', 20: 'FI',
                21: 'RN', 22: 'CN', 23: 'TP', 24: '9K', 25: 'CO', 26: '1K', 27: '3K',
                28: '2K', 29: 'V2', 30: 'MR'
            };
            const bitIndex = Math.log2(modBit);
            return modNames[bitIndex] || 'Unknown';
        },
        
        /**
         * Get the full display name for a mod bit
         * @param {number} modBit - The mod bit (1 << modIndex)
         * @returns {string} - The full display name
         */
        getModFullName(modBit) {
            const fullNames = {
                0: 'No Fail', 1: 'Easy', 2: 'Touchscreen', 3: 'Hidden', 4: 'Hard Rock',
                5: 'Sudden Death', 6: 'Double Time', 7: 'Relax', 8: 'Half Time',
                9: 'Nightcore', 10: 'Flashlight', 11: 'Autoplay', 12: 'Spun Out',
                13: 'Autopilot', 14: 'Perfect', 15: '4K', 16: '5K', 17: '6K',
                18: '7K', 19: '8K', 20: 'Fade In', 21: 'Random', 22: 'Cinema',
                23: 'Target', 24: '9K', 25: 'Co-op', 26: '1K', 27: '3K', 28: '2K',
                29: 'ScoreV2', 30: 'Mirror'
            };
            const bitIndex = Math.log2(modBit);
            return fullNames[bitIndex] || 'Unknown';
        },
        
        /**
         * Get the Font Awesome icon for a mod bit
         * @param {number} modBit - The mod bit (1 << modIndex)
         * @returns {string} - The HTML for the icon
         */
        getModIcon(modBit) {
            const icons = {
                0: '<i class="fas fa-heart"></i>',           // NF - No Fail
                1: '<i class="fas fa-circle"></i>',          // EZ - Easy
                2: '<i class="fas fa-hand-pointer"></i>',    // TD - Touchscreen
                3: '<i class="fas fa-eye"></i>',             // HD - Hidden
                4: '<i class="fas fa-gem"></i>',             // HR - Hard Rock
                5: '<i class="fas fa-skull"></i>',           // SD - Sudden Death
                6: '<i class="fas fa-bolt"></i>',            // DT - Double Time
                7: '<i class="fas fa-couch"></i>',           // RX - Relax
                8: '<i class="fas fa-hourglass-half"></i>',  // HT - Half Time
                9: '<i class="fas fa-moon"></i>',            // NC - Nightcore
                10: '<i class="fas fa-bolt-lightning"></i>', // FL - Flashlight
                11: '<i class="fas fa-robot"></i>',          // AU - Autoplay
                12: '<i class="fas fa-circle-notch"></i>',   // SO - Spun Out
                13: '<i class="fas fa-crosshairs"></i>',     // AP - Autopilot
                14: '<i class="fas fa-check-circle"></i>',   // PF - Perfect
                15: '<i class="fas fa-keyboard"></i>',       // 4K
                16: '<i class="fas fa-keyboard"></i>',       // 5K
                17: '<i class="fas fa-keyboard"></i>',       // 6K
                18: '<i class="fas fa-keyboard"></i>',       // 7K
                19: '<i class="fas fa-keyboard"></i>',       // 8K
                20: '<i class="fas fa-fade"></i>',           // FI - Fade In
                21: '<i class="fas fa-dice"></i>',           // RN - Random
                22: '<i class="fas fa-film"></i>',           // CN - Cinema
                23: '<i class="fas fa-bullseye"></i>',       // TP - Target
                24: '<i class="fas fa-keyboard"></i>',       // 9K
                25: '<i class="fas fa-users"></i>',          // CO - Co-op
                26: '<i class="fas fa-keyboard"></i>',       // 1K
                27: '<i class="fas fa-keyboard"></i>',       // 3K
                28: '<i class="fas fa-keyboard"></i>',       // 2K
                29: '<i class="fas fa-trophy"></i>',         // V2 - ScoreV2
                30: '<i class="fas fa-arrows-left-right"></i>' // MR - Mirror
            };
            const bitIndex = Math.log2(modBit);
            return icons[bitIndex] || '<i class="fas fa-question"></i>';
        }
    }
});

// ================= SCORE WINDOW =================
bootstrapVue('score-panel', {
    el: '#score-panel-modal',
    templateId: 'score-panel-template',
    data() {
        return { 
            show: false, 
            scoreId: null, 
            score: null, 
            replayIsLoading: false, 
            activeTab: 'Score',
            fetchError: null,
            fetchState: 'idle', // 'idle', 'loading', 'success', 'error'
            isLoadingPlayer: false,
            playerError: null
        };
    },
    created() {
        this.$log = ColorfulLogger.child('Score Panel');
        this.$log.info('LIFECYCLE', 'Score Panel created');
        
        // External trigger
        scoreBus.$on('show-score-window', this.openWithScore);

        // URL-based trigger
        try {
            const score = new URLSearchParams(window.location.search).get('score');
            if (score) {
                this.$log.info('LIFECYCLE', 'URL-based trigger detected, score:', score);
                this.openWithScore(score);
            }
        } catch (err) { 
            this.$log.error('LIFECYCLE', 'Failed to parse score from URL', err); 
        }
    },
    beforeDestroy() {
        this.$log.info('LIFECYCLE', 'Score Panel destroyed, cleaning up');
        // Clean up any pending operations
        if (this.fetchState === 'loading') {
            this.$log.warn('LIFECYCLE', 'Component destroyed while fetch was in progress');
        }
    },
    computed: {
        safeScore() {
            if (!this.score) {
                return null;
            }
            return this.score;
        },
        safeBeatmap() {
            if (!this.score || !this.score.beatmap) {
                return null;
            }
            return this.score.beatmap;
        },
        safePlayer() {
            if (!this.score || !this.score.player) {
                return null;
            }
            return this.score.player;
        },
        hasValidData() {
            return this.score !== null && this.score !== undefined;
        },
        hasCheats() {
            const cheats = this.getCheatValues();
            if (!cheats) {
                return false;
            }
            // Check if there are any non-Misc cheat values
            const categories = this.getCheatValuesByCategory();
            return categories.length > 0;
        }
    },
    
    watch: {
        safePlayer: {
            handler: function(newVal) {
                this.$log.debug('DATA', 'safePlayer changed', {
                    safePlayer: newVal,
                    hasSafePlayer: !!newVal,
                    playerName: newVal?.name,
                    playerId: newVal?.id,
                    playerNameInInfo: newVal?.info?.name,
                    playerIdInInfo: newVal?.info?.id,
                    hasInfo: !!newVal?.info
                });
            },
            deep: true
        }
    },
    methods: {
        async openWithScore(scoreId) {
            this.$log.info('LIFECYCLE', 'openWithScore called with scoreId:', scoreId);
            
            // Validate scoreId
            if (!scoreId || isNaN(scoreId)) {
                this.$log.error('LIFECYCLE', 'Invalid scoreId provided:', scoreId);
                this.fetchError = "Invalid score ID";
                this.fetchState = 'error';
                this.show = true; // Show the error modal
                return;
            }
            
            this.resetState();
            this.scoreId = scoreId;
            this.fetchState = 'loading';
            this.show = true; // Show loading state immediately
            this.$log.info('LIFECYCLE', 'Starting fetch for scoreId:', scoreId);
            
            await this.fetchScoreInfo();
            
            // Only show if we have valid data
            if (this.score && this.fetchState === 'success') {
                this.$log.info('LIFECYCLE', 'Score modal opened successfully:', scoreId);
            } else if (this.fetchState === 'error') {
                this.$log.error('LIFECYCLE', 'Failed to open score modal - fetch error', {
                    scoreId: this.scoreId,
                    fetchError: this.fetchError,
                    fetchState: this.fetchState
                });
                // Error state is already set, modal will show error
            } else {
                this.$log.error('LIFECYCLE', 'Failed to open score modal - no valid score data', {
                    scoreId: this.scoreId,
                    score: this.score,
                    fetchState: this.fetchState
                });
                this.fetchError = "No score data received";
                this.fetchState = 'error';
            }
        },
        close() { 
            this.$log.info('LIFECYCLE', 'Closing score modal', {
                scoreId: this.scoreId,
                fetchState: this.fetchState
            });
            this.show = false; 
            this.resetUrl(); 
        },
        resetState() { 
            this.$log.debug('LIFECYCLE', 'Resetting state');
            this.score = null; 
            this.scoreId = null; 
            this.replayIsLoading = false; 
            this.fetchError = null;
            this.fetchState = 'idle';
        },
        resetUrl() {
            try {
                const url = new URL(window.location.href);
                url.searchParams.delete('score');
                window.history.replaceState({}, '', url);
                this.$log.debug('LIFECYCLE', 'URL reset');
            } catch (err) {
                this.$log.error('LIFECYCLE', 'Failed to reset URL', err);
            }
        },
        async fetchScoreInfo() {
            if (!this.scoreId) {
                this.$log.error('API', 'fetchScoreInfo called without scoreId');
                this.fetchState = 'error';
                this.fetchError = "No score ID";
                return;
            }
            
            try {
                const url = `https://api.${domain}/v1/get_score_info?id=${this.scoreId}&b=1`;
                this.$log.info('API', 'Fetching score info from:', url);
                
                const res = await fetch(url);
                
                // Check HTTP response
                if (!res.ok) {
                    this.$log.error('API', 'HTTP error fetching score info', {
                        status: res.status,
                        statusText: res.statusText,
                        scoreId: this.scoreId
                    });
                    this.fetchState = 'error';
                    this.fetchError = `HTTP ${res.status}: ${res.statusText}`;
                    return;
                }
                
                const data = await res.json();
                this.$log.debug('API', 'API response received', { 
                    hasScore: !!data.score, 
                    hasBeatmapInfo: !!data.beatmap_info,
                    rawData: data 
                });
                
                // Validate response structure
                if (!data || typeof data !== 'object') {
                    this.$log.error('API', 'Invalid API response - not an object', { 
                        scoreId: this.scoreId,
                        response: data 
                    });
                    this.fetchState = 'error';
                    this.fetchError = "Invalid API response format";
                    return;
                }
                
                if (!data.score) {
                    this.$log.error('API', "API response missing 'score' property", { 
                        scoreId: this.scoreId,
                        response: data 
                    });
                    this.fetchState = 'error';
                    this.fetchError = "API response missing score data";
                    return;
                }
                
                if (!data.beatmap_info) {
                    this.$log.warn('API', "API response missing 'beatmap_info' property", { 
                        scoreId: this.scoreId,
                        score: data.score 
                    });
                    // Don't fail completely - score data might still be useful
                }
                
                // Create a safe copy of the score data
                this.score = { ...data.score };
                
                // Add beatmap info if available
                if (data.beatmap_info) {
                    this.score.beatmap = { ...data.beatmap_info };
                    this.$log.debug('DATA', 'Beatmap info attached to score');
                } else {
                    this.score.beatmap = null;
                    this.$log.warn('DATA', 'Beatmap info not available for score');
                }
                
                // Validate that the score object has required properties
                if (this.score.id === undefined || this.score.id === null) {
                    this.$log.warn('DATA', 'Score object missing ID property', {
                        score: this.score
                    });
                }
                
                // Fetch player info if available
                if (this.score.userid) {
                    this.$log.debug('API', 'Fetching player info for user_id:', this.score.userid);
                    await this.fetchPlayerInfo(this.score.userid);
                } else {
                    this.$log.warn('DATA', 'No userid found in score data', {
                        score: this.score
                    });
                }
                
                this.fetchState = 'success';
                this.$log.info('API', 'Score info fetched successfully', {
                    scoreId: this.scoreId,
                    scoreIdInResponse: this.score.id,
                    hasBeatmap: !!this.score.beatmap,
                    hasPlayer: !!this.score.player
                });
                
            } catch (err) { 
                this.$log.error('API', 'Failed to fetch score info', {
                    error: err,
                    scoreId: this.scoreId,
                    errorType: err.constructor.name,
                    errorMessage: err.message,
                    stack: err.stack
                });
                this.fetchState = 'error';
                this.fetchError = err.message || "Unknown fetch error";
            }
        },
        async fetchPlayerInfo(userId) {
            if (!userId || this.isLoadingPlayer) {
                this.$log.debug('API', 'fetchPlayerInfo early return', {
                    hasUserId: !!userId,
                    isLoadingPlayer: this.isLoadingPlayer
                });
                return;
            }
            
            this.isLoadingPlayer = true;
            this.playerError = null;
            
            this.$log.debug('API', 'fetchPlayerInfo starting for userId:', userId);
            
            try {
                const url = `https://api.${domain}/v1/get_player_info?id=${userId}&scope=all`;
                this.$log.info('API', 'Fetching player info from:', url);
                
                const res = await fetch(url);
                
                // Check HTTP response
                if (!res.ok) {
                    this.$log.error('API', 'HTTP error fetching player info', {
                        status: res.status,
                        statusText: res.statusText,
                        userId: userId
                    });
                    this.playerError = `HTTP ${res.status}: ${res.statusText}`;
                    return;
                }
                
                const data = await res.json();
                this.$log.debug('API', 'Player API response received', { 
                    hasPlayer: !!data.player,
                    rawData: data 
                });
                
                // Validate response structure
                if (!data || typeof data !== 'object') {
                    this.$log.error('API', 'Invalid player API response - not an object', { 
                        userId: userId,
                        response: data 
                    });
                    this.playerError = "Invalid player API response format";
                    return;
                }
                
                if (!data.player) {
                    this.$log.error('API', "Player API response missing 'player' property", { 
                        userId: userId,
                        response: data 
                    });
                    this.playerError = "Player API response missing player data";
                    return;
                }
                
                // Attach player info to score object
                if (this.score) {
                    // Create a new score object to ensure Vue's reactivity system detects the change
                    this.score = {
                        ...this.score,
                        player: { ...data.player }
                    };
                    this.$log.debug('DATA', 'Player info attached to score', {
                        hasPlayerId: data.player.hasOwnProperty('player_id'),
                        hasId: data.player.hasOwnProperty('id'),
                        playerIdValue: data.player.player_id,
                        idValue: data.player.id,
                        hasInfo: data.player.hasOwnProperty('info'),
                        hasStats: data.player.hasOwnProperty('stats'),
                        playerName: data.player.info?.name,
                        playerIdInInfo: data.player.info?.id
                    });
                    this.$log.debug('DATA', 'safePlayer computed property', {
                        safePlayer: this.safePlayer,
                        hasSafePlayer: !!this.safePlayer
                    });
                } else {
                    this.$log.warn('DATA', 'No score object to attach player info to');
                }
                
            } catch (err) { 
                this.$log.error('API', 'Failed to fetch player info', {
                    error: err,
                    userId: userId,
                    errorType: err.constructor.name,
                    errorMessage: err.message,
                    stack: err.stack
                });
                this.playerError = err.message || "Unknown fetch error";
            } finally {
                this.isLoadingPlayer = false;
                this.$log.debug('API', 'fetchPlayerInfo completed');
            }
        },
        async DownloadReplay(scoreId) {
            if (this.replayIsLoading) {
                this.$log.warn('API', 'DownloadReplay called while already loading');
                return;
            }
            
            this.$log.info('API', 'Starting replay download for scoreId:', scoreId);
            this.replayIsLoading = true;
            
            try { 
                const url = `https://api.${domain}/v1/get_replay?id=${scoreId}`;
                this.$log.debug('API', 'Redirecting to replay URL:', url);
                window.location.href = url; 
            } catch (err) {
                this.$log.error('API', 'Failed to initiate replay download', {
                    error: err,
                    scoreId: scoreId
                });
            }
            finally { 
                this.replayIsLoading = false; 
            }
        },
        shareScore() {
            if (!this.scoreId) {
                this.$log.error('UTIL', 'Cannot share score - no scoreId');
                return;
            }
            
            try {
                const base = `${window.location.protocol}//${window.location.host}${window.location.pathname}`;
                const url = `${base}?score=${this.scoreId}`;
                this.$log.info('UTIL', 'Sharing score URL:', url);
                
                navigator.clipboard.writeText(url)
                    .then(() => this.$log.info('UTIL', 'Score link copied to clipboard'))
                    .catch(err => this.$log.error('UTIL', 'Clipboard error', err));
            } catch (err) {
                this.$log.error('UTIL', 'Failed to share score', err);
            }
        },
        addCommas(n) {
            if (n === null || n === undefined) {
                this.$log.warn('UTIL', 'addCommas called with null/undefined value:', n);
                return '0';
            }
            
            try {
                const parts = String(n).split('.');
                parts[0] = parts[0].replace(/\B(?=(\d{3})+(?!\d))/g, ',');
                return parts.join('.');
            } catch (err) {
                this.$log.error('UTIL', 'Failed to format number with commas', { 
                    value: n, 
                    error: err 
                });
                return String(n);
            }
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
         * Formats a date string to a more readable local date and time.
         * @param {string} dateString - The date string from your score object.
         * @returns {string} - A formatted date string.
         */
        formatDate(dateString) {
            const options = {
                year: 'numeric',
                month: 'long',
                day: 'numeric',
                hour: '2-digit',
                minute: '2-digit',
                second: '2-digit',
                hour12: false // Use 24-hour format
            };
            return new Date(dateString).toLocaleString(undefined, options);
        },
        MAAIntToStr(val) {
            const result = (() => {
                switch(val) {
                    case 0: return 'V1';
                    case 1: return 'V2';
                    case 2: return 'V3';
                    case 3: return 'V-L1';
                    default: return 'Unknown';
                }
            })();
            
            if (result === 'Unknown') {
                this.$log.warn('UTIL', 'Unknown MAA version value:', val);
            }
            
            return result;
        },
        
        // Computed-like helper methods for template safety
        hasScore() {
            return this.score !== null && this.score !== undefined;
        },
        hasBeatmap() {
            return this.hasScore() && this.score.beatmap !== null && this.score.beatmap !== undefined;
        },
        hasPlayer() {
            return this.hasScore() && this.score.player !== null && this.score.player !== undefined;
        },
        getScoreOrEmpty() {
            if (!this.hasScore()) {
                this.$log.warn("DATA", "Template accessed score when null");
                return {};
            }
            return this.score;
        },
        getBeatmapOrEmpty() {
            if (!this.hasBeatmap()) {
                this.$log.warn("DATA", "Template accessed beatmap when null");
                return {};
            }
            return this.score.beatmap;
        },
        getPlayerOrEmpty() {
            if (!this.hasPlayer()) {
                this.$log.warn("DATA", "Template accessed player when null");
                return {};
            }
            return this.score.player;
        },
        // Safe property accessors for template
        getBeatmapProperty(property, defaultValue = 'Unknown') {
            if (!this.score || !this.score.beatmap || this.score.beatmap[property] === undefined || this.score.beatmap[property] === null) {
                this.$log.warn('DATA', `Template accessed beatmap.${property} when null/undefined`, {
                    scoreId: this.scoreId,
                    property: property,
                    value: this.score?.beatmap?.[property]
                });
                return defaultValue;
            }
            return this.score.beatmap[property];
        },
        
        /**
         * Safe property accessor for player data
         * Handles both nested (player.info.property) and direct (player.property) structures
         */
        getPlayerProperty(property, defaultValue = 'Unknown') {
            if (!this.score || !this.score.player) {
                this.$log.warn('DATA', `Template accessed player.${property} when player is null/undefined`, {
                    scoreId: this.scoreId,
                    property: property,
                    value: undefined
                });
                return defaultValue;
            }
            
            // Try player.info.property first (nested structure)
            if (this.score.player.info && this.score.player.info[property] !== undefined && this.score.player.info[property] !== null) {
                return this.score.player.info[property];
            }
            
            // Fall back to player.property (direct structure)
            if (this.score.player[property] !== undefined && this.score.player[property] !== null) {
                return this.score.player[property];
            }
            
            this.$log.warn('DATA', `Template accessed player.${property} when null/undefined`, {
                scoreId: this.scoreId,
                property: property,
                value: undefined,
                hasInfo: !!this.score.player.info,
                infoValue: this.score.player.info?.[property],
                directValue: this.score.player?.[property]
            });
            return defaultValue;
        },
        
        /**
         * Determines if a grade should have the "passed" class based on the score's grade.
         * Grades are ordered from highest to lowest: SS, S, A, B, C, D
         * @param {string} grade - The grade to check (e.g., 'SS', 'S', 'A', 'B', 'C', 'D')
         * @returns {boolean} - True if the grade is at or below the score's grade
         */
        isGradePassed(grade) {
            if (!this.score || !this.score.grade) {
                return false;
            }
            
            const scoreGrade = this.score.grade.toUpperCase();
            const gradeOrder = ['SS', 'S', 'A', 'B', 'C', 'D'];
            
            const scoreIndex = gradeOrder.indexOf(scoreGrade);
            const checkIndex = gradeOrder.indexOf(grade);
            
            if (scoreIndex === -1 || checkIndex === -1) {
                this.$log.warn('DATA', 'Invalid grade value', {
                    scoreGrade: scoreGrade,
                    checkGrade: grade
                });
                return false;
            }
            
            // A grade is "passed" if it's at or below the score's grade
            // (higher index in the array means lower grade)
            return checkIndex >= scoreIndex;
        },
        
        /**
         * Check if the score has cheat values
         * @returns {boolean} - True if cheat values exist
         */
        hasCheatValues() {
            return this.score && this.score.cheat_values && typeof this.score.cheat_values === 'object';
        },
        
        /**
         * Get the cheat values object
         * @returns {object|null} - The cheat values object or null
         */
        getCheatValues() {
            if (!this.hasCheatValues()) {
                return null;
            }
            return this.score.cheat_values;
        },
        
        /**
         * Get a specific cheat value
         * @param {string} key - The key to retrieve
         * @param {*} defaultValue - Default value if not found
         * @returns {*} - The cheat value or default
         */
        getCheatValue(key, defaultValue = null) {
            const cheats = this.getCheatValues();
            if (!cheats) {
                return defaultValue;
            }
            return cheats[key] !== undefined ? cheats[key] : defaultValue;
        },
        
        /**
         * Check if a cheat value exists
         * @param {string} key - The key to check
         * @returns {boolean} - True if the key exists
         */
        hasCheatValue(key) {
            const cheats = this.getCheatValues();
            return cheats && cheats.hasOwnProperty(key);
        },
        
        /**
         * Get the cheat values as a formatted string for display
         * @returns {string} - Formatted cheat values
         */
        getCheatValuesString() {
            const cheats = this.getCheatValues();
            if (!cheats) {
                return 'No cheat values';
            }
            
            try {
                return JSON.stringify(cheats, null, 2);
            } catch (err) {
                this.$log.error('DATA', 'Failed to stringify cheat values', {
                    error: err,
                    cheats: cheats
                });
                return 'Error formatting cheat values';
            }
        },
        
        /**
         * Get cheat values as a formatted object for display
         * @returns {Array} - Array of cheat value objects with key and value
         */
        getCheatValuesArray() {
            const cheats = this.getCheatValues();
            if (!cheats) {
                return [];
            }
            
            const result = [];
            
            // Helper function to recursively process cheat values
            const processValue = (key, value, prefix = '') => {
                const fullKey = prefix ? `${prefix}.${key}` : key;
                
                if (value && typeof value === 'object' && !Array.isArray(value)) {
                    // Recursively process nested objects
                    Object.keys(value).forEach(nestedKey => {
                        processValue(nestedKey, value[nestedKey], fullKey);
                    });
                } else {
                    // Format the value for display
                    let displayValue = value;
                    
                    if (typeof value === 'boolean') {
                        displayValue = value ? 'Enabled' : 'Disabled';
                    } else if (typeof value === 'number') {
                        displayValue = value.toString();
                    } else if (typeof value === 'string') {
                        displayValue = value;
                    } else if (Array.isArray(value)) {
                        displayValue = value.join(', ');
                    } else {
                        displayValue = JSON.stringify(value);
                    }
                    
                    result.push({
                        key: fullKey,
                        value: displayValue,
                        rawValue: value
                    });
                }
            };
            
            Object.keys(cheats).forEach(key => {
                processValue(key, cheats[key]);
            });
            
            return result;
        },
        
        /**
         * Get cheat values grouped by category (excluding Misc)
         * @returns {Array} - Array of category objects with name and values
         */
        getCheatValuesByCategory() {
            const cheats = this.getCheatValues();
            if (!cheats) {
                return [];
            }
            
            const categories = {
                'Timewarp': [],
                'Aim Assist': [],
                'Changers': [],
                'Removers': [],
                'Relax': []
            };
            
            // Helper function to categorize cheat values
            const categorizeValue = (key, value, parentKey = '') => {
                const fullKey = parentKey ? `${parentKey}.${key}` : key;
                
                // Timewarp category
                if (key.startsWith('Timewarp')) {
                    categories['Timewarp'].push({ key: fullKey, value: this.formatCheatValue(value) });
                }
                // Aim Assist category
                else if (key.startsWith('Aim') || key === 'Algorithm' || key.startsWith('FOV') || 
                         key === 'AccelFactor' || key === 'AssistOnSliders' || key === 'Power' ||
                         key === 'SliderPower' || key === 'BaseStrength' || key === 'MinProximityStrength' ||
                         key === 'MaxProximityStrength' || key === 'MinTimingStrength' || key === 'MaxTimingStrength' ||
                         key === 'MovementThreshold' || key === 'MovementSmoothing' || key === 'MaxOffset' ||
                         key === 'ResyncStrength' || key === 'PredictiveAiming' || key === 'PredictionMs' ||
                         key === 'EnhancedSliderHandling' || key === 'SliderProgressionScale' ||
                         key === 'MinSliderStrength' || key === 'MaxSliderStrength' || key === 'AngleInfluence' ||
                         key === 'MaxAngleInfluence' || key === 'MinAngleStrength' || key === 'MaxAngleStrength' ||
                         key === 'UseAcceleration' || key === 'AccelerationExponent' || key === 'TapOnCorrect' ||
                         key === 'TimesCorrected' || key === 'AimCorrectionValue' || key === 'AimCorrectionRelative' ||
                         key === 'AimStartingDistance' || key === 'AimStoppingDistance' || key === 'AimAssistOnSliders') {
                    categories['Aim Assist'].push({ key: fullKey, value: this.formatCheatValue(value) });
                }
                // Changers category
                else if (key.includes('Changer') || key.includes('AR') || key.includes('CS') || 
                         key.includes('FOV') || key.includes('Preempt') || key.includes('Dynamic')) {
                    categories['Changers'].push({ key: fullKey, value: this.formatCheatValue(value) });
                }
                // Removers category
                else if (key.includes('Remover') || key.includes('HD') || key.includes('FL')) {
                    categories['Removers'].push({ key: fullKey, value: this.formatCheatValue(value) });
                }
                // Relax category
                else if (key.includes('Relax') || key === 'Skooter') {
                    categories['Relax'].push({ key: fullKey, value: this.formatCheatValue(value) });
                }
                // Misc category - skip it
                else if (key === 'Misc' || key.includes('Failing') || key.includes('Misses') || 
                         key.includes('Combo') || key.includes('Parallax') || key.includes('Trail') ||
                         key.includes('Glow') || key.includes('Sound')) {
                    // Skip Misc values
                    return;
                }
                // Default - skip if not categorized
                else {
                    return;
                }
            };
            
            Object.keys(cheats).forEach(key => {
                categorizeValue(key, cheats[key]);
            });
            
            // Convert to array and remove empty categories
            const result = [];
            Object.keys(categories).forEach(category => {
                if (categories[category].length > 0) {
                    result.push({
                        name: category,
                        values: categories[category]
                    });
                }
            });
            
            return result;
        },
        
        /**
         * Format a cheat value for display
         * @param {*} value - The value to format
         * @returns {string} - Formatted value
         */
        formatCheatValue(value) {
            if (typeof value === 'boolean') {
                return value ? '✓ Enabled' : '✗ Disabled';
            } else if (typeof value === 'number') {
                return value.toString();
            } else if (typeof value === 'string') {
                return value;
            } else if (Array.isArray(value)) {
                return value.join(', ');
            } else if (value && typeof value === 'object') {
                return JSON.stringify(value);
            } else {
                return String(value);
            }
        },
        
        /**
         * Get a human-readable name for a cheat key
         * @param {string} key - The cheat key
         * @returns {string} - Human-readable name
         */
        getCheatDisplayName(key) {
            const names = {
                'Timewarp': 'Timewarp',
                'TimewarpType': 'Timewarp Type',
                'TimewarpRate': 'Timewarp Rate',
                'TimewarpMultiplier': 'Timewarp Multiplier',
                'AimType': 'Aim Type',
                'Algorithm': 'Algorithm',
                'AimStrength': 'Aim Strength',
                'AccelFactor': 'Acceleration Factor',
                'AssistOnSliders': 'Assist on Sliders',
                'FOV_Base': 'Base FOV',
                'FOV_Min': 'Minimum FOV',
                'FOV_Max': 'Maximum FOV',
                'FOVScale_Max': 'FOV Scale Max',
                'ARChanger': 'AR Changer',
                'ARChangerAR': 'AR Value',
                'HiddenRemover': 'Hidden Remover',
                'FlashlightRemover': 'Flashlight Remover',
                'RelaxHack': 'Relax Hack',
                'RelaxHackType': 'Relax Hack Type',
                'RelaxNoEarlyHits': 'No Early Hits',
                'RelaxNoWaitLate': 'No Late Hits',
                'RelaxStrictTiming': 'Strict Timing',
                'RelaxFailing': 'Relax Failing',
                'RelaxMisses': 'Relax Misses',
                'RelaxComboBreakSound': 'Relax Combo Break Sound',
                'RelaxLowHpGlow': 'Relax Low HP Glow',
                'GameplayParallax': 'Gameplay Parallax',
                'SmoothTrail': 'Smooth Trail',
                'CSChanger': 'CS Changer',
                'CSChangerType': 'CS Changer Type',
                'CSChangerCS': 'CS Value',
                'Power': 'Power',
                'SliderPower': 'Slider Power',
                'BaseStrength': 'Base Strength',
                'MinProximityStrength': 'Min Proximity Strength',
                'MaxProximityStrength': 'Max Proximity Strength',
                'MinTimingStrength': 'Min Timing Strength',
                'MaxTimingStrength': 'Max Timing Strength',
                'MovementThreshold': 'Movement Threshold',
                'MovementSmoothing': 'Movement Smoothing',
                'MaxOffset': 'Max Offset',
                'ResyncStrength': 'Resync Strength',
                'PredictiveAiming': 'Predictive Aiming',
                'PredictionMs': 'Prediction (ms)',
                'EnhancedSliderHandling': 'Enhanced Slider Handling',
                'SliderProgressionScale': 'Slider Progression Scale',
                'MinSliderStrength': 'Min Slider Strength',
                'MaxSliderStrength': 'Max Slider Strength',
                'AngleInfluence': 'Angle Influence',
                'MaxAngleInfluence': 'Max Angle Influence',
                'MinAngleStrength': 'Min Angle Strength',
                'MaxAngleStrength': 'Max Angle Strength',
                'UseAcceleration': 'Use Acceleration',
                'AccelerationExponent': 'Acceleration Exponent',
                'TapOnCorrect': 'Tap on Correct',
                'TimesCorrected': 'Times Corrected',
                'AimCorrectionValue': 'Aim Correction Value',
                'AimCorrectionRelative': 'Aim Correction Relative',
                'AimStartingDistance': 'Aim Starting Distance',
                'AimStoppingDistance': 'Aim Stopping Distance',
                'AimAssistOnSliders': 'Aim Assist on Sliders',
                'FOV_DynamicScale': 'FOV Dynamic Scale',
                'FOV_ScaleMin': 'FOV Scale Min',
                'FOV_ScaleMax': 'FOV Scale Max',
                'PreemptScale': 'Preempt Scale'
            };
            
            return names[key] || key;
        }
    }
});
