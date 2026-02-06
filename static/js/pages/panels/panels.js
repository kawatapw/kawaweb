const searchBus = new EventBus();
const docsBus = new EventBus();

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
                        `${window.location.protocol}//api.${domain}/v1/search_players?limit=10&q=${encodeURIComponent(this.query)}`,
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
    el: '#docs-panel',
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
