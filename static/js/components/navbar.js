// ================= NAVBAR COMPONENT =================
bootstrapVue('navbar', {
    el: '#navbar',
    data: {
        isMobileMenuOpen: false,
        isAnimating: false,
        searchQuery: '',
        searchResults: {
            players: [],
            maps: []
        },
        searchLoading: false,
        searchError: null,
        searchTimeout: null,
        hasSearched: false,
        currentAudio: null,
        searchId: 0,
        isMobile: false
    },
    created() {
        this.$log = ColorfulLogger.child('Navbar');
        this.$log.info('LIFECYCLE', 'Navbar component created');
        
        // Detect mobile on load and window resize
        this.updateMobileState();
        window.addEventListener('resize', this.updateMobileState.bind(this));
        
        // Listen for search window events
        if (window.searchBus) {
            searchBus.$on('show-search-window', () => {
                if (this.isMobile) {
                    this.isMobileMenuOpen = true;
                    this.$nextTick(() => {
                        const searchInput = this.$refs.mobileSearchInput;
                        if (searchInput) {
                            searchInput.focus();
                        }
                    });
                }
            });
        }
    },
    computed: {
        hasSearchResults() {
            return this.searchResults.players.length > 0 || this.searchResults.maps.length > 0;
        }
    },
    methods: {
        updateMobileState() {
            this.isMobile = window.innerWidth < 1024;
        },
        toggleMobileMenu() {
            this.isMobileMenuOpen = !this.isMobileMenuOpen;
            if (this.isMobileMenuOpen) {
                this.$nextTick(() => {
                    const searchInput = this.$refs.mobileSearchInput;
                    if (searchInput) {
                        searchInput.focus();
                    }
                });
            }
        },
        closeMobileMenu() {
            this.isMobileMenuOpen = false;
            this.resetSearch();
        },
        startAnimation() {
            this.isAnimating = true;
        },
        stopAnimation() {
            this.isAnimating = false;
        },
        showSearchWindow() {
            if (this.isMobile) {
                this.isMobileMenuOpen = true;
                this.$nextTick(() => {
                    const searchInput = this.$refs.mobileSearchInput;
                    if (searchInput) {
                        searchInput.focus();
                    }
                });
            } else {
                if (window.searchBus) {
                    searchBus.$emit('show-search-window');
                }
            }
        },
        async performSearch() {
            if (this.searchQuery.trim() === '') {
                this.searchResults = { players: [], maps: [] };
                this.hasSearched = false;
                return;
            }

            const currentSearchId = ++this.searchId;
            this.hasSearched = true;
            this.searchLoading = true;
            this.searchError = null;

            try {
                // Fetch players
                try {
                    const playersResponse = await fetch(
                        `${window.location.protocol}//api.${domain}/v1/search_players?limit=3&q=${encodeURIComponent(this.searchQuery)}`,
                        { signal: AbortSignal.timeout(3000) }
                    );
                    
                    if (!playersResponse.ok) {
                        throw new Error(`HTTP ${playersResponse.status}`);
                    }
                    
                    const playersData = await playersResponse.json();
                    if (currentSearchId === this.searchId) {
                        this.searchResults.players = playersData.result || [];
                    }
                } catch (err) {
                    if (currentSearchId === this.searchId) {
                        this.searchError = 'Failed to load players';
                        this.$log.error('API', 'Search error (players)', err);
                    }
                }

                // Fetch beatmaps
                try {
                    const mapsResponse = await fetch(
                        `https://osu.direct/api/search?amount=3&query=${encodeURIComponent(this.searchQuery)}`,
                        { signal: AbortSignal.timeout(3000) }
                    );
                    
                    if (!mapsResponse.ok) {
                        throw new Error(`HTTP ${mapsResponse.status}`);
                    }
                    
                    const mapsData = await mapsResponse.json();
                    if (currentSearchId === this.searchId) {
                        this.searchResults.maps = (mapsData || []).map(map => ({
                            ...map,
                            thumbnailError: false
                        }));
                    }
                } catch (err) {
                    if (currentSearchId === this.searchId) {
                        this.searchError = 'Failed to load beatmaps';
                        this.$log.error('API', 'Search error (maps)', err);
                    }
                }
            } finally {
                if (currentSearchId === this.searchId) {
                    this.searchLoading = false;
                }
            }
        },
        handleSearchInput() {
            clearTimeout(this.searchTimeout);
            const delay = Math.max(800 - (this.searchQuery.length * 60), 300);
            this.searchTimeout = setTimeout(() => this.performSearch(), delay);
        },
        resetSearch() {
            this.searchQuery = '';
            this.searchResults = { players: [], maps: [] };
            this.searchLoading = false;
            this.searchError = null;
            this.hasSearched = false;
            this.clearAudio();
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
            
            // Close mobile menu
            this.closeMobileMenu();
            
            // Emit event to open beatmap panel
            if (window.beatmapBus) {
                beatmapBus.$emit('show-beatmap-panel', null, map.SetID);
            }
        },
        openPlayerProfile(player) {
            if (!player || !player.info || !player.info.id) return;
            
            // Close mobile menu
            this.closeMobileMenu();
            
            // Navigate to player profile
            window.location.href = `/u/${player.info.id}`;
        },
        getNormalizedDifficulties(map) {
            if (!map || !map.ChildrenBeatmaps) return [];
            
            return map.ChildrenBeatmaps.map(diff => ({
                id: diff.BeatmapID,
                diff: diff.DifficultyRating,
                mode: diff.Mode,
                version: diff.DiffName,
                bpm: diff.BPM,
                hit_length: diff.HitLength,
                difficulty_rating: diff.DifficultyRating
            }));
        },
        toggleMobileDropdown(event) {
            const dropdown = event.currentTarget.parentElement;
            dropdown.classList.toggle('active');
        }
    },
    beforeDestroy() {
        // Clean up event bus listeners
        if (window.searchBus && this.handleShowSearchWindow) {
            searchBus.$off('show-search-window', this.handleShowSearchWindow);
        }
        
        // Clean up audio references
        this.clearAudio();
        
        // Clean up search timeout
   if (this.searchTimeout) {
            clearTimeout(this.searchTimeout);
            this.searchTimeout = null;
        }
        
        // Clean up resize listener
        window.removeEventListener('resize', this.updateMobileState.bind(this));
    }
});