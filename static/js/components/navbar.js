// ================= NAVBAR COMPONENT =================

// Wait for Vue to be available
if (typeof Vue === 'undefined') {
    console.error('Vue is not loaded yet. Navbar component cannot initialize.');
} else {
    // Check if bootstrapVue exists
    if (typeof bootstrapVue === 'undefined') {
        console.error('bootstrapVue is not loaded. Navbar component cannot initialize.');
    } else {
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
                isMobile: false,
                resizeListener: null,
                searchBusListener: null,
                isUserDropdownOpen: false,
                currentHue: 180,
                _userDropdownClickHandler: null,
                _userDropdownKeyHandler: null
            },
            created() {
                this.$log = ColorfulLogger.child('Navbar');
                this.$log.info('LIFECYCLE', 'Navbar component created');
                
                // Detect mobile on load and window resize
                this.updateMobileState();
                this.resizeListener = this.updateMobileState.bind(this);
                window.addEventListener('resize', this.resizeListener);
                
                // User dropdown: close on outside click
                this._userDropdownClickHandler = (e) => {
                    if (this.isUserDropdownOpen) {
                        const container = this.$el.querySelector('.navbar-user-dropdown-container');
                        if (container && !container.contains(e.target)) {
                            this.isUserDropdownOpen = false;
                        }
                    }
                };
                document.addEventListener('mousedown', this._userDropdownClickHandler);

                // User dropdown: close on Escape
                this._userDropdownKeyHandler = (e) => {
                    if (e.key === 'Escape' && this.isUserDropdownOpen) {
                        this.isUserDropdownOpen = false;
                    }
                };
                document.addEventListener('keydown', this._userDropdownKeyHandler);

                // Read initial hue from the CSS variable set by base.html
                const rootHue = getComputedStyle(document.documentElement).getPropertyValue('--main').trim();
                this.currentHue = parseInt(rootHue) || 180;

                // Format donor expiry after DOM renders
                this.$nextTick(() => this._formatDonorExpiry());

                // Listen for search window events
                if (window.searchBus) {
                    this.searchBusListener = () => {
                        if (this.isMobile) {
                            this.isMobileMenuOpen = true;
                            this.$nextTick(() => {
                                const searchInput = this.$refs.mobileSearchInput;
                                if (searchInput) {
                                    searchInput.focus();
                                }
                            });
                        }
                    };
                    searchBus.$on('show-search-window', this.searchBusListener);
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
                // ── User dropdown methods ──
                toggleUserDropdown() {
                    this.isUserDropdownOpen = !this.isUserDropdownOpen;
                },
                closeUserDropdown() {
                    this.isUserDropdownOpen = false;
                },
                previewHue(value) {
                    document.documentElement.style.setProperty('--main', value);
                    this.currentHue = parseInt(value);
                },
                async saveHue(value) {
                    const hue = parseInt(value);
                    try {
                        const formData = new FormData();
                        formData.append('hue', hue);
                        const res = await fetch('/settings/hue', {
                            method: 'POST',
                            body: formData
                        });
                        if (!res.ok) throw new Error('Failed to save');
                        this.currentHue = hue;
                    } catch (err) {
                        this.$log.error('HUE', 'Failed to save hue', err);
                    }
                },
                _formatDonorExpiry() {
                    const el = this.$el.querySelector('.nuc-supporter-expiry');
                    if (!el) return;

                    const donorEnd = parseInt(el.getAttribute('data-donor-end'), 10);
                    if (!donorEnd) return;

                    const now = Date.now() / 1000;
                    if (donorEnd <= now) {
                        el.textContent = 'Expired';
                        return;
                    }

                    let remaining = donorEnd - now;
                    const years = Math.floor(remaining / (365.25 * 86400));
                    remaining -= years * 365.25 * 86400;
                    const months = Math.floor(remaining / (30.44 * 86400));
                    remaining -= months * 30.44 * 86400;
                    const days = Math.floor(remaining / 86400);

                    let parts = [];
                    if (years > 0) parts.push(`${years}y`);
                    if (months > 0) parts.push(`${months}mo`);
                    if (parts.length === 0 && days > 0) parts.push(`${days}d`);
                    if (parts.length === 0) parts.push('< 1d');

                    el.textContent = 'Expires: ' + parts.join(' ');
                },

                toggleMobileDropdown(event) {
                    const dropdown = event.currentTarget.parentElement;
                    dropdown.classList.toggle('active');
                },
                showDocsPanel(doc, page) {
                    docsBus.$emit('show-docs-panel', doc || 'Rules', page || 'Main');
                }
            },
            beforeDestroy() {
                // Clean up event bus listeners
                if (window.searchBus && this.searchBusListener) {
                    searchBus.$off('show-search-window', this.searchBusListener);
                }
                
                // Clean up audio references
                this.clearAudio();
                
                // Clean up search timeout
                if (this.searchTimeout) {
                    clearTimeout(this.searchTimeout);
                    this.searchTimeout = null;
                }
                
                // Clean up resize listener
                if (this.resizeListener) {
                    window.removeEventListener('resize', this.resizeListener);
                }

                // Clean up user dropdown listeners
                if (this._userDropdownClickHandler) {
                    document.removeEventListener('mousedown', this._userDropdownClickHandler);
                }
                if (this._userDropdownKeyHandler) {
                    document.removeEventListener('keydown', this._userDropdownKeyHandler);
                }
            }
        });
    }
}