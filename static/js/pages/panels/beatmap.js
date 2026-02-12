window.beatmapBus = new EventBus();
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
                const res = await fetch(`${window.location.protocol}//api.${domain}/v2/maps/${id}`);
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
        selectedMods: 0, // Bitmask of selected mods
        // Mobile leaderboard expansion state
        expandedScoreId: null
    },
    created() {
        this.$log = ColorfulLogger.child('Beatmap Panel');
        this.$log.info('LIFECYCLE', 'Beatmap Panel created');
        beatmapBus.$on('show-beatmap-panel', this.openPanel);
        beatmapBus.$on('select-beatmap', this.selectMap);

        // Global Escape key handler
        this._onDocKeydown = (e) => {
            if (e.key === 'Escape' && this.show) {
                this.close();
            }
        };
        document.addEventListener('keydown', this._onDocKeydown);
    },
    beforeDestroy() {
        this.$log.info('LIFECYCLE', 'Beatmap Panel destroyed, cleaning up');
        beatmapBus.$off('show-beatmap-panel', this.openPanel);
        beatmapBus.$off('select-beatmap', this.selectMap);
        document.removeEventListener('keydown', this._onDocKeydown);

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
                // Note: AUTOPLAY, CINEMA, TARGET are not submittable
                // Note: RELAX and AUTOPILOT are rulesets, not mods
            } else if (mode === 1) { // taiko
                // Note: AUTOPLAY, CINEMA, TARGET are not submittable
                // Note: RELAX is a ruleset, not a mod
            } else if (mode === 2) { // catch
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
            this.expandedScoreId = null;
        },
        // Toggle expanded state for mobile score cards (accordion pattern)
        toggleScoreExpand(scoreId) {
            this.expandedScoreId = this.expandedScoreId === scoreId ? null : scoreId;
        },
        async fetchBeatmaps() {
            this.$log.info('API', 'Fetching beatmaps', { set_id: this.set_id });
            
            try {
                const url = `${window.location.protocol}//api.${domain}/v2/maps?set_id=${this.set_id}`;
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
                let url = `${window.location.protocol}//api.${domain}/v1/get_map_scores?id=${this.selected.id}&scope=best`;
                
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
            const mobilePlayerRow = document.getElementById(`mobile-player-${setId}`);

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
                }
                if (mobilePlayerRow) {
                    mobilePlayerRow.classList.remove('playing');
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
                // Remove playing class from previous elements
                const prevAudio = this.currentAudio;
                const prevSetId = prevAudio.id.replace('audio-', '');
                const prevPlayButton = document.getElementById(`play-${prevSetId}`);
                const prevMobilePlayer = document.getElementById(`mobile-player-${prevSetId}`);
                if (prevPlayButton) {
                    const prevMapPlayDiv = prevPlayButton.parentElement;
                    if (prevMapPlayDiv) {
                        prevMapPlayDiv.classList.remove('playing');
                        prevMapPlayDiv.style.setProperty('--audio-progress', '0%');
                    }
                }
                if (prevMobilePlayer) {
                    prevMobilePlayer.classList.remove('playing');
                    prevMobilePlayer.style.setProperty('--audio-progress', '0%');
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
            if (mobilePlayerRow) {
                mobilePlayerRow.classList.add('playing');
                mobilePlayerRow.style.setProperty('--audio-progress', '0%');
            }

            // Store references for cleanup
            audio.mapPlayDiv = mapPlayDiv;
            audio.mobilePlayerRow = mobilePlayerRow;

            // Start smooth progress animation
            this.startSmoothProgress(audio);

            // Reset progress when audio ends
            audio.addEventListener('ended', () => {
                if (mapPlayDiv) {
                    mapPlayDiv.classList.remove('playing');
                    mapPlayDiv.style.setProperty('--audio-progress', '0%');
                }
                if (audio.mobilePlayerRow) {
                    audio.mobilePlayerRow.classList.remove('playing');
                    audio.mobilePlayerRow.style.setProperty('--audio-progress', '0%');
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
                if (audio.mobilePlayerRow && audio.currentTime === 0) {
                    audio.mobilePlayerRow.classList.remove('playing');
                    audio.mobilePlayerRow.style.setProperty('--audio-progress', '0%');
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
                if (!audio || audio.paused) return;

                const progress = (audio.currentTime / audio.duration) * 100;
                if (audio.mapPlayDiv) {
                    audio.mapPlayDiv.style.setProperty('--audio-progress', `${progress}%`);
                }
                if (audio.mobilePlayerRow) {
                    audio.mobilePlayerRow.style.setProperty('--audio-progress', `${progress}%`);
                }

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

        /**
         *! @Hinamizawa remove if it in future for something else
         * Converts beatmap status number to readable text.
         * @param {number} status - The status code.
         * @returns {string} - Status name like "Ranked", "Loved", etc.
         */
        getStatusName(status) {
            const statusMap = {
                '-1': 'Not Submitted',
                '0': 'Pending',
                '1': 'Update Available',
                '2': 'Ranked',
                '3': 'Approved',
                '4': 'Qualified',
                '5': 'Loved'
            };
            return statusMap[String(status)] || 'Unknown';
        },

        /**
         * Formats a date string into a readable format.
         * @param {string} dateString - ISO date string.
         * @returns {string} - Formatted date like "Mar 10, 2024".
         */
        formatDate(dateString) {
            if (!dateString) return 'Unknown';
            try {
                const date = new Date(dateString);
                return date.toLocaleDateString('en-US', {
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric'
                });
            } catch (e) {
                return 'Unknown';
            }
        },

        /**
         * Formats a number with thousand separators.
         * @param {number} num - The number to format.
         * @returns {string} - Formatted number like "123,456".
         */
        formatNumber(num) {
            if (num === null || num === undefined) return '0';
            return Number(num).toLocaleString('en-US');
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
         * Get the Font Awesome icon for a mod bit | 
         * Note: All these icons are temp asignments and we need to go through the FA catalog to find proper icons
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
