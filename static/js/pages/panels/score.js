window.scoreBus = new EventBus();
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
            playerError: null,
            showActionSheet: false
        };
    },
    created() {
        this.$log = ColorfulLogger.child('Score Panel');
        this.$log.info('LIFECYCLE', 'Score Panel created');

        // External trigger
        scoreBus.$on('show-score-window', this.openWithScore);

        // Global Escape key handler
        this._onDocKeydown = (e) => {
            if (e.key === 'Escape' && this.show) {
                if (this.showActionSheet) {
                    this.closeActionSheet();
                } else {
                    this.close();
                }
            }
        };
        document.addEventListener('keydown', this._onDocKeydown);

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
        document.removeEventListener('keydown', this._onDocKeydown);
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
        },
        josuUrl() {
            if (!this.scoreId) return null;
            const replayUrl = `${window.location.protocol}//api.${domain}/v1/get_replay?id=${this.scoreId}`;
            return `https://josu.hinamizawa.ai/?r=${encodeURIComponent(replayUrl)}`;
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
            this.showActionSheet = false;
            this.show = false;
            this.resetUrl();
        },
        openActionSheet() {
            this.showActionSheet = true;
            // Lock scroll on the panel content behind the sheet
            var panel = this.$el.querySelector('[data-panel="Score"]');
            if (panel) panel.style.overflow = 'hidden';
            this.$nextTick(() => {
                var first = this.$el.querySelector('.action-sheet-item:not([disabled])');
                if (first) first.focus();
            });
        },
        closeActionSheet() {
            this.showActionSheet = false;
            // Restore scroll on the panel content
            var panel = this.$el.querySelector('[data-panel="Score"]');
            if (panel) panel.style.overflow = '';
            this.$nextTick(() => {
                var trigger = this.$el.querySelector('.action-sheet-trigger');
                if (trigger) trigger.focus();
            });
        },
        viewBeatmapPage() {
            if (!this.safeBeatmap) return;
            // Close score panel, then open beatmap panel
            this.close();
            if (window.beatmapBus) {
                beatmapBus.$emit('show-beatmap-panel', this.safeBeatmap.id, this.safeBeatmap.set_id);
            }
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
                const url = `${window.location.protocol}//api.${domain}/v1/get_score_info?id=${this.scoreId}&b=1`;
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
                const url = `${window.location.protocol}//api.${domain}/v1/get_player_info?id=${userId}&scope=all`;
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
                const url = `${window.location.protocol}//api.${domain}/v1/get_replay?id=${scoreId}`;
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
            const gradeOrder = ['SS', 'S', 'A', 'B', 'C', 'D', 'F'];
            
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
        },
        openReplay(scoreId, external) {
          if (!scoreId) {
            this.$log.error('UTIL', 'openReplay called without scoreId');
            return;
          }

          if (external) {
            // Open JoSu in a new tab
            const replayUrl = `${window.location.protocol}//api.${domain}/v1/get_replay?id=${scoreId}`;
            const josuUrl = `https://josu.hinamizawa.ai/?r=${encodeURIComponent(replayUrl)}`;
            this.$log.info('UTIL', 'Opening replay in JoSu (external)', { scoreId, josuUrl });
            window.open(josuUrl, '_blank', 'noopener,noreferrer');
          } else {
            // Switch to Replay tab (iframe loads automatically via computed josuUrl)
            this.$log.info('UTIL', 'Switching to Replay tab', { scoreId });
            this.activeTab = 'Replay';
          }
        }
    }
});
