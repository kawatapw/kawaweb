new Vue({
    el: "#app",
    delimiters: ["<%", "%>"],
    data() {
        return {
            flags: window.flags,
            boards: {},
            mode: 'std',
            view: 'alltime',
            season: 0, // Fixed default: 0 for all-time, actual season ID for seasonal
            mods: 'vn',
            sort: 'pp',
            page: 1,
            pageSize: 50,
            load: false,
            no_player: false,
            // New properties for season handling
            schedules: [],
            allSeasons: [],
            selectedSchedule: null,
            selectedYear: null,
            yearOptions: [],
            seasonOptions: [],
            // Dropdown focus states
            scheduleFocused: false,
            yearFocused: false,
            seasonFocused: false,
            // Error and loading states
            seasonsLoading: false,
            seasonsError: null,
            seasonsAvailable: true,
            // Fallback data for when API fails
            fallbackSchedules: [],
            fallbackSeasons: [],
            // Debug mode and logging
            debugMode: false,
            debugLogs: [],
        };
    },
    mounted() {
        // Fetch schedule and season data when component is mounted
        this.fetchSeasonData();
        
        // Add keyboard shortcut for debug mode (F12)
        document.addEventListener('keydown', (event) => {
            if (event.key === 'F12') {
                event.preventDefault();
                this.toggleDebugMode();
            }
        });
    },
    
    created() {
        this.$log = ColorfulLogger.child('Leaderboard Page');
        this.LoadData(mode, mods, sort, view, season) ;
        this.LoadLeaderboard(sort, mode, mods, view, season);
    },
    
    methods: {
        // Validate API response structure
        validateApiResponse(response, requiredFields = []) {
            if (!response || !response.data) {
                throw new Error('Invalid API response structure');
            }
            
            for (const field of requiredFields) {
                if (!response.data[field]) {
                    throw new Error(`Missing required field: ${field}`);
                }
            }
            
            return true;
        },
        
        // Sanitize year extraction from season data
        extractYearFromSeason(season) {
            try {
                // Try direct year field first
                if (typeof season.year === 'number' && season.year > 1900 && season.year < 2100) {
                    return season.year;
                }
                
                // Try extracting from name using regex
                if (typeof season.name === 'string') {
                    const yearMatch = season.name.match(/\b(19|20)\d{2}\b/);
                    if (yearMatch) {
                        const year = parseInt(yearMatch[0]);
                        if (year >= 1900 && year <= new Date().getFullYear() + 1) {
                            return year;
                        }
                    }
                }
                
                return null;
            } catch (error) {
                console.warn('Error extracting year from season:', season, error);
                return null;
            }
        },
        
        // Validate season belongs to selected schedule and year
        validateSeasonSelection() {
            if (!this.selectedSchedule || !this.selectedYear) {
                return false;
            }
            
            const validSeasons = this.computeSeasonOptions();
            return validSeasons.some(season => season.id === this.season);
        },
        
        // Get fallback data when API fails
        getFallbackData() {
            return {
                schedules: [
                    { id: 1, name: 'Default Schedule' }
                ],
                seasons: [
                    { id: 0, name: 'All-Time', schedule_id: 1, year: new Date().getFullYear(), is_active: false }
                ]
            };
        },
        
        // Show user-friendly error message
        showError(message) {
            this.seasonsError = message;
            this.seasonsAvailable = false;
            this.$log.error('Seasons Error', message);
            
            // Auto-hide error after 5 seconds
            setTimeout(() => {
                this.seasonsError = null;
                this.seasonsAvailable = true;
            }, 5000);
        },
        
        LoadData(mode, mods, sort, view, season) {
            this.$set(this, 'mode', mode);
            this.$set(this, 'mods', mods);
            this.$set(this, 'sort', sort);
            this.$set(this, 'view', view);
            this.$set(this, 'season', season);
        },
        LoadLeaderboard(sort, mode, mods, view, season) {
            if (window.event)
                window.event.preventDefault();

            window.history.replaceState('', document.title, `/leaderboard/${this.mode}/${this.sort}/${this.mods}/${this.view}/${this.season}`);
            this.$set(this, 'mode', mode);
            this.$set(this, 'mods', mods);
            this.$set(this, 'sort', sort);
            this.$set(this, 'view', view);
            this.$set(this, 'season', season);
            this.$set(this, 'load', true);
            const offset = (this.page - 1) * this.pageSize; // Calculate the offset
            const season_id = this.view === 'alltime' ? 0 : this.season;
            this.$axios.get(`${window.location.protocol}//api.${domain}/v1/get_leaderboard`, {
                params: {
                    mode: this.StrtoGulagInt(),
                    sort: this.sort,
                    offset: offset,
                    limit: this.pageSize,
                    season: season_id
                }
            }).then(res => {
                this.$log.debug("LB-DATA", "Leaderboard data loaded", res.data);
                this.boards = res.data.leaderboard;
                this.$set(this, 'load', false);
            });
        },
        async fetchSeasonData() {
            this.seasonsLoading = true;
            this.seasonsError = null;
            
            try {
                // Try to fetch seasons data directly first using axios (handles CORS properly)
                const schedulesUrl = `${window.location.protocol}//api.${domain}/v2/schedules`;
                const seasonsUrl = `${window.location.protocol}//api.${domain}/v2/seasons`;
                
                // Fetch with timeout and retry logic using axios
                const schedulesRes = await this.fetchWithRetryAxios(schedulesUrl, 'schedules');
                const seasonsRes = await this.fetchWithRetryAxios(seasonsUrl, 'seasons');
                
                // Validate response structure
                this.validateApiResponse(schedulesRes, ['data']);
                this.validateApiResponse(seasonsRes, ['data']);
                
                // Validate data integrity
                const schedules = this.validateSchedulesData(schedulesRes.data.data);
                const seasons = this.validateSeasonsData(seasonsRes.data.data);
                
                if (schedules.length === 0 || seasons.length === 0) {
                    throw new Error('No valid schedule or season data received');
                }
                
                this.schedules = schedules;
                this.allSeasons = seasons;
                
                // Initialize selections with validation
                await this.initializeSeasonSelections();
                
                this.seasonsAvailable = true;
                this.$log.info('Seasons data loaded successfully');
                
            } catch (error) {
                // Only show error if it's not a 404 (API doesn't exist)
                if (error.message.includes('404')) {
                    this.$log.info('Seasons API not available, using fallback mode');
                    this.setupFallbackMode();
                } else {
                    this.handleSeasonsError(error);
                }
            } finally {
                this.seasonsLoading = false;
            }
        },
        
        // Set up fallback mode when API doesn't exist
        setupFallbackMode() {
            // Set up minimal fallback data
            this.schedules = [{ id: 1, name: 'Default Schedule' }];
            this.allSeasons = [
                { id: 0, name: 'All-Time', schedule_id: 1, year: new Date().getFullYear(), is_active: false }
            ];
            
            // Initialize with fallback data
            this.selectedSchedule = this.schedules[0];
            this.selectedYear = new Date().getFullYear();
            this.season = 0;
            this.view = 'alltime'; // Force all-time view when API doesn't exist
            
            // Update UI options
            this.yearOptions = [{ year: this.selectedYear, name: this.selectedYear.toString() }];
            this.seasonOptions = [{ id: 0, name: 'All-Time' }];
            
            this.$log.info('Fallback mode activated - seasons API not available');
        },
        
        // Check if seasons API endpoints exist
        async checkSeasonsAPI() {
            try {
                const schedulesUrl = `${window.location.protocol}//api.${domain}/v2/schedules`;
                const controller = new AbortController();
                const timeoutId = setTimeout(() => controller.abort(), 3000);
                
                const response = await fetch(schedulesUrl, {
                    method: 'HEAD',
                    signal: controller.signal,
                    headers: {
                        'Accept': 'application/json'
                    }
                });
                
                clearTimeout(timeoutId);
                return response.ok;
                
            } catch (error) {
                this.$log.warn('Seasons API check failed:', error.message);
                return false;
            }
        },
        
        // Enhanced fetch with retry logic and timeout using axios (handles CORS properly)
        async fetchWithRetryAxios(url, dataType, maxRetries = 3) {
            const timeout = 10000; // 10 second timeout
            let lastError;
            
            for (let attempt = 1; attempt <= maxRetries; attempt++) {
                try {
                    const response = await this.$axios.get(url, {
                        timeout: timeout,
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    return response;
                    
                } catch (error) {
                    lastError = error;
                    this.$log.warn(`Attempt ${attempt}/${maxRetries} failed for ${dataType}:`, error.message);
                    
                    if (attempt < maxRetries) {
                        // Exponential backoff
                        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
                        await new Promise(resolve => setTimeout(resolve, delay));
                    }
                }
            }
            
            throw lastError;
        },
        
        // Enhanced fetch with retry logic and timeout using fetch (kept for compatibility)
        async fetchWithRetry(url, dataType, maxRetries = 3) {
            const timeout = 10000; // 10 second timeout
            let lastError;
            
            for (let attempt = 1; attempt <= maxRetries; attempt++) {
                try {
                    const controller = new AbortController();
                    const timeoutId = setTimeout(() => controller.abort(), timeout);
                    
                    const response = await fetch(url, {
                        signal: controller.signal,
                        headers: {
                            'Accept': 'application/json',
                            'Content-Type': 'application/json'
                        }
                    });
                    
                    clearTimeout(timeoutId);
                    
                    if (!response.ok) {
                        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
                    }
                    
                    return await response.json();
                    
                } catch (error) {
                    lastError = error;
                    this.$log.warn(`Attempt ${attempt}/${maxRetries} failed for ${dataType}:`, error.message);
                    
                    if (attempt < maxRetries) {
                        // Exponential backoff
                        const delay = Math.min(1000 * Math.pow(2, attempt - 1), 5000);
                        await new Promise(resolve => setTimeout(resolve, delay));
                    }
                }
            }
            
            throw lastError;
        },
        
        // Validate and sanitize schedules data
        validateSchedulesData(schedules) {
            if (!Array.isArray(schedules)) {
                this.$log.warn('Invalid schedules data format, expected array');
                return [];
            }
            
            return schedules
                .filter(schedule => {
                    // Basic validation
                    return schedule && 
                           typeof schedule.id === 'number' && 
                           typeof schedule.name === 'string' &&
                           schedule.name.trim().length > 0;
                })
                .map(schedule => ({
                    id: parseInt(schedule.id),
                    name: schedule.name.trim(),
                    // Add any additional fields safely
                    ...schedule
                }))
                .sort((a, b) => a.id - b.id); // Sort by ID
        },
        
        // Validate and sanitize seasons data
        validateSeasonsData(seasons) {
            if (!Array.isArray(seasons)) {
                this.$log.warn('Invalid seasons data format, expected array');
                return [];
            }
            
            const currentYear = new Date().getFullYear();
            const nextYear = currentYear + 1;
            
            return seasons
                .filter(season => {
                    // Basic validation
                    const hasValidId = typeof season.id === 'number' && season.id > 0;
                    const hasValidName = typeof season.name === 'string' && season.name.trim().length > 0;
                    const hasValidSchedule = typeof season.schedule_id === 'number' && season.schedule_id > 0;
                    
                    // Validate year if present
                    let hasValidYear = true;
                    if (season.year != null) {
                        const year = parseInt(season.year);
                        hasValidYear = !isNaN(year) && year >= 2000 && year <= nextYear;
                    }
                    
                    return hasValidId && hasValidName && hasValidSchedule && hasValidYear;
                })
                .map(season => ({
                    id: parseInt(season.id),
                    name: season.name.trim(),
                    schedule_id: parseInt(season.schedule_id),
                    year: season.year ? parseInt(season.year) : this.extractYearFromSeason(season),
                    is_active: Boolean(season.is_active),
                    // Add any additional fields safely
                    ...season
                }))
                .sort((a, b) => {
                    // Sort by year (descending), then by name
                    if (a.year && b.year) {
                        return b.year - a.year;
                    }
                    return a.name.localeCompare(b.name);
                });
        },
        
        // Initialize season selections with proper validation
        async initializeSeasonSelections() {
            // Find active season
            const activeSeason = this.allSeasons.find(se => se.is_active);
            
            // Set selected schedule
            if (activeSeason) {
                this.selectedSchedule = this.schedules.find(s => s.id === activeSeason.schedule_id) || this.schedules[0];
            } else {
                this.selectedSchedule = this.schedules[0];
            }
            
            // Set initial season
            if (activeSeason) {
                this.season = activeSeason.id;
            } else {
                // Default to first season of selected schedule or 0 (all-time)
                const scheduleSeasons = this.allSeasons.filter(se => se.schedule_id === this.selectedSchedule.id);
                this.season = scheduleSeasons.length > 0 ? scheduleSeasons[0].id : 0;
            }
            
            // Compute and set year options
            this.yearOptions = this.computeYearOptions();
            
            // Set selected year
            if (activeSeason && activeSeason.year) {
                this.selectedYear = activeSeason.year;
            } else if (this.yearOptions.length > 0) {
                this.selectedYear = this.yearOptions[0].year;
            } else {
                this.selectedYear = new Date().getFullYear();
            }
            
            // Compute season options and validate selection
            this.seasonOptions = this.computeSeasonOptions();
            
            // Ensure selected season is valid for current filters
            if (!this.validateSeasonSelection() && this.seasonOptions.length > 0) {
                this.season = this.seasonOptions[0].id;
            }
            
            // If view is seasonal but no valid season, switch to all-time
            if (this.view === 'seasonal' && this.season === 0 && this.seasonOptions.length > 1) {
                this.season = this.seasonOptions[1].id || this.seasonOptions[0].id;
            }
        },
        
        // Handle seasons API errors with fallback
        handleSeasonsError(error) {
            this.$log.error('Seasons API error:', error);
            
            // Show user-friendly error message
            let errorMessage = 'Failed to load seasonal data. Using fallback options.';
            
            if (error.message.includes('timeout')) {
                errorMessage = 'Seasonal data is taking too long to load. Please try again later.';
            } else if (error.message.includes('404')) {
                errorMessage = 'Seasonal features are not available on this server.';
            } else if (error.message.includes('network')) {
                errorMessage = 'Network error while loading seasonal data. Please check your connection.';
            }
            
            this.showError(errorMessage);
            
            // Set up fallback data
            const fallback = this.getFallbackData();
            this.schedules = fallback.schedules;
            this.allSeasons = fallback.seasons;
            
            // Initialize with fallback data
            this.selectedSchedule = fallback.schedules[0];
            this.selectedYear = new Date().getFullYear();
            this.season = 0; // Default to all-time when API fails
            
            // Update UI options
            this.yearOptions = [{ year: this.selectedYear, name: this.selectedYear.toString() }];
            this.seasonOptions = [{ id: 0, name: 'All-Time' }];
            
            // Switch view to all-time if it was seasonal
            if (this.view === 'seasonal') {
                this.view = 'alltime';
                this.$log.warn('Switched to all-time view due to API failure');
            }
            
            // Reload leaderboard with fallback settings
            this.reloadLeaderboard();
        },
        computeYearOptions() {
            const options = [];
            const scheduleId = this.selectedSchedule ? this.selectedSchedule.id : null;
            
            // Get seasons for the selected schedule (or all seasons if none selected)
            const relevantSeasons = scheduleId 
                ? this.allSeasons.filter(se => se.schedule_id === scheduleId)
                : this.allSeasons;
            
            // Extract unique years from seasons, handling potential missing year property
            const years = [...new Set(
                relevantSeasons
                    .map(se => se.year || (se.name && se.name.match(/\d{4}/) ? parseInt(se.name.match(/\d{4}/)[0]) : null))
                    .filter(year => year != null)
            )];
            
            // Sort years in descending order (most recent first)
            years.sort((a, b) => b - a);
            
            // Create options array
            years.forEach(year => {
                options.push({ year: year, name: year.toString() });
            });
            
            return options;
        },
        
        computeSeasonOptions() {
            const options = [];
            const scheduleId = this.selectedSchedule ? this.selectedSchedule.id : null;
            const year = this.selectedYear;
            
            if (scheduleId && year) {
                // Filter seasons by both schedule and year
                const filtered = this.allSeasons.filter(se => {
                    const seasonYear = se.year || (se.name && se.name.match(/\d{4}/) ? parseInt(se.name.match(/\d{4}/)[0]) : null);
                    return se.schedule_id === scheduleId && seasonYear === year;
                });
                options.push(...filtered.map(se => ({id: se.id, name: se.name})));
            } else if (scheduleId) {
                // Only schedule selected, filter by schedule only
                const filtered = this.allSeasons.filter(se => se.schedule_id === scheduleId);
                options.push(...filtered.map(se => ({id: se.id, name: se.name})));
            } else {
                // No filters, show all seasons
                options.push(...this.allSeasons.map(se => ({id: se.id, name: se.name})));
            }
            return options;
        },
        scoreFormat(score) {
            var addCommas = this.addCommas;
            if (score > 1000 * 1000) {
                if (score > 1000 * 1000 * 1000)
                    return `${addCommas((score / 1000000000).toFixed(2))} billion`;
                return `${addCommas((score / 1000000).toFixed(2))} million`;
            }
            return addCommas(score);
        },
        addCommas(nStr) {
            nStr += '';
            var x = nStr.split('.');
            var x1 = x[0];
            var x2 = x.length > 1 ? '.' + x[1] : '';
            var rgx = /(\d+)(\d{3})/;
            while (rgx.test(x1)) {
                x1 = x1.replace(rgx, '$1' + ',' + '$2');
            }
            return x1 + x2;
        },
        StrtoGulagInt() {
            switch (this.mode + "|" + this.mods) {
                case 'std|vn':
                    return 0;
                case 'taiko|vn':
                    return 1;
                case 'catch|vn':
                    return 2;
                case 'mania|vn':
                    return 3;
                case 'std|rx':
                    return 4;
                case 'taiko|rx':
                    return 5;
                case 'catch|rx':
                    return 6;
                case 'std|ap':
                    return 8;
                default:
                    return -1;
            }
        },
        changePage(page) {
            this.page = page;
            this.LoadLeaderboard(this.sort, this.mode, this.mods, this.view, this.season);
        },
        getRank(index) {
            return (this.page - 1) * this.pageSize + index + 1;
        },
        onScheduleChange() {
            try {
                // Validate schedule selection
                if (!this.selectedSchedule) {
                    this.$log.warn('No schedule selected, using first available');
                    if (this.schedules.length > 0) {
                        this.selectedSchedule = this.schedules[0];
                    } else {
                        this.showError('No schedules available');
                        return;
                    }
                }
                
                // Update year options when schedule changes
                this.yearOptions = this.computeYearOptions();
                
                // Set default year to first available year or current year
                if (this.yearOptions.length > 0) {
                    this.selectedYear = this.yearOptions[0].year;
                } else {
                    this.selectedYear = new Date().getFullYear();
                    this.yearOptions = [{ year: this.selectedYear, name: this.selectedYear.toString() }];
                }
                
                // Update season options based on new schedule and year
                this.seasonOptions = this.computeSeasonOptions();
                
                // Select first valid season option
                if (this.seasonOptions.length > 0) {
                    this.season = this.seasonOptions[0].id;
                } else {
                    this.season = 0;
                    this.seasonOptions = [{ id: 0, name: 'All-Time' }];
                }
                
                // Validate the selection is consistent
                if (!this.validateSeasonSelection()) {
                    this.$log.warn('Season selection inconsistent after schedule change');
                    this.season = this.seasonOptions[0].id;
                }
                
                this.reloadLeaderboard();
                
            } catch (error) {
                this.$log.error('Error in schedule change handler:', error);
                this.showError('Error updating schedule. Please try again.');
            }
        },
        
        onYearChange() {
            try {
                // Validate year selection
                if (!this.selectedYear) {
                    this.$log.warn('No year selected, using current year');
                    this.selectedYear = new Date().getFullYear();
                }
                
                // Update season options when year changes
                this.seasonOptions = this.computeSeasonOptions();
                
                // Select first valid season option for the new year
                if (this.seasonOptions.length > 0) {
                    this.season = this.seasonOptions[0].id;
                } else {
                    this.season = 0;
                    this.seasonOptions = [{ id: 0, name: 'All-Time' }];
                    this.$log.warn('No seasons found for selected year');
                }
                
                // Validate the selection is consistent
                if (!this.validateSeasonSelection()) {
                    this.$log.warn('Season selection inconsistent after year change');
                    this.season = this.seasonOptions[0].id;
                }
                
                this.reloadLeaderboard();
                
            } catch (error) {
                this.$log.error('Error in year change handler:', error);
                this.showError('Error updating year. Please try again.');
            }
        },

        handleScheduleChange() {
            this.onScheduleChange();
            this.scheduleFocused = false;
        },

        handleYearChange() {
            this.onYearChange();
            this.yearFocused = false;
        },

        handleSeasonChange() {
            try {
                // Validate season selection
                if (!this.season || this.season < 0) {
                    this.$log.warn('Invalid season selection:', this.season);
                    this.season = 0;
                }
                
                // Validate that selected season is consistent with current filters
                if (this.view === 'seasonal' && this.season > 0) {
                    const isValid = this.validateSeasonSelection();
                    if (!isValid) {
                        this.$log.warn('Selected season is not valid for current schedule/year filters');
                        // Try to find a valid season or fall back to all-time
                        if (this.seasonOptions.length > 0) {
                            this.season = this.seasonOptions[0].id;
                        } else {
                            this.season = 0;
                            this.view = 'alltime';
                            this.$log.warn('Switched to all-time view due to invalid season selection');
                        }
                    }
                }
                
                this.reloadLeaderboard();
                this.seasonFocused = false;
                
            } catch (error) {
                this.$log.error('Error in season change handler:', error);
                this.showError('Error updating season. Please try again.');
                this.season = 0;
                this.reloadLeaderboard();
            }
        },
        
        // Enhanced reloadLeaderboard with validation
        reloadLeaderboard() {
            try {
                // Validate parameters before making API call
                const season_id = this.view === 'alltime' ? 0 : this.season;
                
                // Ensure season_id is valid
                if (season_id < 0) {
                    this.$log.warn('Invalid season_id, defaulting to 0 (all-time)');
                    season_id = 0;
                }
                
                // Ensure mode and mods are valid
                const gulagInt = this.StrtoGulagInt();
                if (gulagInt === -1) {
                    this.$log.warn('Invalid mode/mods combination, defaulting to std/vn');
                    // Default to std/vn
                    this.mode = 'std';
                    this.mods = 'vn';
                }
                
                this.LoadLeaderboard(this.sort, this.mode, this.mods, this.view, season_id);
                
            } catch (error) {
                this.$log.error('Error in reloadLeaderboard:', error);
                this.showError('Error reloading leaderboard. Please try again.');
            }
        },
        
        // Method to manually refresh seasons data
        refreshSeasonsData() {
            this.$log.info('Manual refresh of seasons data requested');
            this.fetchSeasonData();
        },
        
        // Method to reset to default state
        resetToDefaults() {
            this.$log.info('Resetting seasons to default state');
            this.selectedSchedule = this.schedules[0] || null;
            this.selectedYear = new Date().getFullYear();
            this.season = 0;
            this.view = 'alltime';
            
            // Recompute options
            this.yearOptions = this.computeYearOptions();
            this.seasonOptions = this.computeSeasonOptions();
            
            this.reloadLeaderboard();
        },
        
        // Debug logging methods
        logDebug(level, message) {
            if (!this.debugMode) return;
            
            const timestamp = new Date().toLocaleTimeString();
            this.debugLogs.push({
                time: timestamp,
                level: level.toUpperCase(),
                message: message
            });
            
            // Keep only last 50 logs
            if (this.debugLogs.length > 50) {
                this.debugLogs = this.debugLogs.slice(-50);
            }
        },
        
        // Toggle debug mode with keyboard shortcut
        toggleDebugMode() {
            this.debugMode = !this.debugMode;
            this.logDebug('INFO', this.debugMode ? 'Debug mode enabled' : 'Debug mode disabled');
        },
    },
});
