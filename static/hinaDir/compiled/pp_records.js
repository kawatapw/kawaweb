(function () {
    var Vue = window.Vue;
    var domain = window.domain;
    new Vue({
        el: '#pp-records-app',
        data: {
            mode: 0,
            records: [],
            total: 0,
            loading: true,
            error: null,
            page: 1,
            pageSize: 50,
            // Hero banner
            hero: null,
            heroLoading: true,
            // Season state
            schedules: [],
            selectedSchedule: null,
            seasons: [],
            selectedSeason: 0,
            selectedYear: null,
            activeSeason: null,
            // Filter state
            filtersOpen: false,
            cheatType: '',
            cheatMin: '',
            cheatMax: '',
            activeCheatType: '', // currently applied filter
            modes: [
                { value: 0, name: 'osu!standard', short: 'std' },
                { value: 1, name: 'osu!taiko', short: 'taiko' },
                { value: 2, name: 'osu!catch', short: 'catch' },
                { value: 3, name: 'osu!mania', short: 'mania' },
                { value: 4, name: 'std RX', short: 'std rx' },
                { value: 5, name: 'taiko RX', short: 'taiko rx' },
                { value: 6, name: 'catch RX', short: 'catch rx' },
                { value: 8, name: 'std AP', short: 'std ap' },
            ],
            cheatTypes: [
                { key: 'TimewarpMultiplier', label: 'Timewarp Speed (multiplier)', numeric: true, disabled: false },
                { key: 'AimCorrectionValue', label: 'Aim Correction Value', numeric: true, disabled: false },
                { key: 'TimesCorrected', label: 'Times Corrected', numeric: true, disabled: false },
                { key: 'ARChangerAR', label: 'AR Changer Value', numeric: true, disabled: false },
                { key: 'Timewarp', label: 'Timewarp (enabled)', numeric: false, disabled: false },
                { key: 'RelaxHack', label: 'Relax Hack (enabled)', numeric: false, disabled: false },
                { key: 'HiddenRemover', label: 'Hidden Remover', numeric: false, disabled: false },
                { key: 'ARChanger', label: 'AR Changer (enabled)', numeric: false, disabled: false },
                { key: 'CSChanger', label: 'CS Changer (enabled)', numeric: false, disabled: false },
                { key: 'TapOnCorrect', label: 'Tap On Correct', numeric: false, disabled: false },
                // Low-value / future use
                { key: 'TimewarpRate', label: 'Timewarp Rate % (mostly 100)', numeric: true, disabled: true },
                { key: 'TimewarpType', label: 'Timewarp Type', numeric: false, disabled: true },
                { key: 'AimType', label: 'Aim Type', numeric: false, disabled: true },
                { key: 'RelaxHackType', label: 'Relax Hack Type', numeric: false, disabled: true },
                { key: 'CSChangerType', label: 'CS Changer Type', numeric: false, disabled: true },
            ],
        },
        computed: {
            scheduledSeasons: function () {
                var self = this;
                if (!this.selectedSchedule)
                    return this.seasons;
                return this.seasons.filter(function (s) {
                    return s.schedule_id === self.selectedSchedule;
                });
            },
            yearOptions: function () {
                var years = [];
                var ss = this.scheduledSeasons;
                for (var i = 0; i < ss.length; i++) {
                    var y = new Date(ss[i].start_date).getFullYear();
                    if (years.indexOf(y) === -1)
                        years.push(y);
                }
                return years.sort(function (a, b) { return b - a; });
            },
            filteredSeasons: function () {
                var self = this;
                return this.scheduledSeasons
                    .filter(function (s) {
                    return new Date(s.start_date).getFullYear() === self.selectedYear;
                })
                    .map(function (s) {
                    var parts = s.name.split('-');
                    return Object.assign({}, s, { label: parts[parts.length - 1] });
                })
                    .sort(function (a, b) {
                    return new Date(a.start_date).getTime() - new Date(b.start_date).getTime();
                });
            },
            totalPages: function () {
                return Math.max(1, Math.ceil(this.total / this.pageSize));
            },
            isNumericCheat: function () {
                if (!this.cheatType)
                    return false;
                for (var i = 0; i < this.cheatTypes.length; i++) {
                    if (this.cheatTypes[i].key === this.cheatType) {
                        return this.cheatTypes[i].numeric;
                    }
                }
                return false;
            },
        },
        mounted: function () {
            var self = this;
            this.fetchHero();
            this.fetchSeasons().then(function () {
                self.loadRecords();
            });
        },
        methods: {
            fetchHero: function () {
                var self = this;
                var proto = window.location.protocol;
                fetch(proto + '//api.' + domain + '/v1/get_hero_banners?limit=50', {
                    credentials: 'omit',
                })
                    .then(function (resp) {
                    if (!resp.ok)
                        throw new Error('hero fetch ' + resp.status);
                    return resp.json();
                })
                    .then(function (data) {
                    var banners = (data && data.banners) || [];
                    if (banners.length === 0) {
                        self.heroLoading = false;
                        return;
                    }
                    var pick = banners[Math.floor(Math.random() * banners.length)];
                    self.hero = pick;
                    self.heroLoading = false;
                })
                    .catch(function () {
                    self.heroLoading = false;
                });
            },
            openHeroPanel: function () {
                if (!this.hero)
                    return;
                var bus = window.beatmapBus;
                if (bus && typeof bus.$emit === 'function') {
                    bus.$emit('show-beatmap-panel', null, this.hero.set_id);
                }
            },
            loadRecords: function () {
                var self = this;
                self.loading = true;
                self.error = null;
                var offset = (self.page - 1) * self.pageSize;
                var url = 'https://api.' + domain + '/v1/get_pp_records'
                    + '?mode=' + self.mode
                    + '&limit=' + self.pageSize
                    + '&offset=' + offset;
                if (self.selectedSeason) {
                    url += '&season_id=' + self.selectedSeason;
                }
                if (self.activeCheatType) {
                    url += '&cheat_type=' + encodeURIComponent(self.activeCheatType);
                    if (self.cheatMin !== '' && self.cheatMin !== null) {
                        url += '&cheat_min=' + encodeURIComponent(self.cheatMin);
                    }
                    if (self.cheatMax !== '' && self.cheatMax !== null) {
                        url += '&cheat_max=' + encodeURIComponent(self.cheatMax);
                    }
                }
                fetch(url)
                    .then(function (res) { return res.json(); })
                    .then(function (data) {
                    if (data.status === 'success') {
                        self.records = data.records;
                        self.total = data.total;
                    }
                    else {
                        self.error = data.message || 'Failed to load records';
                    }
                    self.loading = false;
                })
                    .catch(function (err) {
                    self.error = 'Network error: ' + err.message;
                    self.loading = false;
                });
            },
            switchMode: function (newMode) {
                if (this.mode === newMode)
                    return;
                this.mode = newMode;
                this.page = 1;
                this.loadRecords();
            },
            toggleFilters: function () {
                this.filtersOpen = !this.filtersOpen;
            },
            applyFilter: function () {
                this.activeCheatType = this.cheatType;
                this.page = 1;
                this.loadRecords();
            },
            onCheatTypeChange: function () {
                // Reset min/max when switching types
                this.cheatMin = '';
                this.cheatMax = '';
                // Auto-apply: for boolean/string types, filter immediately
                this.activeCheatType = this.cheatType;
                this.page = 1;
                this.loadRecords();
            },
            clearFilter: function () {
                this.cheatType = '';
                this.cheatMin = '';
                this.cheatMax = '';
                this.activeCheatType = '';
                this.page = 1;
                this.loadRecords();
            },
            changePage: function (delta) {
                var newPage = this.page + delta;
                if (newPage < 1 || newPage > this.totalPages)
                    return;
                this.page = newPage;
                this.loadRecords();
            },
            getRank: function (index) {
                return (this.page - 1) * this.pageSize + index + 1;
            },
            rankClass: function (index) {
                var rank = this.getRank(index);
                if (rank === 1)
                    return 'gold';
                if (rank === 2)
                    return 'silver';
                if (rank === 3)
                    return 'bronze';
                return '';
            },
            formatAcc: function (acc) {
                return acc.toFixed(2) + '%';
            },
            formatPP: function (pp) {
                return Math.round(pp) + 'pp';
            },
            formatDate: function (dateStr) {
                if (!dateStr)
                    return '';
                var d = new Date(dateStr);
                var month = d.getMonth() + 1;
                var day = d.getDate();
                var year = d.getFullYear();
                return year + '-' + (month < 10 ? '0' : '') + month + '-' + (day < 10 ? '0' : '') + day;
            },
            coverUrl: function (setId) {
                return 'https://assets.ppy.sh/beatmaps/' + setId + '/covers/list.jpg';
            },
            coverError: function (event) {
                event.target.style.display = 'none';
            },
            gradeUrl: function (grade) {
                var gradeMap = {
                    'X': 'SS', 'XH': 'SS',
                    'SH': 'S',
                };
                var mapped = gradeMap[grade] || grade;
                return '/static/images/icons/grades/GradeSmall-' + mapped + '.svg';
            },
            cheatDisplay: function (record) {
                if (!this.activeCheatType || !record.cheat_values)
                    return '';
                var val = record.cheat_values[this.activeCheatType];
                if (val === undefined || val === null)
                    return 'N/A';
                if (typeof val === 'number')
                    return val.toFixed(2);
                return String(val);
            },
            fetchSeasons: function () {
                var self = this;
                var proto = location.protocol;
                return Promise.all([
                    fetch(proto + '//api.' + domain + '/v2/schedules'),
                    fetch(proto + '//api.' + domain + '/v2/seasons?page=1&page_size=100')
                ])
                    .then(function (responses) {
                    return Promise.all(responses.map(function (r) {
                        if (!r.ok)
                            throw new Error('HTTP ' + r.status);
                        return r.json();
                    }));
                })
                    .then(function (results) {
                    var schedData = results[0], seasData = results[1];
                    if (schedData.status === 'success' && schedData.data) {
                        self.schedules = schedData.data;
                        if (self.schedules.length > 0) {
                            self.selectedSchedule = self.schedules[0].id;
                        }
                    }
                    if (seasData.status === 'success' && seasData.data) {
                        self.seasons = seasData.data;
                        self.activeSeason = self.seasons.find(function (s) { return s.is_active; }) || null;
                        if (self.activeSeason && self.schedules.some(function (sc) { return sc.id === self.activeSeason.schedule_id; })) {
                            self.selectedSchedule = self.activeSeason.schedule_id;
                        }
                        if (self.yearOptions.length > 0) {
                            self.selectedYear = self.yearOptions[0];
                        }
                    }
                })
                    .catch(function () {
                    // Seasons not available — switcher stays hidden
                });
            },
            selectSeason: function (seasonId) {
                this.selectedSeason = seasonId;
                this.page = 1;
                this.loadRecords();
            },
            onScheduleChange: function () {
                if (this.yearOptions.length > 0) {
                    this.selectedYear = this.yearOptions[0];
                }
                var seasons = this.filteredSeasons;
                if (seasons.length > 0) {
                    this.selectedSeason = seasons[seasons.length - 1].id;
                    this.page = 1;
                    this.loadRecords();
                }
            },
            onYearChange: function () {
                var seasons = this.filteredSeasons;
                if (seasons.length > 0) {
                    this.selectedSeason = seasons[seasons.length - 1].id;
                    this.page = 1;
                    this.loadRecords();
                }
            },
            onSeasonChange: function () {
                this.page = 1;
                this.loadRecords();
            },
        },
    });
})();
