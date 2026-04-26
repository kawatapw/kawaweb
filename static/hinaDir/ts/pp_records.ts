(function() {
var Vue = (window as any).Vue;
var domain = (window as any).domain;

interface PPRecord {
    id: number;
    pp: number;
    acc: number;
    max_combo: number;
    mods: number;
    mods_readable: string;
    grade: string;
    n300: number;
    n100: number;
    n50: number;
    nmiss: number;
    play_time: string;
    player_id: number;
    player_name: string;
    player_country: string;
    map_id: number;
    set_id: number;
    artist: string;
    title: string;
    version: string;
    diff: number;
    cheat_values: Record<string, any>;
}

interface CheatTypeOption {
    key: string;
    label: string;
    numeric: boolean;
    disabled: boolean;
}

var HeroBannerMixin = (window as any).HeroBannerMixin;

new Vue({
    el: '#pp-records-app',
    mixins: HeroBannerMixin ? [HeroBannerMixin] : [],
    data: {
        mode: 0,
        records: [] as PPRecord[],
        total: 0,
        loading: true,
        error: null as string | null,
        page: 1,
        pageSize: 50,

        // Season state
        schedules: [] as any[],
        selectedSchedule: null as number | null,
        seasons: [] as any[],
        selectedSeason: 0,
        selectedYear: null as number | null,
        activeSeason: null as any,

        // Filter state
        filtersOpen: false,
        cheatType: '',
        cheatMin: '',
        cheatMax: '',
        activeCheatType: '',  // currently applied filter

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
        ] as CheatTypeOption[],
    },
    computed: {
        scheduledSeasons: function(): any[] {
            var self = this;
            if (!this.selectedSchedule) return this.seasons;
            return this.seasons.filter(function(s: any) {
                return s.schedule_id === self.selectedSchedule;
            });
        },
        yearOptions: function(): number[] {
            var years: number[] = [];
            var ss = this.scheduledSeasons;
            for (var i = 0; i < ss.length; i++) {
                var y = new Date(ss[i].start_date).getFullYear();
                if (years.indexOf(y) === -1) years.push(y);
            }
            return years.sort(function(a: number, b: number) { return b - a; });
        },
        filteredSeasons: function(): any[] {
            var self = this;
            return this.scheduledSeasons
                .filter(function(s: any) {
                    return new Date(s.start_date).getFullYear() === self.selectedYear;
                })
                .map(function(s: any) {
                    var parts = s.name.split('-');
                    return Object.assign({}, s, { label: parts[parts.length - 1] });
                })
                .sort(function(a: any, b: any) {
                    return new Date(a.start_date).getTime() - new Date(b.start_date).getTime();
                });
        },
        totalPages: function(): number {
            return Math.max(1, Math.ceil(this.total / this.pageSize));
        },
        isNumericCheat: function(): boolean {
            if (!this.cheatType) return false;
            for (var i = 0; i < this.cheatTypes.length; i++) {
                if (this.cheatTypes[i].key === this.cheatType) {
                    return this.cheatTypes[i].numeric;
                }
            }
            return false;
        },
    },
    mounted: function() {
        var self = this;
        if (typeof (this as any).fetchHero === 'function') {
            (this as any).fetchHero();
        }
        this.fetchSeasons().then(function() {
            self.loadRecords();
        });
    },
    methods: {
        loadRecords: function() {
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
                .then(function(res) { return res.json(); })
                .then(function(data) {
                    if (data.status === 'success') {
                        self.records = data.records;
                        self.total = data.total;
                    } else {
                        self.error = data.message || 'Failed to load records';
                    }
                    self.loading = false;
                })
                .catch(function(err) {
                    self.error = 'Network error: ' + err.message;
                    self.loading = false;
                });
        },

        switchMode: function(newMode: number) {
            if (this.mode === newMode) return;
            this.mode = newMode;
            this.page = 1;
            this.loadRecords();
        },

        toggleFilters: function() {
            this.filtersOpen = !this.filtersOpen;
        },

        applyFilter: function() {
            this.activeCheatType = this.cheatType;
            this.page = 1;
            this.loadRecords();
        },

        onCheatTypeChange: function() {
            // Reset min/max when switching types
            this.cheatMin = '';
            this.cheatMax = '';
            // Auto-apply: for boolean/string types, filter immediately
            this.activeCheatType = this.cheatType;
            this.page = 1;
            this.loadRecords();
        },

        clearFilter: function() {
            this.cheatType = '';
            this.cheatMin = '';
            this.cheatMax = '';
            this.activeCheatType = '';
            this.page = 1;
            this.loadRecords();
        },

        changePage: function(delta: number) {
            var newPage = this.page + delta;
            if (newPage < 1 || newPage > this.totalPages) return;
            this.page = newPage;
            this.loadRecords();
        },

        getRank: function(index: number): number {
            return (this.page - 1) * this.pageSize + index + 1;
        },

        rankClass: function(index: number): string {
            var rank = this.getRank(index);
            if (rank === 1) return 'gold';
            if (rank === 2) return 'silver';
            if (rank === 3) return 'bronze';
            return '';
        },

        formatAcc: function(acc: number): string {
            return acc.toFixed(2) + '%';
        },

        formatPP: function(pp: number): string {
            return Math.round(pp) + 'pp';
        },

        formatDate: function(dateStr: string): string {
            if (!dateStr) return '';
            var d = new Date(dateStr);
            var month = d.getMonth() + 1;
            var day = d.getDate();
            var year = d.getFullYear();
            return year + '-' + (month < 10 ? '0' : '') + month + '-' + (day < 10 ? '0' : '') + day;
        },

        coverUrl: function(setId: number): string {
            return 'https://assets.ppy.sh/beatmaps/' + setId + '/covers/list.jpg';
        },

        coverError: function(event: any) {
            event.target.style.display = 'none';
        },

        gradeUrl: function(grade: string): string {
            var gradeMap: Record<string, string> = {
                'X': 'SS', 'XH': 'SS',
                'SH': 'S',
            };
            var mapped = gradeMap[grade] || grade;
            return '/static/images/icons/grades/GradeSmall-' + mapped + '.svg';
        },

        cheatDisplay: function(record: PPRecord): string {
            if (!this.activeCheatType || !record.cheat_values) return '';
            var val = record.cheat_values[this.activeCheatType];
            if (val === undefined || val === null) return 'N/A';
            if (typeof val === 'number') return val.toFixed(2);
            return String(val);
        },

        fetchSeasons: function() {
            var self = this;
            var proto = location.protocol;
            return Promise.all([
                fetch(proto + '//api.' + domain + '/v2/schedules'),
                fetch(proto + '//api.' + domain + '/v2/seasons?page=1&page_size=100')
            ])
                .then(function(responses: Response[]) {
                    return Promise.all(responses.map(function(r: Response) {
                        if (!r.ok) throw new Error('HTTP ' + r.status);
                        return r.json();
                    }));
                })
                .then(function(results: any[]) {
                    var schedData = results[0], seasData = results[1];
                    if (schedData.status === 'success' && schedData.data) {
                        self.schedules = schedData.data;
                        if (self.schedules.length > 0) {
                            self.selectedSchedule = self.schedules[0].id;
                        }
                    }
                    if (seasData.status === 'success' && seasData.data) {
                        self.seasons = seasData.data;
                        self.activeSeason = self.seasons.find(function(s: any) { return s.is_active; }) || null;
                        if (self.activeSeason && self.schedules.some(function(sc: any) { return sc.id === self.activeSeason.schedule_id; })) {
                            self.selectedSchedule = self.activeSeason.schedule_id;
                        }
                        // Default to current season (was 0 = All Time before).
                        if (self.activeSeason && (self.selectedSeason == null || self.selectedSeason === 0)) {
                            self.selectedSeason = self.activeSeason.id;
                        }
                        if (self.yearOptions.length > 0) {
                            self.selectedYear = self.yearOptions[0];
                        }
                    }
                })
                .catch(function() {
                    // Seasons not available — switcher stays hidden
                });
        },

        selectSeason: function(seasonId: number) {
            this.selectedSeason = seasonId;
            this.page = 1;
            this.loadRecords();
        },

        onScheduleChange: function() {
            if (this.yearOptions.length > 0) {
                this.selectedYear = this.yearOptions[0];
            }
            var seasons = this.filteredSeasons;
            this.page = 1;
            if (seasons.length > 0) {
                this.selectedSeason = seasons[seasons.length - 1].id;
            } else {
                // Empty schedule — clear selection so stale records aren't shown.
                this.selectedSeason = null;
            }
            this.loadRecords();
        },

        onYearChange: function() {
            var seasons = this.filteredSeasons;
            if (seasons.length > 0) {
                this.selectedSeason = seasons[seasons.length - 1].id;
                this.page = 1;
                this.loadRecords();
            }
        },

        onSeasonChange: function() {
            this.page = 1;
            this.loadRecords();
        },
    },
});
})();
