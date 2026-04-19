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

new Vue({
    el: '#pp-records-app',
    data: {
        mode: 0,
        records: [] as PPRecord[],
        total: 0,
        loading: true,
        error: null as string | null,
        page: 1,
        pageSize: 50,

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
        this.loadRecords();
    },
    methods: {
        loadRecords: function() {
            var self = this;
            self.loading = true;
            self.error = null;

            var offset = (self.page - 1) * self.pageSize;
            var url = 'http://api.' + domain + '/v1/get_pp_records'
                + '?mode=' + self.mode
                + '&limit=' + self.pageSize
                + '&offset=' + offset;

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
            return '/static/images/grades/' + grade + '.png';
        },

        cheatDisplay: function(record: PPRecord): string {
            if (!this.activeCheatType || !record.cheat_values) return '';
            var val = record.cheat_values[this.activeCheatType];
            if (val === undefined || val === null) return 'N/A';
            if (typeof val === 'number') return val.toFixed(2);
            return String(val);
        },
    },
});
})();
