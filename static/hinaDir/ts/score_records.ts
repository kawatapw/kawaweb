(function() {
var Vue = (window as any).Vue;
var domain = (window as any).domain;

interface ScoreRecord {
    id: number;
    score: number;
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
    perfect: number;
    player_id: number;
    player_name: string;
    player_country: string;
    map_id: number;
    set_id: number;
    artist: string;
    title: string;
    version: string;
    diff: number;
    map_max_combo: number;
}

var HeroBannerMixin = (window as any).HeroBannerMixin;

new Vue({
    el: '#score-records-app',
    mixins: HeroBannerMixin ? [HeroBannerMixin] : [],
    data: {
        mode: 0,
        records: [] as ScoreRecord[],
        total: 0,
        loading: true,
        error: null as string | null,
        page: 1,
        pageSize: 50,

        schedules: [] as any[],
        selectedSchedule: null as number | null,
        seasons: [] as any[],
        selectedSeason: 0,
        selectedYear: null as number | null,
        activeSeason: null as any,

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
    },
    mounted: function() {
        var self = this;
        this.fetchHero();
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
            var url = 'https://api.' + domain + '/v1/get_score_records'
                    + '?mode=' + self.mode
                    + '&limit=' + self.pageSize
                    + '&offset=' + offset;

            if (self.selectedSeason > 0) {
                url += '&season_id=' + self.selectedSeason;
            }

            fetch(url, { credentials: 'omit' })
                .then(function(r: Response) {
                    if (!r.ok) throw new Error('score_records ' + r.status);
                    return r.json();
                })
                .then(function(d: any) {
                    if (d.status !== 'success') throw new Error(d.message || 'bad response');
                    self.records = d.records || [];
                    self.total = d.total || 0;
                    self.loading = false;
                })
                .catch(function(e: Error) {
                    self.error = 'Failed to load score records: ' + e.message;
                    self.loading = false;
                });
        },

        fetchSeasons: function() {
            var self = this;
            return fetch('https://api.' + domain + '/v2/seasons', { credentials: 'omit' })
                .then(function(r: Response) { return r.ok ? r.json() : { data: [] }; })
                .then(function(d: any) {
                    self.seasons = (d && d.data) || [];
                    self.schedules = [];
                    var sids: Record<number, any> = {};
                    for (var i = 0; i < self.seasons.length; i++) {
                        var s = self.seasons[i];
                        if (s.schedule_id && !sids[s.schedule_id]) {
                            sids[s.schedule_id] = { id: s.schedule_id, name: 'Schedule ' + s.schedule_id };
                            self.schedules.push(sids[s.schedule_id]);
                        }
                        if (s.is_active) self.activeSeason = s;
                    }
                    if (self.schedules.length > 0) {
                        self.selectedSchedule = self.schedules[0].id;
                    }
                    var now = new Date().getFullYear();
                    self.selectedYear = now;
                })
                .catch(function() { self.seasons = []; });
        },

        switchMode: function(newMode: number) {
            if (this.mode === newMode) return;
            this.mode = newMode;
            this.page = 1;
            this.loadRecords();
        },

        selectSeason: function(id: number) {
            this.selectedSeason = id;
            this.page = 1;
            this.loadRecords();
        },

        goToPage: function(p: number) {
            if (p < 1 || p > this.totalPages) return;
            this.page = p;
            this.loadRecords();
            window.scrollTo({ top: 0, behavior: 'smooth' });
        },

        rankClass: function(i: number): string {
            var r = (this.page - 1) * this.pageSize + i + 1;
            if (r === 1) return 'ppr-rank--gold';
            if (r === 2) return 'ppr-rank--silver';
            if (r === 3) return 'ppr-rank--bronze';
            return '';
        },

        getRank: function(i: number): string {
            return '#' + ((this.page - 1) * this.pageSize + i + 1);
        },

        formatScore: function(s: number): string {
            return s.toLocaleString();
        },

        formatAcc: function(acc: number): string {
            return acc.toFixed(2) + '%';
        },

        formatDate: function(t: string): string {
            try {
                var d = new Date(t);
                return d.toISOString().slice(0, 10);
            } catch (e) {
                return t || '';
            }
        },

        coverUrl: function(setId: number): string {
            return 'https://assets.ppy.sh/beatmaps/' + setId + '/covers/card@2x.jpg';
        },

        coverError: function(e: Event) {
            var img = e.target as HTMLImageElement;
            img.style.visibility = 'hidden';
        },

        gradeUrl: function(grade: string): string {
            var g = (grade || 'N').toUpperCase();
            return '/static/images/grades/' + g + '.png';
        },

        onScheduleChange: function() {
            if (this.yearOptions.length > 0) this.selectedYear = this.yearOptions[0];
            var seasons = this.filteredSeasons;
            if (seasons.length > 0) {
                this.selectedSeason = seasons[seasons.length - 1].id;
                this.page = 1;
                this.loadRecords();
            }
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
