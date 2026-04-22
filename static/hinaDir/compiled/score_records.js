(function () {
    var Vue = window.Vue;
    var domain = window.domain;
    var HeroBannerMixin = window.HeroBannerMixin;
    new Vue({
        el: '#score-records-app',
        mixins: HeroBannerMixin ? [HeroBannerMixin] : [],
        data: {
            mode: 0,
            records: [],
            total: 0,
            loading: true,
            error: null,
            page: 1,
            pageSize: 50,
            schedules: [],
            selectedSchedule: null,
            seasons: [],
            selectedSeason: 0,
            selectedYear: null,
            activeSeason: null,
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
        },
        mounted: function () {
            var self = this;
            this.fetchHero();
            this.fetchSeasons().then(function () {
                self.loadRecords();
            });
        },
        methods: {
            loadRecords: function () {
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
                    .then(function (r) {
                    if (!r.ok)
                        throw new Error('score_records ' + r.status);
                    return r.json();
                })
                    .then(function (d) {
                    if (d.status !== 'success')
                        throw new Error(d.message || 'bad response');
                    self.records = d.records || [];
                    self.total = d.total || 0;
                    self.loading = false;
                })
                    .catch(function (e) {
                    self.error = 'Failed to load score records: ' + e.message;
                    self.loading = false;
                });
            },
            fetchSeasons: function () {
                var self = this;
                return fetch('https://api.' + domain + '/v2/seasons', { credentials: 'omit' })
                    .then(function (r) { return r.ok ? r.json() : { data: [] }; })
                    .then(function (d) {
                    self.seasons = (d && d.data) || [];
                    self.schedules = [];
                    var sids = {};
                    for (var i = 0; i < self.seasons.length; i++) {
                        var s = self.seasons[i];
                        if (s.schedule_id && !sids[s.schedule_id]) {
                            sids[s.schedule_id] = { id: s.schedule_id, name: 'Schedule ' + s.schedule_id };
                            self.schedules.push(sids[s.schedule_id]);
                        }
                        if (s.is_active)
                            self.activeSeason = s;
                    }
                    if (self.schedules.length > 0) {
                        self.selectedSchedule = self.schedules[0].id;
                    }
                    var now = new Date().getFullYear();
                    self.selectedYear = now;
                })
                    .catch(function () { self.seasons = []; });
            },
            switchMode: function (newMode) {
                if (this.mode === newMode)
                    return;
                this.mode = newMode;
                this.page = 1;
                this.loadRecords();
            },
            selectSeason: function (id) {
                this.selectedSeason = id;
                this.page = 1;
                this.loadRecords();
            },
            goToPage: function (p) {
                if (p < 1 || p > this.totalPages)
                    return;
                this.page = p;
                this.loadRecords();
                window.scrollTo({ top: 0, behavior: 'smooth' });
            },
            rankClass: function (i) {
                var r = (this.page - 1) * this.pageSize + i + 1;
                if (r === 1)
                    return 'ppr-rank--gold';
                if (r === 2)
                    return 'ppr-rank--silver';
                if (r === 3)
                    return 'ppr-rank--bronze';
                return '';
            },
            getRank: function (i) {
                return '#' + ((this.page - 1) * this.pageSize + i + 1);
            },
            formatScore: function (s) {
                return s.toLocaleString();
            },
            formatAcc: function (acc) {
                return acc.toFixed(2) + '%';
            },
            formatDate: function (t) {
                try {
                    var d = new Date(t);
                    return d.toISOString().slice(0, 10);
                }
                catch (e) {
                    return t || '';
                }
            },
            coverUrl: function (setId) {
                return 'https://assets.ppy.sh/beatmaps/' + setId + '/covers/card@2x.jpg';
            },
            coverError: function (e) {
                var img = e.target;
                img.style.visibility = 'hidden';
            },
            gradeUrl: function (grade) {
                var g = (grade || 'N').toUpperCase();
                return '/static/images/grades/' + g + '.png';
            },
            onScheduleChange: function () {
                if (this.yearOptions.length > 0)
                    this.selectedYear = this.yearOptions[0];
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
