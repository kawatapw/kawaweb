// Hall of Fame — vanilla Vue 2 IIFE. Mirrors most_played.ts shape.
// HoF builds its OWN podium hero (does NOT use HeroBannerMixin — that one
// rotates beatmapsets, this page needs players).
(function () {
    var Vue = window.Vue;
    var domain = window.domain;
    var COUNTRIES = [
        { code: 'us', name: 'United States' },
        { code: 'jp', name: 'Japan' },
        { code: 'kr', name: 'South Korea' },
        { code: 'gb', name: 'United Kingdom' },
        { code: 'de', name: 'Germany' },
        { code: 'fr', name: 'France' },
        { code: 'it', name: 'Italy' },
        { code: 'es', name: 'Spain' },
        { code: 'nl', name: 'Netherlands' },
        { code: 'se', name: 'Sweden' },
        { code: 'no', name: 'Norway' },
        { code: 'fi', name: 'Finland' },
        { code: 'pl', name: 'Poland' },
        { code: 'ru', name: 'Russia' },
        { code: 'ua', name: 'Ukraine' },
        { code: 'ca', name: 'Canada' },
        { code: 'mx', name: 'Mexico' },
        { code: 'br', name: 'Brazil' },
        { code: 'ar', name: 'Argentina' },
        { code: 'cl', name: 'Chile' },
        { code: 'cn', name: 'China' },
        { code: 'tw', name: 'Taiwan' },
        { code: 'hk', name: 'Hong Kong' },
        { code: 'sg', name: 'Singapore' },
        { code: 'my', name: 'Malaysia' },
        { code: 'th', name: 'Thailand' },
        { code: 'id', name: 'Indonesia' },
        { code: 'ph', name: 'Philippines' },
        { code: 'vn', name: 'Vietnam' },
        { code: 'au', name: 'Australia' },
        { code: 'nz', name: 'New Zealand' },
        { code: 'in', name: 'India' },
        { code: 'tr', name: 'Turkey' },
    ];
    var SORT_LABEL = {
        pp: 'PP',
        rscore: 'Ranked Score',
        tscore: 'Total Score',
        acc: 'Accuracy',
        plays: 'Plays',
        playtime: 'Playtime',
    };
    function fmtBig(n) {
        if (n == null || isNaN(n))
            return '0';
        if (n >= 1000000000)
            return (n / 1000000000).toFixed(2) + 'B';
        if (n >= 1000000)
            return (n / 1000000).toFixed(2) + 'M';
        if (n >= 1000)
            return (n / 1000).toFixed(1) + 'K';
        return String(n);
    }
    function fmtHours(secs) {
        var h = Math.floor((secs || 0) / 3600);
        return h.toLocaleString();
    }
    new Vue({
        el: '#hall-of-fame-app',
        data: {
            mode: 0,
            sort: 'pp',
            country: '',
            podium: [],
            list: [],
            loading: true,
            switching: false,
            scrolled: false,
            error: null,
            countries: COUNTRIES,
            modes: [
                { value: 0, name: 'osu!standard', short: 'vn!std' },
                { value: 1, name: 'osu!taiko', short: 'vn!taiko' },
                { value: 2, name: 'osu!catch', short: 'vn!ctb' },
                { value: 3, name: 'osu!mania', short: 'vn!mania' },
                { value: 4, name: 'std RX', short: 'rx!std' },
                { value: 5, name: 'taiko RX', short: 'rx!taiko' },
                { value: 6, name: 'catch RX', short: 'rx!ctb' },
                { value: 8, name: 'std AP', short: 'ap!std' },
            ],
            sorts: [
                { value: 'pp', label: 'PP', icon: 'fas fa-bolt' },
                { value: 'rscore', label: 'Ranked Score', icon: 'fas fa-crown' },
                { value: 'tscore', label: 'Total Score', icon: 'fas fa-coins' },
                { value: 'acc', label: 'Accuracy', icon: 'fas fa-bullseye' },
                { value: 'plays', label: 'Plays', icon: 'fas fa-play' },
                { value: 'playtime', label: 'Playtime', icon: 'fas fa-clock' },
            ],
        },
        computed: {
            primaryLabel: function () {
                return SORT_LABEL[this.sort] || 'Score';
            },
        },
        mounted: function () {
            this.reload();
            this._onScroll = this.onScroll.bind(this);
            window.addEventListener('scroll', this._onScroll, { passive: true });
        },
        beforeDestroy: function () {
            if (this._onScroll) {
                window.removeEventListener('scroll', this._onScroll);
            }
        },
        methods: {
            tierFor: function (i) {
                return ['gold', 'silver', 'bronze'][i] || 'extra';
            },
            tierDelay: function (i) {
                // Bronze (i=2) rises first, silver (i=1) next, gold (i=0) last with overshoot.
                if (i === 0)
                    return '320ms';
                if (i === 1)
                    return '140ms';
                return '0ms';
            },
            primaryStat: function (p) {
                var s = this.sort;
                if (s === 'pp')
                    return Math.round(p.pp).toLocaleString() + ' pp';
                if (s === 'rscore')
                    return fmtBig(p.rscore);
                if (s === 'tscore')
                    return fmtBig(p.tscore);
                if (s === 'acc')
                    return p.acc.toFixed(2) + '%';
                if (s === 'plays')
                    return p.plays.toLocaleString();
                if (s === 'playtime')
                    return fmtHours(p.playtime) + ' h';
                return String(p.pp);
            },
            formatBig: function (n) {
                return fmtBig(n);
            },
            hasGrades: function (p) {
                return (p.xh_count + p.x_count + p.sh_count + p.s_count) > 0;
            },
            switchMode: function (newMode) {
                if (this.mode === newMode)
                    return;
                this.mode = newMode;
                this.reload();
            },
            switchSort: function (newSort) {
                if (this.sort === newSort)
                    return;
                this.sort = newSort;
                this.reload();
            },
            onScroll: function () {
                this.scrolled = window.scrollY > 280;
            },
            reload: function () {
                var self = this;
                self.switching = true;
                self.loading = true;
                self.error = null;
                var proto = window.location.protocol;
                var base = proto + '//api.' + domain + '/v1';
                var cq = self.country ? '&country=' + encodeURIComponent(self.country) : '';
                var podiumUrl = base + '/get_hall_of_fame_podium?mode=' + self.mode +
                    '&sort=' + self.sort + cq;
                var listUrl = base + '/get_leaderboard?mode=' + self.mode +
                    '&sort=' + self.sort + '&season=0&limit=50&offset=0' + cq;
                var pPromise = fetch(podiumUrl, { credentials: 'omit' })
                    .then(function (r) {
                    if (!r.ok)
                        throw new Error('podium ' + r.status);
                    return r.json();
                });
                var lPromise = fetch(listUrl, { credentials: 'omit' })
                    .then(function (r) {
                    if (!r.ok)
                        throw new Error('leaderboard ' + r.status);
                    return r.json();
                });
                Promise.all([pPromise, lPromise])
                    .then(function (results) {
                    var pRes = results[0];
                    var lRes = results[1];
                    self.podium = (pRes && pRes.podium) || [];
                    var lb = (lRes && lRes.leaderboard) || [];
                    // Drop the first 3 — they're already in the podium.
                    self.list = lb.slice(3);
                    self.loading = false;
                    self.error = null;
                })
                    .catch(function (e) {
                    self.error = 'Failed to load Hall of Fame: ' + e.message;
                    self.loading = false;
                })
                    .then(function () {
                    // Two RAFs so Vue re-renders before we clear the switching class —
                    // re-keyed cards will then run their entry animations cleanly.
                    requestAnimationFrame(function () {
                        requestAnimationFrame(function () {
                            self.switching = false;
                        });
                    });
                });
            },
        },
    });
})();
