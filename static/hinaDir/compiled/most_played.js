(function () {
    var Vue = window.Vue;
    var domain = window.domain;
    var HeroBannerMixin = window.HeroBannerMixin;
    new Vue({
        el: '#most-played-app',
        mixins: HeroBannerMixin ? [HeroBannerMixin] : [],
        data: {
            mode: 0,
            maps: [],
            loading: true,
            error: null,
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
        mounted: function () {
            this.fetchHero();
            this.loadMaps();
        },
        methods: {
            loadMaps: function () {
                var self = this;
                self.loading = true;
                self.error = null;
                var proto = window.location.protocol;
                var url = proto + '//api.' + domain + '/v1/get_most_played?mode=' + self.mode + '&limit=100';
                fetch(url, { credentials: 'omit' })
                    .then(function (r) {
                    if (!r.ok)
                        throw new Error('most_played ' + r.status);
                    return r.json();
                })
                    .then(function (d) {
                    self.maps = (d && d.maps) || [];
                    self.loading = false;
                })
                    .catch(function (e) {
                    self.error = 'Failed to load most played maps: ' + e.message;
                    self.loading = false;
                });
            },
            switchMode: function (newMode) {
                if (this.mode === newMode)
                    return;
                this.mode = newMode;
                this.loadMaps();
            },
            openMap: function (map) {
                var bus = window.beatmapBus;
                if (bus && typeof bus.$emit === 'function') {
                    bus.$emit('show-beatmap-panel', map.map_id, map.set_id);
                }
            },
            formatPlays: function (n) {
                if (n >= 1000000)
                    return (n / 1000000).toFixed(1) + 'M';
                if (n >= 1000)
                    return (n / 1000).toFixed(1) + 'K';
                return String(n);
            },
            formatLength: function (secs) {
                var m = Math.floor(secs / 60);
                var s = secs % 60;
                return m + ':' + (s < 10 ? '0' : '') + s;
            },
            statusLabel: function (status) {
                switch (status) {
                    case -2: return 'graveyard';
                    case -1: return 'WIP';
                    case 0: return 'pending';
                    case 1: return 'updated';
                    case 2: return 'ranked';
                    case 3: return 'approved';
                    case 4: return 'qualified';
                    case 5: return 'loved';
                    default: return 'unknown';
                }
            },
        },
    });
})();
