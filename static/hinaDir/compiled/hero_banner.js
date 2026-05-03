(function () {
    var w = window;
    w.HeroBannerMixin = {
        data: function () {
            return {
                hero: null,
                heroLoading: true,
            };
        },
        methods: {
            fetchHero: function () {
                var self = this;
                var proto = window.location.protocol;
                var apiDomain = w.domain || window.location.hostname;
                fetch(proto + '//api.' + apiDomain + '/v1/get_hero_banners?limit=50', {
                    credentials: 'omit',
                })
                    .then(function (resp) {
                    if (!resp.ok)
                        throw new Error('hero ' + resp.status);
                    return resp.json();
                })
                    .then(function (data) {
                    var banners = (data && data.banners) || [];
                    if (banners.length === 0) {
                        self.heroLoading = false;
                        return;
                    }
                    self.hero = banners[Math.floor(Math.random() * banners.length)];
                    self.heroLoading = false;
                })
                    .catch(function () {
                    self.heroLoading = false;
                });
            },
            openHeroPanel: function () {
                if (!this.hero)
                    return;
                var bus = w.beatmapBus;
                if (bus && typeof bus.$emit === 'function') {
                    bus.$emit('show-beatmap-panel', null, this.hero.set_id);
                }
            },
        },
    };
})();
