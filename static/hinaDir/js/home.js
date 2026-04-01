// home.js — Home page Vue app
// Powers the redesigned home page: live player count, online players,
// scroll reveal animations, and hero parallax fade.

bootstrapVue('home', {
    el: '#home-app',
    delimiters: ['<%', '%>'],

    data: function () {
        var homeData = window.__homeData || {};
        return {
            online_users: 0,
            online_players: [],
            domain: window.domain || '',
            // Carousel cards — static content, reusable on any page
            carouselCards: [
                { icon: 'fas fa-gift', title: 'Free Features', description: 'osu!direct, hinai!mirror, supporter features, and more \u2014 all completely free. No paywalls, no restrictions.' },
                { icon: 'fas fa-calculator', title: 'Custom PP System', description: 'Runtime-switchable PP calculators with fair formulas for Relax and Autopilot. Your skills, fairly rewarded.' },
                { icon: 'fas fa-gamepad', title: 'Custom Client', description: 'A purpose-built osu! client with exclusive features, better performance, and built-in server support.' },
                { icon: 'fas fa-comments', title: 'Active Community', description: 'A welcoming Discord community with active staff, tournaments, and players from around the world.' },
                { icon: 'fas fa-code-branch', title: 'Open Development', description: 'Transparent changelog, community-driven features, and an open development process you can follow.' },
            ],
            // Server-rendered map data passed via window.__homeData
            rankedMaps: homeData.rankedMaps || [],
            mostPlayedMaps: homeData.mostPlayedMaps || [],
        };
    },

    created: function () {
        this.fetchPlayerCount();
        this.fetchOnlinePlayers();
    },

    mounted: function () {
        this.initScrollReveal();
        this.initHeroParallax();
    },

    beforeDestroy: function () {
        // Clear the 30s polling interval
        if (this._onlinePlayersInterval) {
            clearInterval(this._onlinePlayersInterval);
            this._onlinePlayersInterval = null;
        }

        // Remove hero parallax scroll listener
        if (this._heroScrollHandler) {
            window.removeEventListener('scroll', this._heroScrollHandler);
            this._heroScrollHandler = null;
        }

        // Disconnect the scroll reveal observer
        if (this._scrollObserver) {
            this._scrollObserver.disconnect();
            this._scrollObserver = null;
        }
    },

    methods: {
        /**
         * Fetch the total online player count from the API.
         * Updates `online_users` from the response.
         */
        fetchPlayerCount: function () {
            var vm = this;
            fetch('https://api.' + vm.domain + '/v1/get_player_count')
                .then(function (res) { return res.json(); })
                .then(function (data) {
                    if (data.status === 'success' && data.counts) {
                        vm.online_users = data.counts.online || 0;
                    }
                })
                .catch(function (err) {
                    console.warn('[home] Failed to fetch player count:', err);
                });
        },

        /**
         * Fetch a sample of currently online players from the API.
         * Updates `online_players` and sets up 30s polling.
         */
        fetchOnlinePlayers: function () {
            var vm = this;

            function doFetch() {
                fetch('https://api.' + vm.domain + '/v1/get_online_players_sample')
                    .then(function (res) { return res.json(); })
                    .then(function (data) {
                        if (data.status === 'success' && Array.isArray(data.players)) {
                            vm.online_players = data.players;
                        }
                    })
                    .catch(function (err) {
                        console.warn('[home] Failed to fetch online players:', err);
                    });
            }

            // Initial fetch
            doFetch();

            // Poll every 30 seconds
            vm._onlinePlayersInterval = setInterval(doFetch, 30000);
        },

        /**
         * Return a CSS class based on the player's action code.
         * Action codes (from bancho protocol):
         *   0 = Idle, 1 = Idle (AFK variant), 2 = Playing, 8 = AFK, 9 = Playing (multi)
         */
        getStatusClass: function (status) {
            if (!status) return 'status-offline';

            var action = status.action;
            switch (action) {
                case 0:
                case 1:
                    return 'status-idle';
                case 2:
                case 9:
                    return 'status-playing';
                case 8:
                    return 'status-afk';
                default:
                    return 'status-online';
            }
        },

        /**
         * Return a human-readable status label from the action code.
         */
        getStatusText: function (status) {
            if (!status) return 'Offline';

            var action = status.action;
            switch (action) {
                case 0:
                case 1:
                    return 'Idle';
                case 2:
                case 9:
                    return 'Playing';
                case 8:
                    return 'AFK';
                default:
                    return 'Online';
            }
        },

        /**
         * Format a number with comma separators (e.g. 1234567 -> "1,234,567").
         */
        formatNumber: function (n) {
            if (n == null) return '0';
            return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        },

        /**
         * Set up an IntersectionObserver that adds the `.visible` class
         * to `.scroll-reveal` elements when they enter the viewport.
         */
        initScrollReveal: function () {
            var vm = this;

            if (!('IntersectionObserver' in window)) {
                // Fallback: make everything visible immediately
                var elements = document.querySelectorAll('.scroll-reveal');
                for (var i = 0; i < elements.length; i++) {
                    elements[i].classList.add('visible');
                }
                return;
            }

            vm._scrollObserver = new IntersectionObserver(
                function (entries) {
                    entries.forEach(function (entry) {
                        if (entry.isIntersecting) {
                            entry.target.classList.add('visible');
                            // Stop observing once revealed (one-shot animation)
                            vm._scrollObserver.unobserve(entry.target);
                        }
                    });
                },
                {
                    threshold: 0.15,
                    rootMargin: '0px 0px -50px 0px',
                }
            );

            var targets = document.querySelectorAll('.scroll-reveal');
            for (var i = 0; i < targets.length; i++) {
                vm._scrollObserver.observe(targets[i]);
            }
        },

        /**
         * Attach a scroll listener that fades and translates the hero
         * content based on vertical scroll position, creating a parallax effect.
         */
        initHeroParallax: function () {
            var vm = this;
            var heroEl = vm.$el.querySelector('.hero') || vm.$el;

            vm._heroScrollHandler = function () {
                var scrollY = window.pageYOffset || document.documentElement.scrollTop;
                var heroHeight = heroEl.offsetHeight;

                if (heroHeight <= 0) return;

                // Clamp progress between 0 and 1
                var progress = Math.min(scrollY / heroHeight, 1);

                // Fade out hero content as user scrolls down
                var heroContent = heroEl.querySelector('.hero-content');
                if (heroContent) {
                    heroContent.style.opacity = 1 - progress;
                    heroContent.style.transform = 'translateY(' + (scrollY * 0.3) + 'px)';
                }
            };

            window.addEventListener('scroll', vm._heroScrollHandler, { passive: true });
        },
    },
});
