(function () {
    var Vue = window.Vue;
    var domain = window.domain;
    var userId = window.userId;
    new Vue({
        el: '#friends-leaderboard-app',
        data: {
            mode: 0,
            leaderboard: [],
            loading: true,
            error: null,
            selfId: userId,
            modes: [
                { value: 0, name: 'osu!standard', short: 'std' },
                { value: 1, name: 'osu!taiko', short: 'taiko' },
                { value: 2, name: 'osu!catch', short: 'catch' },
                { value: 3, name: 'osu!mania', short: 'mania' },
            ],
            // Compare state
            selectedPlayers: [],
            compareVisible: false,
            compareLoading: false,
            compareError: null,
            compareData: null,
            compareMode: 0,
        },
        computed: {
            userHasStats() {
                var self = this;
                for (var i = 0; i < this.leaderboard.length; i++) {
                    if (this.leaderboard[i].id === self.selfId && this.leaderboard[i].pp > 0) {
                        return true;
                    }
                }
                return false;
            },
            selfRank() {
                var self = this;
                var idx = -1;
                for (var i = 0; i < this.leaderboard.length; i++) {
                    if (this.leaderboard[i].id === self.selfId) {
                        idx = i;
                        break;
                    }
                }
                if (idx === -1)
                    return null;
                var me = this.leaderboard[idx];
                var gapAbove = idx > 0 ? Math.round(this.leaderboard[idx - 1].pp - me.pp) : 0;
                var gapBelow = idx < this.leaderboard.length - 1 ? Math.round(me.pp - this.leaderboard[idx + 1].pp) : 0;
                return {
                    rank: idx + 1,
                    ppGapAbove: gapAbove,
                    ppGapBelow: gapBelow,
                    ppLead: idx === 0 ? gapBelow : 0
                };
            },
            cmpStats() {
                if (!this.compareData || !this.compareData.players)
                    return [];
                var players = this.compareData.players;
                function addCommas(n) {
                    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
                }
                function findWinners(vals, higherBetter) {
                    var best = higherBetter ? -Infinity : Infinity;
                    for (var i = 0; i < vals.length; i++) {
                        if (vals[i] === 0)
                            continue;
                        if (higherBetter ? vals[i] > best : vals[i] < best)
                            best = vals[i];
                    }
                    if (best === (higherBetter ? -Infinity : Infinity))
                        return [];
                    var w = [];
                    for (var i = 0; i < vals.length; i++) {
                        if (vals[i] === best && vals[i] !== 0)
                            w.push(i);
                    }
                    return w.length === vals.length ? [] : w;
                }
                var stats = [];
                // Global Rank (lower is better, 0 means unranked)
                var rankVals = players.map(function (p) { return p.rank; });
                var rankFmt = players.map(function (p) { return p.rank > 0 ? '#' + addCommas(p.rank) : '-'; });
                var rankWinners = findWinners(rankVals, false);
                stats.push({ key: 'rank', label: 'Global Rank', values: rankFmt, winners: rankWinners });
                // Higher-is-better stats
                var hiStats = [
                    { key: 'pp', label: 'PP', fmt: function (v) { return addCommas(Math.round(v)); } },
                    { key: 'acc', label: 'Accuracy', fmt: function (v) { return v.toFixed(2) + '%'; } },
                    { key: 'plays', label: 'Playcount', fmt: function (v) { return addCommas(v); } },
                    { key: 'max_combo', label: 'Max Combo', fmt: function (v) { return addCommas(v) + 'x'; } },
                ];
                for (var i = 0; i < hiStats.length; i++) {
                    var s = hiStats[i];
                    var rawVals = players.map(function (p) { return p[s.key] || 0; });
                    var fmtVals = rawVals.map(function (v) { return s.fmt(v); });
                    stats.push({ key: s.key, label: s.label, values: fmtVals, winners: findWinners(rawVals, true) });
                }
                // Grade counts (SS = xh + x, S = sh + s, A)
                var gradeStats = [
                    { key: 'ss', label: 'SS', calc: function (p) { return (p.xh_count || 0) + (p.x_count || 0); } },
                    { key: 's', label: 'S', calc: function (p) { return (p.sh_count || 0) + (p.s_count || 0); } },
                    { key: 'a', label: 'A', calc: function (p) { return p.a_count || 0; } },
                ];
                for (var i = 0; i < gradeStats.length; i++) {
                    var g = gradeStats[i];
                    var gVals = players.map(g.calc);
                    var gFmt = gVals.map(function (v) { return addCommas(v); });
                    stats.push({ key: g.key, label: g.label, values: gFmt, winners: findWinners(gVals, true) });
                }
                return stats;
            },
        },
        created() {
            this.loadLeaderboard(0);
            var self = this;
            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && self.compareVisible) {
                    self.closeCompare();
                }
            });
        },
        methods: {
            loadLeaderboard(m) {
                this.mode = m;
                this.loading = true;
                this.error = null;
                var self = this;
                fetch(location.protocol + '//api.' + domain + '/v1/get_friends_leaderboard?id=' + userId + '&mode=' + m)
                    .then(function (res) {
                    if (!res.ok)
                        throw new Error('HTTP ' + res.status);
                    return res.json();
                })
                    .then(function (data) {
                    if (data.status !== 'success')
                        throw new Error(data.status || 'Unknown error');
                    self.leaderboard = data.leaderboard || [];
                    self.loading = false;
                    self.$nextTick(function () { self.scrollToSelf(); });
                })
                    .catch(function (e) {
                    self.error = 'Failed to load leaderboard.';
                    console.error('[FriendsLeaderboard]', e);
                    self.loading = false;
                });
            },
            switchMode(m) {
                if (m === this.mode)
                    return;
                this.loadLeaderboard(m);
            },
            scrollToSelf() {
                var refs = this.$refs.selfRow;
                if (refs && refs.length) {
                    refs[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
                }
            },
            addCommas(n) {
                return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
            },
            avatarUrl(id) {
                return 'https://a.' + domain + '/' + id;
            },
            profileUrl(id) {
                return '/u/' + id;
            },
            rankClass(idx) {
                if (idx === 0)
                    return 'flb-medal--gold';
                if (idx === 1)
                    return 'flb-medal--silver';
                if (idx === 2)
                    return 'flb-medal--bronze';
                return '';
            },
            // ── Selection methods ──
            isSelected(id) {
                return this.selectedPlayers.indexOf(id) !== -1;
            },
            togglePlayer(id) {
                var idx = this.selectedPlayers.indexOf(id);
                if (idx !== -1) {
                    this.selectedPlayers.splice(idx, 1);
                }
                else if (this.selectedPlayers.length < 3) {
                    this.selectedPlayers.push(id);
                }
            },
            clearSelection() {
                this.selectedPlayers = [];
            },
            // ── Compare methods ──
            openCompare() {
                this.compareVisible = true;
                this.compareMode = this.mode;
                this.loadCompare(this.mode);
            },
            closeCompare() {
                this.compareVisible = false;
                this.compareData = null;
                this.compareError = null;
            },
            loadCompare(m) {
                this.compareMode = m;
                this.compareLoading = true;
                this.compareError = null;
                var self = this;
                var ids = [this.selfId].concat(this.selectedPlayers);
                var url = location.protocol + '//api.' + domain + '/v1/compare_stats?users=' + ids.join(',') + '&mode=' + m;
                fetch(url)
                    .then(function (res) {
                    if (!res.ok)
                        throw new Error('HTTP ' + res.status);
                    return res.json();
                })
                    .then(function (data) {
                    if (data.status !== 'success')
                        throw new Error(data.status || 'Unknown error');
                    self.compareData = data;
                    self.compareLoading = false;
                })
                    .catch(function (e) {
                    self.compareError = 'Failed to load comparison.';
                    console.error('[FriendsLeaderboard] compare error:', e);
                    self.compareLoading = false;
                });
            },
        }
    });
})();
