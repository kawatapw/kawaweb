(function() {
var Vue = (window as any).Vue;
var domain = (window as any).domain;
var userId = (window as any).userId;

interface LeaderboardEntry {
    rank: number;
    id: number;
    name: string;
    country: string;
    clan_tag: string | null;
    global_rank: number;
    pp: number;
    acc: number;
    plays: number;
    is_online: boolean;
    pp_delta: { value: number; type: string } | null;
}

new Vue({
    el: '#friends-leaderboard-app',
    data: {
        mode: 0,
        leaderboard: [] as LeaderboardEntry[],
        loading: true,
        error: null as string | null,
        selfId: userId,
        modes: [
            { value: 0, name: 'osu!standard', short: 'std' },
            { value: 1, name: 'osu!taiko', short: 'taiko' },
            { value: 2, name: 'osu!catch', short: 'catch' },
            { value: 3, name: 'osu!mania', short: 'mania' },
        ],
        // Season state
        seasons: [] as any[],
        selectedSeason: 0,
        selectedYear: null as number | null,
        activeSeason: null as any,
        // Compare state
        selectedPlayers: [] as number[],
        compareVisible: false,
        compareLoading: false,
        compareError: null as string | null,
        compareData: null as any,
        compareMode: 0,
        // Tooltip state
        tooltipId: null as number | null,
        tooltipData: null as any,
        tooltipLoading: false,
        tipCache: {} as Record<string, any>,
        tipTimer: null as number | null,
        tipTop: 0,
        tipLeft: 0,
    },
    computed: {
        yearOptions(): number[] {
            var years: number[] = [];
            for (var i = 0; i < this.seasons.length; i++) {
                var y = new Date(this.seasons[i].start_date).getFullYear();
                if (years.indexOf(y) === -1) years.push(y);
            }
            return years.sort(function(a: number, b: number) { return b - a; });
        },
        filteredSeasons(): any[] {
            var self = this;
            return this.seasons
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
        userHasStats(): boolean {
            var self = this;
            for (var i = 0; i < this.leaderboard.length; i++) {
                if (this.leaderboard[i].id === self.selfId && this.leaderboard[i].pp > 0) {
                    return true;
                }
            }
            return false;
        },
        selfRank(): any {
            var self = this;
            var idx = -1;
            for (var i = 0; i < this.leaderboard.length; i++) {
                if (this.leaderboard[i].id === self.selfId) { idx = i; break; }
            }
            if (idx === -1) return null;

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
        cmpStats(): any[] {
            if (!this.compareData || !this.compareData.players) return [];
            var players = this.compareData.players;

            function addCommas(n: number): string {
                return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
            }

            function findWinners(vals: number[], higherBetter: boolean): number[] {
                var best = higherBetter ? -Infinity : Infinity;
                for (var i = 0; i < vals.length; i++) {
                    if (vals[i] === 0) continue;
                    if (higherBetter ? vals[i] > best : vals[i] < best) best = vals[i];
                }
                if (best === (higherBetter ? -Infinity : Infinity)) return [];
                var w: number[] = [];
                for (var i = 0; i < vals.length; i++) {
                    if (vals[i] === best && vals[i] !== 0) w.push(i);
                }
                return w.length === vals.length ? [] : w;
            }

            var stats: any[] = [];

            // Global Rank (lower is better, 0 means unranked)
            var rankVals = players.map(function(p: any) { return p.rank; });
            var rankFmt = players.map(function(p: any) { return p.rank > 0 ? '#' + addCommas(p.rank) : '-'; });
            var rankWinners = findWinners(rankVals, false);
            stats.push({ key: 'rank', label: 'Global Rank', values: rankFmt, winners: rankWinners });

            // Higher-is-better stats
            var hiStats = [
                { key: 'pp', label: 'PP', fmt: function(v: number) { return addCommas(Math.round(v)); } },
                { key: 'acc', label: 'Accuracy', fmt: function(v: number) { return v.toFixed(2) + '%'; } },
                { key: 'plays', label: 'Playcount', fmt: function(v: number) { return addCommas(v); } },
                { key: 'max_combo', label: 'Max Combo', fmt: function(v: number) { return addCommas(v) + 'x'; } },
            ];

            for (var i = 0; i < hiStats.length; i++) {
                var s = hiStats[i];
                var rawVals = players.map(function(p: any) { return p[s.key] || 0; });
                var fmtVals = rawVals.map(function(v: number) { return s.fmt(v); });
                stats.push({ key: s.key, label: s.label, values: fmtVals, winners: findWinners(rawVals, true) });
            }

            // Grade counts (SS = xh + x, S = sh + s, A)
            var gradeStats = [
                { key: 'ss', label: 'SS', calc: function(p: any) { return (p.xh_count || 0) + (p.x_count || 0); } },
                { key: 's', label: 'S', calc: function(p: any) { return (p.sh_count || 0) + (p.s_count || 0); } },
                { key: 'a', label: 'A', calc: function(p: any) { return p.a_count || 0; } },
            ];

            for (var i = 0; i < gradeStats.length; i++) {
                var g = gradeStats[i];
                var gVals = players.map(g.calc);
                var gFmt = gVals.map(function(v: number) { return addCommas(v); });
                stats.push({ key: g.key, label: g.label, values: gFmt, winners: findWinners(gVals, true) });
            }

            return stats;
        },
    },
    created() {
        this.fetchSeasons();
        this.loadLeaderboard(0);

        var self = this;
        document.addEventListener('keydown', function(e: KeyboardEvent) {
            if (e.key === 'Escape' && self.compareVisible) {
                self.closeCompare();
            }
        });
    },
    methods: {
        loadLeaderboard(m: number) {
            this.mode = m;
            this.loading = true;
            this.error = null;
            var self = this;

            var seasonParam = this.selectedSeason ? '&season_id=' + this.selectedSeason : '';
            fetch(location.protocol + '//api.' + domain + '/v1/get_friends_leaderboard?id=' + userId + '&mode=' + m + seasonParam)
                .then(function(res: Response) {
                    if (!res.ok) throw new Error('HTTP ' + res.status);
                    return res.json();
                })
                .then(function(data: any) {
                    if (data.status !== 'success') throw new Error(data.status || 'Unknown error');
                    self.leaderboard = data.leaderboard || [];
                    self.loading = false;
                    self.$nextTick(function() { self.scrollToSelf(); });
                })
                .catch(function(e: any) {
                    self.error = 'Failed to load leaderboard.';
                    console.error('[FriendsLeaderboard]', e);
                    self.loading = false;
                });
        },

        switchMode(m: number) {
            if (m === this.mode) return;
            this.loadLeaderboard(m);
        },

        scrollToSelf() {
            var refs = this.$refs.selfRow;
            if (refs && refs.length) {
                refs[0].scrollIntoView({ behavior: 'smooth', block: 'center' });
            }
        },

        addCommas(n: number): string {
            return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        },

        avatarUrl(id: number): string {
            return 'https://a.' + domain + '/' + id;
        },

        profileUrl(id: number): string {
            return '/u/' + id;
        },

        rankClass(idx: number): string {
            if (idx === 0) return 'flb-medal--gold';
            if (idx === 1) return 'flb-medal--silver';
            if (idx === 2) return 'flb-medal--bronze';
            return '';
        },

        // ── Selection methods ──

        isSelected(id: number): boolean {
            return this.selectedPlayers.indexOf(id) !== -1;
        },

        togglePlayer(id: number) {
            var idx = this.selectedPlayers.indexOf(id);
            if (idx !== -1) {
                this.selectedPlayers.splice(idx, 1);
            } else if (this.selectedPlayers.length < 3) {
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

        loadCompare(m: number) {
            this.compareMode = m;
            this.compareLoading = true;
            this.compareError = null;
            var self = this;

            var ids = [this.selfId].concat(this.selectedPlayers);
            var cmpSeasonParam = this.selectedSeason ? '&season_id=' + this.selectedSeason : '';
            var url = location.protocol + '//api.' + domain + '/v1/compare_stats?users=' + ids.join(',') + '&mode=' + m + cmpSeasonParam;

            fetch(url)
                .then(function(res: Response) {
                    if (!res.ok) throw new Error('HTTP ' + res.status);
                    return res.json();
                })
                .then(function(data: any) {
                    if (data.status !== 'success') throw new Error(data.status || 'Unknown error');
                    self.compareData = data;
                    self.compareLoading = false;
                })
                .catch(function(e: any) {
                    self.compareError = 'Failed to load comparison.';
                    console.error('[FriendsLeaderboard] compare error:', e);
                    self.compareLoading = false;
                });
        },

        // ── Tooltip methods ──

        showTooltip(id: number, event: MouseEvent) {
            var self = this;
            // Clear any pending timer
            if (this.tipTimer) {
                clearTimeout(this.tipTimer);
                this.tipTimer = null;
            }

            // Calculate fixed position from the hovered cell
            var td = event.currentTarget as HTMLElement;
            var rect = td.getBoundingClientRect();
            this.tipTop = rect.bottom + 8;
            this.tipLeft = rect.left;

            var cacheKey = id + '-' + this.mode + '-' + (this.selectedSeason || 0);
            if (this.tipCache[cacheKey]) {
                // Cached — show immediately
                this.tooltipId = id;
                this.tooltipData = this.tipCache[cacheKey];
                this.tooltipLoading = false;
                return;
            }

            // Debounce 300ms before fetching
            this.tipTimer = window.setTimeout(function() {
                self.tooltipId = id;
                self.tooltipLoading = true;
                self.tooltipData = null;
                self.fetchTooltip(id);
            }, 300);
        },

        hideTooltip() {
            if (this.tipTimer) {
                clearTimeout(this.tipTimer);
                this.tipTimer = null;
            }
            this.tooltipId = null;
            this.tooltipData = null;
            this.tooltipLoading = false;
        },

        fetchTooltip(id: number) {
            var self = this;
            var mode = this.mode;
            var tipSeasonParam = this.selectedSeason ? '&season_id=' + this.selectedSeason : '';
            var cacheKey = id + '-' + mode + '-' + (this.selectedSeason || 0);
            var url = location.protocol + '//api.' + domain + '/v1/get_player_quick_stats?id=' + id + '&mode=' + mode + tipSeasonParam;

            fetch(url)
                .then(function(res: Response) {
                    if (!res.ok) throw new Error('HTTP ' + res.status);
                    return res.json();
                })
                .then(function(data: any) {
                    if (data.status !== 'success') return;
                    self.tipCache[cacheKey] = data;
                    // Only show if still hovering the same player
                    if (self.tooltipId === id) {
                        self.tooltipData = data;
                        self.tooltipLoading = false;
                    }
                })
                .catch(function(e: any) {
                    console.error('[FriendsLeaderboard] tooltip fetch error:', e);
                    if (self.tooltipId === id) {
                        self.tooltipLoading = false;
                    }
                });
        },

        fetchSeasons() {
            var self = this;
            fetch(location.protocol + '//api.' + domain + '/v2/seasons?page=1&page_size=100')
                .then(function(res: Response) {
                    if (!res.ok) throw new Error('HTTP ' + res.status);
                    return res.json();
                })
                .then(function(data: any) {
                    if (data.status === 'success' && data.data) {
                        self.seasons = data.data;
                        self.activeSeason = self.seasons.find(function(s: any) { return s.is_active; }) || null;
                        if (self.yearOptions.length > 0) {
                            self.selectedYear = self.yearOptions[0];
                            // Auto-select active season or latest in year
                            var filtered = self.filteredSeasons;
                            if (self.activeSeason && filtered.some(function(s: any) { return s.id === self.activeSeason.id; })) {
                                self.selectedSeason = self.activeSeason.id;
                            } else if (filtered.length > 0) {
                                self.selectedSeason = filtered[filtered.length - 1].id;
                            }
                            // Reload leaderboard with the selected season
                            if (self.selectedSeason) {
                                self.reloadForSeason();
                            }
                        }
                    }
                })
                .catch(function(err: any) {
                    console.error('[FriendsLeaderboard] Failed to fetch seasons:', err);
                });
        },

        selectSeason(seasonId: number) {
            this.selectedSeason = seasonId;
            this.tipCache = {};
            this.reloadForSeason();
        },

        onYearChange() {
            var seasons = this.filteredSeasons;
            if (seasons.length > 0) {
                this.selectedSeason = seasons[seasons.length - 1].id;
                this.tipCache = {};
                this.reloadForSeason();
            }
        },

        onSeasonChange() {
            this.tipCache = {};
            this.reloadForSeason();
        },

        reloadForSeason() {
            // Soft reload — don't set loading=true so the table stays visible (no layout shift)
            var self = this;
            this.error = null;
            var seasonParam = this.selectedSeason ? '&season_id=' + this.selectedSeason : '';
            fetch(location.protocol + '//api.' + domain + '/v1/get_friends_leaderboard?id=' + userId + '&mode=' + this.mode + seasonParam)
                .then(function(res: Response) {
                    if (!res.ok) throw new Error('HTTP ' + res.status);
                    return res.json();
                })
                .then(function(data: any) {
                    if (data.status !== 'success') throw new Error(data.status || 'Unknown error');
                    self.leaderboard = data.leaderboard || [];
                })
                .catch(function(e: any) {
                    self.error = 'Failed to load leaderboard.';
                    console.error('[FriendsLeaderboard]', e);
                });
        },

        formatTotalScore(n: number): string {
            if (n >= 1e9) return (n / 1e9).toFixed(2) + 'B';
            if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
            if (n >= 1e3) return (n / 1e3).toFixed(0) + 'K';
            return String(n);
        },

        formatPlaytime(seconds: number): string {
            var hours = Math.floor(seconds / 3600);
            if (hours >= 24) {
                var days = Math.floor(hours / 24);
                var rem = hours % 24;
                return days + 'd ' + rem + 'h';
            }
            return hours + 'h';
        },
    }
});
})();
