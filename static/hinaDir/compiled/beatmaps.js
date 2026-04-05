(function () {
    var Vue = window.Vue;
    // Map status strings to display/class info
    var STATUS_DISPLAY = {
        'ranked': 'Ranked',
        'approved': 'Approved',
        'qualified': 'Qualified',
        'loved': 'Loved',
        'pending': 'Pending',
        'wip': 'WIP',
        'graveyard': 'Graveyard',
    };
    new Vue({
        el: '#beatmaps-app',
        data: {
            query: '',
            mode: -1,
            status: 1,
            sets: [],
            loading: false,
            loadingMore: false,
            error: null,
            offset: 0,
            amount: 30,
            hasMore: true,
            searchTimer: null,
            downloadBase: '',
            mirror: 'hinai',
            hinaiOnline: true,
            modes: [
                { value: -1, name: 'All' },
                { value: 0, name: 'osu!' },
                { value: 1, name: 'Taiko' },
                { value: 2, name: 'Catch' },
                { value: 3, name: 'Mania' },
            ],
            statuses: [
                { value: -99, name: 'All' },
                { value: 1, name: 'Ranked' },
                { value: 4, name: 'Loved' },
                { value: 3, name: 'Qualified' },
                { value: 0, name: 'Pending' },
                { value: -2, name: 'Graveyard' },
            ],
            mirrors: [
                { key: 'hinai', name: 'Hinai', enabled: true },
                { key: 'osu_direct', name: 'osu!direct', enabled: true },
                { key: 'osu_api_v1', name: 'osu! API v1', enabled: false },
                { key: 'osu_api_v2', name: 'osu! API v2', enabled: false },
                { key: 'catboy', name: 'catboy.best', enabled: false },
            ],
        },
        mounted: function () {
            this.search();
            // One-time mirror health check on page load
            var self = this;
            fetch('https://mirror.hinamizawa.ai/health', { mode: 'cors' })
                .then(function (r) { self.hinaiOnline = r.ok; })
                .catch(function () { self.hinaiOnline = false; });
        },
        methods: {
            getDownloadUrl: function (setId, noVideo) {
                var self = this;
                var base;
                if (self.mirror === 'osu_direct') {
                    base = 'https://osu.direct/api/d/' + setId;
                }
                else {
                    base = self.downloadBase + '/' + setId;
                }
                return noVideo ? base + '?noVideo=1' : base;
            },
            search: function () {
                var self = this;
                self.offset = 0;
                self.sets = [];
                self.hasMore = true;
                self.fetchResults(false);
            },
            loadMore: function () {
                var self = this;
                self.offset += self.amount;
                self.fetchResults(true);
            },
            fetchResults: function (append) {
                var self = this;
                if (append) {
                    self.loadingMore = true;
                }
                else {
                    self.loading = true;
                }
                self.error = null;
                var statusParam = self.status;
                if (statusParam === -99) {
                    statusParam = -1;
                }
                var source = self.mirror === 'osu_direct' ? 'osu_direct' : 'hinai';
                var url = '/beatmaps/api/search?query=' + encodeURIComponent(self.query)
                    + '&mode=' + self.mode
                    + '&status=' + statusParam
                    + '&amount=' + self.amount
                    + '&offset=' + self.offset
                    + '&source=' + source;
                var xhr = new XMLHttpRequest();
                xhr.open('GET', url, true);
                xhr.onreadystatechange = function () {
                    if (xhr.readyState !== 4)
                        return;
                    self.loading = false;
                    self.loadingMore = false;
                    if (xhr.status !== 200) {
                        try {
                            var errData = JSON.parse(xhr.responseText);
                            self.error = errData.message || 'Failed to load results.';
                        }
                        catch (e) {
                            self.error = 'Failed to load results (status ' + xhr.status + ').';
                        }
                        return;
                    }
                    try {
                        var data = JSON.parse(xhr.responseText);
                    }
                    catch (e) {
                        self.error = 'Invalid response from server.';
                        return;
                    }
                    if (data.status !== 'success') {
                        self.error = data.message || 'Unknown error.';
                        return;
                    }
                    self.downloadBase = data.download_base || '';
                    var newSets = data.sets || [];
                    if (append) {
                        for (var i = 0; i < newSets.length; i++) {
                            self.sets.push(newSets[i]);
                        }
                    }
                    else {
                        self.sets = newSets;
                    }
                    if (newSets.length < self.amount) {
                        self.hasMore = false;
                    }
                };
                xhr.send();
            },
            onSearchInput: function () {
                var self = this;
                if (self.searchTimer !== null) {
                    clearTimeout(self.searchTimer);
                }
                self.searchTimer = setTimeout(function () {
                    self.search();
                }, 300);
            },
            clearSearch: function () {
                var self = this;
                self.query = '';
                self.search();
            },
            setMode: function (m) {
                var self = this;
                self.mode = m;
                self.search();
            },
            setStatus: function (s) {
                var self = this;
                self.status = s;
                self.search();
            },
            setMirror: function (key) {
                var self = this;
                for (var i = 0; i < self.mirrors.length; i++) {
                    if (self.mirrors[i].key === key && self.mirrors[i].enabled) {
                        self.mirror = key;
                        self.search();
                        return;
                    }
                }
            },
            onMirrorChange: function () {
                var self = this;
                // If user somehow selected a disabled mirror, revert
                for (var i = 0; i < self.mirrors.length; i++) {
                    if (self.mirrors[i].key === self.mirror && !self.mirrors[i].enabled) {
                        self.mirror = 'hinai';
                        return;
                    }
                }
                self.search();
            },
            formatDate: function (isoStr) {
                if (!isoStr)
                    return '';
                var d = new Date(isoStr);
                var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                return months[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear();
            },
            formatLength: function (secs) {
                var m = Math.floor(secs / 60);
                var s = secs % 60;
                return m + ':' + (s < 10 ? '0' : '') + s;
            },
            starColor: function (stars) {
                var d3 = window.d3;
                if (d3) {
                    try {
                        var scale = d3.scaleLinear()
                            .domain([0.1, 1.25, 2, 2.5, 3.3, 4.2, 4.9, 5.8, 6.7, 7.7, 9])
                            .clamp(true)
                            .range(['#4290FB', '#4FC0FF', '#4FFFD5', '#7CFF4F', '#F6F05C',
                            '#FF8068', '#FF4E6F', '#C645B8', '#6563DE', '#18158E', '#000000'])
                            .interpolate(d3.interpolateRgb.gamma(2.2));
                        var color = d3.color(scale(stars));
                        if (color)
                            return 'rgb(' + color.r + ',' + color.g + ',' + color.b + ')';
                    }
                    catch (e) { /* fall through to fallback */ }
                }
                // Fallback if d3 not loaded yet
                if (stars < 2)
                    return '#4290FB';
                if (stars < 2.7)
                    return '#4FC0FF';
                if (stars < 4)
                    return '#7CFF4F';
                if (stars < 5.3)
                    return '#FF8068';
                if (stars < 6.5)
                    return '#FF4E6F';
                if (stars < 8)
                    return '#C645B8';
                return '#18158E';
            },
            statusLabel: function (status) {
                return STATUS_DISPLAY[status] || status;
            },
            statusClass: function (status) {
                return status || 'unknown';
            },
            modeIcon: function (mode) {
                if (mode === 0)
                    return 'fas fa-circle';
                if (mode === 1)
                    return 'fas fa-drum';
                if (mode === 2)
                    return 'fas fa-apple-alt';
                if (mode === 3)
                    return 'fas fa-keyboard';
                return 'fas fa-question';
            },
            getDiffModes: function (set) {
                var modes = [];
                var beatmaps = set.beatmaps || [];
                for (var i = 0; i < beatmaps.length; i++) {
                    var m = beatmaps[i].mode_int;
                    if (modes.indexOf(m) === -1) {
                        modes.push(m);
                    }
                }
                modes.sort();
                return modes;
            },
            getDiffCount: function (set) {
                return (set.beatmaps || []).length;
            },
            getSortedDiffs: function (set) {
                var diffs = (set.beatmaps || []).slice();
                diffs.sort(function (a, b) {
                    return a.difficulty_rating - b.difficulty_rating;
                });
                return diffs;
            },
            getBPM: function (set) {
                return Math.round(set.bpm || 0);
            },
            getLength: function (set) {
                var beatmaps = set.beatmaps || [];
                if (beatmaps.length === 0)
                    return 0;
                return beatmaps[0].total_length;
            },
            getCoverUrl: function (set) {
                if (set.covers && set.covers.cover) {
                    return set.covers.cover;
                }
                return 'https://assets.ppy.sh/beatmaps/' + set.id + '/covers/cover.jpg';
            },
            showBeatmapPanel: function (set) {
                var firstDiff = (set.beatmaps && set.beatmaps.length > 0) ? set.beatmaps[0].id : null;
                window.beatmapBus.$emit('show-beatmap-panel', firstDiff, set.id, set);
            },
            openInfo: function (set) {
                window.hinaiInfoBus.$emit('open', set);
            },
        },
    });
})();
