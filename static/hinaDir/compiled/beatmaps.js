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
            infoSet: null,
            ppTableShow: false,
            ppTableLoading: false,
            ppTableMods: 0,
            ppTableData: null,
            ppTableCache: {},
            ppTableError: '',
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
                { key: 'hinai', name: 'hinai', enabled: true },
                { key: 'osu_direct', name: 'osu!direct', enabled: true },
                { key: 'osu_api_v1', name: 'osu! API v1', enabled: false },
                { key: 'osu_api_v2', name: 'osu! API v2', enabled: false },
                { key: 'catboy', name: 'catboy.best', enabled: false },
            ],
        },
        mounted: function () {
            this.search();
        },
        methods: {
            getDownloadUrl: function (setId, noVideo) {
                var self = this;
                var base;
                if (self.mirror === 'osu_direct') {
                    base = 'https://osu.direct/api/d/' + setId;
                } else {
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
                var url = '/beatmaps/api/search?query=' + encodeURIComponent(self.query)
                    + '&mode=' + self.mode
                    + '&status=' + statusParam
                    + '&amount=' + self.amount
                    + '&offset=' + self.offset;
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
            openInfo: function (set) {
                var self = this;
                self.infoSet = set;
                document.body.style.overflow = 'hidden';
            },
            closeInfo: function () {
                var self = this;
                self.infoSet = null;
                self.ppTableShow = false;
                self.ppTableData = null;
                self.ppTableCache = {};
                self.ppTableError = '';
                self.ppTableMods = 0;
                document.body.style.overflow = '';
            },
            addCommas: function (n) {
                if (n == null)
                    return '0';
                return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
            },
            formatDateFull: function (isoStr) {
                if (!isoStr)
                    return '';
                var d = new Date(isoStr);
                var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                var h = d.getHours();
                var min = d.getMinutes();
                return months[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear()
                    + ' at ' + (h < 10 ? '0' : '') + h + ':' + (min < 10 ? '0' : '') + min;
            },
            getDiffModesText: function (set) {
                var MODE_NAMES = { 0: 'osu!', 1: 'Taiko', 2: 'Catch', 3: 'Mania' };
                var modeNums = this.getDiffModes(set);
                var names = [];
                for (var i = 0; i < modeNums.length; i++) {
                    names.push(MODE_NAMES[modeNums[i]] || 'Unknown');
                }
                return names.join(', ');
            },
            // ─── PP Table ────────────────────────────────────────────
            togglePPTable: function () {
                var self = this;
                self.ppTableShow = !self.ppTableShow;
                if (self.ppTableShow && !self.ppTableData) {
                    self.fetchPPData();
                }
            },
            togglePPMod: function (bit) {
                var self = this;
                // EZ(2) / HR(16) conflict
                if (bit === 2 && (self.ppTableMods & 16)) {
                    self.ppTableMods &= ~16;
                }
                if (bit === 16 && (self.ppTableMods & 2)) {
                    self.ppTableMods &= ~2;
                }
                // DT(64) / HT(256) conflict
                if (bit === 64 && (self.ppTableMods & 256)) {
                    self.ppTableMods &= ~256;
                }
                if (bit === 256 && (self.ppTableMods & 64)) {
                    self.ppTableMods &= ~64;
                }
                self.ppTableMods ^= bit;
                self.fetchPPData();
            },
            setPPModCombo: function (mods) {
                var self = this;
                self.ppTableMods = mods;
                self.fetchPPData();
            },
            isPPModActive: function (bit) {
                return (this.ppTableMods & bit) !== 0;
            },
            fetchPPData: function () {
                var self = this;
                if (!self.infoSet || !self.infoSet.beatmaps || self.infoSet.beatmaps.length === 0)
                    return;
                var cacheKey = '' + self.ppTableMods;
                if (self.ppTableCache[cacheKey]) {
                    self.ppTableData = self.ppTableCache[cacheKey];
                    self.ppTableError = '';
                    return;
                }
                self.ppTableLoading = true;
                self.ppTableError = '';
                var ids = [];
                for (var i = 0; i < self.infoSet.beatmaps.length; i++) {
                    ids.push(self.infoSet.beatmaps[i].id);
                }
                var xhr = new XMLHttpRequest();
                xhr.open('GET', '/beatmaps/api/pp-table?ids=' + ids.join(',') + '&mods=' + self.ppTableMods, true);
                xhr.onreadystatechange = function () {
                    if (xhr.readyState !== 4)
                        return;
                    self.ppTableLoading = false;
                    if (xhr.status !== 200) {
                        self.ppTableError = 'Failed to fetch PP data (status ' + xhr.status + ').';
                        return;
                    }
                    try {
                        var data = JSON.parse(xhr.responseText);
                        if (data.status === 'success') {
                            self.ppTableCache[cacheKey] = data.results;
                            self.ppTableData = data.results;
                            self.ppTableError = '';
                        }
                        else {
                            self.ppTableError = data.message || 'Failed to fetch PP data.';
                        }
                    }
                    catch (e) {
                        self.ppTableError = 'Invalid response.';
                    }
                };
                xhr.send();
            },
            formatPPMods: function (mods) {
                if (!mods)
                    return 'None';
                var MOD_BITS = {
                    1: 'NF', 2: 'EZ', 4: 'TD', 8: 'HD', 16: 'HR', 32: 'SD',
                    64: 'DT', 128: 'RX', 256: 'HT', 512: 'NC', 1024: 'FL'
                };
                var names = [];
                for (var bit in MOD_BITS) {
                    if (MOD_BITS.hasOwnProperty(bit)) {
                        var bitNum = parseInt(bit, 10);
                        if (mods & bitNum) {
                            names.push(MOD_BITS[bitNum]);
                        }
                    }
                }
                return names.length ? '+' + names.join('') : 'None';
            },
            getPPValue: function (diffId, accIdx) {
                var self = this;
                if (!self.ppTableData || !self.ppTableData[diffId])
                    return '\u2014';
                var entry = self.ppTableData[diffId];
                if (entry.error)
                    return 'err';
                if (entry.pp_values && entry.pp_values[accIdx]) {
                    return Math.round(entry.pp_values[accIdx].pp) + 'pp';
                }
                return '\u2014';
            },
            getPPStars: function (diffId, fallback) {
                var self = this;
                if (!self.ppTableData || !self.ppTableData[diffId])
                    return (fallback || 0).toFixed(2);
                var entry = self.ppTableData[diffId];
                if (entry.difficulty && entry.difficulty.stars != null) {
                    return entry.difficulty.stars.toFixed(2);
                }
                return (fallback || 0).toFixed(2);
            },
        },
    });
})();
