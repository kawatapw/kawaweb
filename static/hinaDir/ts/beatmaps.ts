(function() {
var Vue = (window as any).Vue;

// osu! API v2 response format (via osu.direct)
interface Beatmap {
    beatmapset_id: number;
    difficulty_rating: number;
    id: number;
    mode: string;
    mode_int: number;
    status: string;
    total_length: number;
    hit_length: number;
    user_id: number;
    version: string;
    accuracy: number;  // OD
    ar: number;
    bpm: number;
    convert: boolean;
    cs: number;
    drain: number;     // HP
    max_combo: number;
    count_circles: number;
    count_sliders: number;
    count_spinners: number;
    playcount: number;
    passcount: number;
}

interface BeatmapSet {
    id: number;
    artist: string;
    artist_unicode: string;
    title: string;
    title_unicode: string;
    creator: string;
    source: string;
    tags: string;
    status: string;
    video: boolean;
    storyboard: boolean;
    nsfw: boolean;
    bpm: number;
    ranked_date: string | null;
    submitted_date: string | null;
    last_updated: string | null;
    play_count: number;
    favourite_count: number;
    preview_url: string;
    is_scoreable: boolean;
    discussion_enabled: boolean;
    legacy_thread_url: string;
    availability: {
        download_disabled: boolean;
        more_information: string | null;
    };
    beatmaps: Beatmap[];
    covers: {
        cover: string;
        card: string;
    };
}

interface ModeOption {
    value: number;
    name: string;
}

interface StatusOption {
    value: number;
    name: string;
}

interface MirrorOption {
    key: string;
    name: string;
    enabled: boolean;
}

// Map status strings to display/class info
var STATUS_DISPLAY: Record<string, string> = {
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
        sets: [] as BeatmapSet[],
        loading: false,
        loadingMore: false,
        error: null as string | null,
        offset: 0,
        amount: 30,
        hasMore: true,
        searchTimer: null as number | null,
        downloadBase: '',
        mirror: 'osu_direct',
        infoSet: null as BeatmapSet | null,
        modes: [
            { value: -1, name: 'All' },
            { value: 0, name: 'osu!' },
            { value: 1, name: 'Taiko' },
            { value: 2, name: 'Catch' },
            { value: 3, name: 'Mania' },
        ] as ModeOption[],
        statuses: [
            { value: -99, name: 'All' },
            { value: 1, name: 'Ranked' },
            { value: 4, name: 'Loved' },
            { value: 3, name: 'Qualified' },
            { value: 0, name: 'Pending' },
            { value: -2, name: 'Graveyard' },
        ] as StatusOption[],
        mirrors: [
            { key: 'osu_direct', name: 'osu!direct', enabled: true },
            { key: 'osu_api_v1', name: 'osu! API v1', enabled: false },
            { key: 'osu_api_v2', name: 'osu! API v2', enabled: false },
            { key: 'catboy', name: 'catboy.best', enabled: false },
        ] as MirrorOption[],
    },
    mounted: function() {
        this.search();
    },
    methods: {
        search: function() {
            var self = this as any;
            self.offset = 0;
            self.sets = [];
            self.hasMore = true;
            self.fetchResults(false);
        },

        loadMore: function() {
            var self = this as any;
            self.offset += self.amount;
            self.fetchResults(true);
        },

        fetchResults: function(append: boolean) {
            var self = this as any;

            if (append) {
                self.loadingMore = true;
            } else {
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
            xhr.onreadystatechange = function() {
                if (xhr.readyState !== 4) return;

                self.loading = false;
                self.loadingMore = false;

                if (xhr.status !== 200) {
                    try {
                        var errData = JSON.parse(xhr.responseText);
                        self.error = errData.message || 'Failed to load results.';
                    } catch (e) {
                        self.error = 'Failed to load results (status ' + xhr.status + ').';
                    }
                    return;
                }

                try {
                    var data = JSON.parse(xhr.responseText);
                } catch (e) {
                    self.error = 'Invalid response from server.';
                    return;
                }

                if (data.status !== 'success') {
                    self.error = data.message || 'Unknown error.';
                    return;
                }

                self.downloadBase = data.download_base || '';

                var newSets: BeatmapSet[] = data.sets || [];

                if (append) {
                    for (var i = 0; i < newSets.length; i++) {
                        self.sets.push(newSets[i]);
                    }
                } else {
                    self.sets = newSets;
                }

                if (newSets.length < self.amount) {
                    self.hasMore = false;
                }
            };
            xhr.send();
        },

        onSearchInput: function() {
            var self = this as any;
            if (self.searchTimer !== null) {
                clearTimeout(self.searchTimer);
            }
            self.searchTimer = setTimeout(function() {
                self.search();
            }, 300) as any;
        },

        clearSearch: function() {
            var self = this as any;
            self.query = '';
            self.search();
        },

        setMode: function(m: number) {
            var self = this as any;
            self.mode = m;
            self.search();
        },

        setStatus: function(s: number) {
            var self = this as any;
            self.status = s;
            self.search();
        },

        setMirror: function(key: string) {
            var self = this as any;
            for (var i = 0; i < self.mirrors.length; i++) {
                if (self.mirrors[i].key === key && self.mirrors[i].enabled) {
                    self.mirror = key;
                    self.search();
                    return;
                }
            }
        },

        onMirrorChange: function() {
            var self = this as any;
            // If user somehow selected a disabled mirror, revert
            for (var i = 0; i < self.mirrors.length; i++) {
                if (self.mirrors[i].key === self.mirror && !self.mirrors[i].enabled) {
                    self.mirror = 'osu_direct';
                    return;
                }
            }
            self.search();
        },

        formatDate: function(isoStr: string): string {
            if (!isoStr) return '';
            var d = new Date(isoStr);
            var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
            return months[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear();
        },

        formatLength: function(secs: number): string {
            var m = Math.floor(secs / 60);
            var s = secs % 60;
            return m + ':' + (s < 10 ? '0' : '') + s;
        },

        starColor: function(stars: number): string {
            var d3 = (window as any).d3;
            if (d3) {
                try {
                    var scale = d3.scaleLinear()
                        .domain([0.1, 1.25, 2, 2.5, 3.3, 4.2, 4.9, 5.8, 6.7, 7.7, 9])
                        .clamp(true)
                        .range(['#4290FB', '#4FC0FF', '#4FFFD5', '#7CFF4F', '#F6F05C',
                                '#FF8068', '#FF4E6F', '#C645B8', '#6563DE', '#18158E', '#000000'])
                        .interpolate(d3.interpolateRgb.gamma(2.2));
                    var color = d3.color(scale(stars));
                    if (color) return 'rgb(' + color.r + ',' + color.g + ',' + color.b + ')';
                } catch (e) { /* fall through to fallback */ }
            }
            // Fallback if d3 not loaded yet
            if (stars < 2) return '#4290FB';
            if (stars < 2.7) return '#4FC0FF';
            if (stars < 4) return '#7CFF4F';
            if (stars < 5.3) return '#FF8068';
            if (stars < 6.5) return '#FF4E6F';
            if (stars < 8) return '#C645B8';
            return '#18158E';
        },

        statusLabel: function(status: string): string {
            return STATUS_DISPLAY[status] || status;
        },

        statusClass: function(status: string): string {
            return status || 'unknown';
        },

        modeIcon: function(mode: number): string {
            if (mode === 0) return 'fas fa-circle';
            if (mode === 1) return 'fas fa-drum';
            if (mode === 2) return 'fas fa-apple-alt';
            if (mode === 3) return 'fas fa-keyboard';
            return 'fas fa-question';
        },

        getDiffModes: function(set: BeatmapSet): number[] {
            var modes: number[] = [];
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

        getDiffCount: function(set: BeatmapSet): number {
            return (set.beatmaps || []).length;
        },

        getSortedDiffs: function(set: BeatmapSet): Beatmap[] {
            var diffs = (set.beatmaps || []).slice();
            diffs.sort(function(a: Beatmap, b: Beatmap) {
                return a.difficulty_rating - b.difficulty_rating;
            });
            return diffs;
        },

        getBPM: function(set: BeatmapSet): number {
            return Math.round(set.bpm || 0);
        },

        getLength: function(set: BeatmapSet): number {
            var beatmaps = set.beatmaps || [];
            if (beatmaps.length === 0) return 0;
            return beatmaps[0].total_length;
        },

        getCoverUrl: function(set: BeatmapSet): string {
            if (set.covers && set.covers.cover) {
                return set.covers.cover;
            }
            return 'https://assets.ppy.sh/beatmaps/' + set.id + '/covers/cover.jpg';
        },

        openInfo: function(set: BeatmapSet) {
            var self = this as any;
            self.infoSet = set;
            document.body.style.overflow = 'hidden';
        },

        closeInfo: function() {
            var self = this as any;
            self.infoSet = null;
            document.body.style.overflow = '';
        },

        addCommas: function(n: number): string {
            if (n == null) return '0';
            return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
        },

        formatDateFull: function(isoStr: string): string {
            if (!isoStr) return '';
            var d = new Date(isoStr);
            var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
            var h = d.getHours();
            var min = d.getMinutes();
            return months[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear()
                + ' at ' + (h < 10 ? '0' : '') + h + ':' + (min < 10 ? '0' : '') + min;
        },

        getDiffModesText: function(set: BeatmapSet): string {
            var MODE_NAMES: Record<number, string> = { 0: 'osu!', 1: 'Taiko', 2: 'Catch', 3: 'Mania' };
            var modeNums = this.getDiffModes(set);
            var names: string[] = [];
            for (var i = 0; i < modeNums.length; i++) {
                names.push(MODE_NAMES[modeNums[i]] || 'Unknown');
            }
            return names.join(', ');
        },
    },
});
})();
