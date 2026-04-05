/**
 * <hinai-info-panel> — Reusable beatmap info modal powered by Hinai Mirror.
 *
 * Usage:
 *   1. Include hinai-info-template.html in your page ({% include %})
 *   2. Include this script
 *   3. Place <hinai-info-panel></hinai-info-panel> in your template
 *   4. Open via: window.hinaiInfoBus.$emit('open', beatmapSetObject)
 *
 * All data comes from mirror.hinamizawa.ai — no kawata backend dependency.
 * PP table uses /v3/osu/pp-calc/{id} with parallel requests.
 */
(function () {
    var Vue = window.Vue;
    if (!Vue) return;

    var MIRROR = 'https://mirror.hinamizawa.ai';
    var PP_CALC = MIRROR + '/v3/osu/pp-calc/';
    var AUDIO = MIRROR + '/v3/osu/music/audio/';
    var DOWNLOAD = MIRROR + '/api/v1/hinai/d/';
    var ACCURACIES = [100, 99, 98, 95];

    // Event bus for opening the panel from anywhere
    if (!window.hinaiInfoBus) {
        window.hinaiInfoBus = new Vue();
    }

    var STATUS_DISPLAY = {
        ranked: 'Ranked', approved: 'Approved', qualified: 'Qualified',
        loved: 'Loved', pending: 'Pending', wip: 'WIP', graveyard: 'Graveyard'
    };

    var MODE_ICONS = {
        0: 'fas fa-circle', 1: 'fas fa-drum',
        2: 'fas fa-apple-alt', 3: 'fas fa-keyboard'
    };

    var MODE_NAMES = { 0: 'osu!', 1: 'Taiko', 2: 'Catch', 3: 'Mania' };

    Vue.component('hinai-info-panel', {
        template: '#hinai-info-panel-template',
        data: function () {
            return {
                infoSet: null,
                ppTableShow: false,
                ppTableLoading: false,
                ppTableMods: 0,
                ppTableData: null,
                ppTableCache: {},
                ppTableError: ''
            };
        },
        created: function () {
            var self = this;
            window.hinaiInfoBus.$on('open', function (set) {
                self.openInfo(set);
            });
        },
        beforeDestroy: function () {
            window.hinaiInfoBus.$off('open');
        },
        methods: {
            openInfo: function (set) {
                this.infoSet = set;
                document.body.style.overflow = 'hidden';
            },

            closeInfo: function () {
                this.infoSet = null;
                this.ppTableShow = false;
                this.ppTableData = null;
                this.ppTableCache = {};
                this.ppTableError = '';
                this.ppTableMods = 0;
                document.body.style.overflow = '';
            },

            // --- PP Table (powered by Hinai Mirror pp-calc) ---

            togglePPTable: function () {
                this.ppTableShow = !this.ppTableShow;
                if (this.ppTableShow && !this.ppTableData) {
                    this.fetchPPData();
                }
            },

            togglePPMod: function (bit) {
                if (bit === 2 && (this.ppTableMods & 16)) this.ppTableMods &= ~16;
                if (bit === 16 && (this.ppTableMods & 2)) this.ppTableMods &= ~2;
                if (bit === 64 && (this.ppTableMods & 256)) this.ppTableMods &= ~256;
                if (bit === 256 && (this.ppTableMods & 64)) this.ppTableMods &= ~64;
                this.ppTableMods ^= bit;
                this.fetchPPData();
            },

            setPPModCombo: function (mods) {
                this.ppTableMods = mods;
                this.fetchPPData();
            },

            isPPModActive: function (bit) {
                return (this.ppTableMods & bit) !== 0;
            },

            fetchPPData: function () {
                var self = this;
                if (!self.infoSet || !self.infoSet.beatmaps || self.infoSet.beatmaps.length === 0) return;

                var cacheKey = '' + self.ppTableMods;
                if (self.ppTableCache[cacheKey]) {
                    self.ppTableData = self.ppTableCache[cacheKey];
                    self.ppTableError = '';
                    return;
                }

                self.ppTableLoading = true;
                self.ppTableError = '';

                // Build parallel requests: one per diff × accuracy
                var diffs = self.infoSet.beatmaps;
                var promises = [];
                var mapping = []; // Track which promise maps to which diff/acc

                for (var i = 0; i < diffs.length; i++) {
                    var diffId = diffs[i].id || diffs[i].beatmap_id;
                    if (!diffId) continue;
                    for (var j = 0; j < ACCURACIES.length; j++) {
                        var url = PP_CALC + diffId + '?accuracy=' + ACCURACIES[j] + '&mods=' + self.ppTableMods;
                        mapping.push({ diffId: diffId, accIdx: j });
                        promises.push(fetch(url).then(function (r) { return r.json(); }));
                    }
                }

                Promise.all(promises).then(function (results) {
                    var data = {};
                    for (var k = 0; k < results.length; k++) {
                        var m = mapping[k];
                        var r = results[k];
                        if (!data[m.diffId]) {
                            data[m.diffId] = {
                                pp_values: [null, null, null, null],
                                difficulty: null,
                                error: null
                            };
                        }
                        if (r.success) {
                            data[m.diffId].pp_values[m.accIdx] = { pp: r.pp && r.pp.total || 0 };
                            if (!data[m.diffId].difficulty && r.difficulty) {
                                data[m.diffId].difficulty = r.difficulty;
                            }
                        } else {
                            data[m.diffId].error = r.message || 'calc failed';
                        }
                    }
                    self.ppTableCache[cacheKey] = data;
                    self.ppTableData = data;
                    self.ppTableLoading = false;
                    self.ppTableError = '';
                }).catch(function () {
                    self.ppTableLoading = false;
                    self.ppTableError = 'Network error.';
                });
            },

            getPPValue: function (diffId, accIdx) {
                if (!this.ppTableData || !this.ppTableData[diffId]) return '\u2014';
                var entry = this.ppTableData[diffId];
                if (entry.error) return 'err';
                if (entry.pp_values && entry.pp_values[accIdx]) {
                    return Math.round(entry.pp_values[accIdx].pp) + 'pp';
                }
                return '\u2014';
            },

            getPPStars: function (diffId, fallback) {
                if (!this.ppTableData || !this.ppTableData[diffId]) return (fallback || 0).toFixed(2);
                var entry = this.ppTableData[diffId];
                if (entry.difficulty && entry.difficulty.stars != null) {
                    return entry.difficulty.stars.toFixed(2);
                }
                return (fallback || 0).toFixed(2);
            },

            formatPPMods: function (mods) {
                var names = [];
                if (mods & 2) names.push('EZ');
                if (mods & 8) names.push('HD');
                if (mods & 16) names.push('HR');
                if (mods & 64) names.push('DT');
                if (mods & 256) names.push('HT');
                if (mods & 1024) names.push('FL');
                return names.length > 0 ? names.join('') : 'NM';
            },

            // --- Display helpers ---

            getSortedDiffs: function (set) {
                if (!set || !set.beatmaps) return [];
                return set.beatmaps.slice().sort(function (a, b) {
                    return (a.difficulty_rating || 0) - (b.difficulty_rating || 0);
                });
            },

            getCoverUrl: function (set) {
                if (set.covers && set.covers.cover) return set.covers.cover;
                return 'https://assets.ppy.sh/beatmaps/' + set.id + '/covers/cover.jpg';
            },

            statusLabel: function (s) { return STATUS_DISPLAY[s] || s; },
            statusClass: function (s) { return (s || 'pending').toLowerCase(); },
            modeIcon: function (m) { return MODE_ICONS[m] || 'fas fa-question'; },

            getBPM: function (set) {
                return Math.round(set.bpm || 0);
            },

            getDiffCount: function (set) {
                return (set.beatmaps && set.beatmaps.length) || 0;
            },

            getDiffModes: function (set) {
                if (!set.beatmaps) return [];
                var seen = {};
                var modes = [];
                for (var i = 0; i < set.beatmaps.length; i++) {
                    var m = set.beatmaps[i].mode_int != null ? set.beatmaps[i].mode_int : set.beatmaps[i].mode;
                    if (m != null && !seen[m]) { seen[m] = true; modes.push(m); }
                }
                return modes.sort();
            },

            getDiffModesText: function (set) {
                var modeNums = this.getDiffModes(set);
                var names = [];
                for (var i = 0; i < modeNums.length; i++) {
                    names.push(MODE_NAMES[modeNums[i]] || 'Unknown');
                }
                return names.join(', ');
            },

            starColor: function (stars) {
                if (stars < 2) return '#88b300';
                if (stars < 2.7) return '#66ccff';
                if (stars < 4) return '#ffcc22';
                if (stars < 5.3) return '#ff66aa';
                if (stars < 6.5) return '#ee5555';
                if (stars < 8) return '#8866ee';
                return '#333';
            },

            addCommas: function (n) {
                if (n == null) return '0';
                return n.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ',');
            },

            formatLength: function (secs) {
                if (!secs) return '0:00';
                var m = Math.floor(secs / 60);
                var s = secs % 60;
                return m + ':' + (s < 10 ? '0' : '') + s;
            },

            formatDateFull: function (isoStr) {
                if (!isoStr) return '';
                var d = new Date(isoStr);
                var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                var h = d.getHours();
                var min = d.getMinutes();
                return months[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear()
                    + ' at ' + (h < 10 ? '0' : '') + h + ':' + (min < 10 ? '0' : '') + min;
            },

            getDownloadUrl: function (setId, noVideo) {
                var url = DOWNLOAD + setId;
                return noVideo ? url + '?noVideo=1' : url;
            },

            getAudioUrl: function (setId) {
                return AUDIO + setId;
            }
        }
    });
})();
