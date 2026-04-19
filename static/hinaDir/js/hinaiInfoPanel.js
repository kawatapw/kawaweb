/**
 * <hinai-info-panel> — Reusable beatmap info modal powered by Hinai Mirror.
 *
 * Usage:
 *   1. Include hinai-info-template.html in your page ({% include %})
 *   2. Include this script
 *   3. Place <hinai-info-panel></hinai-info-panel> in your template
 *   4. Open via: window.hinaiInfoBus.$emit('open', beatmapSetObject)
 *
 * Two-phase data loading:
 *   Phase 1 (instant): CheeseGull data for title/artist/cover (from search)
 *   Phase 2 (~200ms):  Full detail fetch from backend proxy
 *
 * All data flows through the kawata Python backend — no direct mirror calls
 * from the browser (except the health check for the status indicator).
 */
(function () {
    var Vue = window.Vue;
    if (!Vue) return;

    // All endpoints go through kawata backend proxy
    var DETAIL = '/beatmaps/api/details/';
    var PP_CALC = '/beatmaps/api/pp-calc/';
    var AUDIO = '/beatmaps/api/audio/';
    var DOWNLOAD = '/beatmaps/api/download/';
    var JOSU = 'https://josu.hinamizawa.ai/';
    var AVATAR = 'https://a.ppy.sh/';
    var ACCURACIES = [100, 99, 98, 95];

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

    // Map mod bitmask to pp_data keys
    var MOD_KEY_MAP = {
        0: 'NM', 8: 'HD', 16: 'HR', 64: 'DT', 2: 'EZ', 256: 'HT',
        1024: 'FL', 24: 'HDHR', 72: 'HDDT', 80: 'HRDT', 88: 'HDHRDT',
        1040: 'HRFL', 1032: 'HDFL', 1088: 'DTFL', 1096: 'HDDTFL'
    };

    Vue.component('hinai-info-panel', {
        template: '#hinai-info-panel-template',
        data: function () {
            return {
                infoSet: null,
                // Detail fetch state
                detailState: 'idle',   // idle | loading | ready | error
                detailError: '',
                // Diff selector
                selectedDiffId: null,
                // Josu viewer
                josuLoaded: false,
                // Advanced section
                showAdvanced: false,
                // Audio player
                audioPlaying: false,
                audioProgress: 0,
                audioCurrentTime: '0:00',
                audioDuration: '0:00',
                // PP — custom calculator
                ppCustomShow: false,
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

            // ── Lifecycle ──

            openInfo: function (set) {
                this.infoSet = set;
                this.detailState = 'loading';
                this.detailError = '';
                this.selectedDiffId = null;
                this.showAdvanced = false;
                this.josuLoaded = false;
                this.ppCustomShow = false;
                this.ppTableData = null;
                this.ppTableCache = {};
                this.ppTableError = '';
                this.ppTableMods = 0;
                document.body.style.overflow = 'hidden';
                // Auto-select first diff
                var diffs = this.getSortedDiffs(set);
                if (diffs.length > 0) {
                    this.selectedDiffId = diffs[0].id || diffs[0].beatmap_id || null;
                }
                this.fetchDetail();
            },

            closeInfo: function () {
                // Stop audio
                var audio = this.$refs.hinaiAudio;
                if (audio) { audio.pause(); audio.currentTime = 0; }
                this.audioPlaying = false;
                this.audioProgress = 0;
                this.audioCurrentTime = '0:00';
                this.audioDuration = '0:00';
                this.infoSet = null;
                this.detailState = 'idle';
                this.detailError = '';
                this.selectedDiffId = null;
                this.showAdvanced = false;
                this.josuLoaded = false;
                this.ppCustomShow = false;
                this.ppTableData = null;
                this.ppTableCache = {};
                this.ppTableError = '';
                this.ppTableMods = 0;
                document.body.style.overflow = '';
            },

            // ── Detail Fetch (Phase 2) — via kawata backend proxy ──

            fetchDetail: function () {
                var self = this;
                if (!self.infoSet || !self.infoSet.id) {
                    self.detailState = 'error';
                    self.detailError = 'No beatmapset ID.';
                    return;
                }
                var url = DETAIL + self.infoSet.id;
                fetch(url).then(function (r) {
                    if (!r.ok) throw new Error('HTTP ' + r.status);
                    return r.json();
                }).then(function (data) {
                    // The response has a `beatmapset` wrapper or is the beatmapset itself
                    var bs = data.beatmapset || data;
                    // Merge enriched data into infoSet via Vue.set for reactivity
                    var keys = Object.keys(bs);
                    for (var i = 0; i < keys.length; i++) {
                        Vue.set(self.infoSet, keys[i], bs[keys[i]]);
                    }
                    // Re-select first diff from enriched data (IDs may have changed)
                    var diffs = self.getSortedDiffs(self.infoSet);
                    if (diffs.length > 0 && !self.selectedDiffId) {
                        self.selectedDiffId = diffs[0].id || diffs[0].beatmap_id;
                    }
                    self.detailState = 'ready';
                }).catch(function (e) {
                    self.detailState = 'error';
                    self.detailError = e.message || 'Failed to load details.';
                });
            },

            // ── Diff Selector ──

            selectDiff: function (diffId) {
                this.selectedDiffId = diffId;
                this.josuLoaded = false; // Reset Josu when switching diff
            },

            getSelectedDiff: function () {
                if (!this.infoSet || !this.infoSet.beatmaps || !this.selectedDiffId) return null;
                var beatmaps = this.infoSet.beatmaps;
                for (var i = 0; i < beatmaps.length; i++) {
                    var id = beatmaps[i].id || beatmaps[i].beatmap_id;
                    if (id === this.selectedDiffId) return beatmaps[i];
                }
                return null;
            },

            // ── Josu Viewer ──

            toggleJosu: function () {
                this.josuLoaded = !this.josuLoaded;
            },

            getJosuUrl: function () {
                if (!this.selectedDiffId) return '';
                return JOSU + '?b=' + this.selectedDiffId;
            },

            // ── Creator / Mapper ──

            getMapperAvatar: function () {
                if (this.infoSet && this.infoSet.user && this.infoSet.user.id) {
                    return AVATAR + this.infoSet.user.id;
                }
                return '/static/images/default-bg.png';
            },

            getMapperUrl: function () {
                var name = this.getMapperName();
                if (name && name !== 'Unknown') {
                    return 'https://hinamizawa.ai/osu/mappers/' + encodeURIComponent(name) + '/';
                }
                return '#';
            },

            getMapperName: function () {
                if (this.infoSet && this.infoSet.user && this.infoSet.user.username) {
                    return this.infoSet.user.username;
                }
                return (this.infoSet && this.infoSet.creator) || 'Unknown';
            },

            // ── Advanced Toggle ──

            toggleAdvanced: function () {
                this.showAdvanced = !this.showAdvanced;
            },

            // ── PP Quick Reference (from pp_enrichment) ──

            getQuickPP: function (diffId, modKey) {
                if (!this.infoSet || !this.infoSet.beatmaps) return null;
                var beatmaps = this.infoSet.beatmaps;
                for (var i = 0; i < beatmaps.length; i++) {
                    var id = beatmaps[i].id || beatmaps[i].beatmap_id;
                    if (id === diffId && beatmaps[i].pp_data && beatmaps[i].pp_data[modKey]) {
                        return beatmaps[i].pp_data[modKey];
                    }
                }
                return null;
            },

            getQuickPPValue: function (diffId, modKey) {
                var d = this.getQuickPP(diffId, modKey);
                if (d && d.pp != null) return Math.round(d.pp) + 'pp';
                return '\u2014';
            },

            getQuickPPStars: function (diffId, modKey) {
                var d = this.getQuickPP(diffId, modKey);
                if (d && d.stars != null) return d.stars.toFixed(2) + '\u2605';
                return '\u2014';
            },

            // ── PP Custom Calculator — via kawata backend proxy ──

            toggleCustomPP: function () {
                this.ppCustomShow = !this.ppCustomShow;
                if (this.ppCustomShow && !this.ppTableData) {
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

                var diffs = self.infoSet.beatmaps;
                var promises = [];
                var mapping = [];

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
                            data[m.diffId] = { pp_values: [null, null, null, null], difficulty: null, error: null };
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

            // ── Audio Player — via kawata backend proxy ──

            togglePlay: function () {
                var audio = this.$refs.hinaiAudio;
                if (!audio) return;
                if (audio.paused) { audio.play(); } else { audio.pause(); }
            },

            onAudioTime: function () {
                var audio = this.$refs.hinaiAudio;
                if (!audio || !audio.duration) return;
                this.audioProgress = (audio.currentTime / audio.duration) * 100;
                this.audioCurrentTime = this._fmtTime(audio.currentTime);
            },

            onAudioMeta: function () {
                var audio = this.$refs.hinaiAudio;
                if (!audio) return;
                this.audioDuration = this._fmtTime(audio.duration);
            },

            seekAudio: function (e) {
                var audio = this.$refs.hinaiAudio;
                var track = this.$refs.hinaiTrack;
                if (!audio || !track || !audio.duration) return;
                var rect = track.getBoundingClientRect();
                var pct = Math.max(0, Math.min(1, (e.clientX - rect.left) / rect.width));
                audio.currentTime = pct * audio.duration;
            },

            _fmtTime: function (s) {
                if (!s || isNaN(s)) return '0:00';
                var m = Math.floor(s / 60);
                var sec = Math.floor(s % 60);
                return m + ':' + (sec < 10 ? '0' : '') + sec;
            },

            // ── Stat Pills ──

            getStatPill: function (key) {
                var s = this.infoSet;
                if (!s) return '--';
                switch (key) {
                    case 'bpm':
                        var bpm = s.bpm || 0;
                        return bpm > 0 ? Math.round(bpm) : '--';
                    case 'length':
                        var diffs = s.beatmaps || [];
                        if (diffs.length === 0) return '--';
                        var maxLen = 0;
                        for (var i = 0; i < diffs.length; i++) {
                            if ((diffs[i].total_length || 0) > maxLen) maxLen = diffs[i].total_length;
                        }
                        return maxLen > 0 ? this.formatLength(maxLen) : '--';
                    case 'objects':
                        var sel = this.getSelectedDiff();
                        if (!sel) return '--';
                        var total = (sel.count_circles || 0) + (sel.count_sliders || 0) + (sel.count_spinners || 0);
                        return total > 0 ? this.addCommas(total) : '--';
                    case 'plays':
                        var pc = s.play_count || 0;
                        return pc > 0 ? this.addCommas(pc) : '--';
                    case 'favourites':
                        var fc = s.favourite_count || 0;
                        return fc > 0 ? this.addCommas(fc) : '--';
                    default:
                        return '--';
                }
            },

            // ── Display Helpers ──

            getSortedDiffs: function (set) {
                if (!set || !set.beatmaps) return [];
                return set.beatmaps.slice().sort(function (a, b) {
                    return (a.difficulty_rating || 0) - (b.difficulty_rating || 0);
                });
            },

            getCoverUrl: function (set) {
                if (set.covers) {
                    return set.covers['cover@2x'] || set.covers.cover || '';
                }
                return 'https://assets.ppy.sh/beatmaps/' + set.id + '/covers/cover.jpg';
            },

            statusLabel: function (s) { return STATUS_DISPLAY[s] || s; },
            statusClass: function (s) { return (s || 'pending').toLowerCase(); },
            modeIcon: function (m) { return MODE_ICONS[m] || 'fas fa-question'; },

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

            formatDateShort: function (isoStr) {
                if (!isoStr) return '--';
                var d = new Date(isoStr);
                var months = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun',
                    'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
                return months[d.getMonth()] + ' ' + d.getDate() + ', ' + d.getFullYear();
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

            getDiffVal: function (key) {
                var d = this.getSelectedDiff();
                if (!d) return '--';
                // Handle field name differences (v2 vs cheesegull)
                if (key === 'od') return d.accuracy != null ? d.accuracy : (d.od != null ? d.od : '--');
                if (key === 'hp') return d.drain != null ? d.drain : (d.hp != null ? d.hp : '--');
                return d[key] != null ? d[key] : '--';
            },

            getDiffValNum: function (key) {
                var v = this.getDiffVal(key);
                return typeof v === 'number' ? v : 0;
            },

            getDownloadUrl: function (setId, noVideo) {
                // Download still goes through the mirror's /api/v1/hinai/d/ path
                // (not a rich endpoint, just serves .osz files)
                var url = 'https://mirror.hinamizawa.ai/api/v1/hinai/d/' + setId;
                return noVideo ? url + '?noVideo=1' : url;
            },

            getAudioUrl: function (setId) {
                return AUDIO + setId;
            }
        }
    });
})();
