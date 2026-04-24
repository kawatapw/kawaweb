(function () {
    var Vue = window.Vue;
    var domain = window.domain;
    var userId = window.userId;
    var timeago = window.timeago;
    var HeroBannerMixin = window.HeroBannerMixin;
    new Vue({
        el: '#friends-app',
        mixins: HeroBannerMixin ? [HeroBannerMixin] : [],
        data: {
            tab: 'mutuals',
            mutuals: [],
            followers: [],
            blocked: [],
            loading: true,
            error: null,
            actionLoading: {},
            searchQuery: '',
            actionError: null,
            actionErrorTimer: null,
            toastVisible: false,
            toastMessage: '',
            toastTimer: null,
            sections: { online: true, offline: true },
            // Compare modal
            compareVisible: false,
            compareLoading: false,
            compareError: null,
            compareUser: 0,
            compareMode: 0,
            compareData: null,
            compareModes: [
                { value: 0, name: 'osu!standard', short: 'std' },
                { value: 1, name: 'osu!taiko', short: 'taiko' },
                { value: 2, name: 'osu!catch', short: 'catch' },
                { value: 3, name: 'osu!mania', short: 'mania' },
            ],
            pollTimer: null,
            pollAttempts: 0,
            pollError: false,
            isPolling: false,
            _visHandler: null,
        },
        computed: {
            currentList() {
                var list = this.getBaseList();
                if (!this.searchQuery)
                    return list;
                var q = this.searchQuery.toLowerCase();
                return list.filter(function (u) {
                    return u.name.toLowerCase().indexOf(q) !== -1;
                });
            },
            onlineFriends() {
                var self = this;
                return this.currentList
                    .filter(function (u) { return u.is_online; })
                    .sort(function (a, b) {
                    return self._actionPriority(a) - self._actionPriority(b);
                });
            },
            offlineFriends() {
                return this.currentList
                    .filter(function (u) { return !u.is_online; })
                    .sort(function (a, b) {
                    return b.latest_activity - a.latest_activity;
                });
            },
            totalFriends() {
                return this.mutuals.length;
            },
            totalOnline() {
                return this.mutuals.filter(function (u) { return u.is_online; }).length;
            },
            totalFollowers() {
                return this.followers.length;
            },
            compareStats() {
                if (!this.compareData || !this.compareData.players)
                    return [];
                var p1 = this.compareData.players[0];
                var p2 = this.compareData.players[1];
                var stats = [];
                function addCommas(n) {
                    return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
                }
                // Rank: lower is better (skip if both 0)
                if (p1.rank > 0 || p2.rank > 0) {
                    var rw = 0;
                    if (p1.rank > 0 && p2.rank > 0)
                        rw = p1.rank < p2.rank ? 1 : (p2.rank < p1.rank ? 2 : 0);
                    else if (p1.rank > 0)
                        rw = 1;
                    else
                        rw = 2;
                    stats.push({ key: 'rank', label: 'Rank', left: p1.rank > 0 ? '#' + addCommas(p1.rank) : '-', right: p2.rank > 0 ? '#' + addCommas(p2.rank) : '-', winner: rw });
                }
                // Higher-is-better stats
                var higherBetter = [
                    { key: 'pp', label: 'PP', fmt: function (v) { return addCommas(Math.round(v)); } },
                    { key: 'acc', label: 'Accuracy', fmt: function (v) { return v.toFixed(2) + '%'; } },
                    { key: 'plays', label: 'Playcount', fmt: function (v) { return addCommas(v); } },
                    { key: 'max_combo', label: 'Max Combo', fmt: function (v) { return addCommas(v) + 'x'; } },
                ];
                for (var i = 0; i < higherBetter.length; i++) {
                    var s = higherBetter[i];
                    var v1 = p1[s.key] || 0;
                    var v2 = p2[s.key] || 0;
                    var w = v1 > v2 ? 1 : (v2 > v1 ? 2 : 0);
                    stats.push({ key: s.key, label: s.label, left: s.fmt(v1), right: s.fmt(v2), winner: w });
                }
                // Grade counts
                var ss1 = (p1.xh_count || 0) + (p1.x_count || 0);
                var ss2 = (p2.xh_count || 0) + (p2.x_count || 0);
                stats.push({ key: 'ss', label: 'SS', left: addCommas(ss1), right: addCommas(ss2), winner: ss1 > ss2 ? 1 : (ss2 > ss1 ? 2 : 0) });
                var sc1 = (p1.sh_count || 0) + (p1.s_count || 0);
                var sc2 = (p2.sh_count || 0) + (p2.s_count || 0);
                stats.push({ key: 's', label: 'S', left: addCommas(sc1), right: addCommas(sc2), winner: sc1 > sc2 ? 1 : (sc2 > sc1 ? 2 : 0) });
                var a1 = p1.a_count || 0;
                var a2 = p2.a_count || 0;
                stats.push({ key: 'a', label: 'A', left: addCommas(a1), right: addCommas(a2), winner: a1 > a2 ? 1 : (a2 > a1 ? 2 : 0) });
                return stats;
            },
        },
        created() {
            if (typeof this.fetchHero === 'function')
                this.fetchHero();
            this.loadAll();
            this.startPolling();
            var self = this;
            this._visHandler = function () { self._handleVisibility(); };
            document.addEventListener('visibilitychange', this._visHandler);
            document.addEventListener('keydown', function (e) {
                if (e.key === 'Escape' && self.compareVisible) {
                    self.closeCompare();
                }
            });
        },
        beforeDestroy() {
            this.stopPolling();
            if (this._visHandler)
                document.removeEventListener('visibilitychange', this._visHandler);
        },
        methods: {
            getBaseList() {
                if (this.tab === 'mutuals')
                    return this.mutuals;
                if (this.tab === 'followers')
                    return this.followers;
                if (this.tab === 'blocked')
                    return this.blocked;
                return [];
            },
            // ── Sorting helper ──
            _actionPriority(u) {
                if (!u.player_status)
                    return 99;
                var a = u.player_status.action;
                if (a === 2 || a === 9 || a === 10)
                    return 0; // Playing/Submitting/Paused
                if (a === 5 || a === 12)
                    return 1; // Multiplayer
                if (a === 11)
                    return 2; // Lobby
                if (a === 6)
                    return 3; // Watching
                if (a === 0)
                    return 4; // Idle
                if (a === 1)
                    return 5; // AFK
                return 6;
            },
            // ── Mod decoder ──
            formatMods(mods) {
                if (!mods)
                    return '';
                var names = [];
                if (mods & 1)
                    names.push('NF');
                if (mods & 2)
                    names.push('EZ');
                if (mods & 4)
                    names.push('TD');
                if (mods & 8)
                    names.push('HD');
                if (mods & 16)
                    names.push('HR');
                if (mods & 32)
                    names.push('SD');
                if (mods & 64)
                    names.push('DT');
                if (mods & 128)
                    names.push('RX');
                if (mods & 256)
                    names.push('HT');
                if (mods & 512)
                    names.push('NC');
                if (mods & 1024)
                    names.push('FL');
                if (mods & 2048)
                    names.push('AP');
                if (mods & 4096)
                    names.push('SO');
                // NC implies DT — show NC only
                if (names.indexOf('NC') !== -1 && names.indexOf('DT') !== -1) {
                    names.splice(names.indexOf('DT'), 1);
                }
                return names.length ? '+' + names.join('') : '';
            },
            // ── Status display ──
            activityText(user) {
                if (user.is_online && user.player_status) {
                    var s = user.player_status;
                    var modStr = this.formatMods(s.mods);
                    switch (s.action) {
                        case 0: return 'Idle';
                        case 1: return 'AFK';
                        case 2:
                            if (s.info_text && s.map_id) {
                                return ('Playing: ' + s.info_text + ' ' + modStr).trim();
                            }
                            return 'Playing';
                        case 3: return s.info_text ? 'Editing: ' + s.info_text : 'Editing';
                        case 4: return s.info_text ? 'Modding: ' + s.info_text : 'Modding';
                        case 5:
                        case 12:
                            return s.info_text ? 'Multiplayer: ' + s.info_text : 'In Multiplayer';
                        case 6: return s.info_text ? 'Watching: ' + s.info_text : 'Watching';
                        case 8: return s.info_text ? 'Testing: ' + s.info_text : 'Testing';
                        case 9: return 'Submitting score...';
                        case 10: return s.info_text ? 'Paused: ' + s.info_text : 'Paused';
                        case 11: return 'In Lobby';
                        case 13: return 'Browsing osu!direct';
                        default: return 'Online';
                    }
                }
                if (!user.is_online) {
                    return this._formatLastSeen(user.latest_activity);
                }
                return 'Online';
            },
            // ── Beatmap title (just the map name, no "Playing:" prefix) ──
            beatmapTitle(user) {
                if (user.player_status && user.player_status.info_text) {
                    return user.player_status.info_text;
                }
                return 'Unknown';
            },
            // ── Mode text ──
            modeText(user) {
                if (!user.player_status)
                    return '';
                var modes = ['osu!standard', 'osu!taiko', 'osu!catch', 'osu!mania'];
                var m = user.player_status.mode;
                return (m >= 0 && m < modes.length) ? modes[m] : '';
            },
            // ── Precise last seen ──
            _formatLastSeen(ts) {
                if (!ts || ts === 0)
                    return 'Never seen';
                var now = Date.now() / 1000;
                var delta = now - ts;
                if (delta < 300)
                    return 'Just now';
                if (delta < 3600)
                    return Math.floor(delta / 60) + 'm ago';
                if (delta < 86400)
                    return Math.floor(delta / 3600) + 'h ago';
                if (delta < 604800)
                    return Math.floor(delta / 86400) + 'd ago';
                try {
                    return timeago.format(ts * 1000);
                }
                catch (e) {
                    return 'Long ago';
                }
            },
            // ── Activity ring CSS class ──
            activityRingClass(user) {
                if (!user.is_online)
                    return 'ring--none';
                if (!user.player_status)
                    return 'ring--online';
                var a = user.player_status.action;
                if (a === 2 || a === 9 || a === 10)
                    return 'ring--playing';
                if (a === 5 || a === 12)
                    return 'ring--lobby';
                if (a === 11)
                    return 'ring--lobby';
                if (a === 1)
                    return 'ring--away';
                return 'ring--online';
            },
            // ── Status badge CSS class ──
            statusBadgeClass(user) {
                if (!user.is_online || !user.player_status)
                    return '';
                var a = user.player_status.action;
                if (a === 2 || a === 9 || a === 10)
                    return 'badge--playing';
                if (a === 5 || a === 12 || a === 11)
                    return 'badge--lobby';
                if (a === 1)
                    return 'badge--away';
                return 'badge--online';
            },
            // ── Status badge text ──
            statusBadgeText(user) {
                if (!user.is_online || !user.player_status)
                    return '';
                var a = user.player_status.action;
                if (a === 2 || a === 9 || a === 10)
                    return 'PLAYING';
                if (a === 5 || a === 12)
                    return 'MULTI';
                if (a === 11)
                    return 'LOBBY';
                if (a === 1)
                    return 'AFK';
                if (a === 6)
                    return 'WATCHING';
                if (a === 0)
                    return 'IDLE';
                return '';
            },
            isPlaying(user) {
                return user.is_online && !!user.player_status &&
                    (user.player_status.action === 2 || user.player_status.action === 10);
            },
            beatmapUrl(user) {
                if (user.player_status && user.player_status.map_id) {
                    return '/b/' + user.player_status.map_id;
                }
                return null;
            },
            // ── Polling with backoff ──
            startPolling() {
                this.stopPolling();
                this.pollAttempts = 0;
                this.pollError = false;
                var self = this;
                this.pollTimer = window.setInterval(function () { self.pollStatus(); }, 30000);
            },
            stopPolling() {
                if (this.pollTimer) {
                    clearInterval(this.pollTimer);
                    this.pollTimer = null;
                }
            },
            pollStatus() {
                if (this.isPolling || this.loading)
                    return;
                this.isPolling = true;
                var self = this;
                fetch(location.protocol + '//api.' + domain + '/v1/get_friends_status?id=' + userId)
                    .then(function (res) {
                    if (!res.ok)
                        throw new Error('HTTP ' + res.status);
                    return res.json();
                })
                    .then(function (data) {
                    if (data.status !== 'success')
                        throw new Error('Bad response');
                    var online = data.online;
                    var lists = [self.mutuals, self.followers];
                    for (var i = 0; i < lists.length; i++) {
                        var list = lists[i];
                        for (var j = 0; j < list.length; j++) {
                            var user = list[j];
                            var status = online[String(user.id)];
                            if (status) {
                                self.$set(user, 'is_online', true);
                                self.$set(user, 'player_status', status);
                            }
                            else if (user.is_online) {
                                self.$set(user, 'is_online', false);
                                self.$set(user, 'player_status', null);
                            }
                        }
                    }
                    self.pollAttempts = 0;
                    self.pollError = false;
                    self.isPolling = false;
                })
                    .catch(function () {
                    self.pollAttempts++;
                    if (self.pollAttempts >= 3) {
                        self.stopPolling();
                        self.pollError = true;
                    }
                    self.isPolling = false;
                });
            },
            reconnectPolling() {
                this.startPolling();
                this.pollStatus();
            },
            // ── Visibility API ──
            _handleVisibility() {
                if (document.hidden) {
                    this.stopPolling();
                }
                else {
                    this.startPolling();
                    this.pollStatus();
                }
            },
            // ── Actions ──
            doAction(action, targetId) {
                this.$set(this.actionLoading, targetId, true);
                this.stopPolling();
                var self = this;
                var fd = new FormData();
                fd.append('target_id', String(targetId));
                var actionLabels = {
                    add: 'Friend added',
                    remove: 'Friend removed',
                    block: 'User blocked',
                    unblock: 'User unblocked',
                };
                fetch('/friends/' + action, { method: 'POST', body: fd })
                    .then(function (res) {
                    if (!res.ok)
                        throw new Error('Request failed');
                    return self.loadAll();
                })
                    .then(function () {
                    self.$set(self.actionLoading, targetId, false);
                    self.startPolling();
                    self.showToast(actionLabels[action] || 'Done');
                })
                    .catch(function () {
                    self.showActionError('Action failed. Please try again.');
                    self.$set(self.actionLoading, targetId, false);
                    self.startPolling();
                });
            },
            showActionError(msg) {
                this.actionError = msg;
                if (this.actionErrorTimer)
                    clearTimeout(this.actionErrorTimer);
                var self = this;
                this.actionErrorTimer = window.setTimeout(function () {
                    self.actionError = null;
                    self.actionErrorTimer = null;
                }, 5000);
            },
            dismissActionError() {
                this.actionError = null;
                if (this.actionErrorTimer) {
                    clearTimeout(this.actionErrorTimer);
                    this.actionErrorTimer = null;
                }
            },
            showToast(msg) {
                this.toastMessage = msg;
                this.toastVisible = true;
                if (this.toastTimer)
                    clearTimeout(this.toastTimer);
                var self = this;
                this.toastTimer = window.setTimeout(function () {
                    self.toastVisible = false;
                    self.toastTimer = null;
                }, 2000);
            },
            addFriend(id) { this.doAction('add', id); },
            removeFriend(id) { this.doAction('remove', id); },
            blockUser(id) { this.doAction('block', id); },
            unblockUser(id) { this.doAction('unblock', id); },
            // ── Data fetching ──
            loadAll() {
                this.loading = true;
                this.error = null;
                var self = this;
                return fetch(location.protocol + '//api.' + domain + '/v1/get_friends_detailed?id=' + userId + '&scope=all')
                    .then(function (res) {
                    if (!res.ok)
                        throw new Error('API returned ' + res.status);
                    return res.json();
                })
                    .then(function (data) {
                    if (data.status !== 'success')
                        throw new Error(data.status || 'Unknown error');
                    self.mutuals = data.mutuals || [];
                    self.followers = data.followers || [];
                    self.blocked = data.blocked || [];
                    self.loading = false;
                })
                    .catch(function (e) {
                    self.error = 'Failed to load friends data.';
                    console.error('[Friends]', e);
                    self.loading = false;
                });
            },
            // ── UI helpers ──
            switchTab(t) {
                this.tab = t;
            },
            toggleSection(s) {
                this.$set(this.sections, s, !this.sections[s]);
            },
            avatarUrl(id) {
                return 'https://a.' + domain + '/' + id;
            },
            profileUrl(id) {
                return '/u/' + id;
            },
            // ── Compare modal ──
            openCompare(targetId) {
                this.compareVisible = true;
                this.compareUser = targetId;
                this.compareMode = 0;
                this.compareData = null;
                this.compareError = null;
                document.body.style.overflow = 'hidden';
                this.loadCompare(targetId, 0);
            },
            closeCompare() {
                this.compareVisible = false;
                this.compareLoading = false;
                this.compareError = null;
                this.compareUser = 0;
                this.compareData = null;
                document.body.style.overflow = '';
            },
            loadCompare(targetId, mode) {
                this.compareMode = mode;
                this.compareLoading = true;
                this.compareError = null;
                var self = this;
                fetch(location.protocol + '//api.' + domain + '/v1/compare_stats?users=' + userId + ',' + targetId + '&mode=' + mode)
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
                    console.error('[Compare]', e);
                    self.compareLoading = false;
                });
            },
            addCommas(n) {
                return String(n).replace(/\B(?=(\d{3})+(?!\d))/g, ',');
            },
        }
    });
})();
