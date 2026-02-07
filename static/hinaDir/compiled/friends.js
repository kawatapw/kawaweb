new Vue({
    el: '#friends-app',
    data: {
        tab: 'mutuals',
        mutuals: [],
        followers: [],
        blocked: [],
        loading: true,
        error: null,
        actionLoading: {},
        searchQuery: '',
        sections: { online: true, offline: true },
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
    },
    created() {
        this.loadAll();
        this.startPolling();
        var self = this;
        this._visHandler = function () { self._handleVisibility(); };
        document.addEventListener('visibilitychange', this._visHandler);
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
            fetch('/friends/' + action, { method: 'POST', body: fd })
                .then(function (res) {
                if (!res.ok)
                    throw new Error('Request failed');
                return self.loadAll();
            })
                .then(function () {
                self.$set(self.actionLoading, targetId, false);
                self.startPolling();
            })
                .catch(function () {
                self.error = 'Action failed. Please try again.';
                self.$set(self.actionLoading, targetId, false);
                self.startPolling();
            });
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
    }
});
