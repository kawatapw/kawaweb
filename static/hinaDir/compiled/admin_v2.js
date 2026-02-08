/**
 * Admin V2 — Vue 2 SPA for the independent admin panel.
 * Standalone instance, not part of KawataApp.
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
// ─── API Helper ───────────────────────────────────────────────────────
function adminApi(endpoint, options) {
    return __awaiter(this, void 0, void 0, function* () {
        var res = yield fetch("/admin-v2/api/" + endpoint, Object.assign({ headers: { 'Content-Type': 'application/json' } }, options));
        var data = yield res.json();
        if (!res.ok) {
            throw new Error(data.message || data.error || ("HTTP " + res.status));
        }
        return data;
    });
}
// ─── Privilege definitions ────────────────────────────────────────────
var PRIVILEGES = [
    { name: 'Normal', value: 1 },
    { name: 'Verified', value: 2 },
    { name: 'Supporter', value: 4 },
    { name: 'AccessPanel', value: 8 },
    { name: 'ManageUsers', value: 16 },
    { name: 'RestrictUsers', value: 32 },
    { name: 'SilenceUsers', value: 64 },
    { name: 'WipeUsers', value: 128 },
    { name: 'ManageBeatmaps', value: 256 },
    { name: 'ManageBadges', value: 16384 },
    { name: 'ViewPanelLog', value: 32768 },
    { name: 'ManagePrivs', value: 65536 },
    { name: 'SendAlerts', value: 131072 },
    { name: 'ChatMod', value: 262144 },
    { name: 'KickUsers', value: 524288 },
    { name: 'Tournament', value: 2097152 },
    { name: 'ManageClans', value: 268435456 },
    { name: 'ViewSensitiveInfo', value: 536870912 },
    { name: 'IsBot', value: 2147483648 },
    { name: 'Whitelisted', value: 4294967296 },
    { name: 'Premium', value: 8589934592 },
    { name: 'Alumni', value: 17179869184 },
    { name: 'Dangerous', value: 34359738368 },
];
// ─── Mod names (bitmask → human-readable) ─────────────────────────────
var MOD_NAMES = {
    1: 'NF', 2: 'EZ', 4: 'TD', 8: 'HD', 16: 'HR',
    32: 'SD', 64: 'DT', 128: 'RX', 256: 'HT', 512: 'NC',
    1024: 'FL', 2048: 'AP', 4096: 'SO', 8192: 'PF', 16384: 'V2',
};
// ─── Client flags (bitmask → human-readable) ──────────────────────────
var CLIENT_FLAGS = {
    2: 'Speed Hack', 8: 'Multi Client', 16: 'Checksum Fail',
    32: 'FL Checksum', 256: 'FL Image Hack', 512: 'Spinner Hack',
    1024: 'Transparent', 2048: 'Fast Press', 4096: 'Raw Mouse',
    8192: 'Raw Keyboard',
};
// ─── Vue App ──────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', function () {
    var config = window.__ADMIN_V2__;
    // Determine initial view from URL
    var path = window.location.pathname.replace('/admin-v2', '').replace(/^\//, '');
    var validViews = ['users', 'beatmaps', 'badges'];
    var initialView = validViews.indexOf(path) !== -1 ? path : 'dashboard';
    new Vue({
        el: '#admin-v2-app',
        data: {
            config: config,
            currentView: initialView,
            sidebarOpen: window.innerWidth >= 1024,
            // Toast
            toast: { show: false, type: 'success', message: '' },
            toastTimer: null,
            // Confirm dialog
            confirmDialog: {
                show: false,
                title: '',
                message: '',
                action: '',
                needsReason: false,
                needsDuration: false,
                needsPassword: false,
                reason: '',
                duration: 24,
                password: '',
                targetId: 0,
            },
            // Dashboard
            dash: {
                kpis: null,
                topCountries: [],
                recentActions: [],
                recentUsers: [],
                recentScores: [],
                flaggedScores: [],
                displayScores: [],
                scoreFilter: 'all',
                loading: false,
                flaggedLoading: false,
                error: null,
                peakOnline: 0,
            },
            // Global search
            search: {
                query: '',
                scope: 'all',
                results: null,
                isOpen: false,
                loading: false,
            },
            // Users
            users: {
                list: [],
                pagination: { current_page: 1, total_pages: 1, total_count: 0 },
                search: '',
                filters: { priv: '', country: '', sort: 'id', order: 'ASC' },
                editUser: null,
                editTab: 'account',
                editForm: { username: '', email: '', country: '', userpage: '' },
                allBadges: [],
                loading: false,
            },
            // Beatmaps
            beatmaps: {
                requests: [],
                loading: false,
            },
            // Badges
            badges: {
                list: [],
                editBadge: null,
                isNew: false,
                loading: false,
            },
            // Privilege list for the editor
            privilegeList: PRIVILEGES,
            // Debounce timers
            searchTimer: null,
            globalSearchTimer: null,
            // Keyboard handler reference for cleanup
            keydownHandler: null,
        },
        created: function () {
            var self = this;
            self.loadView(self.currentView);
            // Handle browser back/forward
            window.addEventListener('popstate', function () {
                var p = window.location.pathname.replace('/admin-v2', '').replace(/^\//, '');
                var views = ['users', 'beatmaps', 'badges'];
                var view = views.indexOf(p) !== -1 ? p : 'dashboard';
                self.currentView = view;
                self.loadView(view);
            });
            // Close sidebar on mobile when clicking nav
            window.addEventListener('resize', function () {
                if (window.innerWidth >= 1024) {
                    self.sidebarOpen = true;
                }
            });
            // Keyboard shortcuts
            self.keydownHandler = function (e) {
                if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                    e.preventDefault();
                    self.openGlobalSearch();
                }
                if (e.key === 'Escape') {
                    self.closeGlobalSearch();
                }
            };
            document.addEventListener('keydown', self.keydownHandler);
        },
        beforeDestroy: function () {
            if (this.keydownHandler) {
                document.removeEventListener('keydown', this.keydownHandler);
            }
        },
        methods: {
            // ── Navigation ────────────────────────────────────────
            navigateTo: function (view) {
                if (this.currentView === view)
                    return;
                this.currentView = view;
                var url = view === 'dashboard' ? '/admin-v2' : '/admin-v2/' + view;
                history.pushState(null, '', url);
                this.loadView(view);
                // Close sidebar on mobile
                if (window.innerWidth < 1024) {
                    this.sidebarOpen = false;
                }
            },
            navigateUsersFiltered: function (sort, order, priv) {
                this.users.filters.sort = sort;
                this.users.filters.order = order;
                if (priv) {
                    this.users.filters.priv = priv;
                }
                this.navigateTo('users');
            },
            loadView: function (view) {
                switch (view) {
                    case 'dashboard':
                        this.loadDashboard();
                        break;
                    case 'users':
                        this.loadUsers(1);
                        break;
                    case 'beatmaps':
                        this.loadBeatmaps();
                        break;
                    case 'badges':
                        this.loadBadges();
                        break;
                }
            },
            // ── Dashboard ─────────────────────────────────────────
            loadDashboard: function () {
                var self = this;
                self.dash.loading = true;
                self.dash.error = null;
                adminApi('dashboard').then(function (data) {
                    self.dash.kpis = data.kpis || null;
                    self.dash.topCountries = data.top_countries || [];
                    self.dash.recentActions = data.recent_actions || [];
                    self.dash.recentUsers = data.recent_users || [];
                    self.dash.recentScores = data.recent_scores || [];
                    self.dash.displayScores = data.recent_scores || [];
                    // Track peak online (resets on page reload)
                    if (self.dash.kpis && self.dash.kpis.online > self.dash.peakOnline) {
                        self.dash.peakOnline = self.dash.kpis.online;
                    }
                    self.dash.loading = false;
                }).catch(function (e) {
                    self.dash.error = e.message || 'Failed to load dashboard';
                    self.dash.loading = false;
                });
            },
            loadFlaggedScores: function () {
                var self = this;
                self.dash.flaggedLoading = true;
                adminApi('dashboard/flagged-scores?limit=10').then(function (data) {
                    self.dash.flaggedScores = data.scores || [];
                    self.dash.displayScores = self.dash.flaggedScores;
                    self.dash.flaggedLoading = false;
                }).catch(function (e) {
                    self.showToast('error', e.message);
                    self.dash.flaggedLoading = false;
                });
            },
            toggleScoreFilter: function (filter) {
                this.dash.scoreFilter = filter;
                if (filter === 'all') {
                    this.dash.displayScores = this.dash.recentScores;
                }
                else {
                    this.loadFlaggedScores();
                }
            },
            // ── Global Search ─────────────────────────────────────
            openGlobalSearch: function () {
                this.search.isOpen = true;
                var self = this;
                Vue.nextTick(function () {
                    if (self.$refs.globalSearchInput) {
                        self.$refs.globalSearchInput.focus();
                    }
                });
            },
            closeGlobalSearch: function () {
                this.search.isOpen = false;
                this.search.results = null;
                this.search.query = '';
            },
            debouncedGlobalSearch: function () {
                var self = this;
                if (self.globalSearchTimer)
                    clearTimeout(self.globalSearchTimer);
                if (self.search.query.length < 2) {
                    self.search.results = null;
                    return;
                }
                self.globalSearchTimer = setTimeout(function () {
                    self.globalSearch();
                }, 300);
            },
            globalSearch: function () {
                var self = this;
                if (self.search.query.length < 2)
                    return;
                self.search.loading = true;
                adminApi('dashboard/search?q=' + encodeURIComponent(self.search.query) + '&scope=' + self.search.scope).then(function (data) {
                    self.search.results = data;
                    self.search.loading = false;
                }).catch(function (e) {
                    self.search.loading = false;
                });
            },
            searchNavigateUser: function (userId) {
                this.closeGlobalSearch();
                this.navigateTo('users');
                var self = this;
                Vue.nextTick(function () {
                    self.openUserEdit(userId);
                });
            },
            // ── Users ─────────────────────────────────────────────
            loadUsers: function (page) {
                var self = this;
                self.users.loading = true;
                var params = new URLSearchParams({
                    page: String(page),
                    search: self.users.search,
                    sort: self.users.filters.sort,
                    order: self.users.filters.order,
                    priv: self.users.filters.priv,
                    country: self.users.filters.country,
                });
                adminApi('users?' + params).then(function (data) {
                    self.users.list = data.users;
                    self.users.pagination = data.pagination;
                    self.users.loading = false;
                }).catch(function (e) {
                    self.showToast('error', e.message);
                    self.users.loading = false;
                });
            },
            debouncedSearchUsers: function () {
                var self = this;
                if (self.searchTimer)
                    clearTimeout(self.searchTimer);
                self.searchTimer = setTimeout(function () {
                    self.loadUsers(1);
                }, 350);
            },
            openUserEdit: function (userId) {
                var self = this;
                adminApi('user/' + userId).then(function (user) {
                    self.users.editUser = user;
                    self.users.editTab = 'account';
                    self.users.editForm = {
                        username: user.name || '',
                        email: user.email || '',
                        country: user.country || '',
                        userpage: user.userpage_content || '',
                    };
                    // Load all badges for the badge toggle grid
                    if (!self.users.allBadges.length) {
                        adminApi('badges').then(function (badges) {
                            self.users.allBadges = badges;
                        });
                    }
                }).catch(function (e) {
                    self.showToast('error', e.message);
                });
            },
            saveAccount: function () {
                var self = this;
                if (!self.users.editUser)
                    return;
                adminApi('action/editaccount', {
                    method: 'POST',
                    body: JSON.stringify({
                        user: self.users.editUser.id,
                        username: self.users.editForm.username,
                        email: self.users.editForm.email,
                        country: self.users.editForm.country,
                        userpage_content: self.users.editForm.userpage,
                    }),
                }).then(function () {
                    self.showToast('success', 'Account updated.');
                    self.openUserEdit(self.users.editUser.id);
                    self.loadUsers(self.users.pagination.current_page);
                }).catch(function (e) {
                    self.showToast('error', e.message);
                });
            },
            savePrivileges: function () {
                var self = this;
                if (!self.users.editUser)
                    return;
                adminApi('action/changeprivileges', {
                    method: 'POST',
                    body: JSON.stringify({
                        user: self.users.editUser.id,
                        privs: self.users.editUser.priv,
                    }),
                }).then(function () {
                    self.showToast('success', 'Privileges updated.');
                    self.openUserEdit(self.users.editUser.id);
                    self.loadUsers(self.users.pagination.current_page);
                }).catch(function (e) {
                    self.showToast('error', e.message);
                });
            },
            togglePriv: function (value, event) {
                if (!this.users.editUser)
                    return;
                var checked = event.target.checked;
                if (checked) {
                    this.users.editUser.priv = this.users.editUser.priv | value;
                }
                else {
                    this.users.editUser.priv = this.users.editUser.priv & ~value;
                }
            },
            userHasBadge: function (badgeId) {
                if (!this.users.editUser || !this.users.editUser.badges)
                    return false;
                return this.users.editUser.badges.some(function (b) { return b.id === badgeId; });
            },
            toggleUserBadge: function (badgeId) {
                var self = this;
                if (!self.users.editUser)
                    return;
                var has = self.userHasBadge(badgeId);
                var action = has ? 'removebadge' : 'addbadge';
                adminApi('action/' + action, {
                    method: 'POST',
                    body: JSON.stringify({
                        user: self.users.editUser.id,
                        badge: badgeId,
                    }),
                }).then(function () {
                    self.showToast('success', has ? 'Badge removed.' : 'Badge added.');
                    self.openUserEdit(self.users.editUser.id);
                }).catch(function (e) {
                    self.showToast('error', e.message);
                });
            },
            // ── Quick Actions (with confirm dialog) ──────────────
            quickAction: function (action) {
                if (!this.users.editUser)
                    return;
                var userId = this.users.editUser.id;
                var userName = this.users.editUser.name;
                var titles = {
                    restrict: 'Restrict ' + userName + '?',
                    unrestrict: 'Unrestrict ' + userName + '?',
                    silence: 'Silence ' + userName + '?',
                    unsilence: 'Unsilence ' + userName + '?',
                    wipe: 'Wipe all scores for ' + userName + '?',
                    changepassword: 'Change password for ' + userName + '?',
                };
                var messages = {
                    restrict: 'This will set their privilege to 0 (banned).',
                    unrestrict: 'This will restore their privilege to 1 (normal).',
                    silence: 'They will not be able to send messages in-game.',
                    unsilence: 'They will be able to send messages again.',
                    wipe: 'This will delete ALL scores and reset ALL stats. This cannot be undone easily.',
                    changepassword: 'Enter a new password for this user.',
                };
                this.confirmDialog = {
                    show: true,
                    title: titles[action] || action,
                    message: messages[action] || '',
                    action: action,
                    needsReason: true,
                    needsDuration: action === 'silence',
                    needsPassword: action === 'changepassword',
                    reason: '',
                    duration: 24,
                    password: '',
                    targetId: userId,
                };
            },
            executeConfirmedAction: function () {
                var self = this;
                var d = self.confirmDialog;
                var body = { user: d.targetId, reason: d.reason };
                if (d.needsDuration)
                    body.duration = d.duration;
                if (d.needsPassword)
                    body.password = d.password;
                d.show = false;
                adminApi('action/' + d.action, {
                    method: 'POST',
                    body: JSON.stringify(body),
                }).then(function (result) {
                    self.showToast('success', result.message);
                    if (self.users.editUser && self.users.editUser.id === d.targetId) {
                        self.openUserEdit(d.targetId);
                    }
                    self.loadUsers(self.users.pagination.current_page);
                }).catch(function (e) {
                    self.showToast('error', e.message);
                });
            },
            // ── Beatmaps ──────────────────────────────────────────
            loadBeatmaps: function () {
                var self = this;
                self.beatmaps.loading = true;
                adminApi('beatmaps').then(function (data) {
                    self.beatmaps.requests = data.requests || [];
                    self.beatmaps.loading = false;
                }).catch(function (e) {
                    self.showToast('error', e.message);
                    self.beatmaps.loading = false;
                });
            },
            mapAction: function (action, mapId) {
                var self = this;
                if (!confirm('Are you sure you want to ' + action + ' this map?'))
                    return;
                adminApi('action/' + action, {
                    method: 'POST',
                    body: JSON.stringify({ map: mapId }),
                }).then(function (result) {
                    self.showToast('success', result.message);
                    self.loadBeatmaps();
                }).catch(function (e) {
                    self.showToast('error', e.message);
                });
            },
            // ── Badges ────────────────────────────────────────────
            loadBadges: function () {
                var self = this;
                self.badges.loading = true;
                adminApi('badges').then(function (data) {
                    self.badges.list = data;
                    self.badges.loading = false;
                }).catch(function (e) {
                    self.showToast('error', e.message);
                    self.badges.loading = false;
                });
            },
            newBadge: function () {
                this.badges.isNew = true;
                this.badges.editBadge = {
                    name: '',
                    description: '',
                    priority: 0,
                    styles: {},
                    editStyles: [
                        { type: 'background-color', value: '#333' },
                        { type: 'color', value: '#fff' },
                    ],
                };
            },
            editBadge: function (badge) {
                this.badges.isNew = false;
                var stylesObj = badge.styles || {};
                var editStyles = [];
                for (var k in stylesObj) {
                    if (stylesObj.hasOwnProperty(k)) {
                        editStyles.push({ type: k, value: stylesObj[k] });
                    }
                }
                if (editStyles.length === 0) {
                    editStyles.push({ type: '', value: '' });
                }
                this.badges.editBadge = Object.assign({}, badge, { editStyles: editStyles });
            },
            saveBadge: function () {
                var self = this;
                var b = self.badges.editBadge;
                if (!b)
                    return;
                var styles = b.editStyles
                    .filter(function (s) { return s.type && s.value; })
                    .map(function (s) { return { type: s.type, value: s.value }; });
                var payload = {
                    name: b.name,
                    description: b.description,
                    priority: b.priority,
                    styles: styles,
                };
                var endpoint = self.badges.isNew ? 'badge/create' : ('badge/' + b.id + '/update');
                adminApi(endpoint, {
                    method: 'POST',
                    body: JSON.stringify(payload),
                }).then(function () {
                    self.showToast('success', self.badges.isNew ? 'Badge created.' : 'Badge updated.');
                    self.badges.editBadge = null;
                    self.loadBadges();
                }).catch(function (e) {
                    self.showToast('error', e.message);
                });
            },
            // ── Mod & Flag Decoders ───────────────────────────────
            formatMods: function (mods) {
                if (!mods)
                    return '';
                var names = [];
                var hasNC = false;
                for (var bit in MOD_NAMES) {
                    if (MOD_NAMES.hasOwnProperty(bit)) {
                        var bitNum = parseInt(bit, 10);
                        if (mods & bitNum) {
                            if (bitNum === 512) {
                                hasNC = true;
                                continue;
                            }
                            if (bitNum === 64 && hasNC)
                                continue; // NC implies DT
                            names.push(MOD_NAMES[bitNum]);
                        }
                    }
                }
                if (hasNC)
                    names.push('NC');
                return names.length ? ('+' + names.join('')) : '';
            },
            getClientFlagsText: function (flags) {
                if (!flags)
                    return '';
                var names = [];
                for (var bit in CLIENT_FLAGS) {
                    if (CLIENT_FLAGS.hasOwnProperty(bit)) {
                        var bitNum = parseInt(bit, 10);
                        if (flags & bitNum) {
                            names.push(CLIENT_FLAGS[bitNum]);
                        }
                    }
                }
                return names.length ? names.join(', ') : ('Unknown flags: ' + flags);
            },
            // ── Trend Helpers ─────────────────────────────────────
            getTrendClass: function (current, previous) {
                if (previous === 0 && current > 0)
                    return 'av2-stat-trend--positive';
                if (current === previous)
                    return 'av2-stat-trend--neutral';
                return current > previous ? 'av2-stat-trend--positive' : 'av2-stat-trend--negative';
            },
            getTrendText: function (current, previous, period) {
                if (previous === 0 && current > 0)
                    return 'New';
                if (previous === 0 && current === 0)
                    return '—';
                var pct = Math.round(((current - previous) / previous) * 100);
                // Clamp to ±999%
                if (pct > 999)
                    pct = 999;
                if (pct < -999)
                    pct = -999;
                var sign = pct >= 0 ? '+' : '';
                return sign + pct + '% vs ' + period;
            },
            getActionColor: function (action) {
                var colors = {
                    restrict: 'danger',
                    unrestrict: 'success',
                    silence: 'warning',
                    unsilence: 'info',
                    wipe: 'danger',
                    changepassword: 'info',
                    removescore: 'danger',
                    changeprivileges: 'warning',
                    editaccount: 'info',
                    addbadge: 'success',
                    removebadge: 'warning',
                };
                return colors[action] || 'default';
            },
            getCountryBarWidth: function (count) {
                if (!this.dash.topCountries || !this.dash.topCountries.length)
                    return 0;
                var max = this.dash.topCountries[0].count || 1;
                return Math.round((count / max) * 100);
            },
            // ── Utilities ─────────────────────────────────────────
            badgeStyle: function (badge) {
                var styles = badge.styles || {};
                var css = '';
                if (typeof styles === 'object' && !Array.isArray(styles)) {
                    for (var k in styles) {
                        if (styles.hasOwnProperty(k)) {
                            css += k + ': ' + styles[k] + ';';
                        }
                    }
                }
                if (badge.editStyles) {
                    for (var i = 0; i < badge.editStyles.length; i++) {
                        var s = badge.editStyles[i];
                        if (s.type && s.value) {
                            css += s.type + ': ' + s.value + ';';
                        }
                    }
                }
                return css;
            },
            formatTime: function (ts) {
                if (!ts)
                    return '—';
                try {
                    var d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
                    if (isNaN(d.getTime()))
                        return String(ts);
                    return timeago.format(d);
                }
                catch (e) {
                    return String(ts);
                }
            },
            formatNumber: function (n) {
                if (n === null || n === undefined)
                    return '0';
                return n.toLocaleString();
            },
            getPrivLabel: function (priv) {
                if (priv === 0)
                    return 'Restricted';
                if (priv & 34359738368)
                    return 'Developer';
                if (priv & 65536)
                    return 'Admin';
                if (priv & 16)
                    return 'Moderator';
                if (priv & 4)
                    return 'Supporter';
                if (priv === 1)
                    return 'Normal';
                return 'Custom';
            },
            getPrivClass: function (priv) {
                if (priv === 0)
                    return 'av2-priv--restricted';
                if (priv & 34359738368)
                    return 'av2-priv--dev';
                if (priv & 65536)
                    return 'av2-priv--admin';
                if (priv & 16)
                    return 'av2-priv--mod';
                if (priv & 4)
                    return 'av2-priv--supporter';
                return 'av2-priv--normal';
            },
            showToast: function (type, message) {
                this.toast = { show: true, type: type, message: message };
                if (this.toastTimer)
                    clearTimeout(this.toastTimer);
                var self = this;
                self.toastTimer = setTimeout(function () {
                    self.toast.show = false;
                }, 4000);
            },
        },
    });
});
