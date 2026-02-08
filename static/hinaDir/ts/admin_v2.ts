/**
 * Admin V2 — Vue 2 SPA for the independent admin panel.
 * Standalone instance, not part of KawataApp.
 */

declare var Vue: any;
declare var timeago: any;

interface AdminConfig {
    domain: string;
    userId: number;
    userName: string;
    userPriv: number;
    isDev: boolean;
    avatarDomain: string;
    devMode: boolean;
}

// ─── API Helper ───────────────────────────────────────────────────────

async function adminApi(endpoint: string, options?: RequestInit): Promise<any> {
    var res = await fetch("/admin-v2/api/" + endpoint, {
        headers: { 'Content-Type': 'application/json' },
        ...options,
    });
    var data = await res.json();
    if (!res.ok) {
        throw new Error(data.message || data.error || ("HTTP " + res.status));
    }
    return data;
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

var MOD_NAMES: { [key: number]: string } = {
    1: 'NF', 2: 'EZ', 4: 'TD', 8: 'HD', 16: 'HR',
    32: 'SD', 64: 'DT', 128: 'RX', 256: 'HT', 512: 'NC',
    1024: 'FL', 2048: 'AP', 4096: 'SO', 8192: 'PF', 16384: 'V2',
};

// ─── Client flags (bitmask → human-readable) ──────────────────────────

var CLIENT_FLAGS: { [key: number]: string } = {
    2: 'Speed Hack', 8: 'Multi Client', 16: 'Checksum Fail',
    32: 'FL Checksum', 256: 'FL Image Hack', 512: 'Spinner Hack',
    1024: 'Transparent', 2048: 'Fast Press', 4096: 'Raw Mouse',
    8192: 'Raw Keyboard',
};

// ─── Vue App ──────────────────────────────────────────────────────────

document.addEventListener('DOMContentLoaded', function () {
    var config: AdminConfig = (window as any).__ADMIN_V2__;

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
            toastTimer: null as any,

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
                kpis: null as any,
                topCountries: [] as any[],
                recentActions: [] as any[],
                recentUsers: [] as any[],
                recentScores: [] as any[],
                flaggedScores: [] as any[],
                displayScores: [] as any[],
                scoreFilter: 'all',
                loading: false,
                flaggedLoading: false,
                error: null as string | null,
                peakOnline: 0,
                updatedAt: 0,
            },

            // Global search
            search: {
                query: '',
                scope: 'all',
                results: null as any,
                isOpen: false,
                loading: false,
            },

            // Users
            users: {
                list: [] as any[],
                pagination: { current_page: 1, total_pages: 1, total_count: 0 },
                search: '',
                filters: {
                    priv: '', country: '', sort: 'id', order: 'ASC',
                    active: '',
                    registered: '',
                    risk: '',
                },
                showAdvancedFilters: false,
                selectedIds: [] as number[],
                selectAll: false,
                openMenuId: null as number | null,
                editUser: null as any,
                editTab: 'overview',
                editForm: { username: '', email: '', country: '', userpage: '' },
                allBadges: [] as any[],
                loading: false,
                overviewMode: 0,
            },

            // Beatmaps
            beatmaps: {
                requests: [] as any[],
                loading: false,
            },

            // Badges
            badges: {
                list: [] as any[],
                editBadge: null as any,
                isNew: false,
                loading: false,
            },

            // Privilege list for the editor
            privilegeList: PRIVILEGES,

            // Debounce timers
            searchTimer: null as any,
            globalSearchTimer: null as any,

            // Keyboard handler reference for cleanup
            keydownHandler: null as any,
        },

        created: function () {
            var self = this;

            // Restore persisted score filter
            try {
                var savedFilter = localStorage.getItem('av2-score-filter');
                if (savedFilter === 'flagged') {
                    self.dash.scoreFilter = 'flagged';
                }
            } catch (e) { /* localStorage unavailable */ }

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
            self.keydownHandler = function (e: KeyboardEvent) {
                if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                    e.preventDefault();
                    self.openGlobalSearch();
                }
                if (e.key === 'Escape') {
                    self.closeGlobalSearch();
                    self.users.openMenuId = null;
                }
            };
            document.addEventListener('keydown', self.keydownHandler);

            // Close row menu on outside click
            document.addEventListener('click', function (e: Event) {
                if (self.users.openMenuId !== null) {
                    var target = e.target as HTMLElement;
                    if (!target.closest('.av2-row-menu') && !target.closest('.av2-row-menu-trigger')) {
                        self.users.openMenuId = null;
                    }
                }
            });
        },

        beforeDestroy: function () {
            if (this.keydownHandler) {
                document.removeEventListener('keydown', this.keydownHandler);
            }
        },

        methods: {
            // ── Navigation ────────────────────────────────────────

            navigateTo: function (view: string) {
                if (this.currentView === view) return;
                this.currentView = view;
                var url = view === 'dashboard' ? '/admin-v2' : '/admin-v2/' + view;
                history.pushState(null, '', url);
                this.loadView(view);

                // Close sidebar on mobile
                if (window.innerWidth < 1024) {
                    this.sidebarOpen = false;
                }
            },

            navigateUsersFiltered: function (sort: string, order: string, priv?: string) {
                this.users.filters.sort = sort;
                this.users.filters.order = order;
                if (priv) {
                    this.users.filters.priv = priv;
                }
                this.navigateTo('users');
            },

            loadView: function (view: string) {
                switch (view) {
                    case 'dashboard': this.loadDashboard(); break;
                    case 'users': this.loadUsers(1); break;
                    case 'beatmaps': this.loadBeatmaps(); break;
                    case 'badges': this.loadBadges(); break;
                }
            },

            // ── Dashboard ─────────────────────────────────────────

            loadDashboard: function () {
                var self = this;
                self.dash.loading = true;
                self.dash.error = null;

                adminApi('dashboard').then(function (data: any) {
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

                    self.dash.updatedAt = Math.floor(Date.now() / 1000);
                    self.dash.loading = false;

                    // If saved filter is 'flagged', load flagged scores now
                    if (self.dash.scoreFilter === 'flagged') {
                        self.loadFlaggedScores();
                    }
                }).catch(function (e: any) {
                    self.dash.error = e.message || 'Failed to load dashboard';
                    self.dash.loading = false;
                });
            },

            loadFlaggedScores: function () {
                var self = this;
                self.dash.flaggedLoading = true;

                adminApi('dashboard/flagged-scores?limit=10').then(function (data: any) {
                    self.dash.flaggedScores = data.scores || [];
                    self.dash.displayScores = self.dash.flaggedScores;
                    self.dash.flaggedLoading = false;
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                    self.dash.flaggedLoading = false;
                });
            },

            toggleScoreFilter: function (filter: string) {
                this.dash.scoreFilter = filter;
                try { localStorage.setItem('av2-score-filter', filter); } catch (e) {}
                if (filter === 'all') {
                    this.dash.displayScores = this.dash.recentScores;
                } else {
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
                if (self.globalSearchTimer) clearTimeout(self.globalSearchTimer);
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
                if (self.search.query.length < 2) return;
                self.search.loading = true;

                adminApi('dashboard/search?q=' + encodeURIComponent(self.search.query) + '&scope=' + self.search.scope).then(function (data: any) {
                    self.search.results = data;
                    self.search.loading = false;
                }).catch(function (e: any) {
                    self.search.loading = false;
                });
            },

            searchNavigateUser: function (userId: number) {
                this.closeGlobalSearch();
                this.navigateTo('users');
                var self = this;
                Vue.nextTick(function () {
                    self.openUserEdit(userId);
                });
            },

            // ── Users ─────────────────────────────────────────────

            loadUsers: function (page: number) {
                var self = this;
                self.users.loading = true;
                self.users.selectedIds = [];
                self.users.selectAll = false;
                self.users.openMenuId = null;
                var params = new URLSearchParams({
                    page: String(page),
                    search: self.users.search,
                    sort: self.users.filters.sort,
                    order: self.users.filters.order,
                    priv: self.users.filters.priv,
                    country: self.users.filters.country,
                    active: self.users.filters.active,
                    registered: self.users.filters.registered,
                    risk: self.users.filters.risk,
                });

                adminApi('users?' + params).then(function (data: any) {
                    self.users.list = data.users;
                    self.users.pagination = data.pagination;
                    self.users.loading = false;
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                    self.users.loading = false;
                });
            },

            debouncedSearchUsers: function () {
                var self = this;
                if (self.searchTimer) clearTimeout(self.searchTimer);
                self.searchTimer = setTimeout(function () {
                    self.loadUsers(1);
                }, 350);
            },

            openUserEdit: function (userId: number) {
                var self = this;
                adminApi('user/' + userId).then(function (user: any) {
                    self.users.editUser = user;
                    self.users.editTab = 'overview';
                    self.users.overviewMode = user.preferred_mode || 0;
                    self.users.editForm = {
                        username: user.name || '',
                        email: user.email || '',
                        country: user.country || '',
                        userpage: user.userpage_content || '',
                    };
                    // Load all badges for the badge toggle grid
                    if (!self.users.allBadges.length) {
                        adminApi('badges').then(function (badges: any) {
                            self.users.allBadges = badges;
                        });
                    }
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                });
            },

            saveAccount: function () {
                var self = this;
                if (!self.users.editUser) return;

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
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                });
            },

            savePrivileges: function () {
                var self = this;
                if (!self.users.editUser) return;

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
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                });
            },

            togglePriv: function (value: number, event: Event) {
                if (!this.users.editUser) return;
                var checked = (event.target as HTMLInputElement).checked;
                if (checked) {
                    this.users.editUser.priv = this.users.editUser.priv | value;
                } else {
                    this.users.editUser.priv = this.users.editUser.priv & ~value;
                }
            },

            userHasBadge: function (badgeId: number): boolean {
                if (!this.users.editUser || !this.users.editUser.badges) return false;
                return this.users.editUser.badges.some(function (b: any) { return b.id === badgeId; });
            },

            toggleUserBadge: function (badgeId: number) {
                var self = this;
                if (!self.users.editUser) return;
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
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                });
            },

            // ── Bulk Selection ────────────────────────────────────

            toggleSelectAll: function () {
                var self = this;
                if (self.users.selectAll) {
                    self.users.selectedIds = [];
                    self.users.selectAll = false;
                } else {
                    self.users.selectedIds = self.users.list.map(function (u: any) { return u.id; });
                    self.users.selectAll = true;
                }
            },

            toggleSelectUser: function (userId: number) {
                var idx = this.users.selectedIds.indexOf(userId);
                if (idx !== -1) {
                    this.users.selectedIds.splice(idx, 1);
                } else {
                    this.users.selectedIds.push(userId);
                }
                this.users.selectAll = this.users.selectedIds.length === this.users.list.length;
            },

            isUserSelected: function (userId: number): boolean {
                return this.users.selectedIds.indexOf(userId) !== -1;
            },

            clearSelection: function () {
                this.users.selectedIds = [];
                this.users.selectAll = false;
            },

            // ── Bulk Actions ─────────────────────────────────────

            bulkAction: function (action: string) {
                this.confirmDialog = {
                    show: true,
                    title: action.charAt(0).toUpperCase() + action.slice(1) + ' ' + this.users.selectedIds.length + ' users?',
                    message: 'This will ' + action + ' all selected users.',
                    action: 'bulk_' + action,
                    needsReason: true,
                    needsDuration: false,
                    needsPassword: false,
                    reason: '',
                    duration: 0,
                    password: '',
                    targetId: 0,
                };
            },

            executeBulkAction: function (action: string, reason: string) {
                var self = this;
                var realAction = action.replace('bulk_', '');
                adminApi('action/bulk', {
                    method: 'POST',
                    body: JSON.stringify({
                        action: realAction,
                        users: self.users.selectedIds,
                        reason: reason,
                    }),
                }).then(function (result: any) {
                    self.showToast('success', result.message);
                    self.clearSelection();
                    self.loadUsers(self.users.pagination.current_page);
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                });
            },

            // ── Row Menu ─────────────────────────────────────────

            toggleRowMenu: function (userId: number) {
                this.users.openMenuId = this.users.openMenuId === userId ? null : userId;
            },

            closeRowMenu: function () {
                this.users.openMenuId = null;
            },

            rowAction: function (action: string, user: any) {
                this.users.openMenuId = null;
                if (action === 'profile') {
                    window.open('/u/' + user.id, '_blank');
                    return;
                }
                if (action === 'edit') {
                    this.openUserEdit(user.id);
                    return;
                }

                // For restrict/unrestrict/silence/unsilence/wipe/changepassword: use confirm dialog
                var titles: { [key: string]: string } = {
                    restrict: 'Restrict ' + user.name + '?',
                    unrestrict: 'Unrestrict ' + user.name + '?',
                    silence: 'Silence ' + user.name + '?',
                    unsilence: 'Unsilence ' + user.name + '?',
                    wipe: 'Wipe all scores for ' + user.name + '?',
                    changepassword: 'Change password for ' + user.name + '?',
                };
                var messages: { [key: string]: string } = {
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
                    targetId: user.id,
                };
            },

            // ── Advanced Filters ─────────────────────────────────

            toggleAdvancedFilters: function () {
                this.users.showAdvancedFilters = !this.users.showAdvancedFilters;
            },

            // ── Overview Helpers ──────────────────────────────────

            getStatsForMode: function (mode: number): any {
                if (!this.users.editUser || !this.users.editUser.stats) return null;
                for (var i = 0; i < this.users.editUser.stats.length; i++) {
                    if (this.users.editUser.stats[i].mode === mode) return this.users.editUser.stats[i];
                }
                return null;
            },

            formatPlaytime: function (seconds: number): string {
                if (!seconds) return '0h';
                var h = Math.floor(seconds / 3600);
                var m = Math.floor((seconds % 3600) / 60);
                return h + 'h ' + m + 'm';
            },

            getModeName: function (mode: number): string {
                var names: { [key: number]: string } = {
                    0: 'std', 1: 'taiko', 2: 'catch', 3: 'mania',
                    4: 'rx!std', 5: 'rx!taiko', 6: 'rx!catch', 8: 'ap!std'
                };
                return names[mode] || ('mode ' + mode);
            },

            // ── Quick Actions (with confirm dialog) ──────────────

            quickAction: function (action: string) {
                if (!this.users.editUser) return;
                var userId = this.users.editUser.id;
                var userName = this.users.editUser.name;

                var titles: { [key: string]: string } = {
                    restrict: 'Restrict ' + userName + '?',
                    unrestrict: 'Unrestrict ' + userName + '?',
                    silence: 'Silence ' + userName + '?',
                    unsilence: 'Unsilence ' + userName + '?',
                    wipe: 'Wipe all scores for ' + userName + '?',
                    changepassword: 'Change password for ' + userName + '?',
                };
                var messages: { [key: string]: string } = {
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

                // Handle bulk actions
                if (d.action.indexOf('bulk_') === 0) {
                    d.show = false;
                    self.executeBulkAction(d.action, d.reason);
                    return;
                }

                var body: any = { user: d.targetId, reason: d.reason };
                if (d.needsDuration) body.duration = d.duration;
                if (d.needsPassword) body.password = d.password;

                d.show = false;

                adminApi('action/' + d.action, {
                    method: 'POST',
                    body: JSON.stringify(body),
                }).then(function (result: any) {
                    self.showToast('success', result.message);
                    if (self.users.editUser && self.users.editUser.id === d.targetId) {
                        self.openUserEdit(d.targetId);
                    }
                    self.loadUsers(self.users.pagination.current_page);
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                });
            },

            // ── Beatmaps ──────────────────────────────────────────

            loadBeatmaps: function () {
                var self = this;
                self.beatmaps.loading = true;

                adminApi('beatmaps').then(function (data: any) {
                    self.beatmaps.requests = data.requests || [];
                    self.beatmaps.loading = false;
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                    self.beatmaps.loading = false;
                });
            },

            mapAction: function (action: string, mapId: number) {
                var self = this;
                if (!confirm('Are you sure you want to ' + action + ' this map?')) return;

                adminApi('action/' + action, {
                    method: 'POST',
                    body: JSON.stringify({ map: mapId }),
                }).then(function (result: any) {
                    self.showToast('success', result.message);
                    self.loadBeatmaps();
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                });
            },

            // ── Badges ────────────────────────────────────────────

            loadBadges: function () {
                var self = this;
                self.badges.loading = true;

                adminApi('badges').then(function (data: any) {
                    self.badges.list = data;
                    self.badges.loading = false;
                }).catch(function (e: any) {
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

            editBadge: function (badge: any) {
                this.badges.isNew = false;
                var stylesObj = badge.styles || {};
                var editStyles: any[] = [];
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
                if (!b) return;

                var styles = b.editStyles
                    .filter(function (s: any) { return s.type && s.value; })
                    .map(function (s: any) { return { type: s.type, value: s.value }; });

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
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                });
            },

            // ── Mod & Flag Decoders ───────────────────────────────

            formatMods: function (mods: number): string {
                if (!mods) return '';
                var names: string[] = [];
                var hasNC = false;
                for (var bit in MOD_NAMES) {
                    if (MOD_NAMES.hasOwnProperty(bit)) {
                        var bitNum = parseInt(bit, 10);
                        if (mods & bitNum) {
                            if (bitNum === 512) { hasNC = true; continue; }
                            if (bitNum === 64 && hasNC) continue; // NC implies DT
                            names.push(MOD_NAMES[bitNum]);
                        }
                    }
                }
                if (hasNC) names.push('NC');
                return names.length ? ('+' + names.join('')) : '';
            },

            getClientFlagsText: function (flags: number): string {
                if (!flags) return '';
                var names: string[] = [];
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

            getTrendClass: function (current: number, previous: number): string {
                if (previous === 0 && current > 0) return 'av2-stat-trend--positive';
                if (current === previous) return 'av2-stat-trend--neutral';
                return current > previous ? 'av2-stat-trend--positive' : 'av2-stat-trend--negative';
            },

            getTrendText: function (current: number, previous: number, period: string): string {
                if (previous === 0 && current > 0) return 'New';
                if (previous === 0 && current === 0) return '—';
                var pct = Math.round(((current - previous) / previous) * 100);
                // Clamp to ±999%
                if (pct > 999) pct = 999;
                if (pct < -999) pct = -999;
                var sign = pct >= 0 ? '+' : '';
                return sign + pct + '% vs ' + period;
            },

            getActionColor: function (action: string): string {
                var colors: { [key: string]: string } = {
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

            getCountryBarWidth: function (count: number): number {
                if (!this.dash.topCountries || !this.dash.topCountries.length) return 0;
                var max = this.dash.topCountries[0].count || 1;
                return Math.round((count / max) * 100);
            },

            // ── Utilities ─────────────────────────────────────────

            badgeStyle: function (badge: any): string {
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

            formatTime: function (ts: any): string {
                if (!ts) return '—';
                try {
                    var d = typeof ts === 'number' ? new Date(ts * 1000) : new Date(ts);
                    if (isNaN(d.getTime())) return String(ts);
                    return timeago.format(d);
                } catch (e) {
                    return String(ts);
                }
            },

            formatNumber: function (n: number): string {
                if (n === null || n === undefined) return '0';
                return n.toLocaleString();
            },

            getPrivLabel: function (priv: number): string {
                if (priv === 0) return 'Restricted';
                if (priv & 34359738368) return 'Developer';
                if (priv & 65536) return 'Admin';
                if (priv & 16) return 'Moderator';
                if (priv & 4) return 'Supporter';
                if (priv === 1) return 'Normal';
                return 'Custom';
            },

            getPrivClass: function (priv: number): string {
                if (priv === 0) return 'av2-priv--restricted';
                if (priv & 34359738368) return 'av2-priv--dev';
                if (priv & 65536) return 'av2-priv--admin';
                if (priv & 16) return 'av2-priv--mod';
                if (priv & 4) return 'av2-priv--supporter';
                return 'av2-priv--normal';
            },

            showToast: function (type: string, message: string) {
                this.toast = { show: true, type: type, message: message };
                if (this.toastTimer) clearTimeout(this.toastTimer);
                var self = this;
                self.toastTimer = setTimeout(function () {
                    self.toast.show = false;
                }, 4000);
            },
        },
    });
});
