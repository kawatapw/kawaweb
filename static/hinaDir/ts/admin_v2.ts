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
    var validViews = ['users', 'beatmaps', 'badges', 'staff-log', 'manual-map'];
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
                needsScoreId: false,
                reason: '',
                duration: 24,
                password: '',
                scoreId: '',
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
                workItems: [] as any[],
                pagination: { current_page: 1, total_pages: 1, total_count: 0 },
                search: '',
                filters: {
                    status: '',
                    assigned: '',
                    age: '',
                    mode: '',
                    mapStatus: '',
                    mapper: '',
                    requester: '',
                    sort: 'created_at',
                    order: 'DESC',
                },
                showAdvancedFilters: false,
                loading: false,
                activeItem: null as any,
                activeLoading: false,
                commentDraft: '',
                addSetId: '',
                selectedDiffs: [] as number[],
                ppTable: {
                    show: false,
                    loading: false,
                    mods: 0,
                    data: null as any,
                    cache: {} as Record<string, any>,
                    error: '',
                },
            },

            // Badges
            badges: {
                list: [] as any[],
                editBadge: null as any,
                isNew: false,
                loading: false,
            },

            // Staff Activity Log
            staffLog: {
                entries: [] as any[],
                pagination: { current_page: 1, total_pages: 1, total_count: 0 },
                filters: {
                    staff_id: '',
                    action_type: '',
                    action: '',
                    from_date: '',
                    to_date: '',
                    search: '',
                },
                staffList: [] as any[],
                staffListLoaded: false,
                loading: false,
                expandedId: null as number | null,
                pageSize: 50,
            },

            // Manual Beatmap Actions
            manualMap: {
                input: '',
                info: null as any,
                loading: false,
                error: '',
                selectedDiffs: [] as number[],
                action: '',
                reason: '',
                executing: false,
                result: null as any,
                ppTable: {
                    show: false,
                    loading: false,
                    mods: 0,
                    data: null as any,
                    cache: {} as any,
                    error: '',
                },
            },

            // Privilege list for the editor
            privilegeList: PRIVILEGES,

            // Debounce timers
            searchTimer: null as any,
            globalSearchTimer: null as any,
            bmSearchTimer: null as any,

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
                var views = ['users', 'beatmaps', 'badges', 'staff-log', 'manual-map'];
                var view = views.indexOf(p) !== -1 ? p : 'dashboard';
                self.currentView = view;
                self.loadView(view);
            });

            // Re-open sidebar when resizing back to desktop (if it was closed via mobile overlay)
            // Removed: was forcing sidebarOpen=true on desktop, preventing toggle

            // Keyboard shortcuts
            self.keydownHandler = function (e: KeyboardEvent) {
                if ((e.metaKey || e.ctrlKey) && e.key === 'k') {
                    e.preventDefault();
                    self.openGlobalSearch();
                }
                if (e.key === 'Escape') {
                    self.closeGlobalSearch();
                    self.users.openMenuId = null;
                    if (self.beatmaps.activeItem) self.closeWorkItemPanel();
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
                    case 'beatmaps': this.loadWorkItems(1); break;
                    case 'badges': this.loadBadges(); break;
                    case 'staff-log': this.loadStaffLog(1); break;
                    case 'manual-map': break; // no auto-load, user types input
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
                    window.open('/u/' + user.id, '_blank', 'noopener,noreferrer');
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
                    removescore: 'Remove a score for ' + userName + '?',
                    changepassword: 'Change password for ' + userName + '?',
                };
                var messages: { [key: string]: string } = {
                    restrict: 'This will set their privilege to 0 (banned).',
                    unrestrict: 'This will restore their privilege to 1 (normal).',
                    silence: 'They will not be able to send messages in-game.',
                    unsilence: 'They will be able to send messages again.',
                    wipe: 'This will delete ALL scores and reset ALL stats. This cannot be undone easily.',
                    removescore: 'Enter the ID of the score you want to remove. This can be found in console when clicking on a users score in their profile.',
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
                    needsScoreId: action === 'removescore',
                    reason: '',
                    duration: 24,
                    password: '',
                    targetId: userId,
                    scoreId: '',
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

                // Handle beatmap status actions (per-diff)
                if (d.action.indexOf('bm_status_') === 0) {
                    d.show = false;
                    self.executeSetDiffStatus(d.action, d.reason);
                    return;
                }

                // Handle beatmap resolve actions (close work item)
                if (d.action.indexOf('bm_resolve_') === 0) {
                    d.show = false;
                    self.executeBmResolve(d.action, d.reason);
                    return;
                }

                // Handle manual map actions
                if (d.action === 'manual_map_action') {
                    d.show = false;
                    self.doManualAction();
                    return;
                }

                var body: any = { user: d.targetId, reason: d.reason };
                if (d.needsDuration) body.duration = d.duration;
                if (d.needsPassword) body.password = d.password;
                if (d.needsScoreId) {
                    var trimmedScoreId = (d.scoreId || '').trim();
                    if (!/^\d+$/.test(trimmedScoreId)) {
                        self.showToast('error', 'Score ID must be a number.');
                        return;
                    }
                    body.score = trimmedScoreId;
                }

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

        // ── Beatmap Review ────────────────────────────────────

            loadWorkItems: function (page?: number) {
                var self = this;
                if (!page) page = 1;
                self.beatmaps.loading = true;

                var url = 'beatmaps/work-items?page=' + page
                    + '&search=' + encodeURIComponent(self.beatmaps.search)
                    + '&status=' + self.beatmaps.filters.status
                    + '&assigned=' + self.beatmaps.filters.assigned
                    + '&age=' + self.beatmaps.filters.age
                    + '&mode=' + self.beatmaps.filters.mode
                    + '&map_status=' + self.beatmaps.filters.mapStatus
                    + '&mapper=' + encodeURIComponent(self.beatmaps.filters.mapper)
                    + '&requester=' + encodeURIComponent(self.beatmaps.filters.requester)
                    + '&sort=' + self.beatmaps.filters.sort
                    + '&order=' + self.beatmaps.filters.order;

                adminApi(url).then(function (data: any) {
                    self.beatmaps.workItems = data.items || [];
                    self.beatmaps.pagination = data.pagination || { current_page: 1, total_pages: 1, total_count: 0 };
                    self.beatmaps.loading = false;
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                    self.beatmaps.loading = false;
                });
            },

            debouncedSearchBeatmaps: function () {
                var self = this;
                if (self.bmSearchTimer) clearTimeout(self.bmSearchTimer);
                self.bmSearchTimer = setTimeout(function () {
                    self.loadWorkItems(1);
                }, 350);
            },

            selectWorkItem: function (itemId: number) {
                var self = this;
                self.beatmaps.activeLoading = true;
                self.beatmaps.commentDraft = '';
                self.beatmaps.selectedDiffs = [];
                self.beatmaps.ppTable = { show: false, loading: false, mods: 0, data: null, cache: {}, error: '' };

                adminApi('beatmaps/work-items/' + itemId).then(function (data: any) {
                    self.beatmaps.activeItem = data;
                    self.beatmaps.activeLoading = false;
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                    self.beatmaps.activeLoading = false;
                });
            },

            closeWorkItemPanel: function () {
                this.beatmaps.activeItem = null;
            },

            assignToMe: function () {
                var self = this;
                var itemId = self.beatmaps.activeItem.id;
                adminApi('beatmaps/work-items/' + itemId + '/assign', {
                    method: 'POST',
                    body: JSON.stringify({ user_id: self.config.userId }),
                }).then(function () {
                    self.showToast('success', 'Assigned to you.');
                    self.selectWorkItem(itemId);
                    self.loadWorkItems(self.beatmaps.pagination.current_page);
                }).catch(function (e: any) { self.showToast('error', e.message); });
            },

            unassignWorkItem: function () {
                var self = this;
                var itemId = self.beatmaps.activeItem.id;
                adminApi('beatmaps/work-items/' + itemId + '/assign', {
                    method: 'POST',
                    body: JSON.stringify({ user_id: null }),
                }).then(function () {
                    self.showToast('success', 'Unassigned.');
                    self.selectWorkItem(itemId);
                    self.loadWorkItems(self.beatmaps.pagination.current_page);
                }).catch(function (e: any) { self.showToast('error', e.message); });
            },

            toggleChecklist: function (key: string) {
                var self = this;
                var itemId = self.beatmaps.activeItem.id;
                var current = self.beatmaps.activeItem.checklist || {};
                var update: any = {};
                update[key] = !current[key];
                adminApi('beatmaps/work-items/' + itemId + '/checklist', {
                    method: 'POST',
                    body: JSON.stringify(update),
                }).then(function (data: any) {
                    self.beatmaps.activeItem.checklist = data.checklist;
                }).catch(function (e: any) { self.showToast('error', e.message); });
            },

            addBmComment: function () {
                var self = this;
                var body = (self.beatmaps.commentDraft || '').trim();
                if (!body) return;
                var itemId = self.beatmaps.activeItem.id;
                adminApi('beatmaps/work-items/' + itemId + '/comment', {
                    method: 'POST',
                    body: JSON.stringify({ body: body }),
                }).then(function () {
                    self.beatmaps.commentDraft = '';
                    self.selectWorkItem(itemId);
                }).catch(function (e: any) { self.showToast('error', e.message); });
            },

        // ── Diff Selection ─────────────────────────────────────

            toggleDiffSelect: function (diffId: number) {
                var idx = this.beatmaps.selectedDiffs.indexOf(diffId);
                if (idx === -1) {
                    this.beatmaps.selectedDiffs.push(diffId);
                } else {
                    this.beatmaps.selectedDiffs.splice(idx, 1);
                }
            },

            toggleAllDiffs: function () {
                if (!this.beatmaps.activeItem) return;
                var allIds = this.beatmaps.activeItem.diffs.map(function (d: any) { return d.id; });
                if (this.allDiffsSelected()) {
                    this.beatmaps.selectedDiffs = [];
                } else {
                    this.beatmaps.selectedDiffs = allIds.slice();
                }
            },

            allDiffsSelected: function (): boolean {
                if (!this.beatmaps.activeItem || !this.beatmaps.activeItem.diffs.length) return false;
                return this.beatmaps.selectedDiffs.length === this.beatmaps.activeItem.diffs.length;
            },

            isDiffSelected: function (diffId: number): boolean {
                return this.beatmaps.selectedDiffs.indexOf(diffId) !== -1;
            },

        // ── PP Table ──────────────────────────────────────────────

            openPPTable: function () {
                var pp = this.beatmaps.ppTable;
                pp.show = true;
                pp.mods = 0;
                pp.error = '';
                pp.data = null;
                pp.cache = {};
                this.fetchPPData();
            },

            closePPTable: function () {
                this.beatmaps.ppTable.show = false;
            },

            togglePPMod: function (bit: number) {
                var pp = this.beatmaps.ppTable;
                // EZ/HR conflict
                if (bit === 2 && (pp.mods & 16)) { pp.mods &= ~16; }
                if (bit === 16 && (pp.mods & 2)) { pp.mods &= ~2; }
                // DT/HT conflict
                if (bit === 64 && (pp.mods & 256)) { pp.mods &= ~256; }
                if (bit === 256 && (pp.mods & 64)) { pp.mods &= ~64; }
                pp.mods ^= bit;
                this.fetchPPData();
            },

            setPPModCombo: function (mods: number) {
                this.beatmaps.ppTable.mods = mods;
                this.fetchPPData();
            },

            fetchPPData: function () {
                var self = this;
                var pp = self.beatmaps.ppTable;
                var item = self.beatmaps.activeItem;
                if (!item || !item.diffs) return;

                var cacheKey = '' + pp.mods;
                if (pp.cache[cacheKey]) {
                    pp.data = pp.cache[cacheKey];
                    pp.error = '';
                    return;
                }

                pp.loading = true;
                pp.error = '';
                var ids = item.diffs.map(function (d: any) { return d.id; }).join(',');

                fetch('/admin-v2/api/beatmaps/pp-table?ids=' + ids + '&mods=' + pp.mods)
                    .then(function (res: any) { return res.json(); })
                    .then(function (data: any) {
                        if (data.status === 'success') {
                            pp.cache[cacheKey] = data.results;
                            pp.data = data.results;
                            pp.error = '';
                        } else {
                            pp.error = data.message || 'Failed to fetch PP data.';
                        }
                        pp.loading = false;
                    })
                    .catch(function (e: any) {
                        pp.error = e.message || 'Network error.';
                        pp.loading = false;
                    });
            },

            isPPModActive: function (bit: number): boolean {
                return (this.beatmaps.ppTable.mods & bit) !== 0;
            },

            mapStatusLabel: function (status: number): string {
                var labels: { [key: number]: string } = {
                    0: 'Pending', 1: 'Pending', 2: 'Ranked', 3: 'Approved',
                    4: 'Qualified', 5: 'Loved',
                };
                return labels[status] || ('Status ' + status);
            },

            mapStatusClass: function (status: number): string {
                var classes: { [key: number]: string } = {
                    0: 'av2-map-status--pending', 1: 'av2-map-status--pending',
                    2: 'av2-map-status--ranked', 3: 'av2-map-status--approved',
                    4: 'av2-map-status--qualified', 5: 'av2-map-status--loved',
                };
                return classes[status] || 'av2-map-status--pending';
            },

            selectedDiffNames: function (): string {
                var self = this;
                if (!self.beatmaps.activeItem) return '';
                var names: string[] = [];
                for (var i = 0; i < self.beatmaps.activeItem.diffs.length; i++) {
                    var d = self.beatmaps.activeItem.diffs[i];
                    if (self.beatmaps.selectedDiffs.indexOf(d.id) !== -1) {
                        names.push(d.version);
                    }
                }
                return names.join(', ');
            },

        // ── Set Status (per-diff, stays open) ────────────────

            setDiffStatus: function (action: string) {
                var self = this;
                if (!self.beatmaps.selectedDiffs.length) {
                    self.showToast('error', 'Select at least one difficulty first.');
                    return;
                }
                var needsReason = action === 'unrank';
                var labels: { [key: string]: string } = {
                    'rank': 'Rank', 'approve': 'Approve', 'qualify': 'Qualify',
                    'love': 'Love', 'unrank': 'Unrank',
                };
                var count = self.beatmaps.selectedDiffs.length;
                var diffNames = self.selectedDiffNames();
                self.confirmDialog = {
                    show: true,
                    title: labels[action] + ' ' + count + ' difficulty(ies)?',
                    message: diffNames,
                    action: 'bm_status_' + action,
                    needsReason: needsReason,
                    needsDuration: false,
                    needsPassword: false,
                    reason: '',
                    duration: 0,
                    password: '',
                    targetId: self.beatmaps.activeItem.id,
                };
            },

            executeSetDiffStatus: function (action: string, reason: string) {
                var self = this;
                var realAction = action.replace('bm_status_', '');
                var itemId = self.beatmaps.activeItem ? self.beatmaps.activeItem.id : self.confirmDialog.targetId;
                adminApi('beatmaps/work-items/' + itemId + '/set-status', {
                    method: 'POST',
                    body: JSON.stringify({
                        map_ids: self.beatmaps.selectedDiffs.slice(),
                        action: realAction,
                        reason: reason,
                    }),
                }).then(function (data: any) {
                    self.showToast('success', data.message);
                    // Update diffs in-place
                    if (data.diffs && self.beatmaps.activeItem) {
                        self.beatmaps.activeItem.diffs = data.diffs;
                    }
                    // Update review state if it transitioned
                    if (data.review_state && self.beatmaps.activeItem) {
                        self.beatmaps.activeItem.review_state = data.review_state;
                    }
                    self.beatmaps.selectedDiffs = [];
                    // Reload the full item to refresh history
                    self.selectWorkItem(itemId);
                    self.loadWorkItems(self.beatmaps.pagination.current_page);
                }).catch(function (e: any) { self.showToast('error', e.message); });
            },

        // ── Resolve Review (closes work item) ────────────────

            bmResolve: function (action: string) {
                var self = this;
                var needsReason = action === 'needs_changes';
                var labels: { [key: string]: string } = {
                    'mark_complete': 'Mark Complete',
                    'needs_changes': 'Needs Changes',
                    'dismiss': 'Dismiss',
                };
                self.confirmDialog = {
                    show: true,
                    title: labels[action] + '?',
                    message: self.beatmaps.activeItem.artist + ' - '
                        + self.beatmaps.activeItem.title + ' (set ' + self.beatmaps.activeItem.set_id + ')',
                    action: 'bm_resolve_' + action,
                    needsReason: needsReason,
                    needsDuration: false,
                    needsPassword: false,
                    reason: '',
                    duration: 0,
                    password: '',
                    targetId: self.beatmaps.activeItem.id,
                };
            },

            executeBmResolve: function (action: string, reason: string) {
                var self = this;
                var realAction = action.replace('bm_resolve_', '');
                var itemId = self.beatmaps.activeItem ? self.beatmaps.activeItem.id : self.confirmDialog.targetId;
                adminApi('beatmaps/work-items/' + itemId + '/decide', {
                    method: 'POST',
                    body: JSON.stringify({ action: realAction, reason: reason }),
                }).then(function (data: any) {
                    self.showToast('success', data.message);
                    self.beatmaps.activeItem = null;
                    self.loadWorkItems(self.beatmaps.pagination.current_page);
                }).catch(function (e: any) { self.showToast('error', e.message); });
            },

            addManualWorkItem: function () {
                var self = this;
                var setId = parseInt(self.beatmaps.addSetId, 10);
                if (!setId || isNaN(setId)) {
                    self.showToast('error', 'Enter a valid set ID.');
                    return;
                }
                adminApi('beatmaps/work-items', {
                    method: 'POST',
                    body: JSON.stringify({ set_id: setId }),
                }).then(function () {
                    self.showToast('success', 'Work item created.');
                    self.beatmaps.addSetId = '';
                    self.loadWorkItems(1);
                }).catch(function (e: any) { self.showToast('error', e.message); });
            },

            toggleBmAdvancedFilters: function () {
                this.beatmaps.showAdvancedFilters = !this.beatmaps.showAdvancedFilters;
            },

            reviewStateLabel: function (state: string): string {
                var labels: { [key: string]: string } = {
                    'pending': 'Pending', 'in_review': 'In Review',
                    'needs_changes': 'Needs Changes', 'done': 'Done',
                };
                return labels[state] || state;
            },

            starRange: function (item: any): string {
                if (!item.min_stars && !item.max_stars) return '';
                if (item.min_stars === item.max_stars)
                    return (item.min_stars || 0).toFixed(2) + ' \u2605';
                return (item.min_stars || 0).toFixed(1) + ' \u2013 ' + (item.max_stars || 0).toFixed(1) + ' \u2605';
            },

            checklistLabel: function (key: string): string {
                var labels: { [key: string]: string } = {
                    'timing': 'Timing', 'hitsounds': 'Hitsounds',
                    'difficulty_spread': 'Difficulty Spread', 'metadata': 'Metadata',
                    'background': 'Background (no NSFW)', 'no_abuse': 'No Obvious Abuse',
                };
                return labels[key] || key;
            },

            bmModeLabel: function (mode: number): string {
                var names: { [key: number]: string } = { 0: 'osu!', 1: 'Taiko', 2: 'Catch', 3: 'Mania' };
                return names[mode] || 'Mode ' + mode;
            },

            formatDuration: function (seconds: number): string {
                if (!seconds) return '0:00';
                var m = Math.floor(seconds / 60);
                var s = seconds % 60;
                return m + ':' + (s < 10 ? '0' : '') + s;
            },

        // ── Staff Activity Log ─────────────────────────────────

            loadStaffLog: function (page: number) {
                var self = this;
                self.staffLog.loading = true;

                // Load staff list once for dropdown
                if (!self.staffLog.staffListLoaded) {
                    adminApi('staff-list').then(function (data: any) {
                        self.staffLog.staffList = data.staff || [];
                        self.staffLog.staffListLoaded = true;
                    }).catch(function () {});
                }

                var params = new URLSearchParams({
                    page: String(page),
                    page_size: String(self.staffLog.pageSize),
                });
                var f = self.staffLog.filters;
                if (f.staff_id) params.set('staff_id', f.staff_id);
                if (f.action_type !== '') params.set('action_type', f.action_type);
                if (f.action) params.set('action', f.action);
                if (f.from_date) params.set('from_date', f.from_date);
                if (f.to_date) params.set('to_date', f.to_date);
                if (f.search) params.set('search', f.search);

                adminApi('staff-log?' + params).then(function (data: any) {
                    self.staffLog.entries = data.logs || [];
                    var total = data.total || 0;
                    var pageSize = data.page_size || self.staffLog.pageSize;
                    self.staffLog.pagination = {
                        current_page: data.page || 1,
                        total_pages: Math.max(1, Math.ceil(total / pageSize)),
                        total_count: total,
                    };
                    self.staffLog.loading = false;
                }).catch(function (e: any) {
                    self.showToast('error', e.message);
                    self.staffLog.loading = false;
                });
            },

            applyStaffLogFilters: function () {
                this.loadStaffLog(1);
            },

            clearStaffLogFilters: function () {
                this.staffLog.filters = {
                    staff_id: '', action_type: '', action: '',
                    from_date: '', to_date: '', search: '',
                };
                this.loadStaffLog(1);
            },

            toggleLogDetail: function (id: number) {
                this.staffLog.expandedId = this.staffLog.expandedId === id ? null : id;
            },

            staffLogTypePillClass: function (actionType: number): string {
                var classes: { [key: number]: string } = {
                    0: 'av2-sl-type-pill--user',
                    1: 'av2-sl-type-pill--map',
                    2: 'av2-sl-type-pill--badge',
                };
                return classes[actionType] || '';
            },

            staffLogTargetUrl: function (entry: any): string {
                if (entry.action_type === 0) {
                    return '/u/' + entry.target_id;
                }
                if (entry.action_type === 1 && entry.target_set_id) {
                    return '/beatmapsets/' + entry.target_set_id;
                }
                return '';
            },

        // ── Manual Beatmap Actions ────────────────────────────

            parseMapInput: function (input: string): any {
                if (!input || !input.trim()) return null;
                input = input.trim();

                // Try beatmapsets URL: /beatmapsets/123456#osu/789
                var setMatch = input.match(/beatmapsets\/(\d+)(?:#\w+\/(\d+))?/);
                if (setMatch) {
                    return {
                        set_id: parseInt(setMatch[1], 10),
                        map_id: setMatch[2] ? parseInt(setMatch[2], 10) : null,
                    };
                }

                // Try /b/123 URL
                var bMatch = input.match(/\/b\/(\d+)/);
                if (bMatch) {
                    return { set_id: null, map_id: parseInt(bMatch[1], 10) };
                }

                // Try raw number
                if (/^\d+$/.test(input)) {
                    return { set_id: parseInt(input, 10), map_id: null };
                }

                return null;
            },

            loadManualMap: function () {
                var self = this;
                var parsed = self.parseMapInput(self.manualMap.input);
                if (!parsed) {
                    self.manualMap.error = 'Invalid input. Enter a beatmap URL, set ID, or map ID.';
                    return;
                }

                self.manualMap.loading = true;
                self.manualMap.error = '';
                self.manualMap.info = null;
                self.manualMap.result = null;

                var params = '';
                if (parsed.set_id) params = 'set_id=' + parsed.set_id;
                if (parsed.map_id) params += (params ? '&' : '') + 'map_id=' + parsed.map_id;

                adminApi('manual-map-info?' + params).then(function (data: any) {
                    self.manualMap.info = data;
                    self.manualMap.selectedDiffs = [];
                    self.manualMap.action = '';
                    self.manualMap.reason = '';
                    self.manualMap.loading = false;
                }).catch(function (e: any) {
                    self.manualMap.error = e.message;
                    self.manualMap.loading = false;
                });
            },

            toggleManualDiff: function (id: number) {
                var idx = this.manualMap.selectedDiffs.indexOf(id);
                if (idx === -1) {
                    this.manualMap.selectedDiffs.push(id);
                } else {
                    this.manualMap.selectedDiffs.splice(idx, 1);
                }
            },

            toggleAllManualDiffs: function () {
                if (!this.manualMap.info) return;
                var allIds = this.manualMap.info.diffs.map(function (d: any) { return d.id; });
                if (this.manualMap.selectedDiffs.length === allIds.length) {
                    this.manualMap.selectedDiffs = [];
                } else {
                    this.manualMap.selectedDiffs = allIds.slice();
                }
            },

            isManualDiffSelected: function (id: number): boolean {
                return this.manualMap.selectedDiffs.indexOf(id) !== -1;
            },

            allManualDiffsSelected: function (): boolean {
                if (!this.manualMap.info || !this.manualMap.info.diffs.length) return false;
                return this.manualMap.selectedDiffs.length === this.manualMap.info.diffs.length;
            },

            executeManualAction: function () {
                var self = this;
                if (!self.manualMap.info || !self.manualMap.action) return;
                if (!self.manualMap.selectedDiffs.length) {
                    self.showToast('error', 'Select at least one difficulty.');
                    return;
                }
                if (self.manualMap.action === 'unrank' && !self.manualMap.reason.trim()) {
                    self.showToast('error', 'Reason required for unranking.');
                    return;
                }

                var labels: { [key: string]: string } = {
                    'rank': 'Rank', 'approve': 'Approve', 'qualify': 'Qualify',
                    'love': 'Love', 'unrank': 'Unrank',
                };
                var count = self.manualMap.selectedDiffs.length;

                self.confirmDialog = {
                    show: true,
                    title: labels[self.manualMap.action] + ' ' + count + ' difficulty(ies)?',
                    message: self.manualMap.info.artist + ' - ' + self.manualMap.info.title + ' (set ' + self.manualMap.info.set_id + ')',
                    action: 'manual_map_action',
                    needsReason: false,
                    needsDuration: false,
                    needsPassword: false,
                    reason: self.manualMap.reason,
                    duration: 0,
                    password: '',
                    targetId: self.manualMap.info.set_id,
                };
            },

            doManualAction: function () {
                var self = this;
                self.manualMap.executing = true;

                adminApi('manual-map-action', {
                    method: 'POST',
                    body: JSON.stringify({
                        set_id: self.manualMap.info.set_id,
                        map_ids: self.manualMap.selectedDiffs.slice(),
                        action: self.manualMap.action,
                        reason: self.manualMap.reason,
                    }),
                }).then(function (data: any) {
                    self.manualMap.executing = false;
                    self.manualMap.result = {
                        message: data.message,
                        count: data.count,
                        set_id: self.manualMap.info.set_id,
                    };
                    self.showToast('success', data.message);
                }).catch(function (e: any) {
                    self.manualMap.executing = false;
                    self.showToast('error', e.message);
                });
            },

            resetManualMap: function () {
                this.manualMap = {
                    input: '',
                    info: null,
                    loading: false,
                    error: '',
                    selectedDiffs: [],
                    action: '',
                    reason: '',
                    executing: false,
                    result: null,
                    ppTable: { show: false, loading: false, mods: 0, data: null, cache: {}, error: '' },
                };
            },

        // ── Manual Map PP Table ───────────────────────────────

            toggleManualPP: function () {
                var pp = this.manualMap.ppTable;
                pp.show = !pp.show;
                if (pp.show && !pp.data) {
                    this.fetchManualPP();
                }
            },

            toggleManualPPMod: function (bit: number) {
                var pp = this.manualMap.ppTable;
                if (bit === 2 && (pp.mods & 16)) { pp.mods &= ~16; }
                if (bit === 16 && (pp.mods & 2)) { pp.mods &= ~2; }
                if (bit === 64 && (pp.mods & 256)) { pp.mods &= ~256; }
                if (bit === 256 && (pp.mods & 64)) { pp.mods &= ~64; }
                pp.mods ^= bit;
                this.fetchManualPP();
            },

            setManualPPCombo: function (mods: number) {
                this.manualMap.ppTable.mods = mods;
                this.fetchManualPP();
            },

            isManualPPModActive: function (bit: number): boolean {
                return (this.manualMap.ppTable.mods & bit) !== 0;
            },

            fetchManualPP: function () {
                var self = this;
                var pp = self.manualMap.ppTable;
                var info = self.manualMap.info;
                if (!info || !info.diffs) return;

                var cacheKey = '' + pp.mods;
                if (pp.cache[cacheKey]) {
                    pp.data = pp.cache[cacheKey];
                    pp.error = '';
                    return;
                }

                pp.loading = true;
                pp.error = '';
                var ids = info.diffs.map(function (d: any) { return d.id; }).join(',');

                fetch('/admin-v2/api/beatmaps/pp-table?ids=' + ids + '&mods=' + pp.mods)
                    .then(function (res: any) { return res.json(); })
                    .then(function (data: any) {
                        if (data.status === 'success') {
                            pp.cache[cacheKey] = data.results;
                            pp.data = data.results;
                            pp.error = '';
                        } else {
                            pp.error = data.message || 'Failed to fetch PP data.';
                        }
                        pp.loading = false;
                    })
                    .catch(function (e: any) {
                        pp.error = e.message || 'Network error.';
                        pp.loading = false;
                    });
            },

            getManualPPValue: function (diffId: number, accIdx: number): string {
                var pp = this.manualMap.ppTable;
                if (!pp.data || !pp.data[diffId]) return '\u2014';
                var entry = pp.data[diffId];
                if (entry.error) return 'err';
                if (entry.pp_values && entry.pp_values[accIdx]) {
                    return Math.round(entry.pp_values[accIdx].pp) + 'pp';
                }
                return '\u2014';
            },

            getManualPPStars: function (diffId: number, fallback: number): string {
                var pp = this.manualMap.ppTable;
                if (!pp.data || !pp.data[diffId]) return (fallback || 0).toFixed(2);
                var entry = pp.data[diffId];
                if (entry.difficulty && entry.difficulty.stars != null) {
                    return entry.difficulty.stars.toFixed(2);
                }
                return (fallback || 0).toFixed(2);
            },

            viewStaffLogForSet: function (setId: number) {
                this.staffLog.filters = {
                    staff_id: '', action_type: '1', action: '',
                    from_date: '', to_date: '', search: '',
                };
                this.navigateTo('staff-log');
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
