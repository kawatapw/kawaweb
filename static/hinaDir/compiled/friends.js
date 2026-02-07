var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
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
    },
    created() {
        this.loadAll();
    },
    methods: {
        loadAll() {
            return __awaiter(this, void 0, void 0, function* () {
                this.loading = true;
                this.error = null;
                try {
                    var res = yield fetch(location.protocol + '//api.' + domain + '/v1/get_friends_detailed?id=' + userId + '&scope=all');
                    if (!res.ok)
                        throw new Error('API returned ' + res.status);
                    var data = yield res.json();
                    if (data.status !== 'success')
                        throw new Error(data.status || 'Unknown error');
                    this.mutuals = data.mutuals || [];
                    this.followers = data.followers || [];
                    this.blocked = data.blocked || [];
                }
                catch (e) {
                    this.error = 'Failed to load friends data.';
                    console.error('[Friends]', e);
                }
                this.loading = false;
            });
        },
        switchTab(t) {
            this.tab = t;
        },
        doAction(action, targetId) {
            return __awaiter(this, void 0, void 0, function* () {
                this.$set(this.actionLoading, targetId, true);
                try {
                    var fd = new FormData();
                    fd.append('target_id', String(targetId));
                    var res = yield fetch('/friends/' + action, { method: 'POST', body: fd });
                    if (!res.ok) {
                        var errData = yield res.json().catch(function () { return {}; });
                        throw new Error(errData.status || 'Request failed');
                    }
                    yield this.loadAll();
                }
                catch (e) {
                    console.error('[Friends] Action failed:', e);
                }
                this.$set(this.actionLoading, targetId, false);
            });
        },
        addFriend(id) { this.doAction('add', id); },
        removeFriend(id) { this.doAction('remove', id); },
        blockUser(id) { this.doAction('block', id); },
        unblockUser(id) { this.doAction('unblock', id); },
        avatarUrl(id) {
            return 'https://a.' + domain + '/' + id;
        },
        profileUrl(id) {
            return '/u/' + id;
        },
        lastSeen(ts) {
            if (!ts)
                return 'Never seen';
            try {
                return timeago.format(ts * 1000);
            }
            catch (e) {
                return 'Unknown';
            }
        },
    }
});
