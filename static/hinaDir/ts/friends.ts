declare const Vue: any;
declare const domain: string;
declare const userId: number;
declare const timeago: any;

interface FriendUser {
    id: number;
    name: string;
    safe_name: string;
    country: string;
    clan_name: string | null;
    clan_tag: string | null;
    latest_activity: number;
}

new Vue({
    el: '#friends-app',
    data: {
        tab: 'mutuals' as string,
        mutuals: [] as FriendUser[],
        followers: [] as FriendUser[],
        blocked: [] as FriendUser[],
        loading: true,
        error: null as string | null,
        actionLoading: {} as Record<number, boolean>,
    },
    created() {
        this.loadAll();
    },
    methods: {
        async loadAll() {
            this.loading = true;
            this.error = null;
            try {
                var res = await fetch(
                    location.protocol + '//api.' + domain + '/v1/get_friends_detailed?id=' + userId + '&scope=all'
                );
                if (!res.ok) throw new Error('API returned ' + res.status);
                var data = await res.json();
                if (data.status !== 'success') throw new Error(data.status || 'Unknown error');
                this.mutuals = data.mutuals || [];
                this.followers = data.followers || [];
                this.blocked = data.blocked || [];
            } catch (e: any) {
                this.error = 'Failed to load friends data.';
                console.error('[Friends]', e);
            }
            this.loading = false;
        },

        switchTab(t: string) {
            this.tab = t;
        },

        async doAction(action: string, targetId: number) {
            this.$set(this.actionLoading, targetId, true);
            try {
                var fd = new FormData();
                fd.append('target_id', String(targetId));
                var res = await fetch('/friends/' + action, { method: 'POST', body: fd });
                if (!res.ok) {
                    var errData = await res.json().catch(function() { return {}; });
                    throw new Error(errData.status || 'Request failed');
                }
                await this.loadAll();
            } catch (e: any) {
                console.error('[Friends] Action failed:', e);
            }
            this.$set(this.actionLoading, targetId, false);
        },

        addFriend(id: number) { this.doAction('add', id); },
        removeFriend(id: number) { this.doAction('remove', id); },
        blockUser(id: number) { this.doAction('block', id); },
        unblockUser(id: number) { this.doAction('unblock', id); },

        avatarUrl(id: number): string {
            return 'https://a.' + domain + '/' + id;
        },
        profileUrl(id: number): string {
            return '/u/' + id;
        },
        lastSeen(ts: number): string {
            if (!ts) return 'Never seen';
            try {
                return timeago.format(ts * 1000);
            } catch (e) {
                return 'Unknown';
            }
        },
    }
});
