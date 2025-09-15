// Wait for Vue to be available
if (typeof Vue !== 'undefined') {
    new Vue({
        el: "#app",
        delimiters: ["<%", "%>"],
        data() {
            return {
                flags: window.flags || {},
                boards: [],
                mode: window.mode || 'std',
                mods: window.mods || 'vn',
                sort: window.sort || 'pp',
                page: 1,
                pageSize: 50,
                load: false,
                no_player: false, // soon
            };
        },
        mounted() {
            // Initialize after DOM is ready
            this.LoadData(this.mode, this.mods, this.sort);
            this.LoadLeaderboard(this.sort, this.mode, this.mods);
        },
        methods: {
            LoadData(mode, mods, sort) {
                this.$set(this, 'mode', mode);
                this.$set(this, 'mods', mods);
                this.$set(this, 'sort', sort);
            },
            LoadLeaderboard(sort, mode, mods) {
                if (window.event)
                    window.event.preventDefault();
            
                window.history.replaceState('', document.title, `/leaderboard/${this.mode}/${this.sort}/${this.mods}`);
                this.$set(this, 'mode', mode);
                this.$set(this, 'mods', mods);
                this.$set(this, 'sort', sort);
                this.$set(this, 'load', true);
                const offset = (this.page - 1) * this.pageSize; // Calculate the offset
                // Use local API if hinaDebug is enabled, otherwise use production API
                const apiUrl = window.hinaDebug
                    ? `${window.location.protocol}//${window.location.host}/api/v1/get_leaderboard`
                    : `${window.location.protocol}//api.${window.domain ? window.domain.split(':')[0] : window.location.hostname}/v1/get_leaderboard`;
                this.$axios.get(apiUrl, {
                    params: {
                        mode: this.StrtoGulagInt(),
                        sort: this.sort,
                        offset: offset, // Use the offset here
                        limit: this.pageSize // Use 'limit' instead of 'pageSize'
                    }
                }).then(res => {
                    this.boards = res.data.leaderboard || [];
                    this.$set(this, 'load', false);
                }).catch(err => {
                    console.error('Error loading leaderboard:', err);
                    this.boards = [];
                    this.$set(this, 'load', false);
                });
            },
            scoreFormat(score) {
                var addCommas = this.addCommas;
                if (score > 1000 * 1000) {
                    if (score > 1000 * 1000 * 1000)
                        return `${addCommas((score / 1000000000).toFixed(2))} billion`;
                    return `${addCommas((score / 1000000).toFixed(2))} million`;
                }
                return addCommas(score);
            },
            addCommas(nStr) {
                nStr += '';
                var x = nStr.split('.');
                var x1 = x[0];
                var x2 = x.length > 1 ? '.' + x[1] : '';
                var rgx = /(\d+)(\d{3})/;
                while (rgx.test(x1)) {
                    x1 = x1.replace(rgx, '$1' + ',' + '$2');
                }
                return x1 + x2;
            },
            StrtoGulagInt() {
                switch (this.mode + "|" + this.mods) {
                    case 'std|vn':
                        return 0;
                    case 'taiko|vn':
                        return 1;
                    case 'catch|vn':
                        return 2;
                    case 'mania|vn':
                        return 3;
                    case 'std|rx':
                        return 4;
                    case 'taiko|rx':
                        return 5;
                    case 'catch|rx':
                        return 6;
                    case 'std|ap':
                        return 8;
                    default:
                        return -1;
                }
            },
            changePage(page) {
                this.page = page;
                this.LoadLeaderboard(this.sort, this.mode, this.mods);
            },
            getRank(index) {
                return (this.page - 1) * this.pageSize + index + 1;
            },
            goToProfile(playerId) {
                window.location.href = `/u/${playerId}`;
            },
            handleAvatarError(event) {
                // Fallback to GitHub avatar on error
                event.target.src = 'https://avatars.githubusercontent.com/u/15048157?v=4';
            },
        },
    });
} else {
    console.error('Vue is not loaded');
}